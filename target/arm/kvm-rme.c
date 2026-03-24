/*
 * QEMU Arm RME support
 *
 * Copyright Linaro 2024
 * Copyright NVIDIA 2025
 *
 * Ported to v12 CCA host patches (KVM_CAP_ARM_RMI interface).
 * v12 differences from older RME interface:
 *   - No config step (RPV, hash algo, MEC not in v12)
 *   - No explicit create/activate (realm created on first populate,
 *     activated on first KVM_RUN)
 *   - No INIT_RIPAS (kernel does set_ripas_of_protected_regions at activation)
 *   - Populate via KVM_ARM_RMI_POPULATE ioctl with source_uaddr
 *   - No KVM_ARM_VCPU_REC feature bit or finalize step
 */

#include "qemu/osdep.h"

#include "hw/boards.h"
#include "hw/loader.h"
#include "hw/pci/pci.h"
#include "kvm_arm.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qom/object_interfaces.h"
#include "migration/blocker.h"
#include "system/confidential-guest-support.h"
#include "system/kvm.h"
#include "system/runstate.h"
#include "system/address-spaces.h"
#include "system/ram_addr.h"

#define TYPE_RME_GUEST "rme-guest"
OBJECT_DECLARE_SIMPLE_TYPE(RmeGuest, RME_GUEST)

#define RME_PAGE_SIZE qemu_real_host_page_size()

/*
 * Realms have a split guest-physical address space: the bottom half is private
 * to the realm, and the top half is shared with the host. Within QEMU, we use a
 * merged view of both halves. Most of RAM is private to the guest and not
 * accessible to us, but the guest shares some pages with us.
 *
 * For DMA, devices generally target the shared half (top) of the guest address
 * space. Only the devices trusted by the guest (using mechanisms like TDISP for
 * device authentication) can access the bottom half.
 *
 * RealmDmaRegion performs remapping of top-half accesses to system memory.
 */
struct RealmDmaRegion {
    IOMMUMemoryRegion parent_obj;
};

#define TYPE_REALM_DMA_REGION "realm-dma-region"
OBJECT_DECLARE_SIMPLE_TYPE(RealmDmaRegion, REALM_DMA_REGION)
OBJECT_DEFINE_SIMPLE_TYPE(RealmDmaRegion, realm_dma_region,
                          REALM_DMA_REGION, IOMMU_MEMORY_REGION);

typedef struct RealmRamDiscardListener {
    MemoryRegion *mr;
    hwaddr offset_within_address_space;
    uint64_t granularity;
    RamDiscardListener listener;
    QLIST_ENTRY(RealmRamDiscardListener) rrdl_next;
} RealmRamDiscardListener;

typedef struct {
    hwaddr base;
    hwaddr size;
    uint8_t *blob_ptr;
} RmeRamRegion;

struct RmeGuest {
    ConfidentialGuestSupport parent_obj;
    Notifier rom_load_notifier;
    GSList *ram_regions;

    RmeRamRegion init_ram;
    uint8_t ipa_bits;
    size_t num_cpus;

    RealmDmaRegion *dma_region;
    QLIST_HEAD(, RealmRamDiscardListener) ram_discard_list;
    MemoryListener memory_listener;
    AddressSpace dma_as;
};

OBJECT_DEFINE_SIMPLE_TYPE_WITH_INTERFACES(RmeGuest, rme_guest, RME_GUEST,
                                          CONFIDENTIAL_GUEST_SUPPORT,
                                          { TYPE_USER_CREATABLE }, { })

static RmeGuest *rme_guest;

/*
 * Populate a range of realm memory via KVM_ARM_RMI_POPULATE ioctl.
 *
 * v12 requires source_uaddr: the host VA of the page data. Since ROM data
 * has already been written to guest RAM by rom_reset() before we get here,
 * we can obtain the host VA via qemu_map_ram_ptr().
 */
static int rme_populate_range(hwaddr base, size_t size, bool measure,
                              Error **errp)
{
    int ret;
    hwaddr start = QEMU_ALIGN_DOWN(base, RME_PAGE_SIZE);
    hwaddr end = QEMU_ALIGN_UP(base + size, RME_PAGE_SIZE);
    void *host;
    struct kvm_arm_rmi_populate populate_args = {
        .base = start,
        .size = end - start,
        .flags = measure ? KVM_ARM_RMI_POPULATE_FLAGS_MEASURE : 0,
        .reserved = 0,
    };

    /* Mark the region as private before populating */
    ret = kvm_set_memory_attributes_private(start, end - start);
    if (ret) {
        error_setg_errno(errp, -ret,
                   "failed to set private attributes [0x%"HWADDR_PRIx", 0x%"HWADDR_PRIx")",
                   start, end);
        return ret;
    }

    /*
     * Translate GPA to host VA.  memory_region_find resolves the GPA through
     * the system address space; qemu_map_ram_ptr then gives us the mmap'd
     * host pointer that get_user_pages() in the kernel can resolve.
     */
    {
        MemoryRegionSection section = memory_region_find(get_system_memory(),
                                                         start, end - start);
        if (!section.mr || !memory_region_is_ram(section.mr)) {
            error_setg(errp, "no RAM at GPA 0x%" HWADDR_PRIx, start);
            return -EINVAL;
        }
        host = qemu_map_ram_ptr(section.mr->ram_block,
                                section.offset_within_region);
        memory_region_unref(section.mr);
    }
    populate_args.source_uaddr = (__u64)(uintptr_t)host;

    /*
     * Loop to handle partial population (kernel may process in chunks).
     * With _IOWR the kernel updates populate_args in-place (advancing
     * base/source_uaddr, reducing size), so no manual adjustment needed.
     */
    while (populate_args.size > 0) {
        ret = kvm_vm_ioctl(kvm_state, KVM_ARM_RMI_POPULATE, &populate_args);
        if (ret < 0) {
            error_setg_errno(errp, -ret,
                       "failed to populate realm [0x%"HWADDR_PRIx", 0x%"HWADDR_PRIx")",
                       start, end);
            return ret;
        }
    }
    return 0;
}

static void rme_populate_ram_region(gpointer data, gpointer err)
{
    Error **errp = err;
    const RmeRamRegion *region = data;

    if (*errp) {
        return;
    }

    rme_populate_range(region->base, region->size, /* measure */ true, errp);
}

static gint rme_compare_ram_regions(gconstpointer a, gconstpointer b)
{
        const RmeRamRegion *ra = a;
        const RmeRamRegion *rb = b;

        g_assert(ra->base != rb->base);
        return ra->base < rb->base ? -1 : 1;
}

static void rme_rom_load_notify(Notifier *notifier, void *data)
{
    RmeRamRegion *region;
    RomLoaderNotifyData *rom = data;

    if (rom->addr == -1) {
        /*
         * These blobs (ACPI tables) are not loaded into guest RAM at reset.
         * Instead the firmware will load them via fw_cfg and measure them
         * itself.
         */
        return;
    }

    region = g_new0(RmeRamRegion, 1);
    region->base = rom->addr;
    region->size = rom->len;
    /*
     * TODO: double-check lifetime. Is data is still available when we measure
     * it, while writing the log. Should be fine since data is kept for the next
     * reset.
     */
    region->blob_ptr = rom->blob_ptr;

    /*
     * The Realm Initial Measurement (RIM) depends on the order in which we
     * initialize and populate the RAM regions. To help a verifier
     * independently calculate the RIM, sort regions by GPA.
     */
    rme_guest->ram_regions = g_slist_insert_sorted(rme_guest->ram_regions,
                                                   region,
                                                   rme_compare_ram_regions);
}

/*
 * Create and prepare the realm.
 *
 * v12 flow:
 *   1. Populate regions via KVM_ARM_RMI_POPULATE ioctl
 *      (realm is created implicitly on first populate)
 *   2. Mark guest state as protected
 *      (realm is activated implicitly on first KVM_RUN)
 */
static int rme_create_realm(Error **errp)
{
    /* Populate all ROM/image regions — first populate creates the realm */
    g_slist_foreach(rme_guest->ram_regions, rme_populate_ram_region, errp);
    g_slist_free_full(g_steal_pointer(&rme_guest->ram_regions), g_free);
    if (*errp) {
        return -1;
    }

    /* Realm will be activated implicitly on first KVM_RUN */
    kvm_mark_guest_state_protected();
    return 0;
}

static void rme_vm_state_change(void *opaque, bool running, RunState state)
{
    Error *err = NULL;

    if (!running) {
        return;
    }

    if (rme_create_realm(&err)) {
        error_propagate_prepend(&error_fatal, err, "RME: ");
    }
}

static void rme_guest_class_init(ObjectClass *oc, const void *data)
{
}

static void rme_guest_init(Object *obj)
{
    if (rme_guest) {
        error_report("a single instance of RmeGuest is supported");
        exit(1);
    }

    rme_guest = RME_GUEST(obj);
}

static void rme_guest_finalize(Object *obj)
{
    memory_listener_unregister(&rme_guest->memory_listener);
}

int kvm_arm_rme_init(MachineState *ms)
{
    static Error *rme_mig_blocker;
    ConfidentialGuestSupport *cgs = ms->cgs;

    if (!rme_guest) {
        return 0;
    }

    if (!cgs) {
        error_report("missing -machine confidential-guest-support parameter");
        return -EINVAL;
    }

    if (!kvm_check_extension(kvm_state, KVM_CAP_ARM_RMI)) {
        return -ENODEV;
    }

    rme_guest->num_cpus = ms->smp.max_cpus;

    error_setg(&rme_mig_blocker, "RME: migration is not implemented");
    migrate_add_blocker(&rme_mig_blocker, &error_fatal);

    /*
     * The realm activation is done last, when the VM starts, after all images
     * have been loaded and all vcpus finalized.
     */
    qemu_add_vm_change_state_handler(rme_vm_state_change, NULL);

    rme_guest->rom_load_notifier.notify = rme_rom_load_notify;
    rom_add_load_notifier(&rme_guest->rom_load_notifier);

    cgs->require_guest_memfd = true;
    cgs->ready = true;
    return 0;
}

void kvm_arm_rme_init_guest_ram(hwaddr base, size_t size)
{
    if (rme_guest) {
        rme_guest->init_ram.base = base;
        rme_guest->init_ram.size = size;
    }
}

int kvm_arm_rme_vcpu_init(CPUState *cs)
{
    ARMCPU *cpu = ARM_CPU(cs);

    if (rme_guest) {
        cpu->kvm_rme = true;
    }
    return 0;
}

int kvm_arm_rme_vm_type(MachineState *ms)
{
    if (rme_guest) {
        return KVM_VM_TYPE_ARM_REALM;
    }
    return 0;
}

static int rme_ram_discard_notify(RamDiscardListener *rdl,
                                  MemoryRegionSection *section,
                                  bool populate)
{
    hwaddr gpa, next;
    IOMMUTLBEvent event;
    const hwaddr end = section->offset_within_address_space +
                       int128_get64(section->size);
    const hwaddr address_mask = MAKE_64BIT_MASK(0, rme_guest->ipa_bits - 1);
    RealmRamDiscardListener *rrdl = container_of(rdl, RealmRamDiscardListener,
                                                 listener);

    assert(rme_guest->dma_region != NULL);

    event.type = populate ? IOMMU_NOTIFIER_MAP : IOMMU_NOTIFIER_UNMAP;
    event.entry.target_as = &address_space_memory;
    event.entry.perm = populate ? IOMMU_RW : IOMMU_NONE;
    event.entry.addr_mask = rrdl->granularity - 1;

    assert(end <= address_mask);

    /*
     * Create IOMMU mappings from the top half of the address space to the RAM
     * region.
     */
    for (gpa = section->offset_within_address_space; gpa < end; gpa = next) {
        event.entry.iova = gpa + address_mask + 1;
        event.entry.translated_addr = gpa;
        memory_region_notify_iommu(IOMMU_MEMORY_REGION(rme_guest->dma_region),
                                   0, event);

        next = ROUND_UP(gpa + 1, rrdl->granularity);
        next = MIN(next, end);
    }

    return 0;
}

static int rme_ram_discard_notify_populate(RamDiscardListener *rdl,
                                           MemoryRegionSection *section)
{
    return rme_ram_discard_notify(rdl, section, /* populate */ true);
}

static void rme_ram_discard_notify_discard(RamDiscardListener *rdl,
                                          MemoryRegionSection *section)
{
    rme_ram_discard_notify(rdl, section, /* populate */ false);
}

/* Install a RAM discard listener */
static void rme_listener_region_add(MemoryListener *listener,
                                    MemoryRegionSection *section)
{
    RealmRamDiscardListener *rrdl;
    RamDiscardManager *rdm = memory_region_get_ram_discard_manager(section->mr);

    if (!rdm) {
        return;
    }

    rrdl = g_new0(RealmRamDiscardListener, 1);
    rrdl->mr = section->mr;
    rrdl->offset_within_address_space = section->offset_within_address_space;
    rrdl->granularity = ram_discard_manager_get_min_granularity(rdm,
                                                                section->mr);
    QLIST_INSERT_HEAD(&rme_guest->ram_discard_list, rrdl, rrdl_next);

    ram_discard_listener_init(&rrdl->listener,
                              rme_ram_discard_notify_populate,
                              rme_ram_discard_notify_discard, true);
    ram_discard_manager_register_listener(rdm, &rrdl->listener, section);
}

static void rme_listener_region_del(MemoryListener *listener,
                                    MemoryRegionSection *section)
{
    RealmRamDiscardListener *rrdl;
    RamDiscardManager *rdm = memory_region_get_ram_discard_manager(section->mr);

    if (!rdm) {
        return;
    }

    QLIST_FOREACH(rrdl, &rme_guest->ram_discard_list, rrdl_next) {
        if (rrdl->mr == section->mr && rrdl->offset_within_address_space ==
            section->offset_within_address_space) {
            ram_discard_manager_unregister_listener(rdm, &rrdl->listener);
            g_free(rrdl);
            break;
        }
    }
}

static AddressSpace *rme_dma_get_address_space(PCIBus *bus, void *opaque,
                                               int devfn)
{
    return &rme_guest->dma_as;
}

static const PCIIOMMUOps rme_dma_ops = {
    .get_address_space = rme_dma_get_address_space,
};

void kvm_arm_rme_init_gpa_space(hwaddr highest_gpa, PCIBus *pci_bus)
{
    RealmDmaRegion *dma_region;
    const unsigned int ipa_bits = 64 - clz64(highest_gpa) + 1;

    if (!rme_guest) {
        return;
    }

    assert(ipa_bits < 64);

    /*
     * Setup a DMA translation from the shared top half of the guest-physical
     * address space to our merged view of RAM.
     */
    dma_region = g_new0(RealmDmaRegion, 1);

    memory_region_init_iommu(dma_region, sizeof(*dma_region),
                             TYPE_REALM_DMA_REGION, OBJECT(rme_guest),
                             "realm-dma-region", 1ULL << ipa_bits);
    address_space_init(&rme_guest->dma_as, MEMORY_REGION(dma_region),
                       TYPE_REALM_DMA_REGION);
    rme_guest->dma_region = dma_region;

    pci_setup_iommu(pci_bus, &rme_dma_ops, NULL);

    /*
     * Install notifiers to forward RAM discard changes to the IOMMU notifiers
     * (ie. tell VFIO to map shared pages and unmap private ones).
     */
    rme_guest->memory_listener = (MemoryListener) {
        .name = "rme",
        .region_add = rme_listener_region_add,
        .region_del = rme_listener_region_del,
    };
    memory_listener_register(&rme_guest->memory_listener,
                             &address_space_memory);

    rme_guest->ipa_bits = ipa_bits;
}

static void realm_dma_region_init(Object *obj)
{
}

static IOMMUTLBEntry realm_dma_region_translate(IOMMUMemoryRegion *mr,
                                                hwaddr addr,
                                                IOMMUAccessFlags flag,
                                                int iommu_idx)
{
    const hwaddr address_mask = MAKE_64BIT_MASK(0, rme_guest->ipa_bits - 1);
    IOMMUTLBEntry entry = {
        .target_as = &address_space_memory,
        .iova = addr,
        .translated_addr = addr & address_mask,
        /*
         * Somewhat arbitrary granule for users that need one, such as
         * address_space_get_iotlb_entry(). Should be relatively large to
         * avoid frequent TLB misses. It can't be larger than memory region
         * alignment (eg. address_mask) because that would mask the whole
         * address, preventing vhost from finding the correct memory region.
         */
        .addr_mask = 4 * KiB - 1,
        .perm = IOMMU_RW,
    };

    return entry;
}

static void realm_dma_region_replay(IOMMUMemoryRegion *mr, IOMMUNotifier *n)
{
    /* Nothing is shared at boot */
}

static void realm_dma_region_finalize(Object *obj)
{
}

static void realm_dma_region_class_init(ObjectClass *oc, const void *data)
{
    IOMMUMemoryRegionClass *imrc = IOMMU_MEMORY_REGION_CLASS(oc);

    imrc->translate = realm_dma_region_translate;
    imrc->replay = realm_dma_region_replay;
}

Object *kvm_arm_rme_get_measurement_log(void)
{
    return NULL;
}
