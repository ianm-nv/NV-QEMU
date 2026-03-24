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

void kvm_arm_rme_init_gpa_space(hwaddr highest_gpa, PCIBus *pci_bus)
{
}

Object *kvm_arm_rme_get_measurement_log(void)
{
    return NULL;
}
