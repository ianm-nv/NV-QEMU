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
#include "cpu.h"
#include "hw/core/cpu.h"
#include "hw/loader.h"
#include "hw/pci/pci.h"
#include "hw/tpm/tpm_log.h"
#include "internals.h"
#include "kvm_arm.h"
#include "qapi/error.h"
#include "qemu/base64.h"
#include "qemu/error-report.h"
#include "qemu/units.h"
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

#define RME_MEASUREMENT_LOG_SIZE    (64 * KiB)

typedef struct RmeLogFiletype {
    uint32_t event_type;
    /* Description copied into the log event */
    const char *desc;
} RmeLogFiletype;

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
    RmeLogFiletype *filetype;
} RmeRamRegion;

struct RmeGuest {
    ConfidentialGuestSupport parent_obj;
    Notifier rom_load_notifier;
    GSList *ram_regions;

    bool use_measurement_log;

    RmeRamRegion init_ram;
    uint8_t ipa_bits;
    size_t num_cpus;

    RealmDmaRegion *dma_region;
    QLIST_HEAD(, RealmRamDiscardListener) ram_discard_list;
    MemoryListener memory_listener;
    AddressSpace dma_as;

    TpmLog *log;
    GHashTable *images;
};

OBJECT_DEFINE_SIMPLE_TYPE_WITH_INTERFACES(RmeGuest, rme_guest, RME_GUEST,
                                          CONFIDENTIAL_GUEST_SUPPORT,
                                          { TYPE_USER_CREATABLE }, { })

typedef struct {
    char        signature[16];
    char        name[32];
    char        version[40];
    uint64_t    ram_size;
    uint32_t    num_cpus;
    uint64_t    flags;
} EventLogVmmVersion;

typedef struct {
    uint32_t    id;
    uint32_t    data_size;
    uint8_t     data[];
} EventLogTagged;

#define EVENT_LOG_TAG_REALM_CREATE  1
#define EVENT_LOG_TAG_INIT_RIPAS    2
#define EVENT_LOG_TAG_REC_CREATE    3

#define REALM_PARAMS_FLAG_SVE       (1 << 1)
#define REALM_PARAMS_FLAG_PMU       (1 << 2)

#define REC_CREATE_FLAG_RUNNABLE    (1 << 0)

static RmeGuest *rme_guest;

static int rme_init_measurement_log(MachineState *ms)
{
    Object *log;
    gpointer filename;
    TpmLogDigestAlgo algo;
    RmeLogFiletype *filetype;

    if (!rme_guest->use_measurement_log) {
        return 0;
    }

    /*
     * v12 kernel uses SHA512 by default for realm measurements.
     * Use SHA512 for the measurement log to match.
     */
    algo = TPM_LOG_DIGEST_ALGO_SHA512;

    log = object_new_with_props(TYPE_TPM_LOG, OBJECT(rme_guest),
                                "log", &error_fatal,
                                "digest-algo", TpmLogDigestAlgo_lookup.array[algo],
                                NULL);

    tpm_log_create(TPM_LOG(log), RME_MEASUREMENT_LOG_SIZE, &error_fatal);
    rme_guest->log = TPM_LOG(log);

    /*
     * Write down the image names we're expecting to encounter when handling the
     * ROM load notifications, so we can record the type of image being loaded
     * to help the verifier.
     */
    rme_guest->images = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
                                              g_free);

    filename = g_strdup(ms->kernel_filename);
    if (filename) {
        filetype = g_new0(RmeLogFiletype, 1);
        filetype->event_type = TCG_EV_POST_CODE2;
        filetype->desc = "KERNEL";
        g_hash_table_insert(rme_guest->images, filename, (gpointer)filetype);
    }

    filename = g_strdup(ms->initrd_filename);
    if (filename) {
        filetype = g_new0(RmeLogFiletype, 1);
        filetype->event_type = TCG_EV_POST_CODE2;
        filetype->desc = "INITRD";
        g_hash_table_insert(rme_guest->images, filename, (gpointer)filetype);
    }

    filename = g_strdup(ms->firmware);
    if (filename) {
        filetype = g_new0(RmeLogFiletype, 1);
        filetype->event_type = TCG_EV_EFI_PLATFORM_FIRMWARE_BLOB2;
        filetype->desc = "FIRMWARE";
        g_hash_table_insert(rme_guest->images, filename, filetype);
    }

    filename = g_strdup(ms->dtb);
    if (!filename) {
        filename = g_strdup("dtb");
    }
    filetype = g_new0(RmeLogFiletype, 1);
    filetype->event_type = TCG_EV_POST_CODE2;
    filetype->desc = "DTB";
    g_hash_table_insert(rme_guest->images, filename, filetype);

    return 0;
}

static int rme_log_event_tag(uint32_t id, uint8_t *data, size_t size,
                             Error **errp)
{
    int ret;
    EventLogTagged event = {
        .id = id,
        .data_size = size,
    };
    GByteArray *bytes = g_byte_array_new();

    if (!rme_guest->log) {
        return 0;
    }

    g_byte_array_append(bytes, (uint8_t *)&event, sizeof(event));
    g_byte_array_append(bytes, data, size);
    ret = tpm_log_add_event(rme_guest->log, TCG_EV_EVENT_TAG, bytes->data,
                             bytes->len, NULL, 0, errp);
    g_byte_array_free(bytes, true);
    return ret;
}

/* Log VM type and Realm Descriptor create */
static int rme_log_realm_create(Error **errp)
{
    int ret;
    ARMCPU *cpu;
    EventLogVmmVersion vmm_version = {
        .signature = "VM VERSION",
        .name = "QEMU",
        .version = QEMU_VERSION,
        .ram_size = cpu_to_le64(rme_guest->init_ram.size),
        .num_cpus = cpu_to_le32(rme_guest->num_cpus),
        .flags = 0,
    };
    struct {
        uint64_t    flags;
        uint8_t     s2sz;
        uint8_t     sve_vl;
        uint8_t     num_bps;
        uint8_t     num_wps;
        uint8_t     pmu_num_ctrs;
        uint8_t     hash_algo;
    } params = {
        .s2sz = rme_guest->ipa_bits,
        /* v12 kernel defaults to SHA512 */
        .hash_algo = 1, /* SHA512 */
    };

    if (!rme_guest->log) {
        return 0;
    }

    ret = tpm_log_add_event(rme_guest->log, TCG_EV_NO_ACTION,
                            (uint8_t *)&vmm_version, sizeof(vmm_version),
                            NULL, 0, errp);
    if (ret) {
        return ret;
    }

    /* With KVM all CPUs have the same capability */
    cpu = ARM_CPU(first_cpu);
    if (cpu->has_pmu) {
        params.flags |= REALM_PARAMS_FLAG_PMU;
        params.pmu_num_ctrs = FIELD_EX64(cpu->isar.reset_pmcr_el0, PMCR, N);
    }

    if (cpu->sve_max_vq) {
        params.flags |= REALM_PARAMS_FLAG_SVE;
        params.sve_vl = cpu->sve_max_vq - 1;
    }
    params.num_bps = FIELD_EX64_IDREG(&cpu->isar, ID_AA64DFR0, BRPS);
    params.num_wps = FIELD_EX64_IDREG(&cpu->isar, ID_AA64DFR0, WRPS);

    return rme_log_event_tag(EVENT_LOG_TAG_REALM_CREATE, (uint8_t *)&params,
                             sizeof(params), errp);
}

/* unmeasured images are logged with @data == NULL */
static int rme_log_image(RmeLogFiletype *filetype, uint8_t *data, hwaddr base,
                          size_t size, Error **errp)
{
    int ret;
    size_t desc_size;
    GByteArray *event = g_byte_array_new();
    struct UefiPlatformFirmwareBlob2Head head = {0};
    struct UefiPlatformFirmwareBlob2Tail tail = {0};

    if (!rme_guest->log) {
        return 0;
    }

    if (!filetype) {
        error_setg(errp, "cannot log image without a filetype");
        return -1;
    }

    /* EV_POST_CODE2 strings are not NUL-terminated */
    desc_size = strlen(filetype->desc);
    head.blob_description_size = desc_size;
    tail.blob_base = cpu_to_le64(base);
    tail.blob_size = cpu_to_le64(size);

    g_byte_array_append(event, (guint8 *)&head, sizeof(head));
    g_byte_array_append(event, (guint8 *)filetype->desc, desc_size);
    g_byte_array_append(event, (guint8 *)&tail, sizeof(tail));

    ret = tpm_log_add_event(rme_guest->log, filetype->event_type, event->data,
                            event->len, data, size, errp);
    g_byte_array_free(event, true);
    return ret;
}

static int rme_log_ripas(hwaddr base, size_t size, Error **errp)
{
    struct {
        uint64_t base;
        uint64_t size;
    } init_ripas = {
        .base = cpu_to_le64(base),
        .size = cpu_to_le64(size),
    };

    return rme_log_event_tag(EVENT_LOG_TAG_INIT_RIPAS, (uint8_t *)&init_ripas,
                             sizeof(init_ripas), errp);
}

static int rme_log_rec(uint64_t flags, uint64_t pc, uint64_t gprs[8], Error **errp)
{
    struct {
        uint64_t flags;
        uint64_t pc;
        uint64_t gprs[8];
    } rec_create = {
        .flags = cpu_to_le64(flags),
        .pc = cpu_to_le64(pc),
        .gprs[0] = cpu_to_le64(gprs[0]),
        .gprs[1] = cpu_to_le64(gprs[1]),
        .gprs[2] = cpu_to_le64(gprs[2]),
        .gprs[3] = cpu_to_le64(gprs[3]),
        .gprs[4] = cpu_to_le64(gprs[4]),
        .gprs[5] = cpu_to_le64(gprs[5]),
        .gprs[6] = cpu_to_le64(gprs[6]),
        .gprs[7] = cpu_to_le64(gprs[7]),
    };

    return rme_log_event_tag(EVENT_LOG_TAG_REC_CREATE, (uint8_t *)&rec_create,
                             sizeof(rec_create), errp);
}

static int rme_populate_range(hwaddr base, size_t size, bool measure,
                              Error **errp);

static int rme_close_measurement_log(Error **errp)
{
    int ret;
    hwaddr base;
    size_t size;
    RmeLogFiletype filetype = {
        .event_type = TCG_EV_POST_CODE2,
        .desc = "LOG",
    };

    if (!rme_guest->log) {
        return 0;
    }

    base = object_property_get_uint(OBJECT(rme_guest->log), "load-addr", errp);
    if (*errp) {
        return -1;
    }

    size = object_property_get_uint(OBJECT(rme_guest->log), "max-size", errp);
    if (*errp) {
        return -1;
    }

    /* Log the log itself */
    ret = rme_log_image(&filetype, NULL, base, size, errp);
    if (ret) {
        return ret;
    }

    ret = tpm_log_write_and_close(rme_guest->log, errp);
    if (ret) {
        return ret;
    }

    ret = rme_populate_range(base, size, /* measure */ false, errp);
    if (ret) {
        return ret;
    }

    g_hash_table_destroy(rme_guest->images);

    /* The log is now in the guest. Free this object */
    object_unparent(OBJECT(rme_guest->log));
    rme_guest->log = NULL;
    return 0;
}

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

    /* Loop to handle partial population (kernel may process in chunks) */
    while (populate_args.size > 0) {
        ret = kvm_vm_ioctl(kvm_state, KVM_ARM_RMI_POPULATE, &populate_args);
        if (ret < 0) {
            error_setg_errno(errp, -ret,
                       "failed to populate realm [0x%"HWADDR_PRIx", 0x%"HWADDR_PRIx")",
                       start, end);
            return ret;
        }
        populate_args.base += ret;
        populate_args.size -= ret;
        populate_args.source_uaddr += ret;
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
    if (*errp) {
        return;
    }

    rme_log_image(region->filetype, region->blob_ptr, region->base,
                  region->size, errp);
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
     * rme_guest->images is destroyed after ram_regions, so we can store
     * filetype even if we don't own the struct.
     */
    if (rme_guest->images) {
        region->filetype = g_hash_table_lookup(rme_guest->images, rom->name);
    }

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
 * Log REC creation for measurement log purposes.
 * v12 doesn't require explicit vcpu finalize or KVM_ARM_VCPU_REC.
 */
static int rme_log_cpus(Error **errp)
{
    int ret;
    CPUState *cs;
    bool logged_primary_cpu = false;

    CPU_FOREACH(cs) {
        ARMCPU *cpu = ARM_CPU(cs);

        if (!logged_primary_cpu) {
            ret = rme_log_rec(REC_CREATE_FLAG_RUNNABLE, cpu->env.pc,
                              cpu->env.xregs, errp);
            if (ret) {
                return ret;
            }

            logged_primary_cpu = true;
        }
    }
    return 0;
}

/*
 * Create and prepare the realm.
 *
 * v12 flow:
 *   1. Populate regions via KVM_ARM_RMI_POPULATE ioctl
 *      (realm is created implicitly on first populate)
 *   2. Log CPU state for measurement log
 *   3. Close measurement log
 *   4. Mark guest state as protected
 *      (realm is activated implicitly on first KVM_RUN)
 */
static int rme_create_realm(Error **errp)
{
    /* Log realm creation for measurement log */
    if (rme_log_realm_create(errp)) {
        return -1;
    }

    /* Log RIPAS for measurement log (kernel handles actual INIT_RIPAS) */
    if (rme_log_ripas(rme_guest->init_ram.base, rme_guest->init_ram.size,
                      errp)) {
        return -1;
    }

    /* Populate all ROM/image regions — first populate creates the realm */
    g_slist_foreach(rme_guest->ram_regions, rme_populate_ram_region, errp);
    g_slist_free_full(g_steal_pointer(&rme_guest->ram_regions), g_free);
    if (*errp) {
        return -1;
    }

    /* Log REC state for measurement log */
    if (rme_log_cpus(errp)) {
        return -1;
    }

    if (rme_close_measurement_log(errp)) {
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

static bool rme_get_measurement_log(Object *obj, Error **errp)
{
    RmeGuest *guest = RME_GUEST(obj);

    return guest->use_measurement_log;
}

static void rme_set_measurement_log(Object *obj, bool value, Error **errp)
{
    RmeGuest *guest = RME_GUEST(obj);

    guest->use_measurement_log = value;
}

static void rme_guest_class_init(ObjectClass *oc, const void *data)
{
    object_class_property_add_bool(oc, "measurement-log",
                                   rme_get_measurement_log,
                                   rme_set_measurement_log);
    object_class_property_set_description(oc, "measurement-log",
            "Enable/disable Realm measurement log");
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

    if (rme_init_measurement_log(ms)) {
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
    if (rme_guest && rme_guest->log) {
        return OBJECT(rme_guest->log);
    }
    return NULL;
}
