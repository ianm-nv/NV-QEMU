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
#include "kvm_arm.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qom/object_interfaces.h"
#include "system/confidential-guest-support.h"
#include "system/kvm.h"

#define TYPE_RME_GUEST "rme-guest"
OBJECT_DECLARE_SIMPLE_TYPE(RmeGuest, RME_GUEST)

struct RmeGuest {
    ConfidentialGuestSupport parent_obj;
};

OBJECT_DEFINE_SIMPLE_TYPE_WITH_INTERFACES(RmeGuest, rme_guest, RME_GUEST,
                                          CONFIDENTIAL_GUEST_SUPPORT,
                                          { TYPE_USER_CREATABLE }, { })

static RmeGuest *rme_guest;

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

    cgs->require_guest_memfd = true;
    cgs->ready = true;
    return 0;
}

void kvm_arm_rme_init_guest_ram(hwaddr base, size_t size)
{
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
