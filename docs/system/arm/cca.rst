.. _arm-cca:

ARM Confidential Compute Architecture (CCA)
===========================================

ARM Confidential Compute Architecture (CCA) is an extension to the ARMv9-A
architecture that supports running encrypted virtual machines, called
*Realms*, whose memory and CPU state are protected from the hosting
hypervisor. Realms are managed by the Realm Management Monitor (RMM), a
firmware component running at the newly introduced Secure EL2 exception
level. The RMM boot flow, RMI (Realm Management Interface) commands and
Realm attribute definitions used by this code are specified in ARM DEN0137
"Realm Management Monitor Specification".

QEMU support here targets the *host* side: creating a Realm VM through
KVM, populating its initial memory image, and coordinating device
assignment and attestation with the RMM. The guest kernel and firmware
running inside the Realm are separate concerns.

Prerequisites
-------------

To launch a Realm, the host must have:

- A CPU implementing ARMv9-A with the Realm Management Extension (RME).
- An RMM firmware installed at S-EL2. Vendor firmware bundles typically
  package the RMM alongside the rest of the platform firmware; a system
  without an RMM will silently fall back to non-Realm operation.
- A Linux kernel that advertises ``KVM_CAP_ARM_RMI``. Currently this is
  only available in NVIDIA's ``linux-stable``
  ``dev/dev-main-nvidia-pset-linux-7.0.x`` branch; upstreaming to
  mainline is in progress.
- Guest firmware built for CCA (an AAVMF variant that understands the
  Realm boot handshake and consumes the measurement log described below).

If any of the above is missing, ``kvm_arm_rme_init`` returns
``-ENODEV`` at machine init and Realm creation aborts.

Launching a Realm
-----------------

A Realm is requested by attaching an ``rme-guest`` confidential-guest
object to the ``virt`` machine::

    qemu-system-aarch64 \
      -M virt,gic-version=3,confidential-guest-support=rme0 \
      -object rme-guest,id=rme0 \
      -cpu host \
      -accel kvm \
      -bios AAVMF_CODE.fd \
      -drive if=none,id=hd0,file=disk.qcow2,format=qcow2 \
      -device virtio-blk-pci,drive=hd0 \
      ...

The ``rme-guest`` object triggers ``KVM_VM_TYPE_ARM_REALM`` VM creation
and installs a vm-state-change handler. When the VM starts, QEMU:

1. Marks the RAM region backing the initial guest image as private
   with ``kvm_set_memory_attributes_private``.
2. Issues ``KVM_ARM_RMI_POPULATE`` for each ROM/image region the guest
   firmware and kernel will boot from, providing the host virtual
   address as ``source_uaddr``. The Realm is created implicitly on
   the first populate call.
3. Marks the guest state as protected and issues the first ``KVM_RUN``
   for the primary vCPU, which activates the Realm.

Only a single ``rme-guest`` instance is supported per QEMU process.

Realm object properties
-----------------------

The ``rme-guest`` object supports one property:

- ``measurement-log`` (bool): when ``on``, QEMU builds a TCG PC Client
  Platform Firmware Profile event log describing everything that was
  measured into the Realm Initial Measurement (RIM). The log is
  written into the Realm as an additional (unmeasured) memory region
  before activation, where it can be read by the guest firmware or a
  verifier. Default: off.

Measurement log
---------------

When ``measurement-log=on``, QEMU records the following events into a
TCG-format event log:

- an ``EV_NO_ACTION`` header identifying the VMM
  (``QEMU`` and its version string);
- an ``EV_EVENT_TAG`` describing the Realm parameters
  (IPA size, SVE / PMU flags, hash algorithm);
- an ``EV_EVENT_TAG`` recording the initial RIPAS ranges;
- one ``EV_POST_CODE2`` or ``EV_EFI_PLATFORM_FIRMWARE_BLOB2`` for each
  measured RAM region (kernel, initrd, DTB, firmware);
- an ``EV_EVENT_TAG`` for REC creation.

The log is *not* the RIM: the RIM is computed by the RMM from the
same inputs. The measurement log lets an independent verifier
reconstruct the same RIM value without trusting QEMU.

DEN0137 v2.0 defines SHA-256 and SHA-512 as mandatory measurement
algorithms; QEMU currently uses SHA-512 to match the v12 kernel
default.

Device assignment (RME-DA)
--------------------------

VFIO devices attached to a Realm are registered with the kernel via
``VFIO_DEVICE_SET_DEV_INFO`` on VM start, so the kernel can bind the
physical device to the Realm's security context. On kernels that lack
this ioctl, or on policies that block it, QEMU logs a warning and the
device is passed through without RME-DA binding. This is a temporary,
pre-standard mechanism that will be replaced by TSM/TDISP once
PCI-SIG's TEE Device Interface Security Protocol support lands.

QMP
---

``query-cca-capabilities`` reports the measurement algorithms QEMU
advertises. The current implementation returns the two DEN0137 v2.0
mandatory algorithms unconditionally; a future kernel/RMM interface
for enumerating the runtime-supported algorithm set would let this
become a real query.

Restrictions
------------

- **Migration is not supported.** ``rme-guest`` installs an
  unconditional migration blocker.
- **Only one Realm per QEMU process** (a single ``rme-guest`` singleton).
- **Guest firmware requirements are strict.** A non-CCA-aware AAVMF
  build will not boot in a Realm; use a firmware variant that
  implements the DEN0137 v2.0 Realm handshake.
- **No runtime algorithm negotiation.** The measurement algorithm is
  fixed at build time to match the kernel's RMM configuration.

References
----------

- ARM DEN0137 "Realm Management Monitor Specification", v2.0-bet2 or later.
- TCG PC Client Platform Firmware Profile Specification, Level 00
  Version 1.06 Revision 52, Family "2.0".
