# device_sample_001: Smart Card SPDM Responder Mock

## Overview
This is a variant of `spdm-device-sample` configured to mock a **PCI Smart Card** device using SPDM attestation.

## Changes Made for Smart Card Profile

### 1. **Certificates & Cryptography** (`library/spdm_device_secret_lib/`)
- Generated new ECP384 curve certificates with smart card identity:
  - **Root CA**: `CN=Smart Card Test Root CA, O=Sample Device`
  - **Intermediate**: `CN=Smart Card Test Intermediate, O=Sample Device`  
  - **Device Cert**: `CN=Smart Card Sample Device, O=Sample Device`
- PEM files saved (can be converted to DER for `bin/` as needed):
  - `smartcard_root_ca.pem`, `smartcard_root_ca.der`
  - `smartcard_intermediate.pem`, `smartcard_intermediate.der`
  - `smartcard_responder.crt`, `smartcard_responder.der`
  - `smartcard_responder_key.pem`, `smartcard_responder_key.der`

### 2. **Measurements** (`library/spdm_device_secret_lib/meas.c`)
Updated to reflect smart card firmware profile:
- **SVN (Secure Version Number)**: `0x0A` (firmware v1.0)
  - Updated in `libspdm_fill_measurement_svn_block()` to use `LIBSPDM_SMARTCARD_SVN`
  
- **Device Mode**: No debug modes active
  - Changed `device_mode_state` from debug flags to `0` (production mode)
  - Reflects a locked-down smart card with no active debug interfaces
  
- **Manifest & Firmware Hashes**: Preserved (indices 1-4 for firmware components)

### 3. **PCI IDE Key Management** (`library/pci_ide_km_device_lib/pci_ide_km_device_context.c`)
Updated device addressing for smart card slot:
- **PCI Device**: `0x1f` (typical smart card slot device ID)
- **Bus**: `0` (root bus)
- **Segment**: `0`
- **Max IDE Streams**: `3` (reduced from 7 for smart card)

### 4. **PCI TDISP Interface** (`library/pci_tdisp_device_lib/pci_tdisp_device_context.c`)
Updated device capabilities:
- **Address Width**: `40 bits` (instead of 48) —smart cards typically use narrower addressing

### 5. **SPDM Responder Capabilities** (`spdm_device_responder/spdm_responder_init.c`)
Stripped down to smart card essentials:
- Removed: Encryption, MAC, Key Exchange, Encapsulation, Heartbeat, Key Update
- Kept:
  - `CERT_CAP` — certificate presentation
  - `MEAS_CAP_SIG` — measurement signatures for attestation
- **Crypto Stack**: Still uses ECP384 + SHA-384 (industry standard for smart cards)
- **SPDM Version**: 1.2

### 6. **Measurement Constants** (`library/spdm_device_secret_lib/spdm_device_secret_lib_internal.h`)
Added smart card-specific constants:
```c
#define LIBSPDM_SMARTCARD_SVN 0x0A
#define LIBSPDM_SMARTCARD_FIRMWARE_VERSION 0x01020304
```

## File Structure

```
device_sample_001/
└── spdm_device_sample/
    ├── CMakeLists.txt                    (project name: "spdm-device-001")
    ├── spdm_device_responder/
    │   ├── spdm_responder_init.c         (reduced capabilities)
    │   ├── spdm_responder.h
    │   ├── spdm_responder_main.c
    │   └── ... (other responder files)
    └── library/
        ├── spdm_device_secret_lib/
        │   ├── meas.c                    (smart card measurements)
        │   ├── spdm_device_secret_lib_internal.h
        │   ├── bin/
        │   │   ├── ecp384_*.c            (original key/cert arrays — can replace)
        │   │   └── ... (other arrays)
        │   ├── *.pem, *.der              (new smart card certs)
        │   └── ... (other secret files)
        ├── pci_ide_km_device_lib/
        │   ├── pci_ide_km_device_context.c  (PCI device 0x1f, max 3 ports)
        │   └── ... (other IDE KM files)
        ├── pci_tdisp_device_lib/
        │   ├── pci_tdisp_device_context.c   (40-bit address width)
        │   └── ... (other TDISP files)
        └── ... (other library modules)
```

## Building

Same process as `spdm-device-sample`, with additional smart card cert/key files:

```bash
cd device_sample_001/spdm_device_sample
cmake \
  -DARCH=x64 \
  -DTOOLCHAIN=GCC \
  -DTARGET=Debug \
  -DCRYPTO=mbedtls \
  .
make
```

## Smart Card Simulation Behavior

When queried via SPDM, the device will report:
- **Certificates**: Smart Card CA chain (ECP384)
- **Measurements**:
  - Firmware hash blocks (indices 1-4)
  - **SVN = 0x0A** (firmware version 1.0)
  - **Device Mode**: `0x00` (normal, no debug)
  - Manifest & opaque data
- **No Encryption**: Reflects a simple attestation-only card
- **PCI Addressing**: Bus 0, Device 0x1f (slot device)

## Next Steps

1. **Replace Certificate Arrays**: Convert `smartcard_*.der` files to hex C arrays if desired, replacing `bin/ecp384_*.c`
2. **Test with Verifier**: Use an SPDM requester/verifier to validate certificate chain and measurements
3. **Customize Further**: Modify measurements, manifest content, or device IDs as needed for your use case

---

**Notes**:
- All relative paths (`../../libspdm`, `../..`) remain valid from the new folder location
- Project compiles standalone and can be built/tested independently from `spdm-device-sample`
