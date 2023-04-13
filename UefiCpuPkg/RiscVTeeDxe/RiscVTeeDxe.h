/** @file
  RISC-V TEE DXE module header file.

  Copyright (c) 2023, Ventana Micro Systems Inc. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef RISCV_TEE_DXE_H
#define RISCV_TEE_DXE_H

#include <PiDxe.h>

#include <Protocol/Cpu.h>
#include <Protocol/Timer.h>
#include <Library/BaseRiscVSbiLib.h>
#include <Library/BaseLib.h>
#include <Library/IoLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/CacheMaintenanceLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/CpuExceptionHandlerLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Register/RiscV64/RiscVImpl.h>
#include <Register/RiscV64/RiscVEncoding.h>
#include <Library/BaseRiscVSbiLib.h>
#include <Library/BaseRiscVTeeLib.h>

#include "MmCommunicate.h"

#define CSR_HTVAL   0x643
#define CSR_HTINST  0x64A

EFIAPI
UINT64 RiscVGetScauseRegister (VOID);

EFIAPI
UINT64 RiscVGetStvalRegister (VOID);

EFIAPI
EFI_STATUS RiscVTriggerMM (VOID);

#endif /* RISCV_TEE_DXE_H */
