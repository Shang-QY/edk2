/** @file
  Entry point to the Standalone MM Foundation when initialized during the SEC
  phase on RISCV platforms

Copyright (c) 2017 - 2021, Arm Ltd. All rights reserved.<BR>
Copyright (c) 2023, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "Library/BaseRiscVSbiLib.h"
#include <PiMm.h>

#include <Library/StandaloneMmCpu.h>
#include <Library/RiscV64/StandaloneMmCoreEntryPoint.h>

#include <PiPei.h>
#include <Guid/MmramMemoryReserve.h>
#include <Guid/MpInformation.h>

#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/SerialPortLib.h>
#include <Library/PcdLib.h>


#define BOOT_PAYLOAD_VERSION  1

PI_MM_CPU_DRIVER_ENTRYPOINT  CpuDriverEntryPoint = NULL;

/**
  Retrieve a pointer to and print the boot information passed by privileged
  secure firmware.

  @param  [in] SharedBufAddress   The pointer memory shared with privileged
                                  firmware.

**/
EFI_RISCV_MM_BOOT_INFO *
GetAndPrintBootinformation (
  IN VOID  *BootInfoAddress
  )
{
  EFI_RISCV_MM_BOOT_INFO        *PayloadBootInfo;
  EFI_RISCV_MM_CPU_INFO         *PayloadCpuInfo;
  UINTN                         Index;

  PayloadBootInfo = (EFI_RISCV_MM_BOOT_INFO *)BootInfoAddress;

  if (PayloadBootInfo == NULL) {
    DEBUG ((DEBUG_ERROR, "PayloadBootInfo NULL\n"));
    return NULL;
  }

  if (PayloadBootInfo->Header.Version != BOOT_PAYLOAD_VERSION) {
    DEBUG ((
      DEBUG_ERROR,
      "Boot Information Version Mismatch. Current=0x%x, Expected=0x%x.\n",
      PayloadBootInfo->Header.Version,
      BOOT_PAYLOAD_VERSION
      ));
    return NULL;
  }

  DEBUG ((DEBUG_INFO, "NumMmMemRegions - 0x%x\n", PayloadBootInfo->NumMmMemRegions));
  DEBUG ((DEBUG_INFO, "MmMemBase       - 0x%lx\n", PayloadBootInfo->MmMemBase));
  DEBUG ((DEBUG_INFO, "MmMemLimit      - 0x%lx\n", PayloadBootInfo->MmMemLimit));
  DEBUG ((DEBUG_INFO, "MmImageBase     - 0x%lx\n", PayloadBootInfo->MmImageBase));
  DEBUG ((DEBUG_INFO, "MmStackBase     - 0x%lx\n", PayloadBootInfo->MmStackBase));
  DEBUG ((DEBUG_INFO, "MmHeapBase      - 0x%lx\n", PayloadBootInfo->MmHeapBase));
  DEBUG ((DEBUG_INFO, "MmNsCommBufBase - 0x%lx\n", PayloadBootInfo->MmNsCommBufBase));
  DEBUG ((DEBUG_INFO, "MmSharedBufBase - 0x%lx\n", PayloadBootInfo->MmSharedBufBase));

  DEBUG ((DEBUG_INFO, "MmImageSize     - 0x%x\n", PayloadBootInfo->MmImageSize));
  DEBUG ((DEBUG_INFO, "MmPcpuStackSize - 0x%x\n", PayloadBootInfo->MmPcpuStackSize));
  DEBUG ((DEBUG_INFO, "MmHeapSize      - 0x%x\n", PayloadBootInfo->MmHeapSize));
  DEBUG ((DEBUG_INFO, "MmNsCommBufSize - 0x%x\n", PayloadBootInfo->MmNsCommBufSize));
  DEBUG ((DEBUG_INFO, "MmSharedBufSize - 0x%x\n", PayloadBootInfo->MmSharedBufSize));

  DEBUG ((DEBUG_INFO, "NumCpus         - 0x%x\n", PayloadBootInfo->NumCpus));

  PayloadCpuInfo = (EFI_RISCV_MM_CPU_INFO *)&(PayloadBootInfo->CpuInfo);

  for (Index = 0; Index < PayloadBootInfo->NumCpus; Index++) {
    DEBUG ((DEBUG_INFO, "ProcessorId        - 0x%lx\n", PayloadCpuInfo[Index].ProcessorId));
    DEBUG ((DEBUG_INFO, "Package            - 0x%x\n", PayloadCpuInfo[Index].Package));
    DEBUG ((DEBUG_INFO, "Core               - 0x%x\n", PayloadCpuInfo[Index].Core));
  }
  return PayloadBootInfo;
}

// TODO: Penglai will go with the orignal ARM's implementaion, need improve the TVM version as will 
// and have the same implementation here !
#ifdef MM_WITH_TVM_ENABLE
#include <Library/CpuLib.h>
#include <Library/BaseRiscVTeeLib.h>

#define EFI_PARAM_ATTR_APTEE        1
//
// Cache copy of HobList pointer.
//
//extern VOID  *gHobList;

/**
  A loop to delegated events.

  @param  [in] EventCompleteSvcArgs   Pointer to the event completion arguments.

**/
VOID
EFIAPI
DelegatedEventLoop (IN UINTN CpuId, IN UINT64 MmNsCommBufBase)
{
  EFI_STATUS  Status;

  ASSERT (((EFI_MM_COMMUNICATE_HEADER *)MmNsCommBufBase)->MessageLength == 0);

  while (TRUE) {
    CpuSleep ();
    Status = CpuDriverEntryPoint (0, CpuId, MmNsCommBufBase);
    if (EFI_ERROR (Status)) {
      DEBUG ((
        DEBUG_ERROR,
        "Failed delegated Status 0x%x\n",
        Status
        ));
    }
  }
}

/**
  The entry point of Standalone MM Foundation.

  @param  [in]  CpuId             The Id assigned to this running CPU
  @param  [in]  BootInfoAddress   The address of boot info

**/
VOID
EFIAPI
CModuleEntryPoint (
  IN UINT64  CpuId,
  IN VOID    *BootInfoAddress
  )
{
  EFI_RISCV_MM_BOOT_INFO          *PayloadBootInfo;
  VOID                            *HobStart;

  PayloadBootInfo = GetAndPrintBootinformation (BootInfoAddress);
  if (PayloadBootInfo == NULL) {
    return;
  }

  if ((PayloadBootInfo->Header.Attr | EFI_PARAM_ATTR_APTEE) != 0) {
    //
    // Register shared memory
    //
    SbiTeeGuestShareMemoryRegion (PayloadBootInfo->MmNsCommBufBase, PayloadBootInfo->MmNsCommBufSize);
  }

  //
  // Create Hoblist based upon boot information passed by privileged software
  //
  HobStart = CreateHobListFromBootInfo (&CpuDriverEntryPoint, PayloadBootInfo);

  //
  // Call the MM Core entry point
  //
  ProcessModuleEntryPointList (HobStart);

  DEBUG ((DEBUG_INFO, "Cpu Driver EP %p\n", (VOID *)CpuDriverEntryPoint));

  DelegatedEventLoop (CpuId, PayloadBootInfo->MmNsCommBufBase + sizeof (EFI_MMRAM_DESCRIPTOR));
}

#else

typedef struct {
	UINT64 FuncId;
	UINT64 Regs[2];
	UINT64 Return;
} EFI_COMMUNICATE_REG;

/**
  The entry point of Standalone MM Foundation.

  @param  [in]  SharedBufAddress  Pointer to the Buffer between SPM and SP.
  @param  [in]  SharedBufSize     Size of the shared buffer.
  @param  [in]  SharedCpuEntry    Pointer to the Buffer to store the CpuEntryPoint
  @param  [in]  cookie2           Cookie 2

**/
VOID
EFIAPI
CModuleEntryPoint (
  IN UINT64  CpuId,
  IN VOID    *BootInfoAddress
  )
{
  EFI_RISCV_SMM_CONTEXT      CommunicateSmmContext;
  PE_COFF_LOADER_IMAGE_CONTEXT    ImageContext;
  EFI_RISCV_MM_BOOT_INFO          *PayloadBootInfo;
  EFI_STATUS                      Status;
  INT32                           Ret;
  UINT32                          SectionHeaderOffset;
  UINT16                          NumberOfSections;
  VOID                            *HobStart;
  VOID                            *TeData;
  UINTN                           TeDataSize;
  EFI_PHYSICAL_ADDRESS            ImageBase;
  PayloadBootInfo = GetAndPrintBootinformation (BootInfoAddress);
  if (PayloadBootInfo == NULL) {
    Status = EFI_UNSUPPORTED;
    goto finish;
  }
  // Locate PE/COFF File information for the Standalone MM core module
  Status = LocateStandaloneMmCorePeCoffData (
             (EFI_FIRMWARE_VOLUME_HEADER *)(UINTN)PayloadBootInfo->MmImageBase,
             &TeData,
             &TeDataSize
             );

  if (EFI_ERROR (Status)) {
    goto finish;
  }

  // Obtain the PE/COFF Section information for the Standalone MM core module
  Status = GetStandaloneMmCorePeCoffSections (
             TeData,
             &ImageContext,
             &ImageBase,
             &SectionHeaderOffset,
             &NumberOfSections
             );

  if (EFI_ERROR (Status)) {
    goto finish;
  }

  if (ImageContext.ImageAddress != (UINTN)TeData) {
    ImageContext.ImageAddress = (UINTN)TeData;
    Status = PeCoffLoaderRelocateImage (&ImageContext);
    ASSERT_EFI_ERROR (Status);
  }

  //
  // Create Hoblist based upon boot information passed by privileged software
  //
  HobStart = CreateHobListFromBootInfo (&CpuDriverEntryPoint, PayloadBootInfo);

  //
  // Call the MM Core entry point
  //
  ProcessModuleEntryPointList (HobStart);

  DEBUG ((DEBUG_INFO, "Shared Cpu Driver EP %p\n", (VOID *)CpuDriverEntryPoint));

finish:
  if (Status == RETURN_UNSUPPORTED) {
    Ret = -1;
  } else if (Status == RETURN_INVALID_PARAMETER) {
    Ret = -2;
  } else if (Status == EFI_NOT_FOUND) {
    Ret = -7;
  } else {
    Ret = 0;
  }

  ZeroMem (&CommunicateSmmContext, sizeof (EFI_RISCV_SMM_CONTEXT));
  // SMM Func ID
  CommunicateSmmContext.FuncId = SBI_COVE_SMM_EVENT_COMPLETE;

  while (TRUE) {
    DEBUG ((DEBUG_INFO, "In DelegatedEventLoop while loop, before ecall exit ****\n"));
    
    SbiCallCoVESmm(&CommunicateSmmContext);

    EFI_COMMUNICATE_REG *comm_regs = (EFI_COMMUNICATE_REG *)0x80300000;
    DEBUG ((DEBUG_INFO, "In DelegatedEventLoop while loop, resume handling request ****\n"));
    DEBUG ((DEBUG_INFO, "In DelegatedEventLoop while loop, request FuncId: 0x%x, CpuId: 0x%x, BufBase: 0x%lx ****\n", comm_regs->FuncId, comm_regs->Regs[0], comm_regs->Regs[1]));
    Status = CpuDriverEntryPoint (comm_regs->FuncId, comm_regs->Regs[0], comm_regs->Regs[1]);

    if (EFI_ERROR (Status)) {
      DEBUG ((
        DEBUG_ERROR,
        "Failed delegated Status 0x%x\n",
        Status
        ));
    }
  }
}
#endif
