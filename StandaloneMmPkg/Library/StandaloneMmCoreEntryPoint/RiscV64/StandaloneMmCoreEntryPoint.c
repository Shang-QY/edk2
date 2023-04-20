/** @file
  Entry point to the Standalone MM Foundation when initialized during the SEC
  phase on RISCV platforms

Copyright (c) 2017 - 2021, Arm Ltd. All rights reserved.<BR>
Copyright (c) 2023, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

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
  DEBUG ((DEBUG_INFO, "CpuInfo         - 0x%p\n", PayloadBootInfo->CpuInfo));

  PayloadCpuInfo = (EFI_RISCV_MM_CPU_INFO *)PayloadBootInfo->CpuInfo;

  if (PayloadCpuInfo == NULL) {
    DEBUG ((DEBUG_ERROR, "PayloadCpuInfo NULL\n"));
    return NULL;
  }

  for (Index = 0; Index < PayloadBootInfo->NumCpus; Index++) {
    DEBUG ((DEBUG_INFO, "ProcessorId        - 0x%lx\n", PayloadCpuInfo[Index].ProcessorId));
    DEBUG ((DEBUG_INFO, "Package            - 0x%x\n", PayloadCpuInfo[Index].Package));
    DEBUG ((DEBUG_INFO, "Core               - 0x%x\n", PayloadCpuInfo[Index].Core));
  }
  return PayloadBootInfo;
}

/**
  The entry point of Standalone MM Foundation.

  @param  [in]  SharedBufAddress  Pointer to the Buffer between SPM and SP.
  @param  [in]  SharedBufSize     Size of the shared buffer.
  @param  [in]  SharedCpuEntry    Pointer to the Buffer to store the CpuEntryPoint
  @param  [in]  cookie2           Cookie 2

**/
VOID
EFIAPI
_ModuleEntryPoint (
  IN VOID    *SharedBufAddress,
  IN UINT64  SharedBufSize,
  IN UINT64  SharedCpuEntry,
  IN UINT64  cookie
  )
{
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
  PayloadBootInfo = GetAndPrintBootinformation (SharedBufAddress);
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
  if ((VOID **)SharedCpuEntry != NULL) {
	  *((VOID **)SharedCpuEntry) = (VOID *)CpuDriverEntryPoint;
  }

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
}
