/** @file
Load and start StandaloneMm image

Copyright (c) 2023, Ventana Micro Systems Inc. All rights reserved.<BR>

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiPei.h>
#include <Pi/PiMultiPhase.h>
#include <Guid/MmramMemoryReserve.h>
#include <Guid/MpInformation.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseRiscVSbiLib.h>
#include <Library/BaseRiscVTeeLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/PcdLib.h>
#include <Library/PrePiLib.h>

#define MM_VM_RAM_BASE                    0x80000000
#define MM_VM_HOB_START_OFFSET            0x00100000
#define MM_VM_RAM_IMAGE_START_OFFSET      0x00200000
#define MM_VM_RAM_MIN_SIZE                SIZE_32MB
#define MM_NUM_HOBS_PAGES                 1
#define MM_VM_RAM_MM_SHARED_BUF_OFFSET    0x0
#define MM_VM_RAM_MM_SHARED_BUF_SIZE      MM_VM_HOB_START_OFFSET
#define MM_VM_RAM_STACK_TOP_OFFSET        MM_VM_RAM_IMAGE_START_OFFSET
#define MM_VM_RAM_STACK_BOTTOM_OFFSET     (MM_VM_HOB_START_OFFSET + MM_NUM_HOBS_PAGES * SIZE_4KB)
#define ENTRIES_PER_PAGE                  512

STATIC
UINT64
CalculateMaxPtePages (IN UINT64 TotalSize)
{
  // Assuming SV48 mode only
  UINTN NumL1, NumL2, NumL3, NumL4;

  NumL1 = (TotalSize / SIZE_4KB) / ENTRIES_PER_PAGE + 1;
  NumL2 = NumL1 / ENTRIES_PER_PAGE + 1;
  NumL3 = NumL2 / ENTRIES_PER_PAGE + 1;
  NumL4 = 1;

  return NumL1 + NumL2 + NumL3 + NumL4;
}

STATIC
EFI_STATUS
ConvertToConfidentialMemory (IN UINT64 BaseAddr, IN UINT32 NumPage)
{
  SBI_RET   Ret;

  Ret = SbiTeeHostConvertPages (BaseAddr, NumPage);
  if (Ret.Error != SBI_TEE_SUCCESS) {
    DEBUG ((DEBUG_ERROR, "%a: Could not convert non-confidential pages: 0x%llX-0x%llX, ret:%d\n",
            __func__, BaseAddr, BaseAddr + NumPage * SIZE_4KB, Ret.Error));
    return EFI_DEVICE_ERROR;
  }
  SbiTeeHostGlobalFence ();

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
SearchReservedMmMemory (IN OUT UINT64 *MmBase, IN UINT64 MmSize)
{
  // Support 1 continuous region for now
  EFI_HOB_RESOURCE_DESCRIPTOR   *Hob;
  EFI_HOB_RESOURCE_DESCRIPTOR   *HobFound = NULL;
  UINT64                        TopMem = 0;

  if (MmSize == 0 || !MmBase) {
    DEBUG ((DEBUG_ERROR, "%a: Invalid MM memory size: 0x%llX\n",
            __func__, MmSize));
    return EFI_INVALID_PARAMETER;
  }

  Hob = GetHobList ();
  while ((Hob = GetNextHob (EFI_HOB_TYPE_RESOURCE_DESCRIPTOR, Hob)) != NULL) {
    if (Hob->ResourceType == EFI_RESOURCE_SYSTEM_MEMORY) {
      if (Hob->PhysicalStart > TopMem &&
              Hob->ResourceLength >= MmSize &&
              !(Hob->ResourceLength % SIZE_4KB)) {
        TopMem = Hob->PhysicalStart;
        HobFound = Hob;
      }
    }
    Hob = GET_NEXT_HOB (Hob);
  }

  if (HobFound) {
    // Found memory for MM. The memory should not visiable to DXE at all
    HobFound->ResourceLength -= MmSize;
    *MmBase = HobFound->PhysicalStart + HobFound->ResourceLength;
    return EFI_SUCCESS;
  }

  return EFI_NOT_FOUND;
}

STATIC
VOID
CreateMmHandOffHobs (
  IN UINT64 *HobBase,
  IN UINT64 MmVmMemBase,
  IN UINT64 MmVmMemSize
  )
{
  EFI_HOB_GUID_TYPE                 *HobGuid;
  EFI_MMRAM_HOB_DESCRIPTOR_BLOCK    *HobMmDesc;
  EFI_MMRAM_DESCRIPTOR              *MmDesc;
  MP_INFORMATION_HOB_DATA           *MpInfo;
  EFI_HOB_FIRMWARE_VOLUME           *HobFv;
  EFI_HOB_GENERIC_HEADER            *HobEnd;

  ASSERT (HobBase);

  // FV info
  HobFv = (EFI_HOB_FIRMWARE_VOLUME *)(HobBase);
  HobFv->Header.HobType   = EFI_HOB_TYPE_FV;
  HobFv->Header.HobLength = sizeof (EFI_HOB_FIRMWARE_VOLUME);
  HobFv->Header.Reserved  = 0;
  HobFv->BaseAddress = MmVmMemBase + MM_VM_RAM_IMAGE_START_OFFSET;
  HobFv->Length = PcdGet32 (PcdRiscVStandaloneMmFvSize);

  // MM RAM info
  HobGuid = (EFI_HOB_GUID_TYPE *)(HobFv + 1);
  HobGuid->Header.HobType   = EFI_HOB_TYPE_GUID_EXTENSION;
  HobGuid->Header.HobLength = 
            (UINT16)((sizeof (EFI_HOB_GUID_TYPE) +
                      sizeof (EFI_MMRAM_HOB_DESCRIPTOR_BLOCK) +
                      3 * sizeof (EFI_MMRAM_DESCRIPTOR) + 
                      0x7) & (~0x7));
  HobGuid->Header.Reserved  = 0;
  CopyGuid (&HobGuid->Name, &gEfiMmPeiMmramMemoryReserveGuid);
  HobMmDesc = (EFI_MMRAM_HOB_DESCRIPTOR_BLOCK *)(HobGuid + 1);
  HobMmDesc->NumberOfMmReservedRegions = 3;
  // Reserved region for HOB, shared memory and stack
  HobMmDesc->Descriptor[0].PhysicalStart = MM_VM_RAM_BASE;
  HobMmDesc->Descriptor[0].CpuStart = HobMmDesc->Descriptor[0].PhysicalStart;
  HobMmDesc->Descriptor[0].RegionState = EFI_CACHEABLE | EFI_ALLOCATED;
  HobMmDesc->Descriptor[0].PhysicalSize = MM_VM_RAM_IMAGE_START_OFFSET;
  // Reserved for FV
  HobMmDesc->Descriptor[1].PhysicalStart = HobFv->BaseAddress;
  HobMmDesc->Descriptor[1].CpuStart = HobMmDesc->Descriptor[1].PhysicalStart;
  HobMmDesc->Descriptor[1].RegionState = EFI_CACHEABLE | EFI_ALLOCATED;
  HobMmDesc->Descriptor[1].PhysicalSize = HobFv->Length;
  // Available memory
  HobMmDesc->Descriptor[2].PhysicalStart = HobFv->BaseAddress + HobFv->Length;
  HobMmDesc->Descriptor[2].CpuStart = HobMmDesc->Descriptor[2].PhysicalStart;
  HobMmDesc->Descriptor[2].RegionState = EFI_CACHEABLE;
  HobMmDesc->Descriptor[2].PhysicalSize = MmVmMemSize - (HobMmDesc->Descriptor[2].PhysicalStart - MmVmMemBase);

  // MM communication shared memory description
  HobGuid = (EFI_HOB_GUID_TYPE *)(((UINT64)HobGuid + HobGuid->Header.HobLength));
  HobGuid->Header.HobType   = EFI_HOB_TYPE_GUID_EXTENSION;
  HobGuid->Header.HobLength = 
            (UINT16)((sizeof (EFI_HOB_GUID_TYPE) +
                      sizeof (EFI_MMRAM_DESCRIPTOR) +
                      0x7) & (~0x7));
  HobGuid->Header.Reserved  = 0;
  CopyGuid (&HobGuid->Name, &gEfiStandaloneMmNonSecureBufferGuid);
  MmDesc = (EFI_MMRAM_DESCRIPTOR *)(HobGuid + 1);
  MmDesc->PhysicalStart = MM_VM_RAM_BASE + MM_VM_RAM_MM_SHARED_BUF_OFFSET;
  MmDesc->CpuStart = MmDesc->PhysicalStart;
  MmDesc->PhysicalSize = MM_VM_RAM_MM_SHARED_BUF_SIZE;

  // MP info
  HobGuid = (EFI_HOB_GUID_TYPE *)(((UINT64)HobGuid + HobGuid->Header.HobLength));
  HobGuid->Header.HobType   = EFI_HOB_TYPE_GUID_EXTENSION;
  HobGuid->Header.HobLength = 
            (UINT16)((sizeof (EFI_HOB_GUID_TYPE) +
                      sizeof (MP_INFORMATION_HOB_DATA) +
                      sizeof (EFI_PROCESSOR_INFORMATION) +
                      0x7) & (~0x7));
  HobGuid->Header.Reserved  = 0;
  CopyGuid (&HobGuid->Name, &gMpInformationHobGuid);
  MpInfo = (MP_INFORMATION_HOB_DATA *)(HobGuid + 1);
  MpInfo->NumberOfEnabledProcessors = 1;
  MpInfo->NumberOfProcessors = 1;
  MpInfo->ProcessorInfoBuffer[0].ProcessorId = 0;
  MpInfo->ProcessorInfoBuffer[0].Location.Package = 0;
  MpInfo->ProcessorInfoBuffer[0].Location.Core = 0;
  MpInfo->ProcessorInfoBuffer[0].Location.Thread = 0;
  MpInfo->ProcessorInfoBuffer[0].StatusFlag = PROCESSOR_ENABLED_BIT | PROCESSOR_HEALTH_STATUS_BIT;

  HobEnd  = (EFI_HOB_GENERIC_HEADER *)((UINT64)HobGuid + HobGuid->Header.HobLength);
  HobEnd->HobType   = EFI_HOB_TYPE_END_OF_HOB_LIST;
  HobEnd->HobLength = sizeof (EFI_HOB_GENERIC_HEADER);
  HobEnd->Reserved  = 0;
  HobEnd++;
  ASSERT (((VOID *)HobEnd - (VOID *)HobBase) <= (MM_NUM_HOBS_PAGES * SIZE_4KB));
}

EFI_STATUS
EFIAPI
StandaloneMmInitialization (VOID)
{
  EFI_STATUS                      Status;
  SBI_RET                         Ret;
  TSM_INFO                        TsmInfo;
  UINT64                          MmBase, PageStart, StackBottom;
  UINT64                          MmSize, MmTvmSize, NumPtePages;
  TVM_CREATE_PARAMS               TvmCreateParams;
  UINT64                          TvmGuestId;
  VOID*                           Hob;

  if (PcdGet32 (PcdRiscVStandaloneMmFvSize) == 0) {
    // No StandaloneMm FV found
    return EFI_NOT_FOUND;
  }

  // Check TSM info
  Ret = SbiTeeHostGetTsmInfo ((UINT64)&TsmInfo, sizeof (TsmInfo));
  if (Ret.Error != SBI_TEE_SUCCESS) {
    DEBUG ((DEBUG_ERROR, "%a: Cound not get TSM info, ret:%d\n", __func__, Ret.Error));
    return EFI_NOT_STARTED;
  }

  if (TsmInfo.TsmState != TSM_READY) {
    DEBUG ((DEBUG_ERROR, "%a: TSM not ready\n", __func__));
    return EFI_NOT_READY;
  }

  //
  // |----------------------------------------------------------------------------------------------|
  // | Tee TvmState | Tee Page Tables | Tee shared buffer + Tee HOB + Tee FV | Tee page zero Memory |
  // |----------------------------------------------------------------------------------------------|
  MmSize = PcdGet64 (PcdRiscVStandaloneMmMemSize);
  ASSERT (MmSize >= MM_VM_RAM_MIN_SIZE);

  Status = SearchReservedMmMemory (&MmBase, MmSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: Error while searching memory location for MM\n", __func__));
    return Status;
  }

  // TVM Create param
  MmBase = ALIGN_VALUE (MmBase, SIZE_16KB);
  PageStart = MmBase;
  Status = ConvertToConfidentialMemory (PageStart, TsmInfo.TvmStatePages + 4);
  ASSERT_EFI_ERROR (Status);
  TvmCreateParams.TvmPageDirectoryAddr = PageStart;
  TvmCreateParams.TvmStateAddr = TvmCreateParams.TvmPageDirectoryAddr + SIZE_16KB;
  Ret = SbiTeeHostCreateTvm ((UINT64)&TvmCreateParams, sizeof (TvmCreateParams));
  ASSERT (Ret.Error == SBI_TEE_SUCCESS);
  TvmGuestId = Ret.Value;
  PageStart += (TsmInfo.TvmStatePages + 4) * SIZE_4KB;

  // Add Vcpu
  Status = ConvertToConfidentialMemory (PageStart,
                                        TsmInfo.TvmVcpuStatePages);
  ASSERT_EFI_ERROR (Status);
  Ret = SbiTeeHostCreateTvmVcpu (TvmGuestId, 0,
                                  PageStart);
  ASSERT (Ret.Error == SBI_TEE_SUCCESS);
  PageStart += TsmInfo.TvmVcpuStatePages * SIZE_4KB;

  // Add page tables pages
  MmTvmSize = MmSize - (PageStart - MmBase);
  NumPtePages = CalculateMaxPtePages (MmTvmSize);
  Status = ConvertToConfidentialMemory (PageStart, NumPtePages);
  ASSERT_EFI_ERROR (Status);
  Ret = SbiTeeHostAddTvmPageTablePages (TvmGuestId, PageStart, NumPtePages);
  ASSERT (Ret.Error == SBI_TEE_SUCCESS);
  PageStart += NumPtePages * SIZE_4KB;

  // Add usable memory region for TVM
  MmTvmSize = MmSize - (PageStart - MmBase);
  Ret = SbiTeeHostAddTvmMemoryRegion (TvmGuestId, MM_VM_RAM_BASE, MmTvmSize);
  ASSERT (Ret.Error == SBI_TEE_SUCCESS);

  // Reserve shared buffer data
  Status = ConvertToConfidentialMemory (PageStart, MM_VM_HOB_START_OFFSET / SIZE_4KB);
  ASSERT_EFI_ERROR (Status);
  PageStart += MM_VM_HOB_START_OFFSET;

  // Add HOBs to measured data
  Hob = (VOID *)AllocatePages (MM_NUM_HOBS_PAGES);
  ASSERT (Hob);
  CreateMmHandOffHobs ((UINT64 *)Hob, MM_VM_RAM_BASE, MmTvmSize);
  Status = ConvertToConfidentialMemory (PageStart, MM_NUM_HOBS_PAGES);
  ASSERT_EFI_ERROR (Status);
  Ret = SbiTeeHostAddTvmMeasuredPages (TvmGuestId, (UINT64)Hob,
                                        PageStart,
                                        TSM_PAGE_4K, MM_NUM_HOBS_PAGES,
                                        MM_VM_RAM_BASE + MM_VM_HOB_START_OFFSET);
  ASSERT (Ret.Error == SBI_TEE_SUCCESS);
  PageStart +=  MM_NUM_HOBS_PAGES * SIZE_4KB;

  // Convert the stack memory
  StackBottom = PageStart;
  Status = ConvertToConfidentialMemory (PageStart,
                                        (MM_VM_RAM_STACK_TOP_OFFSET - MM_VM_RAM_STACK_BOTTOM_OFFSET) / SIZE_4KB);
  PageStart += (MM_VM_RAM_STACK_TOP_OFFSET - MM_VM_RAM_STACK_BOTTOM_OFFSET);

  // Add FV MM to measured data
  Status = ConvertToConfidentialMemory (PageStart,
                                        PcdGet32 (PcdRiscVStandaloneMmFvSize) / SIZE_4KB);
  ASSERT_EFI_ERROR (Status);

  /* The FV MM main copied at the end of EDK2 FD */
  Ret = SbiTeeHostAddTvmMeasuredPages (TvmGuestId, FixedPcdGet32 (PcdOvmfFdBaseAddress) + FixedPcdGet32 (PcdOvmfFirmwareFdSize),
                                        PageStart,
                                        TSM_PAGE_4K, PcdGet32 (PcdRiscVStandaloneMmFvSize) / SIZE_4KB,
                                        MM_VM_RAM_BASE + MM_VM_RAM_IMAGE_START_OFFSET);
  ASSERT (Ret.Error == SBI_TEE_SUCCESS);
  PageStart += PcdGet32 (PcdRiscVStandaloneMmFvSize);

  // Convert the rest of MM memory
  MmTvmSize = MmSize - (PageStart - MmBase);
  Status = ConvertToConfidentialMemory (PageStart,
                                        MmTvmSize / SIZE_4KB);
  ASSERT_EFI_ERROR (Status);

  // Finalize the TVM
  Ret = SbiTeeHostFinalizeTvm (TvmGuestId,
                                MM_VM_RAM_BASE + MM_VM_RAM_IMAGE_START_OFFSET,
                                MM_VM_RAM_BASE + MM_VM_HOB_START_OFFSET);
  ASSERT (Ret.Error == SBI_TEE_SUCCESS);

  // Add page zeros to the rest of MM meory
  Ret = SbiTeeHostAddTvmZeroPages (TvmGuestId, PageStart,
                                    TSM_PAGE_4K, MmTvmSize / SIZE_4KB,
                                    MM_VM_RAM_BASE +
                                    MM_VM_RAM_IMAGE_START_OFFSET + PcdGet32 (PcdRiscVStandaloneMmFvSize));
  ASSERT (Ret.Error == SBI_TEE_SUCCESS);

  // Add page zeros to the stack memory
  Ret = SbiTeeHostAddTvmZeroPages (TvmGuestId, StackBottom,
                                    TSM_PAGE_4K, (MM_VM_RAM_STACK_TOP_OFFSET - MM_VM_RAM_STACK_BOTTOM_OFFSET) / SIZE_4KB,
                                    MM_VM_RAM_BASE + MM_VM_RAM_STACK_BOTTOM_OFFSET);
  ASSERT (Ret.Error == SBI_TEE_SUCCESS);

  return EFI_SUCCESS;
}