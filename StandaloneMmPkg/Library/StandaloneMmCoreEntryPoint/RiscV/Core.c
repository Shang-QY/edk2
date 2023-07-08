/** @file
  Entry point to the Standalone Mm Core.

Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.
Copyright (c) 2023, Ventana Micro System Inc. All rights reserved.<BR>

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include <Library/StandaloneMmCoreEntryPoint.h>
#include <Library/DebugLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseRiscVTeeLib.h>

//
// Cache copy of HobList pointer.
//
VOID  *gHobList = NULL;

/**
  The entry point of PE/COFF Image for the STANDALONE MM Core.

  This function is the entry point for the STANDALONE MM Core. This function is required to call
  ProcessModuleEntryPointList() and ProcessModuleEntryPointList() is never expected to return.
  The STANDALONE MM Core is responsible for calling ProcessLibraryConstructorList() as soon as the EFI
  System Table and the image handle for the STANDALONE MM Core itself have been established.
  If ProcessModuleEntryPointList() returns, then ASSERT() and halt the system.

  @param  HobStart  Pointer to the beginning of the HOB List passed in from the PEI Phase.

**/
VOID
EFIAPI
CModuleEntryPoint (
  IN VOID  *HobStart
  )
{
  //
  // Register shared memory
  //
  SbiTeeGuestShareMemoryRegion (0x80000000, 0x100000);
  DEBUG ((DEBUG_INFO, "CModuleEntryPoint #####       - \n"));
  //
  // Cache a pointer to the HobList
  //
  gHobList = HobStart;

  //
  // Call the Standalone MM Core entry point
  //
  ProcessModuleEntryPointList (HobStart);

  //
  // TODO: Set page table here?? AARCH64 has this step for some reason
  //
}

/**
  Required by the EBC compiler and identical in functionality to _ModuleEntryPoint().

  This function is required to call _ModuleEntryPoint() passing in HobStart.

  @param  HobStart  Pointer to the beginning of the HOB List passed in from the PEI Phase.

**/
VOID
EFIAPI
EfiMain (
  IN VOID  *HobStart
  )
{
  DEBUG ((DEBUG_INFO, "EfiMain #####       - \n"));
  _ModuleEntryPoint (HobStart);
}
