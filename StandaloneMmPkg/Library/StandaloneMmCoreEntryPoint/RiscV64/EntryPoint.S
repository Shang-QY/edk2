/*
  Copyright (c) 2022 Ventana Micro Systems Inc.

  SPDX-License-Identifier: BSD-2-Clause-Patent

 */
.text
.align 3

#include <Register/RiscV64/RiscVImpl.h>
#include <Library/RiscV64/StandaloneMmCoreEntryPoint.h>

ASM_FUNC (_ModuleEntryPoint)
  /*
   * a0: ID
   * a1: Boot info address
   */
 
#ifdef MM_WITH_TVM_ENABLE 
  li    a2, BOOT_INFO_STACK_BASE_OFFSET
  add   a2, a1, a2
  ld    sp, 0(a2)
#endif
  call  CModuleEntryPoint
