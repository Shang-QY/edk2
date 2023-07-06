/*
  Copyright (c) 2022 Ventana Micro Systems Inc.

  SPDX-License-Identifier: BSD-2-Clause-Patent

 */

.text
.align 3

#include <Register/RiscV64/RiscVImpl.h>

ASM_FUNC (_ModuleEntryPoint)
  /*
   * a0: ID
   * a1: HOB address
   * sp: a1 + 0x100000
   */
  
  li    a2, 0x100000
  add   sp, a1, a2
  mv    a0, a1
  call  CModuleEntryPoint