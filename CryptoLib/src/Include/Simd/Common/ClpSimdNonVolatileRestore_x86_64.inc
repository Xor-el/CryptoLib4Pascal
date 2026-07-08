// Shared nonvolatile-XMM restore (x86-64). Mirror of ClpSimdNonVolatileSave_x86_64.inc:
// restores xmm6..xmm15 and frees the 160-byte save frame. Include it at the
// kernel's restore point (after the last use of xmm6..15, before returning), in
// any procedure that included ClpSimdNonVolatileSave_x86_64.inc. No-op on SysV x86-64.
{$IFNDEF CRYPTOLIB_SYSV_X64_ABI}
  movups    xmm6, [rsp]
  movups    xmm7, [rsp + 16]
  movups    xmm8, [rsp + 32]
  movups    xmm9, [rsp + 48]
  movups    xmm10, [rsp + 64]
  movups    xmm11, [rsp + 80]
  movups    xmm12, [rsp + 96]
  movups    xmm13, [rsp + 112]
  movups    xmm14, [rsp + 128]
  movups    xmm15, [rsp + 144]
  add       rsp, 160
{$ENDIF}
