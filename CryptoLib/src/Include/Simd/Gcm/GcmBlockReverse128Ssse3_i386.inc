// SSSE3 16-byte byte-reverse utility (i386).
// After SimdProc3Begin_i386.inc: ebx = PDst, esi = PSrc, edi = PShuffleCtrl.
// Computes [ebx] := pshufb([esi], [edi]).
// Uses xmm0 (data) and xmm1 (control).
//
  movdqu    xmm0, [esi]
  movdqu    xmm1, [edi]
  pshufb    xmm0, xmm1
  movdqu    [ebx], xmm0

  pop edi
  pop esi
  pop ebx
