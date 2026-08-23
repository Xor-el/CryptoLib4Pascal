// Curve25519 radix-2^51 (fe51 / donna64) field multiply and square (i386).
// -------------------------------------------------------------------
//
// One selector-driven file; exactly one of the following must be defined before
// including this file:
//
//   CRYPTOLIB_CURVE25519_FE51MUL   PH := PF * PG mod (2^255-19)
//   CRYPTOLIB_CURVE25519_FE51SQR   PH := PF^2  mod (2^255-19)
//
// Representation: 5 x 64-bit limbs, radix 2^51 (limb i at [ptr+8i]). Limbs are
// UNSIGNED and loosely reduced (each < 2^52); output limbs < 2^52.
//
// On entry (via ClpSimdProc3Begin_i386): ebx = PH, esi = PF, edi = PG.
// FE51SQR (via ClpSimdProc2Begin_i386): ebx = PH, esi = PF (shuffled to edi = PF).
//
// i386 is register-starved: each 51x51 limb product is four 32x32 muls accumulated
// into a per-column 128-bit stack accumulator; then the donna64 51-bit carry chain
// with the x19 wrap fold. Plain mul/add/adc/shrd/shr/and only. Constant-time.
// Reference: 64-bit radix-2^51 field arithmetic (Bernstein curve25519 / ref10-64).


{$IFDEF CRYPTOLIB_CURVE25519_FE51MUL}
  push ebp
  sub esp, 112
  xor eax, eax
  mov [esp+0], eax
  mov [esp+4], eax
  mov [esp+8], eax
  mov [esp+12], eax
  mov [esp+16], eax
  mov [esp+20], eax
  mov [esp+24], eax
  mov [esp+28], eax
  mov [esp+32], eax
  mov [esp+36], eax
  mov [esp+40], eax
  mov [esp+44], eax
  mov [esp+48], eax
  mov [esp+52], eax
  mov [esp+56], eax
  mov [esp+60], eax
  mov [esp+64], eax
  mov [esp+68], eax
  mov [esp+72], eax
  mov [esp+76], eax
  mov eax, [edi+8]
  mov ecx, 19
  mul ecx
  mov [esp+80], eax
  mov ebp, edx
  mov eax, [edi+12]
  mov ecx, 19
  mul ecx
  add eax, ebp
  mov [esp+84], eax
  mov eax, [edi+16]
  mov ecx, 19
  mul ecx
  mov [esp+88], eax
  mov ebp, edx
  mov eax, [edi+20]
  mov ecx, 19
  mul ecx
  add eax, ebp
  mov [esp+92], eax
  mov eax, [edi+24]
  mov ecx, 19
  mul ecx
  mov [esp+96], eax
  mov ebp, edx
  mov eax, [edi+28]
  mov ecx, 19
  mul ecx
  add eax, ebp
  mov [esp+100], eax
  mov eax, [edi+32]
  mov ecx, 19
  mul ecx
  mov [esp+104], eax
  mov ebp, edx
  mov eax, [edi+36]
  mov ecx, 19
  mul ecx
  add eax, ebp
  mov [esp+108], eax
  mov eax, [esi+0]
  mul dword ptr [edi+0]
  add [esp+0], eax
  adc [esp+4], edx
  adc dword ptr [esp+8], 0
  adc dword ptr [esp+12], 0
  mov eax, [esi+0]
  mul dword ptr [edi+4]
  add [esp+4], eax
  adc [esp+8], edx
  adc dword ptr [esp+12], 0
  mov eax, [esi+4]
  mul dword ptr [edi+0]
  add [esp+4], eax
  adc [esp+8], edx
  adc dword ptr [esp+12], 0
  mov eax, [esi+4]
  mul dword ptr [edi+4]
  add [esp+8], eax
  adc [esp+12], edx
  mov eax, [esi+8]
  mul dword ptr [esp+104]
  add [esp+0], eax
  adc [esp+4], edx
  adc dword ptr [esp+8], 0
  adc dword ptr [esp+12], 0
  mov eax, [esi+8]
  mul dword ptr [esp+108]
  add [esp+4], eax
  adc [esp+8], edx
  adc dword ptr [esp+12], 0
  mov eax, [esi+12]
  mul dword ptr [esp+104]
  add [esp+4], eax
  adc [esp+8], edx
  adc dword ptr [esp+12], 0
  mov eax, [esi+12]
  mul dword ptr [esp+108]
  add [esp+8], eax
  adc [esp+12], edx
  mov eax, [esi+16]
  mul dword ptr [esp+96]
  add [esp+0], eax
  adc [esp+4], edx
  adc dword ptr [esp+8], 0
  adc dword ptr [esp+12], 0
  mov eax, [esi+16]
  mul dword ptr [esp+100]
  add [esp+4], eax
  adc [esp+8], edx
  adc dword ptr [esp+12], 0
  mov eax, [esi+20]
  mul dword ptr [esp+96]
  add [esp+4], eax
  adc [esp+8], edx
  adc dword ptr [esp+12], 0
  mov eax, [esi+20]
  mul dword ptr [esp+100]
  add [esp+8], eax
  adc [esp+12], edx
  mov eax, [esi+24]
  mul dword ptr [esp+88]
  add [esp+0], eax
  adc [esp+4], edx
  adc dword ptr [esp+8], 0
  adc dword ptr [esp+12], 0
  mov eax, [esi+24]
  mul dword ptr [esp+92]
  add [esp+4], eax
  adc [esp+8], edx
  adc dword ptr [esp+12], 0
  mov eax, [esi+28]
  mul dword ptr [esp+88]
  add [esp+4], eax
  adc [esp+8], edx
  adc dword ptr [esp+12], 0
  mov eax, [esi+28]
  mul dword ptr [esp+92]
  add [esp+8], eax
  adc [esp+12], edx
  mov eax, [esi+32]
  mul dword ptr [esp+80]
  add [esp+0], eax
  adc [esp+4], edx
  adc dword ptr [esp+8], 0
  adc dword ptr [esp+12], 0
  mov eax, [esi+32]
  mul dword ptr [esp+84]
  add [esp+4], eax
  adc [esp+8], edx
  adc dword ptr [esp+12], 0
  mov eax, [esi+36]
  mul dword ptr [esp+80]
  add [esp+4], eax
  adc [esp+8], edx
  adc dword ptr [esp+12], 0
  mov eax, [esi+36]
  mul dword ptr [esp+84]
  add [esp+8], eax
  adc [esp+12], edx
  mov eax, [esi+0]
  mul dword ptr [edi+8]
  add [esp+16], eax
  adc [esp+20], edx
  adc dword ptr [esp+24], 0
  adc dword ptr [esp+28], 0
  mov eax, [esi+0]
  mul dword ptr [edi+12]
  add [esp+20], eax
  adc [esp+24], edx
  adc dword ptr [esp+28], 0
  mov eax, [esi+4]
  mul dword ptr [edi+8]
  add [esp+20], eax
  adc [esp+24], edx
  adc dword ptr [esp+28], 0
  mov eax, [esi+4]
  mul dword ptr [edi+12]
  add [esp+24], eax
  adc [esp+28], edx
  mov eax, [esi+8]
  mul dword ptr [edi+0]
  add [esp+16], eax
  adc [esp+20], edx
  adc dword ptr [esp+24], 0
  adc dword ptr [esp+28], 0
  mov eax, [esi+8]
  mul dword ptr [edi+4]
  add [esp+20], eax
  adc [esp+24], edx
  adc dword ptr [esp+28], 0
  mov eax, [esi+12]
  mul dword ptr [edi+0]
  add [esp+20], eax
  adc [esp+24], edx
  adc dword ptr [esp+28], 0
  mov eax, [esi+12]
  mul dword ptr [edi+4]
  add [esp+24], eax
  adc [esp+28], edx
  mov eax, [esi+16]
  mul dword ptr [esp+104]
  add [esp+16], eax
  adc [esp+20], edx
  adc dword ptr [esp+24], 0
  adc dword ptr [esp+28], 0
  mov eax, [esi+16]
  mul dword ptr [esp+108]
  add [esp+20], eax
  adc [esp+24], edx
  adc dword ptr [esp+28], 0
  mov eax, [esi+20]
  mul dword ptr [esp+104]
  add [esp+20], eax
  adc [esp+24], edx
  adc dword ptr [esp+28], 0
  mov eax, [esi+20]
  mul dword ptr [esp+108]
  add [esp+24], eax
  adc [esp+28], edx
  mov eax, [esi+24]
  mul dword ptr [esp+96]
  add [esp+16], eax
  adc [esp+20], edx
  adc dword ptr [esp+24], 0
  adc dword ptr [esp+28], 0
  mov eax, [esi+24]
  mul dword ptr [esp+100]
  add [esp+20], eax
  adc [esp+24], edx
  adc dword ptr [esp+28], 0
  mov eax, [esi+28]
  mul dword ptr [esp+96]
  add [esp+20], eax
  adc [esp+24], edx
  adc dword ptr [esp+28], 0
  mov eax, [esi+28]
  mul dword ptr [esp+100]
  add [esp+24], eax
  adc [esp+28], edx
  mov eax, [esi+32]
  mul dword ptr [esp+88]
  add [esp+16], eax
  adc [esp+20], edx
  adc dword ptr [esp+24], 0
  adc dword ptr [esp+28], 0
  mov eax, [esi+32]
  mul dword ptr [esp+92]
  add [esp+20], eax
  adc [esp+24], edx
  adc dword ptr [esp+28], 0
  mov eax, [esi+36]
  mul dword ptr [esp+88]
  add [esp+20], eax
  adc [esp+24], edx
  adc dword ptr [esp+28], 0
  mov eax, [esi+36]
  mul dword ptr [esp+92]
  add [esp+24], eax
  adc [esp+28], edx
  mov eax, [esi+0]
  mul dword ptr [edi+16]
  add [esp+32], eax
  adc [esp+36], edx
  adc dword ptr [esp+40], 0
  adc dword ptr [esp+44], 0
  mov eax, [esi+0]
  mul dword ptr [edi+20]
  add [esp+36], eax
  adc [esp+40], edx
  adc dword ptr [esp+44], 0
  mov eax, [esi+4]
  mul dword ptr [edi+16]
  add [esp+36], eax
  adc [esp+40], edx
  adc dword ptr [esp+44], 0
  mov eax, [esi+4]
  mul dword ptr [edi+20]
  add [esp+40], eax
  adc [esp+44], edx
  mov eax, [esi+8]
  mul dword ptr [edi+8]
  add [esp+32], eax
  adc [esp+36], edx
  adc dword ptr [esp+40], 0
  adc dword ptr [esp+44], 0
  mov eax, [esi+8]
  mul dword ptr [edi+12]
  add [esp+36], eax
  adc [esp+40], edx
  adc dword ptr [esp+44], 0
  mov eax, [esi+12]
  mul dword ptr [edi+8]
  add [esp+36], eax
  adc [esp+40], edx
  adc dword ptr [esp+44], 0
  mov eax, [esi+12]
  mul dword ptr [edi+12]
  add [esp+40], eax
  adc [esp+44], edx
  mov eax, [esi+16]
  mul dword ptr [edi+0]
  add [esp+32], eax
  adc [esp+36], edx
  adc dword ptr [esp+40], 0
  adc dword ptr [esp+44], 0
  mov eax, [esi+16]
  mul dword ptr [edi+4]
  add [esp+36], eax
  adc [esp+40], edx
  adc dword ptr [esp+44], 0
  mov eax, [esi+20]
  mul dword ptr [edi+0]
  add [esp+36], eax
  adc [esp+40], edx
  adc dword ptr [esp+44], 0
  mov eax, [esi+20]
  mul dword ptr [edi+4]
  add [esp+40], eax
  adc [esp+44], edx
  mov eax, [esi+24]
  mul dword ptr [esp+104]
  add [esp+32], eax
  adc [esp+36], edx
  adc dword ptr [esp+40], 0
  adc dword ptr [esp+44], 0
  mov eax, [esi+24]
  mul dword ptr [esp+108]
  add [esp+36], eax
  adc [esp+40], edx
  adc dword ptr [esp+44], 0
  mov eax, [esi+28]
  mul dword ptr [esp+104]
  add [esp+36], eax
  adc [esp+40], edx
  adc dword ptr [esp+44], 0
  mov eax, [esi+28]
  mul dword ptr [esp+108]
  add [esp+40], eax
  adc [esp+44], edx
  mov eax, [esi+32]
  mul dword ptr [esp+96]
  add [esp+32], eax
  adc [esp+36], edx
  adc dword ptr [esp+40], 0
  adc dword ptr [esp+44], 0
  mov eax, [esi+32]
  mul dword ptr [esp+100]
  add [esp+36], eax
  adc [esp+40], edx
  adc dword ptr [esp+44], 0
  mov eax, [esi+36]
  mul dword ptr [esp+96]
  add [esp+36], eax
  adc [esp+40], edx
  adc dword ptr [esp+44], 0
  mov eax, [esi+36]
  mul dword ptr [esp+100]
  add [esp+40], eax
  adc [esp+44], edx
  mov eax, [esi+0]
  mul dword ptr [edi+24]
  add [esp+48], eax
  adc [esp+52], edx
  adc dword ptr [esp+56], 0
  adc dword ptr [esp+60], 0
  mov eax, [esi+0]
  mul dword ptr [edi+28]
  add [esp+52], eax
  adc [esp+56], edx
  adc dword ptr [esp+60], 0
  mov eax, [esi+4]
  mul dword ptr [edi+24]
  add [esp+52], eax
  adc [esp+56], edx
  adc dword ptr [esp+60], 0
  mov eax, [esi+4]
  mul dword ptr [edi+28]
  add [esp+56], eax
  adc [esp+60], edx
  mov eax, [esi+8]
  mul dword ptr [edi+16]
  add [esp+48], eax
  adc [esp+52], edx
  adc dword ptr [esp+56], 0
  adc dword ptr [esp+60], 0
  mov eax, [esi+8]
  mul dword ptr [edi+20]
  add [esp+52], eax
  adc [esp+56], edx
  adc dword ptr [esp+60], 0
  mov eax, [esi+12]
  mul dword ptr [edi+16]
  add [esp+52], eax
  adc [esp+56], edx
  adc dword ptr [esp+60], 0
  mov eax, [esi+12]
  mul dword ptr [edi+20]
  add [esp+56], eax
  adc [esp+60], edx
  mov eax, [esi+16]
  mul dword ptr [edi+8]
  add [esp+48], eax
  adc [esp+52], edx
  adc dword ptr [esp+56], 0
  adc dword ptr [esp+60], 0
  mov eax, [esi+16]
  mul dword ptr [edi+12]
  add [esp+52], eax
  adc [esp+56], edx
  adc dword ptr [esp+60], 0
  mov eax, [esi+20]
  mul dword ptr [edi+8]
  add [esp+52], eax
  adc [esp+56], edx
  adc dword ptr [esp+60], 0
  mov eax, [esi+20]
  mul dword ptr [edi+12]
  add [esp+56], eax
  adc [esp+60], edx
  mov eax, [esi+24]
  mul dword ptr [edi+0]
  add [esp+48], eax
  adc [esp+52], edx
  adc dword ptr [esp+56], 0
  adc dword ptr [esp+60], 0
  mov eax, [esi+24]
  mul dword ptr [edi+4]
  add [esp+52], eax
  adc [esp+56], edx
  adc dword ptr [esp+60], 0
  mov eax, [esi+28]
  mul dword ptr [edi+0]
  add [esp+52], eax
  adc [esp+56], edx
  adc dword ptr [esp+60], 0
  mov eax, [esi+28]
  mul dword ptr [edi+4]
  add [esp+56], eax
  adc [esp+60], edx
  mov eax, [esi+32]
  mul dword ptr [esp+104]
  add [esp+48], eax
  adc [esp+52], edx
  adc dword ptr [esp+56], 0
  adc dword ptr [esp+60], 0
  mov eax, [esi+32]
  mul dword ptr [esp+108]
  add [esp+52], eax
  adc [esp+56], edx
  adc dword ptr [esp+60], 0
  mov eax, [esi+36]
  mul dword ptr [esp+104]
  add [esp+52], eax
  adc [esp+56], edx
  adc dword ptr [esp+60], 0
  mov eax, [esi+36]
  mul dword ptr [esp+108]
  add [esp+56], eax
  adc [esp+60], edx
  mov eax, [esi+0]
  mul dword ptr [edi+32]
  add [esp+64], eax
  adc [esp+68], edx
  adc dword ptr [esp+72], 0
  adc dword ptr [esp+76], 0
  mov eax, [esi+0]
  mul dword ptr [edi+36]
  add [esp+68], eax
  adc [esp+72], edx
  adc dword ptr [esp+76], 0
  mov eax, [esi+4]
  mul dword ptr [edi+32]
  add [esp+68], eax
  adc [esp+72], edx
  adc dword ptr [esp+76], 0
  mov eax, [esi+4]
  mul dword ptr [edi+36]
  add [esp+72], eax
  adc [esp+76], edx
  mov eax, [esi+8]
  mul dword ptr [edi+24]
  add [esp+64], eax
  adc [esp+68], edx
  adc dword ptr [esp+72], 0
  adc dword ptr [esp+76], 0
  mov eax, [esi+8]
  mul dword ptr [edi+28]
  add [esp+68], eax
  adc [esp+72], edx
  adc dword ptr [esp+76], 0
  mov eax, [esi+12]
  mul dword ptr [edi+24]
  add [esp+68], eax
  adc [esp+72], edx
  adc dword ptr [esp+76], 0
  mov eax, [esi+12]
  mul dword ptr [edi+28]
  add [esp+72], eax
  adc [esp+76], edx
  mov eax, [esi+16]
  mul dword ptr [edi+16]
  add [esp+64], eax
  adc [esp+68], edx
  adc dword ptr [esp+72], 0
  adc dword ptr [esp+76], 0
  mov eax, [esi+16]
  mul dword ptr [edi+20]
  add [esp+68], eax
  adc [esp+72], edx
  adc dword ptr [esp+76], 0
  mov eax, [esi+20]
  mul dword ptr [edi+16]
  add [esp+68], eax
  adc [esp+72], edx
  adc dword ptr [esp+76], 0
  mov eax, [esi+20]
  mul dword ptr [edi+20]
  add [esp+72], eax
  adc [esp+76], edx
  mov eax, [esi+24]
  mul dword ptr [edi+8]
  add [esp+64], eax
  adc [esp+68], edx
  adc dword ptr [esp+72], 0
  adc dword ptr [esp+76], 0
  mov eax, [esi+24]
  mul dword ptr [edi+12]
  add [esp+68], eax
  adc [esp+72], edx
  adc dword ptr [esp+76], 0
  mov eax, [esi+28]
  mul dword ptr [edi+8]
  add [esp+68], eax
  adc [esp+72], edx
  adc dword ptr [esp+76], 0
  mov eax, [esi+28]
  mul dword ptr [edi+12]
  add [esp+72], eax
  adc [esp+76], edx
  mov eax, [esi+32]
  mul dword ptr [edi+0]
  add [esp+64], eax
  adc [esp+68], edx
  adc dword ptr [esp+72], 0
  adc dword ptr [esp+76], 0
  mov eax, [esi+32]
  mul dword ptr [edi+4]
  add [esp+68], eax
  adc [esp+72], edx
  adc dword ptr [esp+76], 0
  mov eax, [esi+36]
  mul dword ptr [edi+0]
  add [esp+68], eax
  adc [esp+72], edx
  adc dword ptr [esp+76], 0
  mov eax, [esi+36]
  mul dword ptr [edi+4]
  add [esp+72], eax
  adc [esp+76], edx
  mov eax, [esp+0]
  mov [ebx+0], eax
  mov eax, [esp+4]
  and eax, $7FFFF
  mov [ebx+4], eax
  mov eax, [esp+4]
  mov ecx, [esp+8]
  shrd eax, ecx, 19
  mov edx, [esp+12]
  shrd ecx, edx, 19
  add [esp+16], eax
  adc [esp+20], ecx
  adc dword ptr [esp+24], 0
  adc dword ptr [esp+28], 0
  mov eax, [esp+16]
  mov [ebx+8], eax
  mov eax, [esp+20]
  and eax, $7FFFF
  mov [ebx+12], eax
  mov eax, [esp+20]
  mov ecx, [esp+24]
  shrd eax, ecx, 19
  mov edx, [esp+28]
  shrd ecx, edx, 19
  add [esp+32], eax
  adc [esp+36], ecx
  adc dword ptr [esp+40], 0
  adc dword ptr [esp+44], 0
  mov eax, [esp+32]
  mov [ebx+16], eax
  mov eax, [esp+36]
  and eax, $7FFFF
  mov [ebx+20], eax
  mov eax, [esp+36]
  mov ecx, [esp+40]
  shrd eax, ecx, 19
  mov edx, [esp+44]
  shrd ecx, edx, 19
  add [esp+48], eax
  adc [esp+52], ecx
  adc dword ptr [esp+56], 0
  adc dword ptr [esp+60], 0
  mov eax, [esp+48]
  mov [ebx+24], eax
  mov eax, [esp+52]
  and eax, $7FFFF
  mov [ebx+28], eax
  mov eax, [esp+52]
  mov ecx, [esp+56]
  shrd eax, ecx, 19
  mov edx, [esp+60]
  shrd ecx, edx, 19
  add [esp+64], eax
  adc [esp+68], ecx
  adc dword ptr [esp+72], 0
  adc dword ptr [esp+76], 0
  mov eax, [esp+64]
  mov [ebx+32], eax
  mov eax, [esp+68]
  and eax, $7FFFF
  mov [ebx+36], eax
  mov eax, [esp+68]
  mov ecx, [esp+72]
  shrd eax, ecx, 19
  mov edx, [esp+76]
  shrd ecx, edx, 19
  mov ebp, ecx
  mov ecx, 19
  mul ecx
  imul ebp, ebp, 19
  add edx, ebp
  add [ebx+0], eax
  adc [ebx+4], edx
  mov edx, [ebx+4]
  mov ecx, edx
  shr ecx, 19
  and edx, $7FFFF
  mov [ebx+4], edx
  add [ebx+8], ecx
  adc dword ptr [ebx+12], 0
  add esp, 112
  pop ebp
  pop edi
  pop esi
  pop ebx
{$ENDIF CRYPTOLIB_CURVE25519_FE51MUL}

{$IFDEF CRYPTOLIB_CURVE25519_FE51SQR}
  push edi
  mov edi, esi
  push ebp
  sub esp, 112
  xor eax, eax
  mov [esp+0], eax
  mov [esp+4], eax
  mov [esp+8], eax
  mov [esp+12], eax
  mov [esp+16], eax
  mov [esp+20], eax
  mov [esp+24], eax
  mov [esp+28], eax
  mov [esp+32], eax
  mov [esp+36], eax
  mov [esp+40], eax
  mov [esp+44], eax
  mov [esp+48], eax
  mov [esp+52], eax
  mov [esp+56], eax
  mov [esp+60], eax
  mov [esp+64], eax
  mov [esp+68], eax
  mov [esp+72], eax
  mov [esp+76], eax
  mov eax, [edi+8]
  mov ecx, 19
  mul ecx
  mov [esp+80], eax
  mov ebp, edx
  mov eax, [edi+12]
  mov ecx, 19
  mul ecx
  add eax, ebp
  mov [esp+84], eax
  mov eax, [edi+16]
  mov ecx, 19
  mul ecx
  mov [esp+88], eax
  mov ebp, edx
  mov eax, [edi+20]
  mov ecx, 19
  mul ecx
  add eax, ebp
  mov [esp+92], eax
  mov eax, [edi+24]
  mov ecx, 19
  mul ecx
  mov [esp+96], eax
  mov ebp, edx
  mov eax, [edi+28]
  mov ecx, 19
  mul ecx
  add eax, ebp
  mov [esp+100], eax
  mov eax, [edi+32]
  mov ecx, 19
  mul ecx
  mov [esp+104], eax
  mov ebp, edx
  mov eax, [edi+36]
  mov ecx, 19
  mul ecx
  add eax, ebp
  mov [esp+108], eax
  mov eax, [esi+0]
  mul dword ptr [edi+0]
  add [esp+0], eax
  adc [esp+4], edx
  adc dword ptr [esp+8], 0
  adc dword ptr [esp+12], 0
  mov eax, [esi+0]
  mul dword ptr [edi+4]
  add [esp+4], eax
  adc [esp+8], edx
  adc dword ptr [esp+12], 0
  mov eax, [esi+4]
  mul dword ptr [edi+0]
  add [esp+4], eax
  adc [esp+8], edx
  adc dword ptr [esp+12], 0
  mov eax, [esi+4]
  mul dword ptr [edi+4]
  add [esp+8], eax
  adc [esp+12], edx
  mov eax, [esi+8]
  mul dword ptr [esp+104]
  add [esp+0], eax
  adc [esp+4], edx
  adc dword ptr [esp+8], 0
  adc dword ptr [esp+12], 0
  mov eax, [esi+8]
  mul dword ptr [esp+108]
  add [esp+4], eax
  adc [esp+8], edx
  adc dword ptr [esp+12], 0
  mov eax, [esi+12]
  mul dword ptr [esp+104]
  add [esp+4], eax
  adc [esp+8], edx
  adc dword ptr [esp+12], 0
  mov eax, [esi+12]
  mul dword ptr [esp+108]
  add [esp+8], eax
  adc [esp+12], edx
  mov eax, [esi+16]
  mul dword ptr [esp+96]
  add [esp+0], eax
  adc [esp+4], edx
  adc dword ptr [esp+8], 0
  adc dword ptr [esp+12], 0
  mov eax, [esi+16]
  mul dword ptr [esp+100]
  add [esp+4], eax
  adc [esp+8], edx
  adc dword ptr [esp+12], 0
  mov eax, [esi+20]
  mul dword ptr [esp+96]
  add [esp+4], eax
  adc [esp+8], edx
  adc dword ptr [esp+12], 0
  mov eax, [esi+20]
  mul dword ptr [esp+100]
  add [esp+8], eax
  adc [esp+12], edx
  mov eax, [esi+24]
  mul dword ptr [esp+88]
  add [esp+0], eax
  adc [esp+4], edx
  adc dword ptr [esp+8], 0
  adc dword ptr [esp+12], 0
  mov eax, [esi+24]
  mul dword ptr [esp+92]
  add [esp+4], eax
  adc [esp+8], edx
  adc dword ptr [esp+12], 0
  mov eax, [esi+28]
  mul dword ptr [esp+88]
  add [esp+4], eax
  adc [esp+8], edx
  adc dword ptr [esp+12], 0
  mov eax, [esi+28]
  mul dword ptr [esp+92]
  add [esp+8], eax
  adc [esp+12], edx
  mov eax, [esi+32]
  mul dword ptr [esp+80]
  add [esp+0], eax
  adc [esp+4], edx
  adc dword ptr [esp+8], 0
  adc dword ptr [esp+12], 0
  mov eax, [esi+32]
  mul dword ptr [esp+84]
  add [esp+4], eax
  adc [esp+8], edx
  adc dword ptr [esp+12], 0
  mov eax, [esi+36]
  mul dword ptr [esp+80]
  add [esp+4], eax
  adc [esp+8], edx
  adc dword ptr [esp+12], 0
  mov eax, [esi+36]
  mul dword ptr [esp+84]
  add [esp+8], eax
  adc [esp+12], edx
  mov eax, [esi+0]
  mul dword ptr [edi+8]
  add [esp+16], eax
  adc [esp+20], edx
  adc dword ptr [esp+24], 0
  adc dword ptr [esp+28], 0
  mov eax, [esi+0]
  mul dword ptr [edi+12]
  add [esp+20], eax
  adc [esp+24], edx
  adc dword ptr [esp+28], 0
  mov eax, [esi+4]
  mul dword ptr [edi+8]
  add [esp+20], eax
  adc [esp+24], edx
  adc dword ptr [esp+28], 0
  mov eax, [esi+4]
  mul dword ptr [edi+12]
  add [esp+24], eax
  adc [esp+28], edx
  mov eax, [esi+8]
  mul dword ptr [edi+0]
  add [esp+16], eax
  adc [esp+20], edx
  adc dword ptr [esp+24], 0
  adc dword ptr [esp+28], 0
  mov eax, [esi+8]
  mul dword ptr [edi+4]
  add [esp+20], eax
  adc [esp+24], edx
  adc dword ptr [esp+28], 0
  mov eax, [esi+12]
  mul dword ptr [edi+0]
  add [esp+20], eax
  adc [esp+24], edx
  adc dword ptr [esp+28], 0
  mov eax, [esi+12]
  mul dword ptr [edi+4]
  add [esp+24], eax
  adc [esp+28], edx
  mov eax, [esi+16]
  mul dword ptr [esp+104]
  add [esp+16], eax
  adc [esp+20], edx
  adc dword ptr [esp+24], 0
  adc dword ptr [esp+28], 0
  mov eax, [esi+16]
  mul dword ptr [esp+108]
  add [esp+20], eax
  adc [esp+24], edx
  adc dword ptr [esp+28], 0
  mov eax, [esi+20]
  mul dword ptr [esp+104]
  add [esp+20], eax
  adc [esp+24], edx
  adc dword ptr [esp+28], 0
  mov eax, [esi+20]
  mul dword ptr [esp+108]
  add [esp+24], eax
  adc [esp+28], edx
  mov eax, [esi+24]
  mul dword ptr [esp+96]
  add [esp+16], eax
  adc [esp+20], edx
  adc dword ptr [esp+24], 0
  adc dword ptr [esp+28], 0
  mov eax, [esi+24]
  mul dword ptr [esp+100]
  add [esp+20], eax
  adc [esp+24], edx
  adc dword ptr [esp+28], 0
  mov eax, [esi+28]
  mul dword ptr [esp+96]
  add [esp+20], eax
  adc [esp+24], edx
  adc dword ptr [esp+28], 0
  mov eax, [esi+28]
  mul dword ptr [esp+100]
  add [esp+24], eax
  adc [esp+28], edx
  mov eax, [esi+32]
  mul dword ptr [esp+88]
  add [esp+16], eax
  adc [esp+20], edx
  adc dword ptr [esp+24], 0
  adc dword ptr [esp+28], 0
  mov eax, [esi+32]
  mul dword ptr [esp+92]
  add [esp+20], eax
  adc [esp+24], edx
  adc dword ptr [esp+28], 0
  mov eax, [esi+36]
  mul dword ptr [esp+88]
  add [esp+20], eax
  adc [esp+24], edx
  adc dword ptr [esp+28], 0
  mov eax, [esi+36]
  mul dword ptr [esp+92]
  add [esp+24], eax
  adc [esp+28], edx
  mov eax, [esi+0]
  mul dword ptr [edi+16]
  add [esp+32], eax
  adc [esp+36], edx
  adc dword ptr [esp+40], 0
  adc dword ptr [esp+44], 0
  mov eax, [esi+0]
  mul dword ptr [edi+20]
  add [esp+36], eax
  adc [esp+40], edx
  adc dword ptr [esp+44], 0
  mov eax, [esi+4]
  mul dword ptr [edi+16]
  add [esp+36], eax
  adc [esp+40], edx
  adc dword ptr [esp+44], 0
  mov eax, [esi+4]
  mul dword ptr [edi+20]
  add [esp+40], eax
  adc [esp+44], edx
  mov eax, [esi+8]
  mul dword ptr [edi+8]
  add [esp+32], eax
  adc [esp+36], edx
  adc dword ptr [esp+40], 0
  adc dword ptr [esp+44], 0
  mov eax, [esi+8]
  mul dword ptr [edi+12]
  add [esp+36], eax
  adc [esp+40], edx
  adc dword ptr [esp+44], 0
  mov eax, [esi+12]
  mul dword ptr [edi+8]
  add [esp+36], eax
  adc [esp+40], edx
  adc dword ptr [esp+44], 0
  mov eax, [esi+12]
  mul dword ptr [edi+12]
  add [esp+40], eax
  adc [esp+44], edx
  mov eax, [esi+16]
  mul dword ptr [edi+0]
  add [esp+32], eax
  adc [esp+36], edx
  adc dword ptr [esp+40], 0
  adc dword ptr [esp+44], 0
  mov eax, [esi+16]
  mul dword ptr [edi+4]
  add [esp+36], eax
  adc [esp+40], edx
  adc dword ptr [esp+44], 0
  mov eax, [esi+20]
  mul dword ptr [edi+0]
  add [esp+36], eax
  adc [esp+40], edx
  adc dword ptr [esp+44], 0
  mov eax, [esi+20]
  mul dword ptr [edi+4]
  add [esp+40], eax
  adc [esp+44], edx
  mov eax, [esi+24]
  mul dword ptr [esp+104]
  add [esp+32], eax
  adc [esp+36], edx
  adc dword ptr [esp+40], 0
  adc dword ptr [esp+44], 0
  mov eax, [esi+24]
  mul dword ptr [esp+108]
  add [esp+36], eax
  adc [esp+40], edx
  adc dword ptr [esp+44], 0
  mov eax, [esi+28]
  mul dword ptr [esp+104]
  add [esp+36], eax
  adc [esp+40], edx
  adc dword ptr [esp+44], 0
  mov eax, [esi+28]
  mul dword ptr [esp+108]
  add [esp+40], eax
  adc [esp+44], edx
  mov eax, [esi+32]
  mul dword ptr [esp+96]
  add [esp+32], eax
  adc [esp+36], edx
  adc dword ptr [esp+40], 0
  adc dword ptr [esp+44], 0
  mov eax, [esi+32]
  mul dword ptr [esp+100]
  add [esp+36], eax
  adc [esp+40], edx
  adc dword ptr [esp+44], 0
  mov eax, [esi+36]
  mul dword ptr [esp+96]
  add [esp+36], eax
  adc [esp+40], edx
  adc dword ptr [esp+44], 0
  mov eax, [esi+36]
  mul dword ptr [esp+100]
  add [esp+40], eax
  adc [esp+44], edx
  mov eax, [esi+0]
  mul dword ptr [edi+24]
  add [esp+48], eax
  adc [esp+52], edx
  adc dword ptr [esp+56], 0
  adc dword ptr [esp+60], 0
  mov eax, [esi+0]
  mul dword ptr [edi+28]
  add [esp+52], eax
  adc [esp+56], edx
  adc dword ptr [esp+60], 0
  mov eax, [esi+4]
  mul dword ptr [edi+24]
  add [esp+52], eax
  adc [esp+56], edx
  adc dword ptr [esp+60], 0
  mov eax, [esi+4]
  mul dword ptr [edi+28]
  add [esp+56], eax
  adc [esp+60], edx
  mov eax, [esi+8]
  mul dword ptr [edi+16]
  add [esp+48], eax
  adc [esp+52], edx
  adc dword ptr [esp+56], 0
  adc dword ptr [esp+60], 0
  mov eax, [esi+8]
  mul dword ptr [edi+20]
  add [esp+52], eax
  adc [esp+56], edx
  adc dword ptr [esp+60], 0
  mov eax, [esi+12]
  mul dword ptr [edi+16]
  add [esp+52], eax
  adc [esp+56], edx
  adc dword ptr [esp+60], 0
  mov eax, [esi+12]
  mul dword ptr [edi+20]
  add [esp+56], eax
  adc [esp+60], edx
  mov eax, [esi+16]
  mul dword ptr [edi+8]
  add [esp+48], eax
  adc [esp+52], edx
  adc dword ptr [esp+56], 0
  adc dword ptr [esp+60], 0
  mov eax, [esi+16]
  mul dword ptr [edi+12]
  add [esp+52], eax
  adc [esp+56], edx
  adc dword ptr [esp+60], 0
  mov eax, [esi+20]
  mul dword ptr [edi+8]
  add [esp+52], eax
  adc [esp+56], edx
  adc dword ptr [esp+60], 0
  mov eax, [esi+20]
  mul dword ptr [edi+12]
  add [esp+56], eax
  adc [esp+60], edx
  mov eax, [esi+24]
  mul dword ptr [edi+0]
  add [esp+48], eax
  adc [esp+52], edx
  adc dword ptr [esp+56], 0
  adc dword ptr [esp+60], 0
  mov eax, [esi+24]
  mul dword ptr [edi+4]
  add [esp+52], eax
  adc [esp+56], edx
  adc dword ptr [esp+60], 0
  mov eax, [esi+28]
  mul dword ptr [edi+0]
  add [esp+52], eax
  adc [esp+56], edx
  adc dword ptr [esp+60], 0
  mov eax, [esi+28]
  mul dword ptr [edi+4]
  add [esp+56], eax
  adc [esp+60], edx
  mov eax, [esi+32]
  mul dword ptr [esp+104]
  add [esp+48], eax
  adc [esp+52], edx
  adc dword ptr [esp+56], 0
  adc dword ptr [esp+60], 0
  mov eax, [esi+32]
  mul dword ptr [esp+108]
  add [esp+52], eax
  adc [esp+56], edx
  adc dword ptr [esp+60], 0
  mov eax, [esi+36]
  mul dword ptr [esp+104]
  add [esp+52], eax
  adc [esp+56], edx
  adc dword ptr [esp+60], 0
  mov eax, [esi+36]
  mul dword ptr [esp+108]
  add [esp+56], eax
  adc [esp+60], edx
  mov eax, [esi+0]
  mul dword ptr [edi+32]
  add [esp+64], eax
  adc [esp+68], edx
  adc dword ptr [esp+72], 0
  adc dword ptr [esp+76], 0
  mov eax, [esi+0]
  mul dword ptr [edi+36]
  add [esp+68], eax
  adc [esp+72], edx
  adc dword ptr [esp+76], 0
  mov eax, [esi+4]
  mul dword ptr [edi+32]
  add [esp+68], eax
  adc [esp+72], edx
  adc dword ptr [esp+76], 0
  mov eax, [esi+4]
  mul dword ptr [edi+36]
  add [esp+72], eax
  adc [esp+76], edx
  mov eax, [esi+8]
  mul dword ptr [edi+24]
  add [esp+64], eax
  adc [esp+68], edx
  adc dword ptr [esp+72], 0
  adc dword ptr [esp+76], 0
  mov eax, [esi+8]
  mul dword ptr [edi+28]
  add [esp+68], eax
  adc [esp+72], edx
  adc dword ptr [esp+76], 0
  mov eax, [esi+12]
  mul dword ptr [edi+24]
  add [esp+68], eax
  adc [esp+72], edx
  adc dword ptr [esp+76], 0
  mov eax, [esi+12]
  mul dword ptr [edi+28]
  add [esp+72], eax
  adc [esp+76], edx
  mov eax, [esi+16]
  mul dword ptr [edi+16]
  add [esp+64], eax
  adc [esp+68], edx
  adc dword ptr [esp+72], 0
  adc dword ptr [esp+76], 0
  mov eax, [esi+16]
  mul dword ptr [edi+20]
  add [esp+68], eax
  adc [esp+72], edx
  adc dword ptr [esp+76], 0
  mov eax, [esi+20]
  mul dword ptr [edi+16]
  add [esp+68], eax
  adc [esp+72], edx
  adc dword ptr [esp+76], 0
  mov eax, [esi+20]
  mul dword ptr [edi+20]
  add [esp+72], eax
  adc [esp+76], edx
  mov eax, [esi+24]
  mul dword ptr [edi+8]
  add [esp+64], eax
  adc [esp+68], edx
  adc dword ptr [esp+72], 0
  adc dword ptr [esp+76], 0
  mov eax, [esi+24]
  mul dword ptr [edi+12]
  add [esp+68], eax
  adc [esp+72], edx
  adc dword ptr [esp+76], 0
  mov eax, [esi+28]
  mul dword ptr [edi+8]
  add [esp+68], eax
  adc [esp+72], edx
  adc dword ptr [esp+76], 0
  mov eax, [esi+28]
  mul dword ptr [edi+12]
  add [esp+72], eax
  adc [esp+76], edx
  mov eax, [esi+32]
  mul dword ptr [edi+0]
  add [esp+64], eax
  adc [esp+68], edx
  adc dword ptr [esp+72], 0
  adc dword ptr [esp+76], 0
  mov eax, [esi+32]
  mul dword ptr [edi+4]
  add [esp+68], eax
  adc [esp+72], edx
  adc dword ptr [esp+76], 0
  mov eax, [esi+36]
  mul dword ptr [edi+0]
  add [esp+68], eax
  adc [esp+72], edx
  adc dword ptr [esp+76], 0
  mov eax, [esi+36]
  mul dword ptr [edi+4]
  add [esp+72], eax
  adc [esp+76], edx
  mov eax, [esp+0]
  mov [ebx+0], eax
  mov eax, [esp+4]
  and eax, $7FFFF
  mov [ebx+4], eax
  mov eax, [esp+4]
  mov ecx, [esp+8]
  shrd eax, ecx, 19
  mov edx, [esp+12]
  shrd ecx, edx, 19
  add [esp+16], eax
  adc [esp+20], ecx
  adc dword ptr [esp+24], 0
  adc dword ptr [esp+28], 0
  mov eax, [esp+16]
  mov [ebx+8], eax
  mov eax, [esp+20]
  and eax, $7FFFF
  mov [ebx+12], eax
  mov eax, [esp+20]
  mov ecx, [esp+24]
  shrd eax, ecx, 19
  mov edx, [esp+28]
  shrd ecx, edx, 19
  add [esp+32], eax
  adc [esp+36], ecx
  adc dword ptr [esp+40], 0
  adc dword ptr [esp+44], 0
  mov eax, [esp+32]
  mov [ebx+16], eax
  mov eax, [esp+36]
  and eax, $7FFFF
  mov [ebx+20], eax
  mov eax, [esp+36]
  mov ecx, [esp+40]
  shrd eax, ecx, 19
  mov edx, [esp+44]
  shrd ecx, edx, 19
  add [esp+48], eax
  adc [esp+52], ecx
  adc dword ptr [esp+56], 0
  adc dword ptr [esp+60], 0
  mov eax, [esp+48]
  mov [ebx+24], eax
  mov eax, [esp+52]
  and eax, $7FFFF
  mov [ebx+28], eax
  mov eax, [esp+52]
  mov ecx, [esp+56]
  shrd eax, ecx, 19
  mov edx, [esp+60]
  shrd ecx, edx, 19
  add [esp+64], eax
  adc [esp+68], ecx
  adc dword ptr [esp+72], 0
  adc dword ptr [esp+76], 0
  mov eax, [esp+64]
  mov [ebx+32], eax
  mov eax, [esp+68]
  and eax, $7FFFF
  mov [ebx+36], eax
  mov eax, [esp+68]
  mov ecx, [esp+72]
  shrd eax, ecx, 19
  mov edx, [esp+76]
  shrd ecx, edx, 19
  mov ebp, ecx
  mov ecx, 19
  mul ecx
  imul ebp, ebp, 19
  add edx, ebp
  add [ebx+0], eax
  adc [ebx+4], edx
  mov edx, [ebx+4]
  mov ecx, edx
  shr ecx, 19
  and edx, $7FFFF
  mov [ebx+4], edx
  add [ebx+8], ecx
  adc dword ptr [ebx+12], 0
  add esp, 112
  pop ebp
  pop edi
  pop esi
  pop ebx
{$ENDIF CRYPTOLIB_CURVE25519_FE51SQR}
