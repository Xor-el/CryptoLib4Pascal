// Curve448 radix-2^56 (fe56 / Goldilocks) field multiply and square (i386).
// -------------------------------------------------------------------
//
// One selector-driven file; exactly one of the following must be defined before
// including this file:
//
//   CRYPTOLIB_CURVE448_FE56MUL   PH := PF * PG mod (2^448-2^224-1)
//   CRYPTOLIB_CURVE448_FE56SQR   PH := PF^2  mod (2^448-2^224-1)
//
// Representation: 8 x 64-bit limbs, radix 2^56 (limb i at [ptr+8i]). Limbs are
// UNSIGNED and loosely reduced (each < 2^57); output limbs < 2^57.
//
// On entry (via ClpSimdProc3Begin_i386): ebx = PH, esi = PF, edi = PG.
// FE56SQR (via ClpSimdProc2Begin_i386): ebx = PH, esi = PF (shuffled to edi = PF).
//
// i386 is register-starved: each 56x56 limb product is four 32x32 muls accumulated
// into a per-column 128-bit (4 x 32-bit) stack accumulator; then the Goldilocks
// fold (column k -> k-4 and k-8 for k=14..8, high-to-low) and a radix-2^56 carry
// (shrd extracts the 56-bit carry) with the top carry into limbs 0 and 4. Plain
// mul/add/adc/shrd/shr/and only. Constant-time.
// Reference: 64-bit radix-2^56 Goldilocks field arithmetic (edwards448 / ed448-goldilocks).


{$IFDEF CRYPTOLIB_CURVE448_FE56MUL}
  push ebp
  sub esp, 240
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
  mov [esp+80], eax
  mov [esp+84], eax
  mov [esp+88], eax
  mov [esp+92], eax
  mov [esp+96], eax
  mov [esp+100], eax
  mov [esp+104], eax
  mov [esp+108], eax
  mov [esp+112], eax
  mov [esp+116], eax
  mov [esp+120], eax
  mov [esp+124], eax
  mov [esp+128], eax
  mov [esp+132], eax
  mov [esp+136], eax
  mov [esp+140], eax
  mov [esp+144], eax
  mov [esp+148], eax
  mov [esp+152], eax
  mov [esp+156], eax
  mov [esp+160], eax
  mov [esp+164], eax
  mov [esp+168], eax
  mov [esp+172], eax
  mov [esp+176], eax
  mov [esp+180], eax
  mov [esp+184], eax
  mov [esp+188], eax
  mov [esp+192], eax
  mov [esp+196], eax
  mov [esp+200], eax
  mov [esp+204], eax
  mov [esp+208], eax
  mov [esp+212], eax
  mov [esp+216], eax
  mov [esp+220], eax
  mov [esp+224], eax
  mov [esp+228], eax
  mov [esp+232], eax
  mov [esp+236], eax
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
  mov eax, [esi+0]
  mul dword ptr [edi+40]
  add [esp+80], eax
  adc [esp+84], edx
  adc dword ptr [esp+88], 0
  adc dword ptr [esp+92], 0
  mov eax, [esi+0]
  mul dword ptr [edi+44]
  add [esp+84], eax
  adc [esp+88], edx
  adc dword ptr [esp+92], 0
  mov eax, [esi+4]
  mul dword ptr [edi+40]
  add [esp+84], eax
  adc [esp+88], edx
  adc dword ptr [esp+92], 0
  mov eax, [esi+4]
  mul dword ptr [edi+44]
  add [esp+88], eax
  adc [esp+92], edx
  mov eax, [esi+0]
  mul dword ptr [edi+48]
  add [esp+96], eax
  adc [esp+100], edx
  adc dword ptr [esp+104], 0
  adc dword ptr [esp+108], 0
  mov eax, [esi+0]
  mul dword ptr [edi+52]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+4]
  mul dword ptr [edi+48]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+4]
  mul dword ptr [edi+52]
  add [esp+104], eax
  adc [esp+108], edx
  mov eax, [esi+0]
  mul dword ptr [edi+56]
  add [esp+112], eax
  adc [esp+116], edx
  adc dword ptr [esp+120], 0
  adc dword ptr [esp+124], 0
  mov eax, [esi+0]
  mul dword ptr [edi+60]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+4]
  mul dword ptr [edi+56]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+4]
  mul dword ptr [edi+60]
  add [esp+120], eax
  adc [esp+124], edx
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
  mov eax, [esi+8]
  mul dword ptr [edi+32]
  add [esp+80], eax
  adc [esp+84], edx
  adc dword ptr [esp+88], 0
  adc dword ptr [esp+92], 0
  mov eax, [esi+8]
  mul dword ptr [edi+36]
  add [esp+84], eax
  adc [esp+88], edx
  adc dword ptr [esp+92], 0
  mov eax, [esi+12]
  mul dword ptr [edi+32]
  add [esp+84], eax
  adc [esp+88], edx
  adc dword ptr [esp+92], 0
  mov eax, [esi+12]
  mul dword ptr [edi+36]
  add [esp+88], eax
  adc [esp+92], edx
  mov eax, [esi+8]
  mul dword ptr [edi+40]
  add [esp+96], eax
  adc [esp+100], edx
  adc dword ptr [esp+104], 0
  adc dword ptr [esp+108], 0
  mov eax, [esi+8]
  mul dword ptr [edi+44]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+12]
  mul dword ptr [edi+40]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+12]
  mul dword ptr [edi+44]
  add [esp+104], eax
  adc [esp+108], edx
  mov eax, [esi+8]
  mul dword ptr [edi+48]
  add [esp+112], eax
  adc [esp+116], edx
  adc dword ptr [esp+120], 0
  adc dword ptr [esp+124], 0
  mov eax, [esi+8]
  mul dword ptr [edi+52]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+12]
  mul dword ptr [edi+48]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+12]
  mul dword ptr [edi+52]
  add [esp+120], eax
  adc [esp+124], edx
  mov eax, [esi+8]
  mul dword ptr [edi+56]
  add [esp+128], eax
  adc [esp+132], edx
  adc dword ptr [esp+136], 0
  adc dword ptr [esp+140], 0
  mov eax, [esi+8]
  mul dword ptr [edi+60]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+12]
  mul dword ptr [edi+56]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+12]
  mul dword ptr [edi+60]
  add [esp+136], eax
  adc [esp+140], edx
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
  mov eax, [esi+16]
  mul dword ptr [edi+24]
  add [esp+80], eax
  adc [esp+84], edx
  adc dword ptr [esp+88], 0
  adc dword ptr [esp+92], 0
  mov eax, [esi+16]
  mul dword ptr [edi+28]
  add [esp+84], eax
  adc [esp+88], edx
  adc dword ptr [esp+92], 0
  mov eax, [esi+20]
  mul dword ptr [edi+24]
  add [esp+84], eax
  adc [esp+88], edx
  adc dword ptr [esp+92], 0
  mov eax, [esi+20]
  mul dword ptr [edi+28]
  add [esp+88], eax
  adc [esp+92], edx
  mov eax, [esi+16]
  mul dword ptr [edi+32]
  add [esp+96], eax
  adc [esp+100], edx
  adc dword ptr [esp+104], 0
  adc dword ptr [esp+108], 0
  mov eax, [esi+16]
  mul dword ptr [edi+36]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+20]
  mul dword ptr [edi+32]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+20]
  mul dword ptr [edi+36]
  add [esp+104], eax
  adc [esp+108], edx
  mov eax, [esi+16]
  mul dword ptr [edi+40]
  add [esp+112], eax
  adc [esp+116], edx
  adc dword ptr [esp+120], 0
  adc dword ptr [esp+124], 0
  mov eax, [esi+16]
  mul dword ptr [edi+44]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+20]
  mul dword ptr [edi+40]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+20]
  mul dword ptr [edi+44]
  add [esp+120], eax
  adc [esp+124], edx
  mov eax, [esi+16]
  mul dword ptr [edi+48]
  add [esp+128], eax
  adc [esp+132], edx
  adc dword ptr [esp+136], 0
  adc dword ptr [esp+140], 0
  mov eax, [esi+16]
  mul dword ptr [edi+52]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+20]
  mul dword ptr [edi+48]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+20]
  mul dword ptr [edi+52]
  add [esp+136], eax
  adc [esp+140], edx
  mov eax, [esi+16]
  mul dword ptr [edi+56]
  add [esp+144], eax
  adc [esp+148], edx
  adc dword ptr [esp+152], 0
  adc dword ptr [esp+156], 0
  mov eax, [esi+16]
  mul dword ptr [edi+60]
  add [esp+148], eax
  adc [esp+152], edx
  adc dword ptr [esp+156], 0
  mov eax, [esi+20]
  mul dword ptr [edi+56]
  add [esp+148], eax
  adc [esp+152], edx
  adc dword ptr [esp+156], 0
  mov eax, [esi+20]
  mul dword ptr [edi+60]
  add [esp+152], eax
  adc [esp+156], edx
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
  mov eax, [esi+24]
  mul dword ptr [edi+16]
  add [esp+80], eax
  adc [esp+84], edx
  adc dword ptr [esp+88], 0
  adc dword ptr [esp+92], 0
  mov eax, [esi+24]
  mul dword ptr [edi+20]
  add [esp+84], eax
  adc [esp+88], edx
  adc dword ptr [esp+92], 0
  mov eax, [esi+28]
  mul dword ptr [edi+16]
  add [esp+84], eax
  adc [esp+88], edx
  adc dword ptr [esp+92], 0
  mov eax, [esi+28]
  mul dword ptr [edi+20]
  add [esp+88], eax
  adc [esp+92], edx
  mov eax, [esi+24]
  mul dword ptr [edi+24]
  add [esp+96], eax
  adc [esp+100], edx
  adc dword ptr [esp+104], 0
  adc dword ptr [esp+108], 0
  mov eax, [esi+24]
  mul dword ptr [edi+28]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+28]
  mul dword ptr [edi+24]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+28]
  mul dword ptr [edi+28]
  add [esp+104], eax
  adc [esp+108], edx
  mov eax, [esi+24]
  mul dword ptr [edi+32]
  add [esp+112], eax
  adc [esp+116], edx
  adc dword ptr [esp+120], 0
  adc dword ptr [esp+124], 0
  mov eax, [esi+24]
  mul dword ptr [edi+36]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+28]
  mul dword ptr [edi+32]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+28]
  mul dword ptr [edi+36]
  add [esp+120], eax
  adc [esp+124], edx
  mov eax, [esi+24]
  mul dword ptr [edi+40]
  add [esp+128], eax
  adc [esp+132], edx
  adc dword ptr [esp+136], 0
  adc dword ptr [esp+140], 0
  mov eax, [esi+24]
  mul dword ptr [edi+44]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+28]
  mul dword ptr [edi+40]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+28]
  mul dword ptr [edi+44]
  add [esp+136], eax
  adc [esp+140], edx
  mov eax, [esi+24]
  mul dword ptr [edi+48]
  add [esp+144], eax
  adc [esp+148], edx
  adc dword ptr [esp+152], 0
  adc dword ptr [esp+156], 0
  mov eax, [esi+24]
  mul dword ptr [edi+52]
  add [esp+148], eax
  adc [esp+152], edx
  adc dword ptr [esp+156], 0
  mov eax, [esi+28]
  mul dword ptr [edi+48]
  add [esp+148], eax
  adc [esp+152], edx
  adc dword ptr [esp+156], 0
  mov eax, [esi+28]
  mul dword ptr [edi+52]
  add [esp+152], eax
  adc [esp+156], edx
  mov eax, [esi+24]
  mul dword ptr [edi+56]
  add [esp+160], eax
  adc [esp+164], edx
  adc dword ptr [esp+168], 0
  adc dword ptr [esp+172], 0
  mov eax, [esi+24]
  mul dword ptr [edi+60]
  add [esp+164], eax
  adc [esp+168], edx
  adc dword ptr [esp+172], 0
  mov eax, [esi+28]
  mul dword ptr [edi+56]
  add [esp+164], eax
  adc [esp+168], edx
  adc dword ptr [esp+172], 0
  mov eax, [esi+28]
  mul dword ptr [edi+60]
  add [esp+168], eax
  adc [esp+172], edx
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
  mov eax, [esi+32]
  mul dword ptr [edi+8]
  add [esp+80], eax
  adc [esp+84], edx
  adc dword ptr [esp+88], 0
  adc dword ptr [esp+92], 0
  mov eax, [esi+32]
  mul dword ptr [edi+12]
  add [esp+84], eax
  adc [esp+88], edx
  adc dword ptr [esp+92], 0
  mov eax, [esi+36]
  mul dword ptr [edi+8]
  add [esp+84], eax
  adc [esp+88], edx
  adc dword ptr [esp+92], 0
  mov eax, [esi+36]
  mul dword ptr [edi+12]
  add [esp+88], eax
  adc [esp+92], edx
  mov eax, [esi+32]
  mul dword ptr [edi+16]
  add [esp+96], eax
  adc [esp+100], edx
  adc dword ptr [esp+104], 0
  adc dword ptr [esp+108], 0
  mov eax, [esi+32]
  mul dword ptr [edi+20]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+36]
  mul dword ptr [edi+16]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+36]
  mul dword ptr [edi+20]
  add [esp+104], eax
  adc [esp+108], edx
  mov eax, [esi+32]
  mul dword ptr [edi+24]
  add [esp+112], eax
  adc [esp+116], edx
  adc dword ptr [esp+120], 0
  adc dword ptr [esp+124], 0
  mov eax, [esi+32]
  mul dword ptr [edi+28]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+36]
  mul dword ptr [edi+24]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+36]
  mul dword ptr [edi+28]
  add [esp+120], eax
  adc [esp+124], edx
  mov eax, [esi+32]
  mul dword ptr [edi+32]
  add [esp+128], eax
  adc [esp+132], edx
  adc dword ptr [esp+136], 0
  adc dword ptr [esp+140], 0
  mov eax, [esi+32]
  mul dword ptr [edi+36]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+36]
  mul dword ptr [edi+32]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+36]
  mul dword ptr [edi+36]
  add [esp+136], eax
  adc [esp+140], edx
  mov eax, [esi+32]
  mul dword ptr [edi+40]
  add [esp+144], eax
  adc [esp+148], edx
  adc dword ptr [esp+152], 0
  adc dword ptr [esp+156], 0
  mov eax, [esi+32]
  mul dword ptr [edi+44]
  add [esp+148], eax
  adc [esp+152], edx
  adc dword ptr [esp+156], 0
  mov eax, [esi+36]
  mul dword ptr [edi+40]
  add [esp+148], eax
  adc [esp+152], edx
  adc dword ptr [esp+156], 0
  mov eax, [esi+36]
  mul dword ptr [edi+44]
  add [esp+152], eax
  adc [esp+156], edx
  mov eax, [esi+32]
  mul dword ptr [edi+48]
  add [esp+160], eax
  adc [esp+164], edx
  adc dword ptr [esp+168], 0
  adc dword ptr [esp+172], 0
  mov eax, [esi+32]
  mul dword ptr [edi+52]
  add [esp+164], eax
  adc [esp+168], edx
  adc dword ptr [esp+172], 0
  mov eax, [esi+36]
  mul dword ptr [edi+48]
  add [esp+164], eax
  adc [esp+168], edx
  adc dword ptr [esp+172], 0
  mov eax, [esi+36]
  mul dword ptr [edi+52]
  add [esp+168], eax
  adc [esp+172], edx
  mov eax, [esi+32]
  mul dword ptr [edi+56]
  add [esp+176], eax
  adc [esp+180], edx
  adc dword ptr [esp+184], 0
  adc dword ptr [esp+188], 0
  mov eax, [esi+32]
  mul dword ptr [edi+60]
  add [esp+180], eax
  adc [esp+184], edx
  adc dword ptr [esp+188], 0
  mov eax, [esi+36]
  mul dword ptr [edi+56]
  add [esp+180], eax
  adc [esp+184], edx
  adc dword ptr [esp+188], 0
  mov eax, [esi+36]
  mul dword ptr [edi+60]
  add [esp+184], eax
  adc [esp+188], edx
  mov eax, [esi+40]
  mul dword ptr [edi+0]
  add [esp+80], eax
  adc [esp+84], edx
  adc dword ptr [esp+88], 0
  adc dword ptr [esp+92], 0
  mov eax, [esi+40]
  mul dword ptr [edi+4]
  add [esp+84], eax
  adc [esp+88], edx
  adc dword ptr [esp+92], 0
  mov eax, [esi+44]
  mul dword ptr [edi+0]
  add [esp+84], eax
  adc [esp+88], edx
  adc dword ptr [esp+92], 0
  mov eax, [esi+44]
  mul dword ptr [edi+4]
  add [esp+88], eax
  adc [esp+92], edx
  mov eax, [esi+40]
  mul dword ptr [edi+8]
  add [esp+96], eax
  adc [esp+100], edx
  adc dword ptr [esp+104], 0
  adc dword ptr [esp+108], 0
  mov eax, [esi+40]
  mul dword ptr [edi+12]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+44]
  mul dword ptr [edi+8]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+44]
  mul dword ptr [edi+12]
  add [esp+104], eax
  adc [esp+108], edx
  mov eax, [esi+40]
  mul dword ptr [edi+16]
  add [esp+112], eax
  adc [esp+116], edx
  adc dword ptr [esp+120], 0
  adc dword ptr [esp+124], 0
  mov eax, [esi+40]
  mul dword ptr [edi+20]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+44]
  mul dword ptr [edi+16]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+44]
  mul dword ptr [edi+20]
  add [esp+120], eax
  adc [esp+124], edx
  mov eax, [esi+40]
  mul dword ptr [edi+24]
  add [esp+128], eax
  adc [esp+132], edx
  adc dword ptr [esp+136], 0
  adc dword ptr [esp+140], 0
  mov eax, [esi+40]
  mul dword ptr [edi+28]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+44]
  mul dword ptr [edi+24]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+44]
  mul dword ptr [edi+28]
  add [esp+136], eax
  adc [esp+140], edx
  mov eax, [esi+40]
  mul dword ptr [edi+32]
  add [esp+144], eax
  adc [esp+148], edx
  adc dword ptr [esp+152], 0
  adc dword ptr [esp+156], 0
  mov eax, [esi+40]
  mul dword ptr [edi+36]
  add [esp+148], eax
  adc [esp+152], edx
  adc dword ptr [esp+156], 0
  mov eax, [esi+44]
  mul dword ptr [edi+32]
  add [esp+148], eax
  adc [esp+152], edx
  adc dword ptr [esp+156], 0
  mov eax, [esi+44]
  mul dword ptr [edi+36]
  add [esp+152], eax
  adc [esp+156], edx
  mov eax, [esi+40]
  mul dword ptr [edi+40]
  add [esp+160], eax
  adc [esp+164], edx
  adc dword ptr [esp+168], 0
  adc dword ptr [esp+172], 0
  mov eax, [esi+40]
  mul dword ptr [edi+44]
  add [esp+164], eax
  adc [esp+168], edx
  adc dword ptr [esp+172], 0
  mov eax, [esi+44]
  mul dword ptr [edi+40]
  add [esp+164], eax
  adc [esp+168], edx
  adc dword ptr [esp+172], 0
  mov eax, [esi+44]
  mul dword ptr [edi+44]
  add [esp+168], eax
  adc [esp+172], edx
  mov eax, [esi+40]
  mul dword ptr [edi+48]
  add [esp+176], eax
  adc [esp+180], edx
  adc dword ptr [esp+184], 0
  adc dword ptr [esp+188], 0
  mov eax, [esi+40]
  mul dword ptr [edi+52]
  add [esp+180], eax
  adc [esp+184], edx
  adc dword ptr [esp+188], 0
  mov eax, [esi+44]
  mul dword ptr [edi+48]
  add [esp+180], eax
  adc [esp+184], edx
  adc dword ptr [esp+188], 0
  mov eax, [esi+44]
  mul dword ptr [edi+52]
  add [esp+184], eax
  adc [esp+188], edx
  mov eax, [esi+40]
  mul dword ptr [edi+56]
  add [esp+192], eax
  adc [esp+196], edx
  adc dword ptr [esp+200], 0
  adc dword ptr [esp+204], 0
  mov eax, [esi+40]
  mul dword ptr [edi+60]
  add [esp+196], eax
  adc [esp+200], edx
  adc dword ptr [esp+204], 0
  mov eax, [esi+44]
  mul dword ptr [edi+56]
  add [esp+196], eax
  adc [esp+200], edx
  adc dword ptr [esp+204], 0
  mov eax, [esi+44]
  mul dword ptr [edi+60]
  add [esp+200], eax
  adc [esp+204], edx
  mov eax, [esi+48]
  mul dword ptr [edi+0]
  add [esp+96], eax
  adc [esp+100], edx
  adc dword ptr [esp+104], 0
  adc dword ptr [esp+108], 0
  mov eax, [esi+48]
  mul dword ptr [edi+4]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+52]
  mul dword ptr [edi+0]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+52]
  mul dword ptr [edi+4]
  add [esp+104], eax
  adc [esp+108], edx
  mov eax, [esi+48]
  mul dword ptr [edi+8]
  add [esp+112], eax
  adc [esp+116], edx
  adc dword ptr [esp+120], 0
  adc dword ptr [esp+124], 0
  mov eax, [esi+48]
  mul dword ptr [edi+12]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+52]
  mul dword ptr [edi+8]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+52]
  mul dword ptr [edi+12]
  add [esp+120], eax
  adc [esp+124], edx
  mov eax, [esi+48]
  mul dword ptr [edi+16]
  add [esp+128], eax
  adc [esp+132], edx
  adc dword ptr [esp+136], 0
  adc dword ptr [esp+140], 0
  mov eax, [esi+48]
  mul dword ptr [edi+20]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+52]
  mul dword ptr [edi+16]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+52]
  mul dword ptr [edi+20]
  add [esp+136], eax
  adc [esp+140], edx
  mov eax, [esi+48]
  mul dword ptr [edi+24]
  add [esp+144], eax
  adc [esp+148], edx
  adc dword ptr [esp+152], 0
  adc dword ptr [esp+156], 0
  mov eax, [esi+48]
  mul dword ptr [edi+28]
  add [esp+148], eax
  adc [esp+152], edx
  adc dword ptr [esp+156], 0
  mov eax, [esi+52]
  mul dword ptr [edi+24]
  add [esp+148], eax
  adc [esp+152], edx
  adc dword ptr [esp+156], 0
  mov eax, [esi+52]
  mul dword ptr [edi+28]
  add [esp+152], eax
  adc [esp+156], edx
  mov eax, [esi+48]
  mul dword ptr [edi+32]
  add [esp+160], eax
  adc [esp+164], edx
  adc dword ptr [esp+168], 0
  adc dword ptr [esp+172], 0
  mov eax, [esi+48]
  mul dword ptr [edi+36]
  add [esp+164], eax
  adc [esp+168], edx
  adc dword ptr [esp+172], 0
  mov eax, [esi+52]
  mul dword ptr [edi+32]
  add [esp+164], eax
  adc [esp+168], edx
  adc dword ptr [esp+172], 0
  mov eax, [esi+52]
  mul dword ptr [edi+36]
  add [esp+168], eax
  adc [esp+172], edx
  mov eax, [esi+48]
  mul dword ptr [edi+40]
  add [esp+176], eax
  adc [esp+180], edx
  adc dword ptr [esp+184], 0
  adc dword ptr [esp+188], 0
  mov eax, [esi+48]
  mul dword ptr [edi+44]
  add [esp+180], eax
  adc [esp+184], edx
  adc dword ptr [esp+188], 0
  mov eax, [esi+52]
  mul dword ptr [edi+40]
  add [esp+180], eax
  adc [esp+184], edx
  adc dword ptr [esp+188], 0
  mov eax, [esi+52]
  mul dword ptr [edi+44]
  add [esp+184], eax
  adc [esp+188], edx
  mov eax, [esi+48]
  mul dword ptr [edi+48]
  add [esp+192], eax
  adc [esp+196], edx
  adc dword ptr [esp+200], 0
  adc dword ptr [esp+204], 0
  mov eax, [esi+48]
  mul dword ptr [edi+52]
  add [esp+196], eax
  adc [esp+200], edx
  adc dword ptr [esp+204], 0
  mov eax, [esi+52]
  mul dword ptr [edi+48]
  add [esp+196], eax
  adc [esp+200], edx
  adc dword ptr [esp+204], 0
  mov eax, [esi+52]
  mul dword ptr [edi+52]
  add [esp+200], eax
  adc [esp+204], edx
  mov eax, [esi+48]
  mul dword ptr [edi+56]
  add [esp+208], eax
  adc [esp+212], edx
  adc dword ptr [esp+216], 0
  adc dword ptr [esp+220], 0
  mov eax, [esi+48]
  mul dword ptr [edi+60]
  add [esp+212], eax
  adc [esp+216], edx
  adc dword ptr [esp+220], 0
  mov eax, [esi+52]
  mul dword ptr [edi+56]
  add [esp+212], eax
  adc [esp+216], edx
  adc dword ptr [esp+220], 0
  mov eax, [esi+52]
  mul dword ptr [edi+60]
  add [esp+216], eax
  adc [esp+220], edx
  mov eax, [esi+56]
  mul dword ptr [edi+0]
  add [esp+112], eax
  adc [esp+116], edx
  adc dword ptr [esp+120], 0
  adc dword ptr [esp+124], 0
  mov eax, [esi+56]
  mul dword ptr [edi+4]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+60]
  mul dword ptr [edi+0]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+60]
  mul dword ptr [edi+4]
  add [esp+120], eax
  adc [esp+124], edx
  mov eax, [esi+56]
  mul dword ptr [edi+8]
  add [esp+128], eax
  adc [esp+132], edx
  adc dword ptr [esp+136], 0
  adc dword ptr [esp+140], 0
  mov eax, [esi+56]
  mul dword ptr [edi+12]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+60]
  mul dword ptr [edi+8]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+60]
  mul dword ptr [edi+12]
  add [esp+136], eax
  adc [esp+140], edx
  mov eax, [esi+56]
  mul dword ptr [edi+16]
  add [esp+144], eax
  adc [esp+148], edx
  adc dword ptr [esp+152], 0
  adc dword ptr [esp+156], 0
  mov eax, [esi+56]
  mul dword ptr [edi+20]
  add [esp+148], eax
  adc [esp+152], edx
  adc dword ptr [esp+156], 0
  mov eax, [esi+60]
  mul dword ptr [edi+16]
  add [esp+148], eax
  adc [esp+152], edx
  adc dword ptr [esp+156], 0
  mov eax, [esi+60]
  mul dword ptr [edi+20]
  add [esp+152], eax
  adc [esp+156], edx
  mov eax, [esi+56]
  mul dword ptr [edi+24]
  add [esp+160], eax
  adc [esp+164], edx
  adc dword ptr [esp+168], 0
  adc dword ptr [esp+172], 0
  mov eax, [esi+56]
  mul dword ptr [edi+28]
  add [esp+164], eax
  adc [esp+168], edx
  adc dword ptr [esp+172], 0
  mov eax, [esi+60]
  mul dword ptr [edi+24]
  add [esp+164], eax
  adc [esp+168], edx
  adc dword ptr [esp+172], 0
  mov eax, [esi+60]
  mul dword ptr [edi+28]
  add [esp+168], eax
  adc [esp+172], edx
  mov eax, [esi+56]
  mul dword ptr [edi+32]
  add [esp+176], eax
  adc [esp+180], edx
  adc dword ptr [esp+184], 0
  adc dword ptr [esp+188], 0
  mov eax, [esi+56]
  mul dword ptr [edi+36]
  add [esp+180], eax
  adc [esp+184], edx
  adc dword ptr [esp+188], 0
  mov eax, [esi+60]
  mul dword ptr [edi+32]
  add [esp+180], eax
  adc [esp+184], edx
  adc dword ptr [esp+188], 0
  mov eax, [esi+60]
  mul dword ptr [edi+36]
  add [esp+184], eax
  adc [esp+188], edx
  mov eax, [esi+56]
  mul dword ptr [edi+40]
  add [esp+192], eax
  adc [esp+196], edx
  adc dword ptr [esp+200], 0
  adc dword ptr [esp+204], 0
  mov eax, [esi+56]
  mul dword ptr [edi+44]
  add [esp+196], eax
  adc [esp+200], edx
  adc dword ptr [esp+204], 0
  mov eax, [esi+60]
  mul dword ptr [edi+40]
  add [esp+196], eax
  adc [esp+200], edx
  adc dword ptr [esp+204], 0
  mov eax, [esi+60]
  mul dword ptr [edi+44]
  add [esp+200], eax
  adc [esp+204], edx
  mov eax, [esi+56]
  mul dword ptr [edi+48]
  add [esp+208], eax
  adc [esp+212], edx
  adc dword ptr [esp+216], 0
  adc dword ptr [esp+220], 0
  mov eax, [esi+56]
  mul dword ptr [edi+52]
  add [esp+212], eax
  adc [esp+216], edx
  adc dword ptr [esp+220], 0
  mov eax, [esi+60]
  mul dword ptr [edi+48]
  add [esp+212], eax
  adc [esp+216], edx
  adc dword ptr [esp+220], 0
  mov eax, [esi+60]
  mul dword ptr [edi+52]
  add [esp+216], eax
  adc [esp+220], edx
  mov eax, [esi+56]
  mul dword ptr [edi+56]
  add [esp+224], eax
  adc [esp+228], edx
  adc dword ptr [esp+232], 0
  adc dword ptr [esp+236], 0
  mov eax, [esi+56]
  mul dword ptr [edi+60]
  add [esp+228], eax
  adc [esp+232], edx
  adc dword ptr [esp+236], 0
  mov eax, [esi+60]
  mul dword ptr [edi+56]
  add [esp+228], eax
  adc [esp+232], edx
  adc dword ptr [esp+236], 0
  mov eax, [esi+60]
  mul dword ptr [edi+60]
  add [esp+232], eax
  adc [esp+236], edx
  mov eax, [esp+224]
  add [esp+160], eax
  mov eax, [esp+228]
  adc [esp+164], eax
  mov eax, [esp+232]
  adc [esp+168], eax
  mov eax, [esp+236]
  adc [esp+172], eax
  mov eax, [esp+224]
  add [esp+96], eax
  mov eax, [esp+228]
  adc [esp+100], eax
  mov eax, [esp+232]
  adc [esp+104], eax
  mov eax, [esp+236]
  adc [esp+108], eax
  mov eax, [esp+208]
  add [esp+144], eax
  mov eax, [esp+212]
  adc [esp+148], eax
  mov eax, [esp+216]
  adc [esp+152], eax
  mov eax, [esp+220]
  adc [esp+156], eax
  mov eax, [esp+208]
  add [esp+80], eax
  mov eax, [esp+212]
  adc [esp+84], eax
  mov eax, [esp+216]
  adc [esp+88], eax
  mov eax, [esp+220]
  adc [esp+92], eax
  mov eax, [esp+192]
  add [esp+128], eax
  mov eax, [esp+196]
  adc [esp+132], eax
  mov eax, [esp+200]
  adc [esp+136], eax
  mov eax, [esp+204]
  adc [esp+140], eax
  mov eax, [esp+192]
  add [esp+64], eax
  mov eax, [esp+196]
  adc [esp+68], eax
  mov eax, [esp+200]
  adc [esp+72], eax
  mov eax, [esp+204]
  adc [esp+76], eax
  mov eax, [esp+176]
  add [esp+112], eax
  mov eax, [esp+180]
  adc [esp+116], eax
  mov eax, [esp+184]
  adc [esp+120], eax
  mov eax, [esp+188]
  adc [esp+124], eax
  mov eax, [esp+176]
  add [esp+48], eax
  mov eax, [esp+180]
  adc [esp+52], eax
  mov eax, [esp+184]
  adc [esp+56], eax
  mov eax, [esp+188]
  adc [esp+60], eax
  mov eax, [esp+160]
  add [esp+96], eax
  mov eax, [esp+164]
  adc [esp+100], eax
  mov eax, [esp+168]
  adc [esp+104], eax
  mov eax, [esp+172]
  adc [esp+108], eax
  mov eax, [esp+160]
  add [esp+32], eax
  mov eax, [esp+164]
  adc [esp+36], eax
  mov eax, [esp+168]
  adc [esp+40], eax
  mov eax, [esp+172]
  adc [esp+44], eax
  mov eax, [esp+144]
  add [esp+80], eax
  mov eax, [esp+148]
  adc [esp+84], eax
  mov eax, [esp+152]
  adc [esp+88], eax
  mov eax, [esp+156]
  adc [esp+92], eax
  mov eax, [esp+144]
  add [esp+16], eax
  mov eax, [esp+148]
  adc [esp+20], eax
  mov eax, [esp+152]
  adc [esp+24], eax
  mov eax, [esp+156]
  adc [esp+28], eax
  mov eax, [esp+128]
  add [esp+64], eax
  mov eax, [esp+132]
  adc [esp+68], eax
  mov eax, [esp+136]
  adc [esp+72], eax
  mov eax, [esp+140]
  adc [esp+76], eax
  mov eax, [esp+128]
  add [esp+0], eax
  mov eax, [esp+132]
  adc [esp+4], eax
  mov eax, [esp+136]
  adc [esp+8], eax
  mov eax, [esp+140]
  adc [esp+12], eax
  mov eax, [esp+0]
  mov [ebx+0], eax
  mov eax, [esp+4]
  and eax, $00FFFFFF
  mov [ebx+4], eax
  mov eax, [esp+4]
  mov ecx, [esp+8]
  shrd eax, ecx, 24
  mov edx, [esp+12]
  shrd ecx, edx, 24
  add [esp+16], eax
  adc [esp+20], ecx
  adc dword ptr [esp+24], 0
  adc dword ptr [esp+28], 0
  mov eax, [esp+16]
  mov [ebx+8], eax
  mov eax, [esp+20]
  and eax, $00FFFFFF
  mov [ebx+12], eax
  mov eax, [esp+20]
  mov ecx, [esp+24]
  shrd eax, ecx, 24
  mov edx, [esp+28]
  shrd ecx, edx, 24
  add [esp+32], eax
  adc [esp+36], ecx
  adc dword ptr [esp+40], 0
  adc dword ptr [esp+44], 0
  mov eax, [esp+32]
  mov [ebx+16], eax
  mov eax, [esp+36]
  and eax, $00FFFFFF
  mov [ebx+20], eax
  mov eax, [esp+36]
  mov ecx, [esp+40]
  shrd eax, ecx, 24
  mov edx, [esp+44]
  shrd ecx, edx, 24
  add [esp+48], eax
  adc [esp+52], ecx
  adc dword ptr [esp+56], 0
  adc dword ptr [esp+60], 0
  mov eax, [esp+48]
  mov [ebx+24], eax
  mov eax, [esp+52]
  and eax, $00FFFFFF
  mov [ebx+28], eax
  mov eax, [esp+52]
  mov ecx, [esp+56]
  shrd eax, ecx, 24
  mov edx, [esp+60]
  shrd ecx, edx, 24
  add [esp+64], eax
  adc [esp+68], ecx
  adc dword ptr [esp+72], 0
  adc dword ptr [esp+76], 0
  mov eax, [esp+64]
  mov [ebx+32], eax
  mov eax, [esp+68]
  and eax, $00FFFFFF
  mov [ebx+36], eax
  mov eax, [esp+68]
  mov ecx, [esp+72]
  shrd eax, ecx, 24
  mov edx, [esp+76]
  shrd ecx, edx, 24
  add [esp+80], eax
  adc [esp+84], ecx
  adc dword ptr [esp+88], 0
  adc dword ptr [esp+92], 0
  mov eax, [esp+80]
  mov [ebx+40], eax
  mov eax, [esp+84]
  and eax, $00FFFFFF
  mov [ebx+44], eax
  mov eax, [esp+84]
  mov ecx, [esp+88]
  shrd eax, ecx, 24
  mov edx, [esp+92]
  shrd ecx, edx, 24
  add [esp+96], eax
  adc [esp+100], ecx
  adc dword ptr [esp+104], 0
  adc dword ptr [esp+108], 0
  mov eax, [esp+96]
  mov [ebx+48], eax
  mov eax, [esp+100]
  and eax, $00FFFFFF
  mov [ebx+52], eax
  mov eax, [esp+100]
  mov ecx, [esp+104]
  shrd eax, ecx, 24
  mov edx, [esp+108]
  shrd ecx, edx, 24
  add [esp+112], eax
  adc [esp+116], ecx
  adc dword ptr [esp+120], 0
  adc dword ptr [esp+124], 0
  mov eax, [esp+112]
  mov [ebx+56], eax
  mov eax, [esp+116]
  and eax, $00FFFFFF
  mov [ebx+60], eax
  mov eax, [esp+116]
  mov ecx, [esp+120]
  shrd eax, ecx, 24
  mov edx, [esp+124]
  shrd ecx, edx, 24
  add [ebx+0], eax
  adc [ebx+4], ecx
  add [ebx+32], eax
  adc [ebx+36], ecx
  mov eax, [ebx+4]
  mov ecx, eax
  shr ecx, 24
  and eax, $00FFFFFF
  mov [ebx+4], eax
  add [ebx+8], ecx
  adc dword ptr [ebx+12], 0
  mov eax, [ebx+36]
  mov ecx, eax
  shr ecx, 24
  and eax, $00FFFFFF
  mov [ebx+36], eax
  add [ebx+40], ecx
  adc dword ptr [ebx+44], 0
  add esp, 240
  pop ebp
  pop edi
  pop esi
  pop ebx
{$ENDIF CRYPTOLIB_CURVE448_FE56MUL}

{$IFDEF CRYPTOLIB_CURVE448_FE56SQR}
  push edi
  mov edi, esi
  push ebp
  sub esp, 240
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
  mov [esp+80], eax
  mov [esp+84], eax
  mov [esp+88], eax
  mov [esp+92], eax
  mov [esp+96], eax
  mov [esp+100], eax
  mov [esp+104], eax
  mov [esp+108], eax
  mov [esp+112], eax
  mov [esp+116], eax
  mov [esp+120], eax
  mov [esp+124], eax
  mov [esp+128], eax
  mov [esp+132], eax
  mov [esp+136], eax
  mov [esp+140], eax
  mov [esp+144], eax
  mov [esp+148], eax
  mov [esp+152], eax
  mov [esp+156], eax
  mov [esp+160], eax
  mov [esp+164], eax
  mov [esp+168], eax
  mov [esp+172], eax
  mov [esp+176], eax
  mov [esp+180], eax
  mov [esp+184], eax
  mov [esp+188], eax
  mov [esp+192], eax
  mov [esp+196], eax
  mov [esp+200], eax
  mov [esp+204], eax
  mov [esp+208], eax
  mov [esp+212], eax
  mov [esp+216], eax
  mov [esp+220], eax
  mov [esp+224], eax
  mov [esp+228], eax
  mov [esp+232], eax
  mov [esp+236], eax
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
  mov eax, [esi+0]
  mul dword ptr [edi+40]
  add [esp+80], eax
  adc [esp+84], edx
  adc dword ptr [esp+88], 0
  adc dword ptr [esp+92], 0
  mov eax, [esi+0]
  mul dword ptr [edi+44]
  add [esp+84], eax
  adc [esp+88], edx
  adc dword ptr [esp+92], 0
  mov eax, [esi+4]
  mul dword ptr [edi+40]
  add [esp+84], eax
  adc [esp+88], edx
  adc dword ptr [esp+92], 0
  mov eax, [esi+4]
  mul dword ptr [edi+44]
  add [esp+88], eax
  adc [esp+92], edx
  mov eax, [esi+0]
  mul dword ptr [edi+48]
  add [esp+96], eax
  adc [esp+100], edx
  adc dword ptr [esp+104], 0
  adc dword ptr [esp+108], 0
  mov eax, [esi+0]
  mul dword ptr [edi+52]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+4]
  mul dword ptr [edi+48]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+4]
  mul dword ptr [edi+52]
  add [esp+104], eax
  adc [esp+108], edx
  mov eax, [esi+0]
  mul dword ptr [edi+56]
  add [esp+112], eax
  adc [esp+116], edx
  adc dword ptr [esp+120], 0
  adc dword ptr [esp+124], 0
  mov eax, [esi+0]
  mul dword ptr [edi+60]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+4]
  mul dword ptr [edi+56]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+4]
  mul dword ptr [edi+60]
  add [esp+120], eax
  adc [esp+124], edx
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
  mov eax, [esi+8]
  mul dword ptr [edi+32]
  add [esp+80], eax
  adc [esp+84], edx
  adc dword ptr [esp+88], 0
  adc dword ptr [esp+92], 0
  mov eax, [esi+8]
  mul dword ptr [edi+36]
  add [esp+84], eax
  adc [esp+88], edx
  adc dword ptr [esp+92], 0
  mov eax, [esi+12]
  mul dword ptr [edi+32]
  add [esp+84], eax
  adc [esp+88], edx
  adc dword ptr [esp+92], 0
  mov eax, [esi+12]
  mul dword ptr [edi+36]
  add [esp+88], eax
  adc [esp+92], edx
  mov eax, [esi+8]
  mul dword ptr [edi+40]
  add [esp+96], eax
  adc [esp+100], edx
  adc dword ptr [esp+104], 0
  adc dword ptr [esp+108], 0
  mov eax, [esi+8]
  mul dword ptr [edi+44]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+12]
  mul dword ptr [edi+40]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+12]
  mul dword ptr [edi+44]
  add [esp+104], eax
  adc [esp+108], edx
  mov eax, [esi+8]
  mul dword ptr [edi+48]
  add [esp+112], eax
  adc [esp+116], edx
  adc dword ptr [esp+120], 0
  adc dword ptr [esp+124], 0
  mov eax, [esi+8]
  mul dword ptr [edi+52]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+12]
  mul dword ptr [edi+48]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+12]
  mul dword ptr [edi+52]
  add [esp+120], eax
  adc [esp+124], edx
  mov eax, [esi+8]
  mul dword ptr [edi+56]
  add [esp+128], eax
  adc [esp+132], edx
  adc dword ptr [esp+136], 0
  adc dword ptr [esp+140], 0
  mov eax, [esi+8]
  mul dword ptr [edi+60]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+12]
  mul dword ptr [edi+56]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+12]
  mul dword ptr [edi+60]
  add [esp+136], eax
  adc [esp+140], edx
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
  mov eax, [esi+16]
  mul dword ptr [edi+24]
  add [esp+80], eax
  adc [esp+84], edx
  adc dword ptr [esp+88], 0
  adc dword ptr [esp+92], 0
  mov eax, [esi+16]
  mul dword ptr [edi+28]
  add [esp+84], eax
  adc [esp+88], edx
  adc dword ptr [esp+92], 0
  mov eax, [esi+20]
  mul dword ptr [edi+24]
  add [esp+84], eax
  adc [esp+88], edx
  adc dword ptr [esp+92], 0
  mov eax, [esi+20]
  mul dword ptr [edi+28]
  add [esp+88], eax
  adc [esp+92], edx
  mov eax, [esi+16]
  mul dword ptr [edi+32]
  add [esp+96], eax
  adc [esp+100], edx
  adc dword ptr [esp+104], 0
  adc dword ptr [esp+108], 0
  mov eax, [esi+16]
  mul dword ptr [edi+36]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+20]
  mul dword ptr [edi+32]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+20]
  mul dword ptr [edi+36]
  add [esp+104], eax
  adc [esp+108], edx
  mov eax, [esi+16]
  mul dword ptr [edi+40]
  add [esp+112], eax
  adc [esp+116], edx
  adc dword ptr [esp+120], 0
  adc dword ptr [esp+124], 0
  mov eax, [esi+16]
  mul dword ptr [edi+44]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+20]
  mul dword ptr [edi+40]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+20]
  mul dword ptr [edi+44]
  add [esp+120], eax
  adc [esp+124], edx
  mov eax, [esi+16]
  mul dword ptr [edi+48]
  add [esp+128], eax
  adc [esp+132], edx
  adc dword ptr [esp+136], 0
  adc dword ptr [esp+140], 0
  mov eax, [esi+16]
  mul dword ptr [edi+52]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+20]
  mul dword ptr [edi+48]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+20]
  mul dword ptr [edi+52]
  add [esp+136], eax
  adc [esp+140], edx
  mov eax, [esi+16]
  mul dword ptr [edi+56]
  add [esp+144], eax
  adc [esp+148], edx
  adc dword ptr [esp+152], 0
  adc dword ptr [esp+156], 0
  mov eax, [esi+16]
  mul dword ptr [edi+60]
  add [esp+148], eax
  adc [esp+152], edx
  adc dword ptr [esp+156], 0
  mov eax, [esi+20]
  mul dword ptr [edi+56]
  add [esp+148], eax
  adc [esp+152], edx
  adc dword ptr [esp+156], 0
  mov eax, [esi+20]
  mul dword ptr [edi+60]
  add [esp+152], eax
  adc [esp+156], edx
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
  mov eax, [esi+24]
  mul dword ptr [edi+16]
  add [esp+80], eax
  adc [esp+84], edx
  adc dword ptr [esp+88], 0
  adc dword ptr [esp+92], 0
  mov eax, [esi+24]
  mul dword ptr [edi+20]
  add [esp+84], eax
  adc [esp+88], edx
  adc dword ptr [esp+92], 0
  mov eax, [esi+28]
  mul dword ptr [edi+16]
  add [esp+84], eax
  adc [esp+88], edx
  adc dword ptr [esp+92], 0
  mov eax, [esi+28]
  mul dword ptr [edi+20]
  add [esp+88], eax
  adc [esp+92], edx
  mov eax, [esi+24]
  mul dword ptr [edi+24]
  add [esp+96], eax
  adc [esp+100], edx
  adc dword ptr [esp+104], 0
  adc dword ptr [esp+108], 0
  mov eax, [esi+24]
  mul dword ptr [edi+28]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+28]
  mul dword ptr [edi+24]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+28]
  mul dword ptr [edi+28]
  add [esp+104], eax
  adc [esp+108], edx
  mov eax, [esi+24]
  mul dword ptr [edi+32]
  add [esp+112], eax
  adc [esp+116], edx
  adc dword ptr [esp+120], 0
  adc dword ptr [esp+124], 0
  mov eax, [esi+24]
  mul dword ptr [edi+36]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+28]
  mul dword ptr [edi+32]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+28]
  mul dword ptr [edi+36]
  add [esp+120], eax
  adc [esp+124], edx
  mov eax, [esi+24]
  mul dword ptr [edi+40]
  add [esp+128], eax
  adc [esp+132], edx
  adc dword ptr [esp+136], 0
  adc dword ptr [esp+140], 0
  mov eax, [esi+24]
  mul dword ptr [edi+44]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+28]
  mul dword ptr [edi+40]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+28]
  mul dword ptr [edi+44]
  add [esp+136], eax
  adc [esp+140], edx
  mov eax, [esi+24]
  mul dword ptr [edi+48]
  add [esp+144], eax
  adc [esp+148], edx
  adc dword ptr [esp+152], 0
  adc dword ptr [esp+156], 0
  mov eax, [esi+24]
  mul dword ptr [edi+52]
  add [esp+148], eax
  adc [esp+152], edx
  adc dword ptr [esp+156], 0
  mov eax, [esi+28]
  mul dword ptr [edi+48]
  add [esp+148], eax
  adc [esp+152], edx
  adc dword ptr [esp+156], 0
  mov eax, [esi+28]
  mul dword ptr [edi+52]
  add [esp+152], eax
  adc [esp+156], edx
  mov eax, [esi+24]
  mul dword ptr [edi+56]
  add [esp+160], eax
  adc [esp+164], edx
  adc dword ptr [esp+168], 0
  adc dword ptr [esp+172], 0
  mov eax, [esi+24]
  mul dword ptr [edi+60]
  add [esp+164], eax
  adc [esp+168], edx
  adc dword ptr [esp+172], 0
  mov eax, [esi+28]
  mul dword ptr [edi+56]
  add [esp+164], eax
  adc [esp+168], edx
  adc dword ptr [esp+172], 0
  mov eax, [esi+28]
  mul dword ptr [edi+60]
  add [esp+168], eax
  adc [esp+172], edx
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
  mov eax, [esi+32]
  mul dword ptr [edi+8]
  add [esp+80], eax
  adc [esp+84], edx
  adc dword ptr [esp+88], 0
  adc dword ptr [esp+92], 0
  mov eax, [esi+32]
  mul dword ptr [edi+12]
  add [esp+84], eax
  adc [esp+88], edx
  adc dword ptr [esp+92], 0
  mov eax, [esi+36]
  mul dword ptr [edi+8]
  add [esp+84], eax
  adc [esp+88], edx
  adc dword ptr [esp+92], 0
  mov eax, [esi+36]
  mul dword ptr [edi+12]
  add [esp+88], eax
  adc [esp+92], edx
  mov eax, [esi+32]
  mul dword ptr [edi+16]
  add [esp+96], eax
  adc [esp+100], edx
  adc dword ptr [esp+104], 0
  adc dword ptr [esp+108], 0
  mov eax, [esi+32]
  mul dword ptr [edi+20]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+36]
  mul dword ptr [edi+16]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+36]
  mul dword ptr [edi+20]
  add [esp+104], eax
  adc [esp+108], edx
  mov eax, [esi+32]
  mul dword ptr [edi+24]
  add [esp+112], eax
  adc [esp+116], edx
  adc dword ptr [esp+120], 0
  adc dword ptr [esp+124], 0
  mov eax, [esi+32]
  mul dword ptr [edi+28]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+36]
  mul dword ptr [edi+24]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+36]
  mul dword ptr [edi+28]
  add [esp+120], eax
  adc [esp+124], edx
  mov eax, [esi+32]
  mul dword ptr [edi+32]
  add [esp+128], eax
  adc [esp+132], edx
  adc dword ptr [esp+136], 0
  adc dword ptr [esp+140], 0
  mov eax, [esi+32]
  mul dword ptr [edi+36]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+36]
  mul dword ptr [edi+32]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+36]
  mul dword ptr [edi+36]
  add [esp+136], eax
  adc [esp+140], edx
  mov eax, [esi+32]
  mul dword ptr [edi+40]
  add [esp+144], eax
  adc [esp+148], edx
  adc dword ptr [esp+152], 0
  adc dword ptr [esp+156], 0
  mov eax, [esi+32]
  mul dword ptr [edi+44]
  add [esp+148], eax
  adc [esp+152], edx
  adc dword ptr [esp+156], 0
  mov eax, [esi+36]
  mul dword ptr [edi+40]
  add [esp+148], eax
  adc [esp+152], edx
  adc dword ptr [esp+156], 0
  mov eax, [esi+36]
  mul dword ptr [edi+44]
  add [esp+152], eax
  adc [esp+156], edx
  mov eax, [esi+32]
  mul dword ptr [edi+48]
  add [esp+160], eax
  adc [esp+164], edx
  adc dword ptr [esp+168], 0
  adc dword ptr [esp+172], 0
  mov eax, [esi+32]
  mul dword ptr [edi+52]
  add [esp+164], eax
  adc [esp+168], edx
  adc dword ptr [esp+172], 0
  mov eax, [esi+36]
  mul dword ptr [edi+48]
  add [esp+164], eax
  adc [esp+168], edx
  adc dword ptr [esp+172], 0
  mov eax, [esi+36]
  mul dword ptr [edi+52]
  add [esp+168], eax
  adc [esp+172], edx
  mov eax, [esi+32]
  mul dword ptr [edi+56]
  add [esp+176], eax
  adc [esp+180], edx
  adc dword ptr [esp+184], 0
  adc dword ptr [esp+188], 0
  mov eax, [esi+32]
  mul dword ptr [edi+60]
  add [esp+180], eax
  adc [esp+184], edx
  adc dword ptr [esp+188], 0
  mov eax, [esi+36]
  mul dword ptr [edi+56]
  add [esp+180], eax
  adc [esp+184], edx
  adc dword ptr [esp+188], 0
  mov eax, [esi+36]
  mul dword ptr [edi+60]
  add [esp+184], eax
  adc [esp+188], edx
  mov eax, [esi+40]
  mul dword ptr [edi+0]
  add [esp+80], eax
  adc [esp+84], edx
  adc dword ptr [esp+88], 0
  adc dword ptr [esp+92], 0
  mov eax, [esi+40]
  mul dword ptr [edi+4]
  add [esp+84], eax
  adc [esp+88], edx
  adc dword ptr [esp+92], 0
  mov eax, [esi+44]
  mul dword ptr [edi+0]
  add [esp+84], eax
  adc [esp+88], edx
  adc dword ptr [esp+92], 0
  mov eax, [esi+44]
  mul dword ptr [edi+4]
  add [esp+88], eax
  adc [esp+92], edx
  mov eax, [esi+40]
  mul dword ptr [edi+8]
  add [esp+96], eax
  adc [esp+100], edx
  adc dword ptr [esp+104], 0
  adc dword ptr [esp+108], 0
  mov eax, [esi+40]
  mul dword ptr [edi+12]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+44]
  mul dword ptr [edi+8]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+44]
  mul dword ptr [edi+12]
  add [esp+104], eax
  adc [esp+108], edx
  mov eax, [esi+40]
  mul dword ptr [edi+16]
  add [esp+112], eax
  adc [esp+116], edx
  adc dword ptr [esp+120], 0
  adc dword ptr [esp+124], 0
  mov eax, [esi+40]
  mul dword ptr [edi+20]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+44]
  mul dword ptr [edi+16]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+44]
  mul dword ptr [edi+20]
  add [esp+120], eax
  adc [esp+124], edx
  mov eax, [esi+40]
  mul dword ptr [edi+24]
  add [esp+128], eax
  adc [esp+132], edx
  adc dword ptr [esp+136], 0
  adc dword ptr [esp+140], 0
  mov eax, [esi+40]
  mul dword ptr [edi+28]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+44]
  mul dword ptr [edi+24]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+44]
  mul dword ptr [edi+28]
  add [esp+136], eax
  adc [esp+140], edx
  mov eax, [esi+40]
  mul dword ptr [edi+32]
  add [esp+144], eax
  adc [esp+148], edx
  adc dword ptr [esp+152], 0
  adc dword ptr [esp+156], 0
  mov eax, [esi+40]
  mul dword ptr [edi+36]
  add [esp+148], eax
  adc [esp+152], edx
  adc dword ptr [esp+156], 0
  mov eax, [esi+44]
  mul dword ptr [edi+32]
  add [esp+148], eax
  adc [esp+152], edx
  adc dword ptr [esp+156], 0
  mov eax, [esi+44]
  mul dword ptr [edi+36]
  add [esp+152], eax
  adc [esp+156], edx
  mov eax, [esi+40]
  mul dword ptr [edi+40]
  add [esp+160], eax
  adc [esp+164], edx
  adc dword ptr [esp+168], 0
  adc dword ptr [esp+172], 0
  mov eax, [esi+40]
  mul dword ptr [edi+44]
  add [esp+164], eax
  adc [esp+168], edx
  adc dword ptr [esp+172], 0
  mov eax, [esi+44]
  mul dword ptr [edi+40]
  add [esp+164], eax
  adc [esp+168], edx
  adc dword ptr [esp+172], 0
  mov eax, [esi+44]
  mul dword ptr [edi+44]
  add [esp+168], eax
  adc [esp+172], edx
  mov eax, [esi+40]
  mul dword ptr [edi+48]
  add [esp+176], eax
  adc [esp+180], edx
  adc dword ptr [esp+184], 0
  adc dword ptr [esp+188], 0
  mov eax, [esi+40]
  mul dword ptr [edi+52]
  add [esp+180], eax
  adc [esp+184], edx
  adc dword ptr [esp+188], 0
  mov eax, [esi+44]
  mul dword ptr [edi+48]
  add [esp+180], eax
  adc [esp+184], edx
  adc dword ptr [esp+188], 0
  mov eax, [esi+44]
  mul dword ptr [edi+52]
  add [esp+184], eax
  adc [esp+188], edx
  mov eax, [esi+40]
  mul dword ptr [edi+56]
  add [esp+192], eax
  adc [esp+196], edx
  adc dword ptr [esp+200], 0
  adc dword ptr [esp+204], 0
  mov eax, [esi+40]
  mul dword ptr [edi+60]
  add [esp+196], eax
  adc [esp+200], edx
  adc dword ptr [esp+204], 0
  mov eax, [esi+44]
  mul dword ptr [edi+56]
  add [esp+196], eax
  adc [esp+200], edx
  adc dword ptr [esp+204], 0
  mov eax, [esi+44]
  mul dword ptr [edi+60]
  add [esp+200], eax
  adc [esp+204], edx
  mov eax, [esi+48]
  mul dword ptr [edi+0]
  add [esp+96], eax
  adc [esp+100], edx
  adc dword ptr [esp+104], 0
  adc dword ptr [esp+108], 0
  mov eax, [esi+48]
  mul dword ptr [edi+4]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+52]
  mul dword ptr [edi+0]
  add [esp+100], eax
  adc [esp+104], edx
  adc dword ptr [esp+108], 0
  mov eax, [esi+52]
  mul dword ptr [edi+4]
  add [esp+104], eax
  adc [esp+108], edx
  mov eax, [esi+48]
  mul dword ptr [edi+8]
  add [esp+112], eax
  adc [esp+116], edx
  adc dword ptr [esp+120], 0
  adc dword ptr [esp+124], 0
  mov eax, [esi+48]
  mul dword ptr [edi+12]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+52]
  mul dword ptr [edi+8]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+52]
  mul dword ptr [edi+12]
  add [esp+120], eax
  adc [esp+124], edx
  mov eax, [esi+48]
  mul dword ptr [edi+16]
  add [esp+128], eax
  adc [esp+132], edx
  adc dword ptr [esp+136], 0
  adc dword ptr [esp+140], 0
  mov eax, [esi+48]
  mul dword ptr [edi+20]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+52]
  mul dword ptr [edi+16]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+52]
  mul dword ptr [edi+20]
  add [esp+136], eax
  adc [esp+140], edx
  mov eax, [esi+48]
  mul dword ptr [edi+24]
  add [esp+144], eax
  adc [esp+148], edx
  adc dword ptr [esp+152], 0
  adc dword ptr [esp+156], 0
  mov eax, [esi+48]
  mul dword ptr [edi+28]
  add [esp+148], eax
  adc [esp+152], edx
  adc dword ptr [esp+156], 0
  mov eax, [esi+52]
  mul dword ptr [edi+24]
  add [esp+148], eax
  adc [esp+152], edx
  adc dword ptr [esp+156], 0
  mov eax, [esi+52]
  mul dword ptr [edi+28]
  add [esp+152], eax
  adc [esp+156], edx
  mov eax, [esi+48]
  mul dword ptr [edi+32]
  add [esp+160], eax
  adc [esp+164], edx
  adc dword ptr [esp+168], 0
  adc dword ptr [esp+172], 0
  mov eax, [esi+48]
  mul dword ptr [edi+36]
  add [esp+164], eax
  adc [esp+168], edx
  adc dword ptr [esp+172], 0
  mov eax, [esi+52]
  mul dword ptr [edi+32]
  add [esp+164], eax
  adc [esp+168], edx
  adc dword ptr [esp+172], 0
  mov eax, [esi+52]
  mul dword ptr [edi+36]
  add [esp+168], eax
  adc [esp+172], edx
  mov eax, [esi+48]
  mul dword ptr [edi+40]
  add [esp+176], eax
  adc [esp+180], edx
  adc dword ptr [esp+184], 0
  adc dword ptr [esp+188], 0
  mov eax, [esi+48]
  mul dword ptr [edi+44]
  add [esp+180], eax
  adc [esp+184], edx
  adc dword ptr [esp+188], 0
  mov eax, [esi+52]
  mul dword ptr [edi+40]
  add [esp+180], eax
  adc [esp+184], edx
  adc dword ptr [esp+188], 0
  mov eax, [esi+52]
  mul dword ptr [edi+44]
  add [esp+184], eax
  adc [esp+188], edx
  mov eax, [esi+48]
  mul dword ptr [edi+48]
  add [esp+192], eax
  adc [esp+196], edx
  adc dword ptr [esp+200], 0
  adc dword ptr [esp+204], 0
  mov eax, [esi+48]
  mul dword ptr [edi+52]
  add [esp+196], eax
  adc [esp+200], edx
  adc dword ptr [esp+204], 0
  mov eax, [esi+52]
  mul dword ptr [edi+48]
  add [esp+196], eax
  adc [esp+200], edx
  adc dword ptr [esp+204], 0
  mov eax, [esi+52]
  mul dword ptr [edi+52]
  add [esp+200], eax
  adc [esp+204], edx
  mov eax, [esi+48]
  mul dword ptr [edi+56]
  add [esp+208], eax
  adc [esp+212], edx
  adc dword ptr [esp+216], 0
  adc dword ptr [esp+220], 0
  mov eax, [esi+48]
  mul dword ptr [edi+60]
  add [esp+212], eax
  adc [esp+216], edx
  adc dword ptr [esp+220], 0
  mov eax, [esi+52]
  mul dword ptr [edi+56]
  add [esp+212], eax
  adc [esp+216], edx
  adc dword ptr [esp+220], 0
  mov eax, [esi+52]
  mul dword ptr [edi+60]
  add [esp+216], eax
  adc [esp+220], edx
  mov eax, [esi+56]
  mul dword ptr [edi+0]
  add [esp+112], eax
  adc [esp+116], edx
  adc dword ptr [esp+120], 0
  adc dword ptr [esp+124], 0
  mov eax, [esi+56]
  mul dword ptr [edi+4]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+60]
  mul dword ptr [edi+0]
  add [esp+116], eax
  adc [esp+120], edx
  adc dword ptr [esp+124], 0
  mov eax, [esi+60]
  mul dword ptr [edi+4]
  add [esp+120], eax
  adc [esp+124], edx
  mov eax, [esi+56]
  mul dword ptr [edi+8]
  add [esp+128], eax
  adc [esp+132], edx
  adc dword ptr [esp+136], 0
  adc dword ptr [esp+140], 0
  mov eax, [esi+56]
  mul dword ptr [edi+12]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+60]
  mul dword ptr [edi+8]
  add [esp+132], eax
  adc [esp+136], edx
  adc dword ptr [esp+140], 0
  mov eax, [esi+60]
  mul dword ptr [edi+12]
  add [esp+136], eax
  adc [esp+140], edx
  mov eax, [esi+56]
  mul dword ptr [edi+16]
  add [esp+144], eax
  adc [esp+148], edx
  adc dword ptr [esp+152], 0
  adc dword ptr [esp+156], 0
  mov eax, [esi+56]
  mul dword ptr [edi+20]
  add [esp+148], eax
  adc [esp+152], edx
  adc dword ptr [esp+156], 0
  mov eax, [esi+60]
  mul dword ptr [edi+16]
  add [esp+148], eax
  adc [esp+152], edx
  adc dword ptr [esp+156], 0
  mov eax, [esi+60]
  mul dword ptr [edi+20]
  add [esp+152], eax
  adc [esp+156], edx
  mov eax, [esi+56]
  mul dword ptr [edi+24]
  add [esp+160], eax
  adc [esp+164], edx
  adc dword ptr [esp+168], 0
  adc dword ptr [esp+172], 0
  mov eax, [esi+56]
  mul dword ptr [edi+28]
  add [esp+164], eax
  adc [esp+168], edx
  adc dword ptr [esp+172], 0
  mov eax, [esi+60]
  mul dword ptr [edi+24]
  add [esp+164], eax
  adc [esp+168], edx
  adc dword ptr [esp+172], 0
  mov eax, [esi+60]
  mul dword ptr [edi+28]
  add [esp+168], eax
  adc [esp+172], edx
  mov eax, [esi+56]
  mul dword ptr [edi+32]
  add [esp+176], eax
  adc [esp+180], edx
  adc dword ptr [esp+184], 0
  adc dword ptr [esp+188], 0
  mov eax, [esi+56]
  mul dword ptr [edi+36]
  add [esp+180], eax
  adc [esp+184], edx
  adc dword ptr [esp+188], 0
  mov eax, [esi+60]
  mul dword ptr [edi+32]
  add [esp+180], eax
  adc [esp+184], edx
  adc dword ptr [esp+188], 0
  mov eax, [esi+60]
  mul dword ptr [edi+36]
  add [esp+184], eax
  adc [esp+188], edx
  mov eax, [esi+56]
  mul dword ptr [edi+40]
  add [esp+192], eax
  adc [esp+196], edx
  adc dword ptr [esp+200], 0
  adc dword ptr [esp+204], 0
  mov eax, [esi+56]
  mul dword ptr [edi+44]
  add [esp+196], eax
  adc [esp+200], edx
  adc dword ptr [esp+204], 0
  mov eax, [esi+60]
  mul dword ptr [edi+40]
  add [esp+196], eax
  adc [esp+200], edx
  adc dword ptr [esp+204], 0
  mov eax, [esi+60]
  mul dword ptr [edi+44]
  add [esp+200], eax
  adc [esp+204], edx
  mov eax, [esi+56]
  mul dword ptr [edi+48]
  add [esp+208], eax
  adc [esp+212], edx
  adc dword ptr [esp+216], 0
  adc dword ptr [esp+220], 0
  mov eax, [esi+56]
  mul dword ptr [edi+52]
  add [esp+212], eax
  adc [esp+216], edx
  adc dword ptr [esp+220], 0
  mov eax, [esi+60]
  mul dword ptr [edi+48]
  add [esp+212], eax
  adc [esp+216], edx
  adc dword ptr [esp+220], 0
  mov eax, [esi+60]
  mul dword ptr [edi+52]
  add [esp+216], eax
  adc [esp+220], edx
  mov eax, [esi+56]
  mul dword ptr [edi+56]
  add [esp+224], eax
  adc [esp+228], edx
  adc dword ptr [esp+232], 0
  adc dword ptr [esp+236], 0
  mov eax, [esi+56]
  mul dword ptr [edi+60]
  add [esp+228], eax
  adc [esp+232], edx
  adc dword ptr [esp+236], 0
  mov eax, [esi+60]
  mul dword ptr [edi+56]
  add [esp+228], eax
  adc [esp+232], edx
  adc dword ptr [esp+236], 0
  mov eax, [esi+60]
  mul dword ptr [edi+60]
  add [esp+232], eax
  adc [esp+236], edx
  mov eax, [esp+224]
  add [esp+160], eax
  mov eax, [esp+228]
  adc [esp+164], eax
  mov eax, [esp+232]
  adc [esp+168], eax
  mov eax, [esp+236]
  adc [esp+172], eax
  mov eax, [esp+224]
  add [esp+96], eax
  mov eax, [esp+228]
  adc [esp+100], eax
  mov eax, [esp+232]
  adc [esp+104], eax
  mov eax, [esp+236]
  adc [esp+108], eax
  mov eax, [esp+208]
  add [esp+144], eax
  mov eax, [esp+212]
  adc [esp+148], eax
  mov eax, [esp+216]
  adc [esp+152], eax
  mov eax, [esp+220]
  adc [esp+156], eax
  mov eax, [esp+208]
  add [esp+80], eax
  mov eax, [esp+212]
  adc [esp+84], eax
  mov eax, [esp+216]
  adc [esp+88], eax
  mov eax, [esp+220]
  adc [esp+92], eax
  mov eax, [esp+192]
  add [esp+128], eax
  mov eax, [esp+196]
  adc [esp+132], eax
  mov eax, [esp+200]
  adc [esp+136], eax
  mov eax, [esp+204]
  adc [esp+140], eax
  mov eax, [esp+192]
  add [esp+64], eax
  mov eax, [esp+196]
  adc [esp+68], eax
  mov eax, [esp+200]
  adc [esp+72], eax
  mov eax, [esp+204]
  adc [esp+76], eax
  mov eax, [esp+176]
  add [esp+112], eax
  mov eax, [esp+180]
  adc [esp+116], eax
  mov eax, [esp+184]
  adc [esp+120], eax
  mov eax, [esp+188]
  adc [esp+124], eax
  mov eax, [esp+176]
  add [esp+48], eax
  mov eax, [esp+180]
  adc [esp+52], eax
  mov eax, [esp+184]
  adc [esp+56], eax
  mov eax, [esp+188]
  adc [esp+60], eax
  mov eax, [esp+160]
  add [esp+96], eax
  mov eax, [esp+164]
  adc [esp+100], eax
  mov eax, [esp+168]
  adc [esp+104], eax
  mov eax, [esp+172]
  adc [esp+108], eax
  mov eax, [esp+160]
  add [esp+32], eax
  mov eax, [esp+164]
  adc [esp+36], eax
  mov eax, [esp+168]
  adc [esp+40], eax
  mov eax, [esp+172]
  adc [esp+44], eax
  mov eax, [esp+144]
  add [esp+80], eax
  mov eax, [esp+148]
  adc [esp+84], eax
  mov eax, [esp+152]
  adc [esp+88], eax
  mov eax, [esp+156]
  adc [esp+92], eax
  mov eax, [esp+144]
  add [esp+16], eax
  mov eax, [esp+148]
  adc [esp+20], eax
  mov eax, [esp+152]
  adc [esp+24], eax
  mov eax, [esp+156]
  adc [esp+28], eax
  mov eax, [esp+128]
  add [esp+64], eax
  mov eax, [esp+132]
  adc [esp+68], eax
  mov eax, [esp+136]
  adc [esp+72], eax
  mov eax, [esp+140]
  adc [esp+76], eax
  mov eax, [esp+128]
  add [esp+0], eax
  mov eax, [esp+132]
  adc [esp+4], eax
  mov eax, [esp+136]
  adc [esp+8], eax
  mov eax, [esp+140]
  adc [esp+12], eax
  mov eax, [esp+0]
  mov [ebx+0], eax
  mov eax, [esp+4]
  and eax, $00FFFFFF
  mov [ebx+4], eax
  mov eax, [esp+4]
  mov ecx, [esp+8]
  shrd eax, ecx, 24
  mov edx, [esp+12]
  shrd ecx, edx, 24
  add [esp+16], eax
  adc [esp+20], ecx
  adc dword ptr [esp+24], 0
  adc dword ptr [esp+28], 0
  mov eax, [esp+16]
  mov [ebx+8], eax
  mov eax, [esp+20]
  and eax, $00FFFFFF
  mov [ebx+12], eax
  mov eax, [esp+20]
  mov ecx, [esp+24]
  shrd eax, ecx, 24
  mov edx, [esp+28]
  shrd ecx, edx, 24
  add [esp+32], eax
  adc [esp+36], ecx
  adc dword ptr [esp+40], 0
  adc dword ptr [esp+44], 0
  mov eax, [esp+32]
  mov [ebx+16], eax
  mov eax, [esp+36]
  and eax, $00FFFFFF
  mov [ebx+20], eax
  mov eax, [esp+36]
  mov ecx, [esp+40]
  shrd eax, ecx, 24
  mov edx, [esp+44]
  shrd ecx, edx, 24
  add [esp+48], eax
  adc [esp+52], ecx
  adc dword ptr [esp+56], 0
  adc dword ptr [esp+60], 0
  mov eax, [esp+48]
  mov [ebx+24], eax
  mov eax, [esp+52]
  and eax, $00FFFFFF
  mov [ebx+28], eax
  mov eax, [esp+52]
  mov ecx, [esp+56]
  shrd eax, ecx, 24
  mov edx, [esp+60]
  shrd ecx, edx, 24
  add [esp+64], eax
  adc [esp+68], ecx
  adc dword ptr [esp+72], 0
  adc dword ptr [esp+76], 0
  mov eax, [esp+64]
  mov [ebx+32], eax
  mov eax, [esp+68]
  and eax, $00FFFFFF
  mov [ebx+36], eax
  mov eax, [esp+68]
  mov ecx, [esp+72]
  shrd eax, ecx, 24
  mov edx, [esp+76]
  shrd ecx, edx, 24
  add [esp+80], eax
  adc [esp+84], ecx
  adc dword ptr [esp+88], 0
  adc dword ptr [esp+92], 0
  mov eax, [esp+80]
  mov [ebx+40], eax
  mov eax, [esp+84]
  and eax, $00FFFFFF
  mov [ebx+44], eax
  mov eax, [esp+84]
  mov ecx, [esp+88]
  shrd eax, ecx, 24
  mov edx, [esp+92]
  shrd ecx, edx, 24
  add [esp+96], eax
  adc [esp+100], ecx
  adc dword ptr [esp+104], 0
  adc dword ptr [esp+108], 0
  mov eax, [esp+96]
  mov [ebx+48], eax
  mov eax, [esp+100]
  and eax, $00FFFFFF
  mov [ebx+52], eax
  mov eax, [esp+100]
  mov ecx, [esp+104]
  shrd eax, ecx, 24
  mov edx, [esp+108]
  shrd ecx, edx, 24
  add [esp+112], eax
  adc [esp+116], ecx
  adc dword ptr [esp+120], 0
  adc dword ptr [esp+124], 0
  mov eax, [esp+112]
  mov [ebx+56], eax
  mov eax, [esp+116]
  and eax, $00FFFFFF
  mov [ebx+60], eax
  mov eax, [esp+116]
  mov ecx, [esp+120]
  shrd eax, ecx, 24
  mov edx, [esp+124]
  shrd ecx, edx, 24
  add [ebx+0], eax
  adc [ebx+4], ecx
  add [ebx+32], eax
  adc [ebx+36], ecx
  mov eax, [ebx+4]
  mov ecx, eax
  shr ecx, 24
  and eax, $00FFFFFF
  mov [ebx+4], eax
  add [ebx+8], ecx
  adc dword ptr [ebx+12], 0
  mov eax, [ebx+36]
  mov ecx, eax
  shr ecx, 24
  and eax, $00FFFFFF
  mov [ebx+36], eax
  add [ebx+40], ecx
  adc dword ptr [ebx+44], 0
  add esp, 240
  pop ebp
  pop edi
  pop esi
  pop ebx
{$ENDIF CRYPTOLIB_CURVE448_FE56SQR}
