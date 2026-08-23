// Curve25519 radix-2^32 saturated (8 x 32-bit) MULX field multiply and square
// (i386, BMI2 + ADX), with the fe51 boundary conversion done inside the kernel.
// -------------------------------------------------------------------
//
// One selector-driven file; exactly one of the following must be defined before
// including this file:
//
//   CRYPTOLIB_CURVE25519_ADX32MUL   PH := PF * PG mod (2^255-19)
//   CRYPTOLIB_CURVE25519_ADX32SQR   PH := PF^2  mod (2^255-19)
//
// External representation: 5 x 64-bit limbs, radix 2^51 (limb i at [ptr+8i]),
// loosely reduced (each < 2^52) - the same fe51 interface as the plain-mul i386
// kernel, so this is a drop-in alternative tier. Internally the loose limbs are
// carry-propagated + x19-folded into a canonical value, repacked to 8 x 32-bit
// saturated limbs, multiplied by product-scanning (Comba) with 32-bit MULX and a
// register-resident 3-word accumulator, reduced mod 2^255-19 (2^256 === 38, x38
// fold), then repacked to 5 x 2^51 limbs.
//
// On entry (via ClpSimdProc3Begin_i386): ebx = PH, esi = PF, edi = PG.
// ADX32SQR (via ClpSimdProc2Begin_i386): ebx = PH, esi = PF.
//
// MULX is db-encoded for broad assembler compatibility. Constant-time: no
// data-dependent branches or addresses (plain mul/imul/add/adc/shld/shrd/shr/and).
// Reference: 32-bit radix-2^32 saturated field arithmetic (Bernstein curve25519).


{$IFDEF CRYPTOLIB_CURVE25519_ADX32MUL}
  push ebp
  sub esp, 176
  mov [esp+168], ebx
// convert fe51 loose -> 8x32 saturated
  xor eax, eax
  mov [esp], eax
  mov [esp+4], eax
  mov [esp+8], eax
  mov [esp+12], eax
  mov [esp+16], eax
  mov [esp+20], eax
  mov [esp+24], eax
  mov [esp+28], eax
  mov [esp+32], eax
  mov eax, [esi+0]
  mov edx, [esi+4]
  add [esp], eax
  adc [esp+4], edx
  adc dword ptr [esp+8], 0
  adc dword ptr [esp+12], 0
  adc dword ptr [esp+16], 0
  adc dword ptr [esp+20], 0
  adc dword ptr [esp+24], 0
  adc dword ptr [esp+28], 0
  adc dword ptr [esp+32], 0
  mov eax, [esi+8]
  mov edx, [esi+12]
  mov ebx, edx
  shr ebx, 13
  shld edx, eax, 19
  shl eax, 19
  add [esp+4], eax
  adc [esp+8], edx
  adc [esp+12], ebx
  adc dword ptr [esp+16], 0
  adc dword ptr [esp+20], 0
  adc dword ptr [esp+24], 0
  adc dword ptr [esp+28], 0
  adc dword ptr [esp+32], 0
  mov eax, [esi+16]
  mov edx, [esi+20]
  mov ebx, edx
  shr ebx, 26
  shld edx, eax, 6
  shl eax, 6
  add [esp+12], eax
  adc [esp+16], edx
  adc [esp+20], ebx
  adc dword ptr [esp+24], 0
  adc dword ptr [esp+28], 0
  adc dword ptr [esp+32], 0
  mov eax, [esi+24]
  mov edx, [esi+28]
  mov ebx, edx
  shr ebx, 7
  shld edx, eax, 25
  shl eax, 25
  add [esp+16], eax
  adc [esp+20], edx
  adc [esp+24], ebx
  adc dword ptr [esp+28], 0
  adc dword ptr [esp+32], 0
  mov eax, [esi+32]
  mov edx, [esi+36]
  mov ebx, edx
  shr ebx, 20
  shld edx, eax, 12
  shl eax, 12
  add [esp+24], eax
  adc [esp+28], edx
  adc [esp+32], ebx
  mov eax, [esp+32]
  imul eax, eax, 38
  mov dword ptr [esp+32], 0
  add [esp], eax
  adc dword ptr [esp+4], 0
  adc dword ptr [esp+8], 0
  adc dword ptr [esp+12], 0
  adc dword ptr [esp+16], 0
  adc dword ptr [esp+20], 0
  adc dword ptr [esp+24], 0
  adc dword ptr [esp+28], 0
// convert fe51 loose -> 8x32 saturated
  xor eax, eax
  mov [esp+36], eax
  mov [esp+40], eax
  mov [esp+44], eax
  mov [esp+48], eax
  mov [esp+52], eax
  mov [esp+56], eax
  mov [esp+60], eax
  mov [esp+64], eax
  mov [esp+68], eax
  mov eax, [edi+0]
  mov edx, [edi+4]
  add [esp+36], eax
  adc [esp+40], edx
  adc dword ptr [esp+44], 0
  adc dword ptr [esp+48], 0
  adc dword ptr [esp+52], 0
  adc dword ptr [esp+56], 0
  adc dword ptr [esp+60], 0
  adc dword ptr [esp+64], 0
  adc dword ptr [esp+68], 0
  mov eax, [edi+8]
  mov edx, [edi+12]
  mov ebx, edx
  shr ebx, 13
  shld edx, eax, 19
  shl eax, 19
  add [esp+40], eax
  adc [esp+44], edx
  adc [esp+48], ebx
  adc dword ptr [esp+52], 0
  adc dword ptr [esp+56], 0
  adc dword ptr [esp+60], 0
  adc dword ptr [esp+64], 0
  adc dword ptr [esp+68], 0
  mov eax, [edi+16]
  mov edx, [edi+20]
  mov ebx, edx
  shr ebx, 26
  shld edx, eax, 6
  shl eax, 6
  add [esp+48], eax
  adc [esp+52], edx
  adc [esp+56], ebx
  adc dword ptr [esp+60], 0
  adc dword ptr [esp+64], 0
  adc dword ptr [esp+68], 0
  mov eax, [edi+24]
  mov edx, [edi+28]
  mov ebx, edx
  shr ebx, 7
  shld edx, eax, 25
  shl eax, 25
  add [esp+52], eax
  adc [esp+56], edx
  adc [esp+60], ebx
  adc dword ptr [esp+64], 0
  adc dword ptr [esp+68], 0
  mov eax, [edi+32]
  mov edx, [edi+36]
  mov ebx, edx
  shr ebx, 20
  shld edx, eax, 12
  shl eax, 12
  add [esp+60], eax
  adc [esp+64], edx
  adc [esp+68], ebx
  mov eax, [esp+68]
  imul eax, eax, 38
  mov dword ptr [esp+68], 0
  add [esp+36], eax
  adc dword ptr [esp+40], 0
  adc dword ptr [esp+44], 0
  adc dword ptr [esp+48], 0
  adc dword ptr [esp+52], 0
  adc dword ptr [esp+56], 0
  adc dword ptr [esp+60], 0
  adc dword ptr [esp+64], 0
// 8x8 Comba multiply (MULX) -> 16 limbs
  xor ecx, ecx
  xor esi, esi
  xor edi, edi
  mov edx, [esp]
  db $C4, $E2, $7B, $F6, $5C, $24, $24                 // mulx ebx, eax, dword ptr [esp + 0x24]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+72], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp]
  db $C4, $E2, $7B, $F6, $5C, $24, $28                 // mulx ebx, eax, dword ptr [esp + 0x28]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+4]
  db $C4, $E2, $7B, $F6, $5C, $24, $24                 // mulx ebx, eax, dword ptr [esp + 0x24]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+76], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp]
  db $C4, $E2, $7B, $F6, $5C, $24, $2C                 // mulx ebx, eax, dword ptr [esp + 0x2c]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+4]
  db $C4, $E2, $7B, $F6, $5C, $24, $28                 // mulx ebx, eax, dword ptr [esp + 0x28]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+8]
  db $C4, $E2, $7B, $F6, $5C, $24, $24                 // mulx ebx, eax, dword ptr [esp + 0x24]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+80], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp]
  db $C4, $E2, $7B, $F6, $5C, $24, $30                 // mulx ebx, eax, dword ptr [esp + 0x30]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+4]
  db $C4, $E2, $7B, $F6, $5C, $24, $2C                 // mulx ebx, eax, dword ptr [esp + 0x2c]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+8]
  db $C4, $E2, $7B, $F6, $5C, $24, $28                 // mulx ebx, eax, dword ptr [esp + 0x28]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+12]
  db $C4, $E2, $7B, $F6, $5C, $24, $24                 // mulx ebx, eax, dword ptr [esp + 0x24]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+84], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp]
  db $C4, $E2, $7B, $F6, $5C, $24, $34                 // mulx ebx, eax, dword ptr [esp + 0x34]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+4]
  db $C4, $E2, $7B, $F6, $5C, $24, $30                 // mulx ebx, eax, dword ptr [esp + 0x30]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+8]
  db $C4, $E2, $7B, $F6, $5C, $24, $2C                 // mulx ebx, eax, dword ptr [esp + 0x2c]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+12]
  db $C4, $E2, $7B, $F6, $5C, $24, $28                 // mulx ebx, eax, dword ptr [esp + 0x28]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+16]
  db $C4, $E2, $7B, $F6, $5C, $24, $24                 // mulx ebx, eax, dword ptr [esp + 0x24]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+88], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp]
  db $C4, $E2, $7B, $F6, $5C, $24, $38                 // mulx ebx, eax, dword ptr [esp + 0x38]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+4]
  db $C4, $E2, $7B, $F6, $5C, $24, $34                 // mulx ebx, eax, dword ptr [esp + 0x34]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+8]
  db $C4, $E2, $7B, $F6, $5C, $24, $30                 // mulx ebx, eax, dword ptr [esp + 0x30]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+12]
  db $C4, $E2, $7B, $F6, $5C, $24, $2C                 // mulx ebx, eax, dword ptr [esp + 0x2c]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+16]
  db $C4, $E2, $7B, $F6, $5C, $24, $28                 // mulx ebx, eax, dword ptr [esp + 0x28]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+20]
  db $C4, $E2, $7B, $F6, $5C, $24, $24                 // mulx ebx, eax, dword ptr [esp + 0x24]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+92], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp]
  db $C4, $E2, $7B, $F6, $5C, $24, $3C                 // mulx ebx, eax, dword ptr [esp + 0x3c]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+4]
  db $C4, $E2, $7B, $F6, $5C, $24, $38                 // mulx ebx, eax, dword ptr [esp + 0x38]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+8]
  db $C4, $E2, $7B, $F6, $5C, $24, $34                 // mulx ebx, eax, dword ptr [esp + 0x34]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+12]
  db $C4, $E2, $7B, $F6, $5C, $24, $30                 // mulx ebx, eax, dword ptr [esp + 0x30]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+16]
  db $C4, $E2, $7B, $F6, $5C, $24, $2C                 // mulx ebx, eax, dword ptr [esp + 0x2c]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+20]
  db $C4, $E2, $7B, $F6, $5C, $24, $28                 // mulx ebx, eax, dword ptr [esp + 0x28]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+24]
  db $C4, $E2, $7B, $F6, $5C, $24, $24                 // mulx ebx, eax, dword ptr [esp + 0x24]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+96], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp]
  db $C4, $E2, $7B, $F6, $5C, $24, $40                 // mulx ebx, eax, dword ptr [esp + 0x40]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+4]
  db $C4, $E2, $7B, $F6, $5C, $24, $3C                 // mulx ebx, eax, dword ptr [esp + 0x3c]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+8]
  db $C4, $E2, $7B, $F6, $5C, $24, $38                 // mulx ebx, eax, dword ptr [esp + 0x38]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+12]
  db $C4, $E2, $7B, $F6, $5C, $24, $34                 // mulx ebx, eax, dword ptr [esp + 0x34]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+16]
  db $C4, $E2, $7B, $F6, $5C, $24, $30                 // mulx ebx, eax, dword ptr [esp + 0x30]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+20]
  db $C4, $E2, $7B, $F6, $5C, $24, $2C                 // mulx ebx, eax, dword ptr [esp + 0x2c]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+24]
  db $C4, $E2, $7B, $F6, $5C, $24, $28                 // mulx ebx, eax, dword ptr [esp + 0x28]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+28]
  db $C4, $E2, $7B, $F6, $5C, $24, $24                 // mulx ebx, eax, dword ptr [esp + 0x24]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+100], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp+4]
  db $C4, $E2, $7B, $F6, $5C, $24, $40                 // mulx ebx, eax, dword ptr [esp + 0x40]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+8]
  db $C4, $E2, $7B, $F6, $5C, $24, $3C                 // mulx ebx, eax, dword ptr [esp + 0x3c]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+12]
  db $C4, $E2, $7B, $F6, $5C, $24, $38                 // mulx ebx, eax, dword ptr [esp + 0x38]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+16]
  db $C4, $E2, $7B, $F6, $5C, $24, $34                 // mulx ebx, eax, dword ptr [esp + 0x34]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+20]
  db $C4, $E2, $7B, $F6, $5C, $24, $30                 // mulx ebx, eax, dword ptr [esp + 0x30]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+24]
  db $C4, $E2, $7B, $F6, $5C, $24, $2C                 // mulx ebx, eax, dword ptr [esp + 0x2c]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+28]
  db $C4, $E2, $7B, $F6, $5C, $24, $28                 // mulx ebx, eax, dword ptr [esp + 0x28]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+104], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp+8]
  db $C4, $E2, $7B, $F6, $5C, $24, $40                 // mulx ebx, eax, dword ptr [esp + 0x40]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+12]
  db $C4, $E2, $7B, $F6, $5C, $24, $3C                 // mulx ebx, eax, dword ptr [esp + 0x3c]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+16]
  db $C4, $E2, $7B, $F6, $5C, $24, $38                 // mulx ebx, eax, dword ptr [esp + 0x38]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+20]
  db $C4, $E2, $7B, $F6, $5C, $24, $34                 // mulx ebx, eax, dword ptr [esp + 0x34]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+24]
  db $C4, $E2, $7B, $F6, $5C, $24, $30                 // mulx ebx, eax, dword ptr [esp + 0x30]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+28]
  db $C4, $E2, $7B, $F6, $5C, $24, $2C                 // mulx ebx, eax, dword ptr [esp + 0x2c]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+108], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp+12]
  db $C4, $E2, $7B, $F6, $5C, $24, $40                 // mulx ebx, eax, dword ptr [esp + 0x40]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+16]
  db $C4, $E2, $7B, $F6, $5C, $24, $3C                 // mulx ebx, eax, dword ptr [esp + 0x3c]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+20]
  db $C4, $E2, $7B, $F6, $5C, $24, $38                 // mulx ebx, eax, dword ptr [esp + 0x38]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+24]
  db $C4, $E2, $7B, $F6, $5C, $24, $34                 // mulx ebx, eax, dword ptr [esp + 0x34]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+28]
  db $C4, $E2, $7B, $F6, $5C, $24, $30                 // mulx ebx, eax, dword ptr [esp + 0x30]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+112], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp+16]
  db $C4, $E2, $7B, $F6, $5C, $24, $40                 // mulx ebx, eax, dword ptr [esp + 0x40]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+20]
  db $C4, $E2, $7B, $F6, $5C, $24, $3C                 // mulx ebx, eax, dword ptr [esp + 0x3c]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+24]
  db $C4, $E2, $7B, $F6, $5C, $24, $38                 // mulx ebx, eax, dword ptr [esp + 0x38]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+28]
  db $C4, $E2, $7B, $F6, $5C, $24, $34                 // mulx ebx, eax, dword ptr [esp + 0x34]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+116], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp+20]
  db $C4, $E2, $7B, $F6, $5C, $24, $40                 // mulx ebx, eax, dword ptr [esp + 0x40]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+24]
  db $C4, $E2, $7B, $F6, $5C, $24, $3C                 // mulx ebx, eax, dword ptr [esp + 0x3c]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+28]
  db $C4, $E2, $7B, $F6, $5C, $24, $38                 // mulx ebx, eax, dword ptr [esp + 0x38]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+120], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp+24]
  db $C4, $E2, $7B, $F6, $5C, $24, $40                 // mulx ebx, eax, dword ptr [esp + 0x40]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+28]
  db $C4, $E2, $7B, $F6, $5C, $24, $3C                 // mulx ebx, eax, dword ptr [esp + 0x3c]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+124], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp+28]
  db $C4, $E2, $7B, $F6, $5C, $24, $40                 // mulx ebx, eax, dword ptr [esp + 0x40]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+128], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov [esp+132], ecx
// reduce 16 limbs mod 2^255-19 (x38 fold)
  mov edx, 38
  xor ebp, ebp
  db $C4, $E2, $7B, $F6, $5C, $24, $68                 // mulx ebx, eax, dword ptr [esp + 0x68]
  add eax, ebp
  adc ebx, 0
  add eax, [esp+72]
  adc ebx, 0
  mov [esp+136], eax
  mov ebp, ebx
  db $C4, $E2, $7B, $F6, $5C, $24, $6C                 // mulx ebx, eax, dword ptr [esp + 0x6c]
  add eax, ebp
  adc ebx, 0
  add eax, [esp+76]
  adc ebx, 0
  mov [esp+140], eax
  mov ebp, ebx
  db $C4, $E2, $7B, $F6, $5C, $24, $70                 // mulx ebx, eax, dword ptr [esp + 0x70]
  add eax, ebp
  adc ebx, 0
  add eax, [esp+80]
  adc ebx, 0
  mov [esp+144], eax
  mov ebp, ebx
  db $C4, $E2, $7B, $F6, $5C, $24, $74                 // mulx ebx, eax, dword ptr [esp + 0x74]
  add eax, ebp
  adc ebx, 0
  add eax, [esp+84]
  adc ebx, 0
  mov [esp+148], eax
  mov ebp, ebx
  db $C4, $E2, $7B, $F6, $5C, $24, $78                 // mulx ebx, eax, dword ptr [esp + 0x78]
  add eax, ebp
  adc ebx, 0
  add eax, [esp+88]
  adc ebx, 0
  mov [esp+152], eax
  mov ebp, ebx
  db $C4, $E2, $7B, $F6, $5C, $24, $7C                 // mulx ebx, eax, dword ptr [esp + 0x7c]
  add eax, ebp
  adc ebx, 0
  add eax, [esp+92]
  adc ebx, 0
  mov [esp+156], eax
  mov ebp, ebx
  db $C4, $E2, $7B, $F6, $9C, $24, $80, $00, $00, $00  // mulx ebx, eax, dword ptr [esp + 0x80]
  add eax, ebp
  adc ebx, 0
  add eax, [esp+96]
  adc ebx, 0
  mov [esp+160], eax
  mov ebp, ebx
  db $C4, $E2, $7B, $F6, $9C, $24, $84, $00, $00, $00  // mulx ebx, eax, dword ptr [esp + 0x84]
  add eax, ebp
  adc ebx, 0
  add eax, [esp+100]
  adc ebx, 0
  mov [esp+164], eax
  mov ebp, ebx
  mov eax, ebp
  imul eax, eax, 38
  add [esp+136], eax
  adc dword ptr [esp+140], 0
  adc dword ptr [esp+144], 0
  adc dword ptr [esp+148], 0
  adc dword ptr [esp+152], 0
  adc dword ptr [esp+156], 0
  adc dword ptr [esp+160], 0
  adc dword ptr [esp+164], 0
  mov eax, 0
  adc eax, 0
  imul eax, eax, 38
  add [esp+136], eax
  adc dword ptr [esp+140], 0
  adc dword ptr [esp+144], 0
  adc dword ptr [esp+148], 0
  adc dword ptr [esp+152], 0
  adc dword ptr [esp+156], 0
  adc dword ptr [esp+160], 0
  adc dword ptr [esp+164], 0
  mov edi, [esp+168]
// fold bit 255 (x19) then slice into 5 x 2^51 limbs
  mov eax, [esp+164]
  shr eax, 31
  imul eax, eax, 19
  and dword ptr [esp+164], 2147483647
  add [esp+136], eax
  adc dword ptr [esp+140], 0
  adc dword ptr [esp+144], 0
  adc dword ptr [esp+148], 0
  adc dword ptr [esp+152], 0
  adc dword ptr [esp+156], 0
  adc dword ptr [esp+160], 0
  adc dword ptr [esp+164], 0
  mov eax, [esp+164]
  shr eax, 31
  imul eax, eax, 19
  and dword ptr [esp+164], 2147483647
  add [esp+136], eax
  adc dword ptr [esp+140], 0
  adc dword ptr [esp+144], 0
  adc dword ptr [esp+148], 0
  adc dword ptr [esp+152], 0
  adc dword ptr [esp+156], 0
  adc dword ptr [esp+160], 0
  adc dword ptr [esp+164], 0
  mov eax, [esp+136]
  mov edx, [esp+140]
  and edx, 524287
  mov [edi+0], eax
  mov [edi+4], edx
  mov eax, [esp+140]
  mov edx, [esp+144]
  shrd eax, edx, 19
  mov edx, [esp+144]
  mov ebx, [esp+148]
  shrd edx, ebx, 19
  and edx, 524287
  mov [edi+8], eax
  mov [edi+12], edx
  mov eax, [esp+148]
  mov edx, [esp+152]
  shrd eax, edx, 6
  mov edx, [esp+152]
  mov ebx, [esp+156]
  shrd edx, ebx, 6
  and edx, 524287
  mov [edi+16], eax
  mov [edi+20], edx
  mov eax, [esp+152]
  mov edx, [esp+156]
  shrd eax, edx, 25
  mov edx, [esp+156]
  mov ebx, [esp+160]
  shrd edx, ebx, 25
  and edx, 524287
  mov [edi+24], eax
  mov [edi+28], edx
  mov eax, [esp+160]
  mov edx, [esp+164]
  shrd eax, edx, 12
  mov edx, [esp+164]
  shr edx, 12
  and edx, 524287
  mov [edi+32], eax
  mov [edi+36], edx
  add esp, 176
  pop ebp
  pop edi
  pop esi
  pop ebx
{$ENDIF CRYPTOLIB_CURVE25519_ADX32MUL}

{$IFDEF CRYPTOLIB_CURVE25519_ADX32SQR}
  push ebp
  push edi
  sub esp, 176
  mov [esp+168], ebx
// convert fe51 loose -> 8x32 saturated
  xor eax, eax
  mov [esp], eax
  mov [esp+4], eax
  mov [esp+8], eax
  mov [esp+12], eax
  mov [esp+16], eax
  mov [esp+20], eax
  mov [esp+24], eax
  mov [esp+28], eax
  mov [esp+32], eax
  mov eax, [esi+0]
  mov edx, [esi+4]
  add [esp], eax
  adc [esp+4], edx
  adc dword ptr [esp+8], 0
  adc dword ptr [esp+12], 0
  adc dword ptr [esp+16], 0
  adc dword ptr [esp+20], 0
  adc dword ptr [esp+24], 0
  adc dword ptr [esp+28], 0
  adc dword ptr [esp+32], 0
  mov eax, [esi+8]
  mov edx, [esi+12]
  mov ebx, edx
  shr ebx, 13
  shld edx, eax, 19
  shl eax, 19
  add [esp+4], eax
  adc [esp+8], edx
  adc [esp+12], ebx
  adc dword ptr [esp+16], 0
  adc dword ptr [esp+20], 0
  adc dword ptr [esp+24], 0
  adc dword ptr [esp+28], 0
  adc dword ptr [esp+32], 0
  mov eax, [esi+16]
  mov edx, [esi+20]
  mov ebx, edx
  shr ebx, 26
  shld edx, eax, 6
  shl eax, 6
  add [esp+12], eax
  adc [esp+16], edx
  adc [esp+20], ebx
  adc dword ptr [esp+24], 0
  adc dword ptr [esp+28], 0
  adc dword ptr [esp+32], 0
  mov eax, [esi+24]
  mov edx, [esi+28]
  mov ebx, edx
  shr ebx, 7
  shld edx, eax, 25
  shl eax, 25
  add [esp+16], eax
  adc [esp+20], edx
  adc [esp+24], ebx
  adc dword ptr [esp+28], 0
  adc dword ptr [esp+32], 0
  mov eax, [esi+32]
  mov edx, [esi+36]
  mov ebx, edx
  shr ebx, 20
  shld edx, eax, 12
  shl eax, 12
  add [esp+24], eax
  adc [esp+28], edx
  adc [esp+32], ebx
  mov eax, [esp+32]
  imul eax, eax, 38
  mov dword ptr [esp+32], 0
  add [esp], eax
  adc dword ptr [esp+4], 0
  adc dword ptr [esp+8], 0
  adc dword ptr [esp+12], 0
  adc dword ptr [esp+16], 0
  adc dword ptr [esp+20], 0
  adc dword ptr [esp+24], 0
  adc dword ptr [esp+28], 0
// 8x8 Comba multiply (MULX) -> 16 limbs
  xor ecx, ecx
  xor esi, esi
  xor edi, edi
  mov edx, [esp]
  db $C4, $E2, $7B, $F6, $1C, $24                      // mulx ebx, eax, dword ptr [esp]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+72], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp]
  db $C4, $E2, $7B, $F6, $5C, $24, $04                 // mulx ebx, eax, dword ptr [esp + 4]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+4]
  db $C4, $E2, $7B, $F6, $1C, $24                      // mulx ebx, eax, dword ptr [esp]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+76], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp]
  db $C4, $E2, $7B, $F6, $5C, $24, $08                 // mulx ebx, eax, dword ptr [esp + 8]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+4]
  db $C4, $E2, $7B, $F6, $5C, $24, $04                 // mulx ebx, eax, dword ptr [esp + 4]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+8]
  db $C4, $E2, $7B, $F6, $1C, $24                      // mulx ebx, eax, dword ptr [esp]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+80], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp]
  db $C4, $E2, $7B, $F6, $5C, $24, $0C                 // mulx ebx, eax, dword ptr [esp + 0xc]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+4]
  db $C4, $E2, $7B, $F6, $5C, $24, $08                 // mulx ebx, eax, dword ptr [esp + 8]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+8]
  db $C4, $E2, $7B, $F6, $5C, $24, $04                 // mulx ebx, eax, dword ptr [esp + 4]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+12]
  db $C4, $E2, $7B, $F6, $1C, $24                      // mulx ebx, eax, dword ptr [esp]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+84], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp]
  db $C4, $E2, $7B, $F6, $5C, $24, $10                 // mulx ebx, eax, dword ptr [esp + 0x10]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+4]
  db $C4, $E2, $7B, $F6, $5C, $24, $0C                 // mulx ebx, eax, dword ptr [esp + 0xc]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+8]
  db $C4, $E2, $7B, $F6, $5C, $24, $08                 // mulx ebx, eax, dword ptr [esp + 8]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+12]
  db $C4, $E2, $7B, $F6, $5C, $24, $04                 // mulx ebx, eax, dword ptr [esp + 4]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+16]
  db $C4, $E2, $7B, $F6, $1C, $24                      // mulx ebx, eax, dword ptr [esp]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+88], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp]
  db $C4, $E2, $7B, $F6, $5C, $24, $14                 // mulx ebx, eax, dword ptr [esp + 0x14]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+4]
  db $C4, $E2, $7B, $F6, $5C, $24, $10                 // mulx ebx, eax, dword ptr [esp + 0x10]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+8]
  db $C4, $E2, $7B, $F6, $5C, $24, $0C                 // mulx ebx, eax, dword ptr [esp + 0xc]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+12]
  db $C4, $E2, $7B, $F6, $5C, $24, $08                 // mulx ebx, eax, dword ptr [esp + 8]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+16]
  db $C4, $E2, $7B, $F6, $5C, $24, $04                 // mulx ebx, eax, dword ptr [esp + 4]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+20]
  db $C4, $E2, $7B, $F6, $1C, $24                      // mulx ebx, eax, dword ptr [esp]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+92], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp]
  db $C4, $E2, $7B, $F6, $5C, $24, $18                 // mulx ebx, eax, dword ptr [esp + 0x18]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+4]
  db $C4, $E2, $7B, $F6, $5C, $24, $14                 // mulx ebx, eax, dword ptr [esp + 0x14]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+8]
  db $C4, $E2, $7B, $F6, $5C, $24, $10                 // mulx ebx, eax, dword ptr [esp + 0x10]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+12]
  db $C4, $E2, $7B, $F6, $5C, $24, $0C                 // mulx ebx, eax, dword ptr [esp + 0xc]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+16]
  db $C4, $E2, $7B, $F6, $5C, $24, $08                 // mulx ebx, eax, dword ptr [esp + 8]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+20]
  db $C4, $E2, $7B, $F6, $5C, $24, $04                 // mulx ebx, eax, dword ptr [esp + 4]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+24]
  db $C4, $E2, $7B, $F6, $1C, $24                      // mulx ebx, eax, dword ptr [esp]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+96], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp]
  db $C4, $E2, $7B, $F6, $5C, $24, $1C                 // mulx ebx, eax, dword ptr [esp + 0x1c]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+4]
  db $C4, $E2, $7B, $F6, $5C, $24, $18                 // mulx ebx, eax, dword ptr [esp + 0x18]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+8]
  db $C4, $E2, $7B, $F6, $5C, $24, $14                 // mulx ebx, eax, dword ptr [esp + 0x14]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+12]
  db $C4, $E2, $7B, $F6, $5C, $24, $10                 // mulx ebx, eax, dword ptr [esp + 0x10]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+16]
  db $C4, $E2, $7B, $F6, $5C, $24, $0C                 // mulx ebx, eax, dword ptr [esp + 0xc]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+20]
  db $C4, $E2, $7B, $F6, $5C, $24, $08                 // mulx ebx, eax, dword ptr [esp + 8]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+24]
  db $C4, $E2, $7B, $F6, $5C, $24, $04                 // mulx ebx, eax, dword ptr [esp + 4]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+28]
  db $C4, $E2, $7B, $F6, $1C, $24                      // mulx ebx, eax, dword ptr [esp]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+100], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp+4]
  db $C4, $E2, $7B, $F6, $5C, $24, $1C                 // mulx ebx, eax, dword ptr [esp + 0x1c]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+8]
  db $C4, $E2, $7B, $F6, $5C, $24, $18                 // mulx ebx, eax, dword ptr [esp + 0x18]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+12]
  db $C4, $E2, $7B, $F6, $5C, $24, $14                 // mulx ebx, eax, dword ptr [esp + 0x14]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+16]
  db $C4, $E2, $7B, $F6, $5C, $24, $10                 // mulx ebx, eax, dword ptr [esp + 0x10]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+20]
  db $C4, $E2, $7B, $F6, $5C, $24, $0C                 // mulx ebx, eax, dword ptr [esp + 0xc]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+24]
  db $C4, $E2, $7B, $F6, $5C, $24, $08                 // mulx ebx, eax, dword ptr [esp + 8]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+28]
  db $C4, $E2, $7B, $F6, $5C, $24, $04                 // mulx ebx, eax, dword ptr [esp + 4]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+104], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp+8]
  db $C4, $E2, $7B, $F6, $5C, $24, $1C                 // mulx ebx, eax, dword ptr [esp + 0x1c]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+12]
  db $C4, $E2, $7B, $F6, $5C, $24, $18                 // mulx ebx, eax, dword ptr [esp + 0x18]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+16]
  db $C4, $E2, $7B, $F6, $5C, $24, $14                 // mulx ebx, eax, dword ptr [esp + 0x14]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+20]
  db $C4, $E2, $7B, $F6, $5C, $24, $10                 // mulx ebx, eax, dword ptr [esp + 0x10]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+24]
  db $C4, $E2, $7B, $F6, $5C, $24, $0C                 // mulx ebx, eax, dword ptr [esp + 0xc]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+28]
  db $C4, $E2, $7B, $F6, $5C, $24, $08                 // mulx ebx, eax, dword ptr [esp + 8]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+108], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp+12]
  db $C4, $E2, $7B, $F6, $5C, $24, $1C                 // mulx ebx, eax, dword ptr [esp + 0x1c]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+16]
  db $C4, $E2, $7B, $F6, $5C, $24, $18                 // mulx ebx, eax, dword ptr [esp + 0x18]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+20]
  db $C4, $E2, $7B, $F6, $5C, $24, $14                 // mulx ebx, eax, dword ptr [esp + 0x14]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+24]
  db $C4, $E2, $7B, $F6, $5C, $24, $10                 // mulx ebx, eax, dword ptr [esp + 0x10]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+28]
  db $C4, $E2, $7B, $F6, $5C, $24, $0C                 // mulx ebx, eax, dword ptr [esp + 0xc]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+112], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp+16]
  db $C4, $E2, $7B, $F6, $5C, $24, $1C                 // mulx ebx, eax, dword ptr [esp + 0x1c]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+20]
  db $C4, $E2, $7B, $F6, $5C, $24, $18                 // mulx ebx, eax, dword ptr [esp + 0x18]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+24]
  db $C4, $E2, $7B, $F6, $5C, $24, $14                 // mulx ebx, eax, dword ptr [esp + 0x14]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+28]
  db $C4, $E2, $7B, $F6, $5C, $24, $10                 // mulx ebx, eax, dword ptr [esp + 0x10]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+116], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp+20]
  db $C4, $E2, $7B, $F6, $5C, $24, $1C                 // mulx ebx, eax, dword ptr [esp + 0x1c]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+24]
  db $C4, $E2, $7B, $F6, $5C, $24, $18                 // mulx ebx, eax, dword ptr [esp + 0x18]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+28]
  db $C4, $E2, $7B, $F6, $5C, $24, $14                 // mulx ebx, eax, dword ptr [esp + 0x14]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+120], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp+24]
  db $C4, $E2, $7B, $F6, $5C, $24, $1C                 // mulx ebx, eax, dword ptr [esp + 0x1c]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov edx, [esp+28]
  db $C4, $E2, $7B, $F6, $5C, $24, $18                 // mulx ebx, eax, dword ptr [esp + 0x18]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+124], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov edx, [esp+28]
  db $C4, $E2, $7B, $F6, $5C, $24, $1C                 // mulx ebx, eax, dword ptr [esp + 0x1c]
  add ecx, eax
  adc esi, ebx
  adc edi, 0
  mov [esp+128], ecx
  mov ecx, esi
  mov esi, edi
  xor edi, edi
  mov [esp+132], ecx
// reduce 16 limbs mod 2^255-19 (x38 fold)
  mov edx, 38
  xor ebp, ebp
  db $C4, $E2, $7B, $F6, $5C, $24, $68                 // mulx ebx, eax, dword ptr [esp + 0x68]
  add eax, ebp
  adc ebx, 0
  add eax, [esp+72]
  adc ebx, 0
  mov [esp+136], eax
  mov ebp, ebx
  db $C4, $E2, $7B, $F6, $5C, $24, $6C                 // mulx ebx, eax, dword ptr [esp + 0x6c]
  add eax, ebp
  adc ebx, 0
  add eax, [esp+76]
  adc ebx, 0
  mov [esp+140], eax
  mov ebp, ebx
  db $C4, $E2, $7B, $F6, $5C, $24, $70                 // mulx ebx, eax, dword ptr [esp + 0x70]
  add eax, ebp
  adc ebx, 0
  add eax, [esp+80]
  adc ebx, 0
  mov [esp+144], eax
  mov ebp, ebx
  db $C4, $E2, $7B, $F6, $5C, $24, $74                 // mulx ebx, eax, dword ptr [esp + 0x74]
  add eax, ebp
  adc ebx, 0
  add eax, [esp+84]
  adc ebx, 0
  mov [esp+148], eax
  mov ebp, ebx
  db $C4, $E2, $7B, $F6, $5C, $24, $78                 // mulx ebx, eax, dword ptr [esp + 0x78]
  add eax, ebp
  adc ebx, 0
  add eax, [esp+88]
  adc ebx, 0
  mov [esp+152], eax
  mov ebp, ebx
  db $C4, $E2, $7B, $F6, $5C, $24, $7C                 // mulx ebx, eax, dword ptr [esp + 0x7c]
  add eax, ebp
  adc ebx, 0
  add eax, [esp+92]
  adc ebx, 0
  mov [esp+156], eax
  mov ebp, ebx
  db $C4, $E2, $7B, $F6, $9C, $24, $80, $00, $00, $00  // mulx ebx, eax, dword ptr [esp + 0x80]
  add eax, ebp
  adc ebx, 0
  add eax, [esp+96]
  adc ebx, 0
  mov [esp+160], eax
  mov ebp, ebx
  db $C4, $E2, $7B, $F6, $9C, $24, $84, $00, $00, $00  // mulx ebx, eax, dword ptr [esp + 0x84]
  add eax, ebp
  adc ebx, 0
  add eax, [esp+100]
  adc ebx, 0
  mov [esp+164], eax
  mov ebp, ebx
  mov eax, ebp
  imul eax, eax, 38
  add [esp+136], eax
  adc dword ptr [esp+140], 0
  adc dword ptr [esp+144], 0
  adc dword ptr [esp+148], 0
  adc dword ptr [esp+152], 0
  adc dword ptr [esp+156], 0
  adc dword ptr [esp+160], 0
  adc dword ptr [esp+164], 0
  mov eax, 0
  adc eax, 0
  imul eax, eax, 38
  add [esp+136], eax
  adc dword ptr [esp+140], 0
  adc dword ptr [esp+144], 0
  adc dword ptr [esp+148], 0
  adc dword ptr [esp+152], 0
  adc dword ptr [esp+156], 0
  adc dword ptr [esp+160], 0
  adc dword ptr [esp+164], 0
  mov edi, [esp+168]
// fold bit 255 (x19) then slice into 5 x 2^51 limbs
  mov eax, [esp+164]
  shr eax, 31
  imul eax, eax, 19
  and dword ptr [esp+164], 2147483647
  add [esp+136], eax
  adc dword ptr [esp+140], 0
  adc dword ptr [esp+144], 0
  adc dword ptr [esp+148], 0
  adc dword ptr [esp+152], 0
  adc dword ptr [esp+156], 0
  adc dword ptr [esp+160], 0
  adc dword ptr [esp+164], 0
  mov eax, [esp+164]
  shr eax, 31
  imul eax, eax, 19
  and dword ptr [esp+164], 2147483647
  add [esp+136], eax
  adc dword ptr [esp+140], 0
  adc dword ptr [esp+144], 0
  adc dword ptr [esp+148], 0
  adc dword ptr [esp+152], 0
  adc dword ptr [esp+156], 0
  adc dword ptr [esp+160], 0
  adc dword ptr [esp+164], 0
  mov eax, [esp+136]
  mov edx, [esp+140]
  and edx, 524287
  mov [edi+0], eax
  mov [edi+4], edx
  mov eax, [esp+140]
  mov edx, [esp+144]
  shrd eax, edx, 19
  mov edx, [esp+144]
  mov ebx, [esp+148]
  shrd edx, ebx, 19
  and edx, 524287
  mov [edi+8], eax
  mov [edi+12], edx
  mov eax, [esp+148]
  mov edx, [esp+152]
  shrd eax, edx, 6
  mov edx, [esp+152]
  mov ebx, [esp+156]
  shrd edx, ebx, 6
  and edx, 524287
  mov [edi+16], eax
  mov [edi+20], edx
  mov eax, [esp+152]
  mov edx, [esp+156]
  shrd eax, edx, 25
  mov edx, [esp+156]
  mov ebx, [esp+160]
  shrd edx, ebx, 25
  and edx, 524287
  mov [edi+24], eax
  mov [edi+28], edx
  mov eax, [esp+160]
  mov edx, [esp+164]
  shrd eax, edx, 12
  mov edx, [esp+164]
  shr edx, 12
  and edx, 524287
  mov [edi+32], eax
  mov [edi+36], edx
  add esp, 176
  pop edi
  pop ebp
  pop esi
  pop ebx
{$ENDIF CRYPTOLIB_CURVE25519_ADX32SQR}
