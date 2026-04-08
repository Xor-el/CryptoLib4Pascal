// One-block AES-NI encrypt/decrypt (scheduled round keys), i386.
// After SimdProc3Begin_i386: ebx = state, esi = round keys, edi = mode (Dec128=1 .. Enc256=6).
// Db-encoded AES-NI / SSE2 (broad assembler support).
//
  push ebp
  cmp edi, 1
  je @aes_d128
  cmp edi, 2
  je @aes_d192
  cmp edi, 3
  je @aes_d256
  cmp edi, 4
  je @aes_e128
  cmp edi, 5
  je @aes_e192
  cmp edi, 6
  je @aes_e256
  jmp @aes_ir_done
@aes_e128:
  movdqu xmm0, [ebx]
  movdqu xmm1, [esi]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [ebx], xmm0
  mov ebp, 1
@aes_e128_mid:
  cmp ebp, 9
  ja @aes_e128_last
  movdqu xmm0, [ebx]
  mov eax, ebp
  shl eax, 4
  movdqu xmm1, [esi + eax]
  db $66, $0F, $38, $DC, $C1       // aesenc xmm0, xmm1
  movdqu [ebx], xmm0
  inc ebp
  jmp @aes_e128_mid
@aes_e128_last:
  movdqu xmm0, [ebx]
  movdqu xmm1, [esi + 160]
  db $66, $0F, $38, $DD, $C1       // aesenclast xmm0, xmm1
  movdqu [ebx], xmm0
  jmp @aes_ir_done
@aes_e192:
  movdqu xmm0, [ebx]
  movdqu xmm1, [esi]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [ebx], xmm0
  mov ebp, 1
@aes_e192_mid:
  cmp ebp, 11
  ja @aes_e192_last
  movdqu xmm0, [ebx]
  mov eax, ebp
  shl eax, 4
  movdqu xmm1, [esi + eax]
  db $66, $0F, $38, $DC, $C1       // aesenc xmm0, xmm1
  movdqu [ebx], xmm0
  inc ebp
  jmp @aes_e192_mid
@aes_e192_last:
  movdqu xmm0, [ebx]
  movdqu xmm1, [esi + 192]
  db $66, $0F, $38, $DD, $C1       // aesenclast xmm0, xmm1
  movdqu [ebx], xmm0
  jmp @aes_ir_done
@aes_e256:
  movdqu xmm0, [ebx]
  movdqu xmm1, [esi]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [ebx], xmm0
  mov ebp, 1
@aes_e256_mid:
  cmp ebp, 13
  ja @aes_e256_last
  movdqu xmm0, [ebx]
  mov eax, ebp
  shl eax, 4
  movdqu xmm1, [esi + eax]
  db $66, $0F, $38, $DC, $C1       // aesenc xmm0, xmm1
  movdqu [ebx], xmm0
  inc ebp
  jmp @aes_e256_mid
@aes_e256_last:
  movdqu xmm0, [ebx]
  movdqu xmm1, [esi + 224]
  db $66, $0F, $38, $DD, $C1       // aesenclast xmm0, xmm1
  movdqu [ebx], xmm0
  jmp @aes_ir_done
@aes_d128:
  movdqu xmm0, [ebx]
  movdqu xmm1, [esi]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [ebx], xmm0
  mov ebp, 1
@aes_d128_mid:
  cmp ebp, 9
  ja @aes_d128_last
  movdqu xmm0, [ebx]
  mov eax, ebp
  shl eax, 4
  movdqu xmm1, [esi + eax]
  db $66, $0F, $38, $DE, $C1       // aesdec xmm0, xmm1
  movdqu [ebx], xmm0
  inc ebp
  jmp @aes_d128_mid
@aes_d128_last:
  movdqu xmm0, [ebx]
  movdqu xmm1, [esi + 160]
  db $66, $0F, $38, $DF, $C1       // aesdeclast xmm0, xmm1
  movdqu [ebx], xmm0
  jmp @aes_ir_done
@aes_d192:
  movdqu xmm0, [ebx]
  movdqu xmm1, [esi]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [ebx], xmm0
  mov ebp, 1
@aes_d192_mid:
  cmp ebp, 11
  ja @aes_d192_last
  movdqu xmm0, [ebx]
  mov eax, ebp
  shl eax, 4
  movdqu xmm1, [esi + eax]
  db $66, $0F, $38, $DE, $C1       // aesdec xmm0, xmm1
  movdqu [ebx], xmm0
  inc ebp
  jmp @aes_d192_mid
@aes_d192_last:
  movdqu xmm0, [ebx]
  movdqu xmm1, [esi + 192]
  db $66, $0F, $38, $DF, $C1       // aesdeclast xmm0, xmm1
  movdqu [ebx], xmm0
  jmp @aes_ir_done
@aes_d256:
  movdqu xmm0, [ebx]
  movdqu xmm1, [esi]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [ebx], xmm0
  mov ebp, 1
@aes_d256_mid:
  cmp ebp, 13
  ja @aes_d256_last
  movdqu xmm0, [ebx]
  mov eax, ebp
  shl eax, 4
  movdqu xmm1, [esi + eax]
  db $66, $0F, $38, $DE, $C1       // aesdec xmm0, xmm1
  movdqu [ebx], xmm0
  inc ebp
  jmp @aes_d256_mid
@aes_d256_last:
  movdqu xmm0, [ebx]
  movdqu xmm1, [esi + 224]
  db $66, $0F, $38, $DF, $C1       // aesdeclast xmm0, xmm1
  movdqu [ebx], xmm0
@aes_ir_done:
  pop ebp
  pop edi
  pop esi
  pop ebx
