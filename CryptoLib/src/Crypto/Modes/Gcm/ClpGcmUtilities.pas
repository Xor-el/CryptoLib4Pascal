{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpGcmUtilities;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBitOperations,
  ClpInt64Utilities,
  ClpPack,
  ClpInterleave,
  ClpCpuFeatures,
  ClpCryptoLibTypes,
  ClpIntrinsicsVector;

type
  TFieldElement = record
    N0, N1: UInt64;
  end;

  TGcmUtilities = class sealed(TObject)
  strict private
    const
      E1: UInt32 = UInt32($E1000000);
      E1UL: UInt64 = UInt64($E100000000000000); // UInt64(E1) shl 32

    class function ImplMul64(AX, AY: UInt64): UInt64; static;
  public
    class procedure One(out AX: TFieldElement); static;

    class procedure AsBytes(AX0, AX1: UInt64; const AZ: TCryptoLibByteArray); overload; static; inline;
    class procedure AsBytes(var AX: TFieldElement; const AZ: TCryptoLibByteArray); overload; static; inline;

    class procedure AsFieldElement(const AX: TCryptoLibByteArray; out AZ: TFieldElement); static; inline;

    class procedure DivideP(var AX: TFieldElement; out AZ: TFieldElement); static;

    class procedure Multiply(const AX, AY: TCryptoLibByteArray); overload; static;
    class procedure Multiply(var AX: TFieldElement; var AY: TFieldElement); overload; static;

    class procedure MultiplyP7(var AX: TFieldElement); static;
    class procedure MultiplyP8(var AX: TFieldElement); overload; static;
    class procedure MultiplyP8(var AX: TFieldElement; out AY: TFieldElement); overload; static;
    class procedure MultiplyP16(var AX: TFieldElement); static;

    class procedure Square(var AX: TFieldElement); static;

    /// <summary>True when this build includes the PCLMULQDQ GHASH asm path and the CPU supports it.</summary>
    class function PclmulFieldMultiplyAvailable: Boolean; static;
    /// <summary>Carryless multiply: three 128-bit limbs (48 bytes). Operands 16 bytes each as two little-endian UInt64 halves.</summary>
    class procedure MultiplyExt(PX, PY, POut48: PByte); static;
    /// <summary>Fold middle limb Z1 into Z0 and Z2, then reduce to one 128-bit block.</summary>
    class procedure Reduce3(PZ0, PZ1, PZ2, PSVector16: PByte); static;
    /// <summary>Xor three 16-byte limbs with three 16-byte slices from a 48-byte MultiplyExt output.</summary>
    class procedure XorMultiplyExtLimbs48(PA0, PA1, PA2, PSrc48: PByte); static;
    /// <summary>HPow[0..3] = H^4..H^1 as 16-byte limbs for fused four-block GHASH (index 0 = H^4, index 3 = H^1).</summary>
    class procedure InitFourWayHPowFromH(const AH: TCryptoLibByteArray; const AHPow64: TCryptoLibByteArray); static;
    /// <summary>HPow[0..7] = H^8..H^1 as 16-byte limbs at offsets 0,16,...,112 (index 0 = H^8). Four-way fused GHASH uses offsets 64..112 (H^4..H^1).</summary>
    class procedure InitEightWayHPowFromH(const AH: TCryptoLibByteArray; const AHPow128: TCryptoLibByteArray); static;

{$IFDEF CRYPTOLIB_X86_SIMD}
    /// <summary>Fused GHASH for four 16-byte ciphertext blocks. PFS 16-byte in/out (canonical); PC0 points to 64 contiguous ciphertext bytes; PHPow64 = H^4..H^1 (64 bytes); PMask = 16-byte SSSE3 PSHUFB control.</summary>
    class procedure FusedFourShuffledGhash(PFS, PC0, PHPow64, PMask: PByte); static;
    /// <summary>Fused GHASH for eight 16-byte ciphertext blocks. PHPow128 = H^8..H^1 (128 bytes at FHPow[0]).</summary>
    class procedure FusedEightShuffledGhash(PFS, PC0, PHPow128, PMask: PByte); static;
{$ENDIF CRYPTOLIB_X86_SIMD}

    class procedure &Xor(const AX, AY: TCryptoLibByteArray); overload; static;
    class procedure &Xor(const AX, AY: TCryptoLibByteArray; AYOff: Int32); overload; static;
    class procedure &Xor(const AX, AY: TCryptoLibByteArray; AYOff, AYLen: Int32); overload; static;
    class procedure &Xor(const AX: TCryptoLibByteArray; AXOff: Int32;
      const AY: TCryptoLibByteArray; AYOff, ALen: Int32); overload; static;
    class procedure &Xor(var AX: TFieldElement; var AY: TFieldElement); overload; static;
    class procedure &Xor(var AX: TFieldElement; var AY: TFieldElement;
      out AZ: TFieldElement); overload; static;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}
type
  TGcmPartial128 = record
    T3, T2, T1, T0: UInt64;
  end;

{$IFDEF CRYPTOLIB_X86_64_ASM}
procedure GcmPclmulFieldPartial(PX, PY, POut: Pointer);
{$I ..\..\..\Include\Simd\Common\SimdProc3Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Gcm\GcmPclmulPartial_x86_64.inc}
end;

procedure GcmPclmulMultiplyExtBytes(PX, PY, POut48: Pointer);
{$I ..\..\..\Include\Simd\Common\SimdProc3Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Gcm\GcmPclmulMultiplyExt_x86_64.inc}
end;

procedure GcmReduce3FoldSse2(PZ0, PZ1, PZ2, POut: Pointer);
{$I ..\..\..\Include\Simd\Common\SimdProc4Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Gcm\GcmReduce3FoldSse2_x86_64.inc}
end;

procedure GcmXorMultiplyExtLimbs48Sse2(PA0, PA1, PA2, PSrc48: Pointer);
{$I ..\..\..\Include\Simd\Common\SimdProc4Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Gcm\GcmXorMultiplyExtLimbs48Sse2_x86_64.inc}
end;

procedure GcmBlockReverse128Ssse3(PDst, PSrc, PMask: Pointer);
{$I ..\..\..\Include\Simd\Common\SimdProc3Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\Gcm\GcmBlockReverse128Ssse3_x86_64.inc}
end;
{$ENDIF CRYPTOLIB_X86_64_ASM}

{$IFDEF CRYPTOLIB_I386_ASM}
procedure GcmPclmulFieldPartial(PX, PY, POut: Pointer);
{$I ..\..\..\Include\Simd\Common\SimdProc3Begin_i386.inc}
{$I ..\..\..\Include\Simd\Gcm\GcmPclmulPartial_i386.inc}
end;

procedure GcmPclmulMultiplyExtBytes(PX, PY, POut48: Pointer);
{$I ..\..\..\Include\Simd\Common\SimdProc3Begin_i386.inc}
{$I ..\..\..\Include\Simd\Gcm\GcmPclmulMultiplyExt_i386.inc}
end;

procedure GcmReduce3FoldSse2(PZ0, PZ1, PZ2, POut: Pointer);
{$I ..\..\..\Include\Simd\Common\SimdProc4Begin_i386.inc}
{$I ..\..\..\Include\Simd\Gcm\GcmReduce3FoldSse2_i386.inc}
end;

procedure GcmXorMultiplyExtLimbs48Sse2(PA0, PA1, PA2, PSrc48: Pointer);
{$I ..\..\..\Include\Simd\Common\SimdProc4Begin_i386.inc}
{$I ..\..\..\Include\Simd\Gcm\GcmXorMultiplyExtLimbs48Sse2_i386.inc}
end;

procedure GcmBlockReverse128Ssse3(PDst, PSrc, PMask: Pointer);
{$I ..\..\..\Include\Simd\Common\SimdProc3Begin_i386.inc}
{$I ..\..\..\Include\Simd\Gcm\GcmBlockReverse128Ssse3_i386.inc}
end;
{$ENDIF CRYPTOLIB_I386_ASM}

procedure GcmPclmulReducePartial(const APartial: TGcmPartial128; var AZ: TFieldElement);
var
  LT3, LT2, LT1, LT0: UInt64;
  LZ0, LZ1, LZ2: UInt64;
begin
  LT3 := APartial.T3;
  LT2 := APartial.T2;
  LT1 := APartial.T1;
  LT0 := APartial.T0;
  LT1 := LT1 xor LT3 xor (LT3 shr 1) xor (LT3 shr 2) xor (LT3 shr 7);
  LT2 := LT2 xor (LT3 shl 63) xor (LT3 shl 62) xor (LT3 shl 57);
  LZ0 := (LT0 shl 1) or (LT1 shr 63);
  LZ1 := (LT1 shl 1) or (LT2 shr 63);
  LZ2 := LT2 shl 1;
  LZ0 := LZ0 xor LZ2 xor (LZ2 shr 1) xor (LZ2 shr 2) xor (LZ2 shr 7);
  LZ1 := LZ1 xor (LT2 shl 63) xor (LT2 shl 58);
  AZ.N0 := LZ0;
  AZ.N1 := LZ1;
end;
{$ENDIF CRYPTOLIB_X86_SIMD}

{ TGcmUtilities }

class procedure TGcmUtilities.One(out AX: TFieldElement);
begin
  AX.N0 := UInt64(1) shl 63;
  AX.N1 := UInt64(0);
end;

class procedure TGcmUtilities.AsBytes(AX0, AX1: UInt64; const AZ: TCryptoLibByteArray);
begin
  TPack.UInt64_To_BE(AX0, AZ, 0);
  TPack.UInt64_To_BE(AX1, AZ, 8);
end;

class procedure TGcmUtilities.AsBytes(var AX: TFieldElement; const AZ: TCryptoLibByteArray);
begin
  AsBytes(AX.N0, AX.N1, AZ);
end;

class procedure TGcmUtilities.AsFieldElement(const AX: TCryptoLibByteArray; out AZ: TFieldElement);
begin
  AZ.N0 := TPack.BE_To_UInt64(AX, 0);
  AZ.N1 := TPack.BE_To_UInt64(AX, 8);
end;

class procedure TGcmUtilities.DivideP(var AX: TFieldElement; out AZ: TFieldElement);
var
  LX0, LX1, LM: UInt64;
begin
  LX0 := AX.N0;
  LX1 := AX.N1;
  LM := UInt64(TBitOperations.Asr64(Int64(LX0), 63));
  LX0 := LX0 xor (LM and E1UL);
  AZ.N0 := (LX0 shl 1) or (LX1 shr 63);
  AZ.N1 := (LX1 shl 1) or UInt64(-Int64(LM));
end;

class procedure TGcmUtilities.Multiply(const AX, AY: TCryptoLibByteArray);
var
  LFieldX, LFieldY: TFieldElement;
begin
  AsFieldElement(AX, LFieldX);
  AsFieldElement(AY, LFieldY);
  Multiply(LFieldX, LFieldY);
  AsBytes(LFieldX, AX);
end;

class procedure TGcmUtilities.Multiply(var AX: TFieldElement; var AY: TFieldElement);
var
  LX0, LX1, LY0, LY1: UInt64;
  LX0R, LX1R, LY0R, LY1R: UInt64;
  LZ0, LZ1, LZ2, LZ3: UInt64;
  LH0, LH1, LH2, LH3, LH4, LH5: UInt64;
  {$IFDEF CRYPTOLIB_X86_SIMD}
  LPartial: TGcmPartial128;
  {$ENDIF}
begin
  {$IFDEF CRYPTOLIB_X86_SIMD}
  if TCpuFeatures.X86.HasPCLMULQDQ then
  begin
    GcmPclmulFieldPartial(@AX, @AY, @LPartial);
    GcmPclmulReducePartial(LPartial, AX);
    Exit;
  end;
  {$ENDIF}
  LX0 := AX.N0;
  LX1 := AX.N1;
  LY0 := AY.N0;
  LY1 := AY.N1;
  LX0R := TInt64Utilities.Reverse(LX0);
  LX1R := TInt64Utilities.Reverse(LX1);
  LY0R := TInt64Utilities.Reverse(LY0);
  LY1R := TInt64Utilities.Reverse(LY1);

  LH0 := TInt64Utilities.Reverse(ImplMul64(LX0R, LY0R));
  LH1 := ImplMul64(LX0, LY0) shl 1;
  LH2 := TInt64Utilities.Reverse(ImplMul64(LX1R, LY1R));
  LH3 := ImplMul64(LX1, LY1) shl 1;
  LH4 := TInt64Utilities.Reverse(ImplMul64(LX0R xor LX1R, LY0R xor LY1R));
  LH5 := ImplMul64(LX0 xor LX1, LY0 xor LY1) shl 1;

  LZ0 := LH0;
  LZ1 := LH1 xor LH0 xor LH2 xor LH4;
  LZ2 := LH2 xor LH1 xor LH3 xor LH5;
  LZ3 := LH3;

  LZ1 := LZ1 xor LZ3 xor (LZ3 shr 1) xor (LZ3 shr 2) xor (LZ3 shr 7);
  LZ2 := LZ2 xor (LZ3 shl 62) xor (LZ3 shl 57);

  LZ0 := LZ0 xor LZ2 xor (LZ2 shr 1) xor (LZ2 shr 2) xor (LZ2 shr 7);
  LZ1 := LZ1 xor (LZ2 shl 63) xor (LZ2 shl 62) xor (LZ2 shl 57);

  AX.N0 := LZ0;
  AX.N1 := LZ1;
end;

class procedure TGcmUtilities.MultiplyP7(var AX: TFieldElement);
var
  LX0, LX1, LC: UInt64;
begin
  LX0 := AX.N0;
  LX1 := AX.N1;
  LC := LX1 shl 57;
  AX.N0 := (LX0 shr 7) xor LC xor (LC shr 1) xor (LC shr 2) xor (LC shr 7);
  AX.N1 := (LX1 shr 7) or (LX0 shl 57);
end;

class procedure TGcmUtilities.MultiplyP8(var AX: TFieldElement);
var
  LX0, LX1, LC: UInt64;
begin
  LX0 := AX.N0;
  LX1 := AX.N1;
  LC := LX1 shl 56;
  AX.N0 := (LX0 shr 8) xor LC xor (LC shr 1) xor (LC shr 2) xor (LC shr 7);
  AX.N1 := (LX1 shr 8) or (LX0 shl 56);
end;

class procedure TGcmUtilities.MultiplyP8(var AX: TFieldElement; out AY: TFieldElement);
var
  LX0, LX1, LC: UInt64;
begin
  LX0 := AX.N0;
  LX1 := AX.N1;
  LC := LX1 shl 56;
  AY.N0 := (LX0 shr 8) xor LC xor (LC shr 1) xor (LC shr 2) xor (LC shr 7);
  AY.N1 := (LX1 shr 8) or (LX0 shl 56);
end;

class procedure TGcmUtilities.MultiplyP16(var AX: TFieldElement);
var
  LX0, LX1, LC: UInt64;
begin
  LX0 := AX.N0;
  LX1 := AX.N1;
  LC := LX1 shl 48;
  AX.N0 := (LX0 shr 16) xor LC xor (LC shr 1) xor (LC shr 2) xor (LC shr 7);
  AX.N1 := (LX1 shr 16) or (LX0 shl 48);
end;

class procedure TGcmUtilities.Square(var AX: TFieldElement);
var
  LT0, LT1, LT2, LT3, LZ1, LZ2: UInt64;
begin
  LT1 := TInterleave.Expand64To128Rev(AX.N0, LT0);
  LT3 := TInterleave.Expand64To128Rev(AX.N1, LT2);

  LZ1 := LT1 xor LT3 xor (LT3 shr 1) xor (LT3 shr 2) xor (LT3 shr 7);
  LZ2 := LT2 xor (LT3 shl 62) xor (LT3 shl 57);

  AX.N0 := LT0 xor LZ2 xor (LZ2 shr 1) xor (LZ2 shr 2) xor (LZ2 shr 7);
  AX.N1 := LZ1 xor (LT2 shl 62) xor (LT2 shl 57);
end;

class procedure TGcmUtilities.&Xor(const AX, AY: TCryptoLibByteArray);
var
  LI: Int32;
begin
  LI := 0;
  repeat
    AX[LI] := AX[LI] xor AY[LI]; System.Inc(LI);
    AX[LI] := AX[LI] xor AY[LI]; System.Inc(LI);
    AX[LI] := AX[LI] xor AY[LI]; System.Inc(LI);
    AX[LI] := AX[LI] xor AY[LI]; System.Inc(LI);
  until LI >= 16;
end;

class procedure TGcmUtilities.&Xor(const AX, AY: TCryptoLibByteArray; AYOff: Int32);
var
  LI: Int32;
begin
  LI := 0;
  repeat
    AX[LI] := AX[LI] xor AY[AYOff + LI]; System.Inc(LI);
    AX[LI] := AX[LI] xor AY[AYOff + LI]; System.Inc(LI);
    AX[LI] := AX[LI] xor AY[AYOff + LI]; System.Inc(LI);
    AX[LI] := AX[LI] xor AY[AYOff + LI]; System.Inc(LI);
  until LI >= 16;
end;

class procedure TGcmUtilities.&Xor(const AX, AY: TCryptoLibByteArray; AYOff, AYLen: Int32);
begin
  System.Dec(AYLen);
  while AYLen >= 0 do
  begin
    AX[AYLen] := AX[AYLen] xor AY[AYOff + AYLen];
    System.Dec(AYLen);
  end;
end;

class procedure TGcmUtilities.&Xor(const AX: TCryptoLibByteArray; AXOff: Int32;
  const AY: TCryptoLibByteArray; AYOff, ALen: Int32);
begin
  System.Dec(ALen);
  while ALen >= 0 do
  begin
    AX[AXOff + ALen] := AX[AXOff + ALen] xor AY[AYOff + ALen];
    System.Dec(ALen);
  end;
end;

class procedure TGcmUtilities.&Xor(var AX: TFieldElement; var AY: TFieldElement);
begin
  AX.N0 := AX.N0 xor AY.N0;
  AX.N1 := AX.N1 xor AY.N1;
end;

class procedure TGcmUtilities.&Xor(var AX: TFieldElement; var AY: TFieldElement;
  out AZ: TFieldElement);
begin
  AZ.N0 := AX.N0 xor AY.N0;
  AZ.N1 := AX.N1 xor AY.N1;
end;

class function TGcmUtilities.ImplMul64(AX, AY: UInt64): UInt64;
var
  LX0, LX1, LX2, LX3: UInt64;
  LY0, LY1, LY2, LY3: UInt64;
  LZ0, LZ1, LZ2, LZ3: UInt64;
begin
  LX0 := AX and UInt64($1111111111111111);
  LX1 := AX and UInt64($2222222222222222);
  LX2 := AX and UInt64($4444444444444444);
  LX3 := AX and UInt64($8888888888888888);

  LY0 := AY and UInt64($1111111111111111);
  LY1 := AY and UInt64($2222222222222222);
  LY2 := AY and UInt64($4444444444444444);
  LY3 := AY and UInt64($8888888888888888);

  LZ0 := (LX0 * LY0) xor (LX1 * LY3) xor (LX2 * LY2) xor (LX3 * LY1);
  LZ1 := (LX0 * LY1) xor (LX1 * LY0) xor (LX2 * LY3) xor (LX3 * LY2);
  LZ2 := (LX0 * LY2) xor (LX1 * LY1) xor (LX2 * LY0) xor (LX3 * LY3);
  LZ3 := (LX0 * LY3) xor (LX1 * LY2) xor (LX2 * LY1) xor (LX3 * LY0);

  LZ0 := LZ0 and UInt64($1111111111111111);
  LZ1 := LZ1 and UInt64($2222222222222222);
  LZ2 := LZ2 and UInt64($4444444444444444);
  LZ3 := LZ3 and UInt64($8888888888888888);

  Result := LZ0 or LZ1 or LZ2 or LZ3;
end;

class function TGcmUtilities.PclmulFieldMultiplyAvailable: Boolean;
begin
  Result := False;
{$IFDEF CRYPTOLIB_X86_SIMD}
  Result := TCpuFeatures.X86.HasPCLMULQDQ;
{$ENDIF}
end;

class procedure TGcmUtilities.MultiplyExt(PX, PY, POut48: PByte);
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if TCpuFeatures.X86.HasPCLMULQDQ then
  begin
    GcmPclmulMultiplyExtBytes(PX, PY, POut48);
    Exit;
  end;
{$ENDIF}
  raise EInvalidOperationCryptoLibException.Create(
    'PCLMULQDQ multiply-ext is not available on this target.');
end;

class procedure TGcmUtilities.XorMultiplyExtLimbs48(PA0, PA1, PA2, PSrc48: PByte);
var
  LK: Int32;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if TCpuFeatures.X86.HasSSE2 then
  begin
    GcmXorMultiplyExtLimbs48Sse2(PA0, PA1, PA2, PSrc48);
    Exit;
  end;
{$ENDIF CRYPTOLIB_X86_SIMD}
  for LK := 0 to 1 do
  begin
    PUInt64(PA0 + LK * 8)^ := PUInt64(PA0 + LK * 8)^ xor PUInt64(PSrc48 + LK * 8)^;
    PUInt64(PA1 + LK * 8)^ := PUInt64(PA1 + LK * 8)^ xor PUInt64(PSrc48 + 16 + LK * 8)^;
    PUInt64(PA2 + LK * 8)^ := PUInt64(PA2 + LK * 8)^ xor PUInt64(PSrc48 + 32 + LK * 8)^;
  end;
end;

class procedure TGcmUtilities.Reduce3(PZ0, PZ1, PZ2, PSVector16: PByte);
var
  B0, B1, B2: array[0..15] of Byte;
  SL, SR: array[0..15] of Byte;
  LI: Int32;
  LT3, LT2, LT1, LT0, LZ0, LZ1, LZ2: UInt64;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if TCpuFeatures.X86.HasSSE2 then
  begin
    GcmReduce3FoldSse2(PZ0, PZ1, PZ2, PSVector16);
    Exit;
  end;
{$ENDIF CRYPTOLIB_X86_SIMD}
  System.Move(PZ0^, B0[0], 16);
  System.Move(PZ1^, B1[0], 16);
  System.Move(PZ2^, B2[0], 16);
  System.FillChar(SL[0], 16, 0);
  System.Move(B1[0], SL[8], 8);
  for LI := 0 to 15 do
    B0[LI] := B0[LI] xor SL[LI];
  System.FillChar(SR[0], 16, 0);
  System.Move(B1[8], SR[0], 8);
  for LI := 0 to 15 do
    B2[LI] := B2[LI] xor SR[LI];
  LT3 := PUInt64(@B0[0])^;
  LT2 := PUInt64(@B0[8])^;
  LT1 := PUInt64(@B2[0])^;
  LT0 := PUInt64(@B2[8])^;
  LT1 := LT1 xor LT3 xor (LT3 shr 1) xor (LT3 shr 2) xor (LT3 shr 7);
  LT2 := LT2 xor (LT3 shl 63) xor (LT3 shl 62) xor (LT3 shl 57);
  LZ0 := (LT0 shl 1) or (LT1 shr 63);
  LZ1 := (LT1 shl 1) or (LT2 shr 63);
  LZ2 := LT2 shl 1;
  LZ0 := LZ0 xor LZ2 xor (LZ2 shr 1) xor (LZ2 shr 2) xor (LZ2 shr 7);
  LZ1 := LZ1 xor (LT2 shl 63) xor (LT2 shl 58);
  PUInt64(PSVector16)^ := LZ1;
  PUInt64(PSVector16 + 8)^ := LZ0;
end;

{$IFDEF CRYPTOLIB_X86_SIMD}
class procedure TGcmUtilities.FusedFourShuffledGhash(PFS, PC0, PHPow64, PMask: PByte);
var
  LB, LI: Int32;
  LDblk: array [0 .. 15] of Byte;
  LBuf48: array [0 .. 47] of Byte;
  LU0, LU1, LU2: array [0 .. 15] of Byte;
  LSRev: array [0 .. 15] of Byte;
  LPCiph: PByte;
  LPH: PByte;
begin
  if (not TCpuFeatures.X86.HasSSSE3) or (not TCpuFeatures.X86.HasPCLMULQDQ) or
    (not TIntrinsicsVector.IsPacked) then
    raise EInvalidOperationCryptoLibException.Create(
      'Fused four-way GHASH requires SSSE3, PCLMULQDQ, and packed XMM layout.');

  GcmBlockReverse128Ssse3(@LSRev[0], PFS, PMask);
  PUInt64(@LU0[0])^ := 0;
  PUInt64(@LU0[8])^ := 0;
  PUInt64(@LU1[0])^ := 0;
  PUInt64(@LU1[8])^ := 0;
  PUInt64(@LU2[0])^ := 0;
  PUInt64(@LU2[8])^ := 0;

  for LB := 0 to 3 do
  begin
    LPCiph := PByte(NativeUInt(PC0) + UInt32(LB) shl 4);
    GcmBlockReverse128Ssse3(@LDblk[0], LPCiph, PMask);
    if LB = 0 then
      for LI := 0 to 15 do
        LDblk[LI] := LDblk[LI] xor LSRev[LI];
    LPH := PByte(NativeUInt(PHPow64) + UInt32(LB) shl 4);
    GcmPclmulMultiplyExtBytes(@LDblk[0], LPH, @LBuf48[0]);
    GcmXorMultiplyExtLimbs48Sse2(@LU0[0], @LU1[0], @LU2[0], @LBuf48[0]);
  end;

  Reduce3(@LU0[0], @LU1[0], @LU2[0], @LSRev[0]);
  GcmBlockReverse128Ssse3(PFS, @LSRev[0], PMask);
end;

class procedure TGcmUtilities.FusedEightShuffledGhash(PFS, PC0, PHPow128, PMask: PByte);
var
  LB, LI: Int32;
  LDblk: array [0 .. 15] of Byte;
  LBuf48: array [0 .. 47] of Byte;
  LU0, LU1, LU2: array [0 .. 15] of Byte;
  LSRev: array [0 .. 15] of Byte;
  LPCiph: PByte;
  LPH: PByte;
begin
  if (not TCpuFeatures.X86.HasSSSE3) or (not TCpuFeatures.X86.HasPCLMULQDQ) or
    (not TIntrinsicsVector.IsPacked) then
    raise EInvalidOperationCryptoLibException.Create(
      'Fused eight-way GHASH requires SSSE3, PCLMULQDQ, and packed XMM layout.');

  GcmBlockReverse128Ssse3(@LSRev[0], PFS, PMask);
  PUInt64(@LU0[0])^ := 0;
  PUInt64(@LU0[8])^ := 0;
  PUInt64(@LU1[0])^ := 0;
  PUInt64(@LU1[8])^ := 0;
  PUInt64(@LU2[0])^ := 0;
  PUInt64(@LU2[8])^ := 0;

  for LB := 0 to 7 do
  begin
    LPCiph := PByte(NativeUInt(PC0) + UInt32(LB) shl 4);
    GcmBlockReverse128Ssse3(@LDblk[0], LPCiph, PMask);
    if LB = 0 then
      for LI := 0 to 15 do
        LDblk[LI] := LDblk[LI] xor LSRev[LI];
    LPH := PByte(NativeUInt(PHPow128) + UInt32(LB) shl 4);
    GcmPclmulMultiplyExtBytes(@LDblk[0], LPH, @LBuf48[0]);
    GcmXorMultiplyExtLimbs48Sse2(@LU0[0], @LU1[0], @LU2[0], @LBuf48[0]);
  end;

  Reduce3(@LU0[0], @LU1[0], @LU2[0], @LSRev[0]);
  GcmBlockReverse128Ssse3(PFS, @LSRev[0], PMask);
end;
{$ENDIF CRYPTOLIB_X86_SIMD}

class procedure TGcmUtilities.InitFourWayHPowFromH(const AH: TCryptoLibByteArray;
  const AHPow64: TCryptoLibByteArray);
var
  LF1, LF2, LF3, LF4: TFieldElement;
  LAcc, LY: TFieldElement;
begin
  if (System.Length(AH) < 16) or (System.Length(AHPow64) < 64) then
    Exit;
  AsFieldElement(AH, LF1);
  LAcc := LF1;
  LY := LF1;
  Multiply(LAcc, LY);
  LF2 := LAcc;
  LF3 := LF1;
  Multiply(LF3, LF2);
  LAcc := LF2;
  LY := LF2;
  Multiply(LAcc, LY);
  LF4 := LAcc;
  PUInt64(@AHPow64[0])^ := LF4.N1;
  PUInt64(@AHPow64[8])^ := LF4.N0;
  PUInt64(@AHPow64[16])^ := LF3.N1;
  PUInt64(@AHPow64[24])^ := LF3.N0;
  PUInt64(@AHPow64[32])^ := LF2.N1;
  PUInt64(@AHPow64[40])^ := LF2.N0;
  PUInt64(@AHPow64[48])^ := LF1.N1;
  PUInt64(@AHPow64[56])^ := LF1.N0;
end;

class procedure TGcmUtilities.InitEightWayHPowFromH(const AH: TCryptoLibByteArray;
  const AHPow128: TCryptoLibByteArray);
var
  LF1, LF2, LF3, LF4, LF5, LF6, LF7, LF8: TFieldElement;
  LAcc, LY: TFieldElement;
begin
  if (System.Length(AH) < 16) or (System.Length(AHPow128) < 128) then
    Exit;
  AsFieldElement(AH, LF1);
  LAcc := LF1;
  LY := LF1;
  Multiply(LAcc, LY);
  LF2 := LAcc;
  LF3 := LF1;
  Multiply(LF3, LF2);
  LAcc := LF2;
  LY := LF2;
  Multiply(LAcc, LY);
  LF4 := LAcc;
  LF5 := LF4;
  LY := LF1;
  Multiply(LF5, LY);
  LF6 := LF4;
  LY := LF2;
  Multiply(LF6, LY);
  LF7 := LF4;
  LY := LF3;
  Multiply(LF7, LY);
  LAcc := LF4;
  LY := LF4;
  Multiply(LAcc, LY);
  LF8 := LAcc;
  PUInt64(@AHPow128[0])^ := LF8.N1;
  PUInt64(@AHPow128[8])^ := LF8.N0;
  PUInt64(@AHPow128[16])^ := LF7.N1;
  PUInt64(@AHPow128[24])^ := LF7.N0;
  PUInt64(@AHPow128[32])^ := LF6.N1;
  PUInt64(@AHPow128[40])^ := LF6.N0;
  PUInt64(@AHPow128[48])^ := LF5.N1;
  PUInt64(@AHPow128[56])^ := LF5.N0;
  PUInt64(@AHPow128[64])^ := LF4.N1;
  PUInt64(@AHPow128[72])^ := LF4.N0;
  PUInt64(@AHPow128[80])^ := LF3.N1;
  PUInt64(@AHPow128[88])^ := LF3.N0;
  PUInt64(@AHPow128[96])^ := LF2.N1;
  PUInt64(@AHPow128[104])^ := LF2.N0;
  PUInt64(@AHPow128[112])^ := LF1.N1;
  PUInt64(@AHPow128[120])^ := LF1.N0;
end;

end.
