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

unit ClpX25519;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpArrayUtilities,
  ClpBinaryPrimitives,
  ClpBitOperations,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  ClpCurveFieldSimd,
  ClpEd25519,
  ClpISecureRandom,
  ClpX25519Field;

resourcestring
  SInvalidKeyLength = 'invalid key length';
  SRandomNil = 'random cannot be nil';

type
  TX25519 = class sealed
  strict private
  const
    C_A = 486662;
    C_A24 = (C_A + 2) div 4;
  type
    // radix-2^64 (saturated) field element: four unsigned 64-bit limbs.
    TFe64 = array [0 .. 3] of UInt64;
  class procedure DecodeScalar(const AK: TCryptoLibByteArray; AKOff: Int32;
    AN: TCryptoLibUInt32Array); static;
  class procedure PointDouble(var AX, AZ: TX25519Fe); static;
  // fe64 (radix-2^64 ADX) driver: a structural twin of the fe51 driver, selected
  // once at the top of ScalarMult when TCurveFieldSimd.Fe64Supported.
  class procedure Fe64Decode(const ABs: TCryptoLibByteArray; AOff: Int32; var AZ: TFe64); static;
  class procedure Fe64Encode(const AX: TFe64; ABs: TCryptoLibByteArray; AOff: Int32); static;
  class procedure Fe64PointDouble(var AX, AZ: TFe64); static;
  class procedure Fe64Inv(const AX: TFe64; var AZ: TFe64); static;
  class procedure Fe64ScalarMult(const AK: TCryptoLibByteArray; AKOff: Int32;
    const AU: TCryptoLibByteArray; AUOff: Int32; AR: TCryptoLibByteArray; AROff: Int32); static;
  public
  const
    PointSize = 32;
    ScalarSize = 32;

    class function CalculateAgreement(const AK: TCryptoLibByteArray; AKOff: Int32;
      const AU: TCryptoLibByteArray; AUOff: Int32; AR: TCryptoLibByteArray; AROff: Int32): Boolean; static;

    class procedure ClampPrivateKey(AK: TCryptoLibByteArray); static;

    class procedure GeneratePrivateKey(const ARandom: ISecureRandom; const AK: TCryptoLibByteArray); static;

    class procedure GeneratePublicKey(const AK: TCryptoLibByteArray; AKOff: Int32;
      AR: TCryptoLibByteArray; AROff: Int32); static;

    class procedure ScalarMult(const AK: TCryptoLibByteArray; AKOff: Int32;
      const AU: TCryptoLibByteArray; AUOff: Int32; AR: TCryptoLibByteArray; AROff: Int32); static;

    class procedure ScalarMultBase(const AK: TCryptoLibByteArray; AKOff: Int32;
      AR: TCryptoLibByteArray; AROff: Int32); static;
  end;

implementation

{ TX25519 }

class function TX25519.CalculateAgreement(const AK: TCryptoLibByteArray; AKOff: Int32;
  const AU: TCryptoLibByteArray; AUOff: Int32; AR: TCryptoLibByteArray; AROff: Int32): Boolean;
begin
  ScalarMult(AK, AKOff, AU, AUOff, AR, AROff);
  Result := not TArrayUtilities.AreAllZeroes(AR, AROff, PointSize);
end;

class procedure TX25519.ClampPrivateKey(AK: TCryptoLibByteArray);
begin
  TArrayUtilities.ValidateBuffer(AK);
  if System.Length(AK) <> ScalarSize then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidKeyLength);
  AK[0] := AK[0] and $F8;
  AK[ScalarSize - 1] := AK[ScalarSize - 1] and $7F;
  AK[ScalarSize - 1] := AK[ScalarSize - 1] or $40;
end;

class procedure TX25519.DecodeScalar(const AK: TCryptoLibByteArray; AKOff: Int32;
  AN: TCryptoLibUInt32Array);
var
  LI: Int32;
begin
  LI := 0;
  while LI < 8 do
  begin
    AN[LI] := TX25519Field.Decode32(AK, AKOff + LI * 4);
    System.Inc(LI);
  end;
  AN[0] := AN[0] and $FFFFFFF8;
  AN[7] := AN[7] and $7FFFFFFF;
  AN[7] := AN[7] or $40000000;
end;

class procedure TX25519.GeneratePrivateKey(const ARandom: ISecureRandom; const AK: TCryptoLibByteArray);
begin
  if ARandom = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SRandomNil);
  if System.Length(AK) <> ScalarSize then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidKeyLength);
  ARandom.NextBytes(AK);
  ClampPrivateKey(AK);
end;

class procedure TX25519.GeneratePublicKey(const AK: TCryptoLibByteArray; AKOff: Int32;
  AR: TCryptoLibByteArray; AROff: Int32);
begin
  ScalarMultBase(AK, AKOff, AR, AROff);
end;

class procedure TX25519.PointDouble(var AX, AZ: TX25519Fe);
var
  LA, LB: TX25519Fe;
begin
  TX25519Field.Apm(AX, AZ, LA, LB);
  TX25519Field.Sqr(LA, LA);
  TX25519Field.Sqr(LB, LB);
  TX25519Field.Mul(LA, LB, AX);
  TX25519Field.Sub(LA, LB, LA);
  TX25519Field.Mul(LA, C_A24, AZ);
  TX25519Field.Add(AZ, LB, AZ);
  TX25519Field.Mul(AZ, LA, AZ);
end;

class procedure TX25519.ScalarMult(const AK: TCryptoLibByteArray; AKOff: Int32;
  const AU: TCryptoLibByteArray; AUOff: Int32; AR: TCryptoLibByteArray; AROff: Int32);
var
  LN: TCryptoLibUInt32Array;
  LX1, LX2, LZ2, LX3, LZ3, LT1, LT2: TX25519Fe;
  LBit, LSwap, LWord, LShift, LKt: Int32;
  LI: Int32;
begin
  TArrayUtilities.ValidateSegment(AK, AKOff, ScalarSize);
  TArrayUtilities.ValidateSegment(AU, AUOff, PointSize);
  TArrayUtilities.ValidateSegment(AR, AROff, PointSize);
  if TCurveFieldSimd.Fe64Supported then
  begin
    Fe64ScalarMult(AK, AKOff, AU, AUOff, AR, AROff);
    Exit;
  end;
  System.SetLength(LN, 8);
  DecodeScalar(AK, AKOff, LN);
  TX25519Field.Decode(AU, AUOff, LX1);
  TX25519Field.Copy(LX1, LX2);
  TX25519Field.Zero(LZ2);
  LZ2.L[0] := 1;
  TX25519Field.Zero(LX3);
  LX3.L[0] := 1;
  TX25519Field.Zero(LZ3);
  LBit := 254;
  LSwap := 1;
  repeat
    TX25519Field.Apm(LX3, LZ3, LT1, LX3);
    TX25519Field.Apm(LX2, LZ2, LZ3, LX2);
    TX25519Field.Mul(LT1, LX2, LT1);
    TX25519Field.Mul(LX3, LZ3, LX3);
    TX25519Field.Sqr(LZ3, LZ3);
    TX25519Field.Sqr(LX2, LX2);
    TX25519Field.Sub(LZ3, LX2, LT2);
    TX25519Field.Mul(LT2, C_A24, LZ2);
    TX25519Field.Add(LZ2, LX2, LZ2);
    TX25519Field.Mul(LZ2, LT2, LZ2);
    TX25519Field.Mul(LX2, LZ3, LX2);
    TX25519Field.Apm(LT1, LX3, LX3, LZ3);
    TX25519Field.Sqr(LX3, LX3);
    TX25519Field.Sqr(LZ3, LZ3);
    TX25519Field.Mul(LZ3, LX1, LZ3);
    System.Dec(LBit);
    LWord := TBitOperations.Asr32(LBit, 5);
    LShift := LBit and $1F;
    LKt := Int32(LN[LWord] shr LShift) and 1;
    LSwap := LSwap xor LKt;
    TX25519Field.CSwap(LSwap, LX2, LX3);
    TX25519Field.CSwap(LSwap, LZ2, LZ3);
    LSwap := LKt;
  until LBit < 3;
  {$IFDEF DEBUG}
  System.Assert(LSwap = 0);
  {$ENDIF}
  for LI := 0 to 2 do
    PointDouble(LX2, LZ2);
  TX25519Field.Inv(LZ2, LZ2);
  TX25519Field.Mul(LX2, LZ2, LX2);
  TX25519Field.Normalize(LX2);
  TX25519Field.Encode(LX2, AR, AROff);
end;

class procedure TX25519.Fe64Decode(const ABs: TCryptoLibByteArray; AOff: Int32; var AZ: TFe64);
var
  LI: Int32;
begin
  for LI := 0 to 3 do
    AZ[LI] := TBinaryPrimitives.ReadUInt64LittleEndian(ABs, AOff + LI * 8);
  AZ[3] := AZ[3] and UInt64($7FFFFFFFFFFFFFFF); // drop bit 255 (RFC 7748 u-decode)
end;

class procedure TX25519.Fe64Encode(const AX: TFe64; ABs: TCryptoLibByteArray; AOff: Int32);
const
  // p = 2^255 - 19, little-endian limbs.
  LP: array [0 .. 3] of UInt64 = ($FFFFFFFFFFFFFFED, $FFFFFFFFFFFFFFFF,
    $FFFFFFFFFFFFFFFF, $7FFFFFFFFFFFFFFF);
var
  LSel, LT: TFe64;
  LBorrow, LMask, LTmp, LB1, LB2: UInt64;
  LPass, LI: Int32;
begin
  // freeze to [0, p): input < 2^256 < 2p + 38, so conditionally subtract p twice.
  // Constant-time: the borrow is computed arithmetically (no branch on the value)
  // and expanded to an all-ones/all-zeros mask for the select.
  LSel := AX;
  for LPass := 0 to 1 do
  begin
    LBorrow := 0;
    for LI := 0 to 3 do
    begin
      LTmp := LSel[LI] - LBorrow;
      LB1 := UInt64(Ord(LSel[LI] < LBorrow));
      LT[LI] := LTmp - LP[LI];
      LB2 := UInt64(Ord(LTmp < LP[LI]));
      LBorrow := LB1 or LB2;
    end;
    LMask := UInt64(0) - (UInt64(1) - LBorrow);
    for LI := 0 to 3 do
      LSel[LI] := (LSel[LI] and (not LMask)) or (LT[LI] and LMask);
  end;
  for LI := 0 to 3 do
    TBinaryPrimitives.WriteUInt64LittleEndian(ABs, AOff + LI * 8, LSel[LI]);
end;

class procedure TX25519.Fe64PointDouble(var AX, AZ: TFe64);
var
  LA, LB: TFe64;
begin
  TCurveFieldSimd.TryFe64Add(@AX[0], @AZ[0], @LA[0]);
  TCurveFieldSimd.TryFe64Sub(@AX[0], @AZ[0], @LB[0]);
  TCurveFieldSimd.TryFe64Sqr25519(@LA[0], @LA[0]);
  TCurveFieldSimd.TryFe64Sqr25519(@LB[0], @LB[0]);
  TCurveFieldSimd.TryFe64Mul25519(@LA[0], @LB[0], @AX[0]);
  TCurveFieldSimd.TryFe64Sub(@LA[0], @LB[0], @LA[0]);
  TCurveFieldSimd.TryFe64Mul121666(@LA[0], @AZ[0]);
  TCurveFieldSimd.TryFe64Add(@AZ[0], @LB[0], @AZ[0]);
  TCurveFieldSimd.TryFe64Mul25519(@AZ[0], @LA[0], @AZ[0]);
end;

class procedure TX25519.Fe64Inv(const AX: TFe64; var AZ: TFe64);
var
  Lz2, Lz9, Lz11, Lz2_5_0, Lz2_10_0, Lz2_20_0, Lz2_50_0, Lz2_100_0, Lt: TFe64;
begin
  // x^(p-2) = x^-1 via the standard 254S+11M addition chain (twin of TX25519Field.Inv).
  TCurveFieldSimd.TryFe64Sqr25519(@AX[0], @Lz2[0]);
  TCurveFieldSimd.TryFe64SqrN(@Lz2[0], @Lt[0], 2);
  TCurveFieldSimd.TryFe64Mul25519(@Lt[0], @AX[0], @Lz9[0]);
  TCurveFieldSimd.TryFe64Mul25519(@Lz9[0], @Lz2[0], @Lz11[0]);
  TCurveFieldSimd.TryFe64Sqr25519(@Lz11[0], @Lt[0]);
  TCurveFieldSimd.TryFe64Mul25519(@Lt[0], @Lz9[0], @Lz2_5_0[0]);
  TCurveFieldSimd.TryFe64SqrN(@Lz2_5_0[0], @Lt[0], 5);
  TCurveFieldSimd.TryFe64Mul25519(@Lt[0], @Lz2_5_0[0], @Lz2_10_0[0]);
  TCurveFieldSimd.TryFe64SqrN(@Lz2_10_0[0], @Lt[0], 10);
  TCurveFieldSimd.TryFe64Mul25519(@Lt[0], @Lz2_10_0[0], @Lz2_20_0[0]);
  TCurveFieldSimd.TryFe64SqrN(@Lz2_20_0[0], @Lt[0], 20);
  TCurveFieldSimd.TryFe64Mul25519(@Lt[0], @Lz2_20_0[0], @Lt[0]);
  TCurveFieldSimd.TryFe64SqrN(@Lt[0], @Lt[0], 10);
  TCurveFieldSimd.TryFe64Mul25519(@Lt[0], @Lz2_10_0[0], @Lz2_50_0[0]);
  TCurveFieldSimd.TryFe64SqrN(@Lz2_50_0[0], @Lt[0], 50);
  TCurveFieldSimd.TryFe64Mul25519(@Lt[0], @Lz2_50_0[0], @Lz2_100_0[0]);
  TCurveFieldSimd.TryFe64SqrN(@Lz2_100_0[0], @Lt[0], 100);
  TCurveFieldSimd.TryFe64Mul25519(@Lt[0], @Lz2_100_0[0], @Lt[0]);
  TCurveFieldSimd.TryFe64SqrN(@Lt[0], @Lt[0], 50);
  TCurveFieldSimd.TryFe64Mul25519(@Lt[0], @Lz2_50_0[0], @Lt[0]);
  TCurveFieldSimd.TryFe64SqrN(@Lt[0], @Lt[0], 5);
  TCurveFieldSimd.TryFe64Mul25519(@Lt[0], @Lz11[0], @AZ[0]);
end;

class procedure TX25519.Fe64ScalarMult(const AK: TCryptoLibByteArray; AKOff: Int32;
  const AU: TCryptoLibByteArray; AUOff: Int32; AR: TCryptoLibByteArray; AROff: Int32);
var
  LN: TCryptoLibUInt32Array;
  LU, LX2, LZ2: TFe64;
  LState: array [0 .. 19] of UInt64; // x1(0..3) x2(4..7) z2(8..11) x3(12..15) z3(16..19)
  LBit, LSwap, LWord, LShift, LKt, LI: Int32;
  LMask: UInt64;
begin
  System.SetLength(LN, 8);
  DecodeScalar(AK, AKOff, LN);
  Fe64Decode(AU, AUOff, LU);
  // state (radix-2^64), same convention as the fe51 ladder: x2=u, z2=1, x3=1, z3=0.
  for LI := 0 to 3 do
  begin
    LState[LI] := LU[LI];       // x1 = u
    LState[4 + LI] := LU[LI];   // x2 = u
    LState[8 + LI] := 0;        // z2
    LState[12 + LI] := 0;       // x3
    LState[16 + LI] := 0;       // z3
  end;
  LState[8] := 1;               // z2 = 1
  LState[12] := 1;              // x3 = 1
  LBit := 254;
  LSwap := 1;
  repeat
    System.Dec(LBit);
    LWord := TBitOperations.Asr32(LBit, 5);
    LShift := LBit and $1F;
    LKt := Int32(LN[LWord] shr LShift) and 1;
    LSwap := LSwap xor LKt;
    LMask := UInt64(0) - UInt64(LSwap);
    TCurveFieldSimd.TryFe64LadderStep25519(@LState[0], LMask);
    LSwap := LKt;
  until LBit < 3;
  {$IFDEF DEBUG}
  System.Assert(LSwap = 0);
  {$ENDIF}
  for LI := 0 to 3 do
  begin
    LX2[LI] := LState[4 + LI];
    LZ2[LI] := LState[8 + LI];
  end;
  for LI := 0 to 2 do
    Fe64PointDouble(LX2, LZ2);
  Fe64Inv(LZ2, LZ2);
  TCurveFieldSimd.TryFe64Mul25519(@LX2[0], @LZ2[0], @LX2[0]);
  Fe64Encode(LX2, AR, AROff);
end;

class procedure TX25519.ScalarMultBase(const AK: TCryptoLibByteArray; AKOff: Int32;
  AR: TCryptoLibByteArray; AROff: Int32);
var
  LY, LZ: TX25519Fe;
begin
  TArrayUtilities.ValidateSegment(AK, AKOff, ScalarSize);
  TArrayUtilities.ValidateSegment(AR, AROff, PointSize);
  TEd25519.ScalarMultBaseYZ(AK, AKOff, LY, LZ);
  TX25519Field.Apm(LZ, LY, LY, LZ);
  TX25519Field.Inv(LZ, LZ);
  TX25519Field.Mul(LY, LZ, LY);
  TX25519Field.Normalize(LY);
  TX25519Field.Encode(LY, AR, AROff);
end;

end.
