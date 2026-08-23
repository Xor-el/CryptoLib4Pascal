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

unit ClpX448Field;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpMod,
  ClpNat,
  ClpCurveFieldSimd,
  ClpCryptoLibTypes;

type
  // radix-2^56 field element: eight unsigned 64-bit limbs, each < 2^57.
  TX448Fe = record
    L: array [0 .. 7] of UInt64;
  end;

  PX448Fe = ^TX448Fe;
  TX448FeArray = array of TX448Fe;

  TX448Field = class sealed
  public
  const
    Size = 8;
  strict private
  const
    MASK56 = UInt64($00FFFFFFFFFFFFFF);
  class var
    FP32: TCryptoLibUInt32Array;
    class constructor Create;
    class procedure Mul64(AX, AY: UInt64; out AHi, ALo: UInt64); static;
    class procedure MulCore(const AF, AG: TX448Fe; var AH: TX448Fe); static;
    class procedure Freeze(var AZ: TX448Fe); static;
    class procedure PowPm3d4(const AX: TX448Fe; var AZ: TX448Fe); static;
    class procedure Encode32(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32); static;
  public
    class function Create: TX448Fe; static;
    class function MakeFe(A0, A1, A2, A3, A4, A5, A6, A7: UInt64): TX448Fe; static;
    class function CreateTable(AN: Int32): TX448FeArray; static;

    class procedure Add(const AX, AY: TX448Fe; var AZ: TX448Fe); static;
    class procedure Sub(const AX, AY: TX448Fe; var AZ: TX448Fe); static;
    class procedure Negate(const AX: TX448Fe; var AZ: TX448Fe); static;
    class procedure Carry(var AZ: TX448Fe); static;

    class procedure Mul(const AX, AY: TX448Fe; var AZ: TX448Fe); overload; static;
    class procedure Mul(const AX: TX448Fe; AY: Int32; var AZ: TX448Fe); overload; static;
    class procedure Sqr(const AX: TX448Fe; var AZ: TX448Fe); overload; static;
    class procedure Sqr(const AX: TX448Fe; AN: Int32; var AZ: TX448Fe); overload; static;

    class procedure CMov(ACond: Int32; const AX: TX448Fe; var AZ: TX448Fe); static;
    class procedure CNegate(ANegate: Int32; var AZ: TX448Fe); static;
    class procedure CSwap(ASwap: Int32; var AA, AB: TX448Fe); static;
    class procedure Copy(const AX: TX448Fe; var AZ: TX448Fe); static;

    class procedure Zero(var AZ: TX448Fe); static;
    class procedure One(var AZ: TX448Fe); static;
    class procedure AddOne(var AZ: TX448Fe); static;
    class procedure SubOne(var AZ: TX448Fe); static;
    class procedure Normalize(var AZ: TX448Fe); static;

    class function AreEqual(const AX, AY: TX448Fe): Int32; static;
    class function AreEqualVar(const AX, AY: TX448Fe): Boolean; static;
    class function IsOne(const AX: TX448Fe): Int32; static;
    class function IsOneVar(const AX: TX448Fe): Boolean; static;
    class function IsZero(const AX: TX448Fe): Int32; static;
    class function IsZeroVar(const AX: TX448Fe): Boolean; static;

    class procedure Inv(const AX: TX448Fe; var AZ: TX448Fe); static;
    class procedure InvVar(const AX: TX448Fe; var AZ: TX448Fe); static;
    class function SqrtRatioVar(const AU, AV: TX448Fe; var AZ: TX448Fe): Boolean; static;

    class function Decode32(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32; static;
    class procedure Decode(const ABs: TCryptoLibByteArray; AOff: Int32; var AZ: TX448Fe); overload; static;
    class procedure Decode(const ABs: TCryptoLibByteArray; var AZ: TX448Fe); overload; static;
    class procedure Encode(const AX: TX448Fe; const ABs: TCryptoLibByteArray; AOff: Int32); overload; static;
    class procedure Encode(const AX: TX448Fe; const ABs: TCryptoLibByteArray); overload; static;
  end;

implementation

class constructor TX448Field.Create;
begin
  // p = 2^448 - 2^224 - 1, little-endian 32-bit words.
  FP32 := TCryptoLibUInt32Array.Create($FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF,
    $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFE, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF,
    $FFFFFFFF, $FFFFFFFF, $FFFFFFFF);
end;

class procedure TX448Field.Mul64(AX, AY: UInt64; out AHi, ALo: UInt64);
var
  LXl, LXh, LYl, LYh, LLL, LLh, LHl, LMid: UInt64;
begin
  LXl := AX and $FFFFFFFF;
  LXh := AX shr 32;
  LYl := AY and $FFFFFFFF;
  LYh := AY shr 32;
  LLL := LXl * LYl;
  LLh := LXl * LYh;
  LHl := LXh * LYl;
  LMid := (LLL shr 32) + (LLh and $FFFFFFFF) + (LHl and $FFFFFFFF);
  ALo := (LLL and $FFFFFFFF) or (LMid shl 32);
  AHi := LXh * LYh + (LLh shr 32) + (LHl shr 32) + (LMid shr 32);
end;

class function TX448Field.Create: TX448Fe;
var
  LI: Int32;
begin
  for LI := 0 to 7 do
    Result.L[LI] := 0;
end;

class function TX448Field.MakeFe(A0, A1, A2, A3, A4, A5, A6, A7: UInt64): TX448Fe;
begin
  Result.L[0] := A0;
  Result.L[1] := A1;
  Result.L[2] := A2;
  Result.L[3] := A3;
  Result.L[4] := A4;
  Result.L[5] := A5;
  Result.L[6] := A6;
  Result.L[7] := A7;
end;

class function TX448Field.CreateTable(AN: Int32): TX448FeArray;
begin
  System.SetLength(Result, AN);
end;

class procedure TX448Field.Add(const AX, AY: TX448Fe; var AZ: TX448Fe);
var
  LI: Int32;
begin
  for LI := 0 to 7 do
    AZ.L[LI] := AX.L[LI] + AY.L[LI];
end;

class procedure TX448Field.Sub(const AX, AY: TX448Fe; var AZ: TX448Fe);
var
  LT: TX448Fe;
begin
  // add 2p (bias) so unsigned limbs never underflow; value unchanged mod p.
  LT.L[0] := AX.L[0] + UInt64($01FFFFFFFFFFFFFE) - AY.L[0];
  LT.L[1] := AX.L[1] + UInt64($01FFFFFFFFFFFFFE) - AY.L[1];
  LT.L[2] := AX.L[2] + UInt64($01FFFFFFFFFFFFFE) - AY.L[2];
  LT.L[3] := AX.L[3] + UInt64($01FFFFFFFFFFFFFE) - AY.L[3];
  LT.L[4] := AX.L[4] + UInt64($01FFFFFFFFFFFFFC) - AY.L[4];
  LT.L[5] := AX.L[5] + UInt64($01FFFFFFFFFFFFFE) - AY.L[5];
  LT.L[6] := AX.L[6] + UInt64($01FFFFFFFFFFFFFE) - AY.L[6];
  LT.L[7] := AX.L[7] + UInt64($01FFFFFFFFFFFFFE) - AY.L[7];
  Carry(LT);
  AZ := LT;
end;

class procedure TX448Field.Negate(const AX: TX448Fe; var AZ: TX448Fe);
var
  LZero: TX448Fe;
  LI: Int32;
begin
  for LI := 0 to 7 do
    LZero.L[LI] := 0;
  Sub(LZero, AX, AZ);
end;

class procedure TX448Field.Carry(var AZ: TX448Fe);
var
  Lc: UInt64;
  LI: Int32;
begin
  Lc := 0;
  for LI := 0 to 7 do
  begin
    AZ.L[LI] := AZ.L[LI] + Lc;
    Lc := AZ.L[LI] shr 56;
    AZ.L[LI] := AZ.L[LI] and MASK56;
  end;
  // top carry (weight 2^448 = 2^224 + 1) folds into limb0 and limb4.
  AZ.L[0] := AZ.L[0] + Lc;
  AZ.L[4] := AZ.L[4] + Lc;
  Lc := AZ.L[0] shr 56;
  AZ.L[0] := AZ.L[0] and MASK56;
  AZ.L[1] := AZ.L[1] + Lc;
  Lc := AZ.L[4] shr 56;
  AZ.L[4] := AZ.L[4] and MASK56;
  AZ.L[5] := AZ.L[5] + Lc;
end;

class procedure TX448Field.MulCore(const AF, AG: TX448Fe; var AH: TX448Fe);
var
  Lclo, Lchi: array [0 .. 14] of UInt64;
  LI, LJ, LK: Int32;
  Lc, LpHi, LpLo: UInt64;

  procedure Acc(AK: Int32; AA, AB: UInt64);
  begin
    Mul64(AA, AB, LpHi, LpLo);
    Lclo[AK] := Lclo[AK] + LpLo;
    Lchi[AK] := Lchi[AK] + LpHi + UInt64(Ord(Lclo[AK] < LpLo));
  end;

begin
  for LK := 0 to 14 do
  begin
    Lclo[LK] := 0;
    Lchi[LK] := 0;
  end;
  for LI := 0 to 7 do
    for LJ := 0 to 7 do
      Acc(LI + LJ, AF.L[LI], AG.L[LJ]);
  // Goldilocks fold: 2^(56k) = 2^(56(k-4)) + 2^(56(k-8)) for k >= 8. High-to-low.
  for LK := 14 downto 8 do
  begin
    Lclo[LK - 4] := Lclo[LK - 4] + Lclo[LK];
    Lchi[LK - 4] := Lchi[LK - 4] + Lchi[LK] + UInt64(Ord(Lclo[LK - 4] < Lclo[LK]));
    Lclo[LK - 8] := Lclo[LK - 8] + Lclo[LK];
    Lchi[LK - 8] := Lchi[LK - 8] + Lchi[LK] + UInt64(Ord(Lclo[LK - 8] < Lclo[LK]));
  end;
  Lc := 0;
  for LK := 0 to 7 do
  begin
    Lclo[LK] := Lclo[LK] + Lc;
    Lchi[LK] := Lchi[LK] + UInt64(Ord(Lclo[LK] < Lc));
    AH.L[LK] := Lclo[LK] and MASK56;
    Lc := (Lchi[LK] shl 8) or (Lclo[LK] shr 56);
  end;
  // top carry folds into limb0 and limb4.
  AH.L[0] := AH.L[0] + Lc;
  AH.L[4] := AH.L[4] + Lc;
  Lc := AH.L[0] shr 56;
  AH.L[0] := AH.L[0] and MASK56;
  AH.L[1] := AH.L[1] + Lc;
  Lc := AH.L[4] shr 56;
  AH.L[4] := AH.L[4] and MASK56;
  AH.L[5] := AH.L[5] + Lc;
end;

class procedure TX448Field.Mul(const AX, AY: TX448Fe; var AZ: TX448Fe);
begin
  if TCurveFieldSimd.TryMul448(@AX.L[0], @AY.L[0], @AZ.L[0]) then
    Exit;
  MulCore(AX, AY, AZ);
end;

class procedure TX448Field.Mul(const AX: TX448Fe; AY: Int32; var AZ: TX448Fe);
var
  LW, LHi, LLo, LCarry: UInt64;
  LI: Int32;
begin
  LW := UInt64(AY);
  LCarry := 0;
  for LI := 0 to 7 do
  begin
    Mul64(AX.L[LI], LW, LHi, LLo);
    LLo := LLo + LCarry;
    LHi := LHi + UInt64(Ord(LLo < LCarry));
    AZ.L[LI] := LLo and MASK56;
    LCarry := (LHi shl 8) or (LLo shr 56);
  end;
  // top carry folds into limb0 and limb4.
  AZ.L[0] := AZ.L[0] + LCarry;
  AZ.L[4] := AZ.L[4] + LCarry;
  LCarry := AZ.L[0] shr 56;
  AZ.L[0] := AZ.L[0] and MASK56;
  AZ.L[1] := AZ.L[1] + LCarry;
  LCarry := AZ.L[4] shr 56;
  AZ.L[4] := AZ.L[4] and MASK56;
  AZ.L[5] := AZ.L[5] + LCarry;
end;

class procedure TX448Field.Sqr(const AX: TX448Fe; var AZ: TX448Fe);
begin
  if TCurveFieldSimd.TrySqr448(@AX.L[0], @AZ.L[0]) then
    Exit;
  MulCore(AX, AX, AZ);
end;

class procedure TX448Field.Sqr(const AX: TX448Fe; AN: Int32; var AZ: TX448Fe);
begin
  Sqr(AX, AZ);
  while AN > 1 do
  begin
    System.Dec(AN);
    Sqr(AZ, AZ);
  end;
end;

class procedure TX448Field.CMov(ACond: Int32; const AX: TX448Fe; var AZ: TX448Fe);
var
  LI: Int32;
  LMask, LT: UInt64;
begin
  LMask := UInt64(Int64(ACond));
  for LI := 0 to 7 do
  begin
    LT := (AZ.L[LI] xor AX.L[LI]) and LMask;
    AZ.L[LI] := AZ.L[LI] xor LT;
  end;
end;

class procedure TX448Field.CNegate(ANegate: Int32; var AZ: TX448Fe);
var
  LNeg: TX448Fe;
  LMask, LI: Int32;
  LT: UInt64;
begin
  // carry first: Negate's 2p bias underflows on unreduced limbs.
  Carry(AZ);
  Negate(AZ, LNeg);
  LMask := 0 - ANegate;
  for LI := 0 to 7 do
  begin
    LT := (AZ.L[LI] xor LNeg.L[LI]) and UInt64(Int64(LMask));
    AZ.L[LI] := AZ.L[LI] xor LT;
  end;
end;

class procedure TX448Field.CSwap(ASwap: Int32; var AA, AB: TX448Fe);
var
  LMask, LI: Int32;
  LT: UInt64;
begin
  LMask := 0 - ASwap;
  for LI := 0 to 7 do
  begin
    LT := (AA.L[LI] xor AB.L[LI]) and UInt64(Int64(LMask));
    AA.L[LI] := AA.L[LI] xor LT;
    AB.L[LI] := AB.L[LI] xor LT;
  end;
end;

class procedure TX448Field.Copy(const AX: TX448Fe; var AZ: TX448Fe);
begin
  AZ := AX;
end;

class procedure TX448Field.Zero(var AZ: TX448Fe);
var
  LI: Int32;
begin
  for LI := 0 to 7 do
    AZ.L[LI] := 0;
end;

class procedure TX448Field.One(var AZ: TX448Fe);
var
  LI: Int32;
begin
  AZ.L[0] := 1;
  for LI := 1 to 7 do
    AZ.L[LI] := 0;
end;

class procedure TX448Field.AddOne(var AZ: TX448Fe);
begin
  AZ.L[0] := AZ.L[0] + 1;
end;

class procedure TX448Field.SubOne(var AZ: TX448Fe);
var
  LOne: TX448Fe;
begin
  One(LOne);
  Sub(AZ, LOne, AZ);
end;

class procedure TX448Field.Freeze(var AZ: TX448Fe);
var
  LT: TX448Fe;
  LK: Int32;
  Borrow, Diff, Mask, LSub: UInt64;
begin
  Carry(AZ);
  Carry(AZ);
  // conditional subtract p = [M56 x4, M56-1 @limb4, M56 x3].
  Borrow := 0;
  for LK := 0 to 7 do
  begin
    if LK = 4 then
      LSub := MASK56 - 1
    else
      LSub := MASK56;
    Diff := AZ.L[LK] - LSub - Borrow;
    Borrow := (Diff shr 63) and 1;
    LT.L[LK] := Diff and MASK56;
  end;
  // keep AZ - p when it did not borrow, else keep AZ.
  Mask := UInt64(0) - (1 - Borrow);
  for LK := 0 to 7 do
    AZ.L[LK] := (LT.L[LK] and Mask) or (AZ.L[LK] and (not Mask));
end;

class procedure TX448Field.Normalize(var AZ: TX448Fe);
begin
  Freeze(AZ);
end;

class function TX448Field.AreEqual(const AX, AY: TX448Fe): Int32;
var
  LA, LB: TX448Fe;
  Ld: UInt64;
  LI: Int32;
begin
  LA := AX;
  Normalize(LA);
  LB := AY;
  Normalize(LB);
  Ld := 0;
  for LI := 0 to 7 do
    Ld := Ld or (LA.L[LI] xor LB.L[LI]);
  Result := Int32(TNat.CZero(UInt32(Ld) or UInt32(Ld shr 32)));
end;

class function TX448Field.AreEqualVar(const AX, AY: TX448Fe): Boolean;
begin
  Result := AreEqual(AX, AY) <> 0;
end;

class function TX448Field.IsOne(const AX: TX448Fe): Int32;
var
  LT: TX448Fe;
  Ld: UInt64;
  LI: Int32;
begin
  LT := AX;
  Normalize(LT);
  Ld := LT.L[0] xor 1;
  for LI := 1 to 7 do
    Ld := Ld or LT.L[LI];
  Result := Int32(TNat.CZero(UInt32(Ld) or UInt32(Ld shr 32)));
end;

class function TX448Field.IsOneVar(const AX: TX448Fe): Boolean;
begin
  Result := IsOne(AX) <> 0;
end;

class function TX448Field.IsZero(const AX: TX448Fe): Int32;
var
  LT: TX448Fe;
  Ld: UInt64;
  LI: Int32;
begin
  LT := AX;
  Normalize(LT);
  Ld := 0;
  for LI := 0 to 7 do
    Ld := Ld or LT.L[LI];
  Result := Int32(TNat.CZero(UInt32(Ld) or UInt32(Ld shr 32)));
end;

class function TX448Field.IsZeroVar(const AX: TX448Fe): Boolean;
begin
  Result := IsZero(AX) <> 0;
end;

class procedure TX448Field.Inv(const AX: TX448Fe; var AZ: TX448Fe);
var
  LBytes: TCryptoLibByteArray;
  LU: TCryptoLibUInt32Array;
  LI: Int32;
begin
  // freeze to canonical bytes, invert as a saturated 14-word integer, reload.
  System.SetLength(LBytes, 56);
  Encode(AX, LBytes, 0);
  System.SetLength(LU, 14);
  for LI := 0 to 13 do
    LU[LI] := Decode32(LBytes, LI * 4);
  TMod.ModOddInverse(FP32, LU, LU);
  for LI := 0 to 13 do
    Encode32(LU[LI], LBytes, LI * 4);
  Decode(LBytes, 0, AZ);
end;

class procedure TX448Field.InvVar(const AX: TX448Fe; var AZ: TX448Fe);
var
  LBytes: TCryptoLibByteArray;
  LU: TCryptoLibUInt32Array;
  LI: Int32;
begin
  System.SetLength(LBytes, 56);
  Encode(AX, LBytes, 0);
  System.SetLength(LU, 14);
  for LI := 0 to 13 do
    LU[LI] := Decode32(LBytes, LI * 4);
  TMod.ModOddInverseVar(FP32, LU, LU);
  for LI := 0 to 13 do
    Encode32(LU[LI], LBytes, LI * 4);
  Decode(LBytes, 0, AZ);
end;

class procedure TX448Field.PowPm3d4(const AX: TX448Fe; var AZ: TX448Fe);
var
  Lx2, Lx3, Lx6, Lx9, Lx18, Lx19, Lx37, Lx74, Lx111, Lx222, Lx223, Lt: TX448Fe;
begin
  // x^((p-3)/4).
  Sqr(AX, Lx2);
  Mul(AX, Lx2, Lx2);
  Sqr(Lx2, Lx3);
  Mul(AX, Lx3, Lx3);
  Sqr(Lx3, 3, Lx6);
  Mul(Lx3, Lx6, Lx6);
  Sqr(Lx6, 3, Lx9);
  Mul(Lx3, Lx9, Lx9);
  Sqr(Lx9, 9, Lx18);
  Mul(Lx9, Lx18, Lx18);
  Sqr(Lx18, Lx19);
  Mul(AX, Lx19, Lx19);
  Sqr(Lx19, 18, Lx37);
  Mul(Lx18, Lx37, Lx37);
  Sqr(Lx37, 37, Lx74);
  Mul(Lx37, Lx74, Lx74);
  Sqr(Lx74, 37, Lx111);
  Mul(Lx37, Lx111, Lx111);
  Sqr(Lx111, 111, Lx222);
  Mul(Lx111, Lx222, Lx222);
  Sqr(Lx222, Lx223);
  Mul(AX, Lx223, Lx223);
  Sqr(Lx223, 223, Lt);
  Mul(Lt, Lx222, AZ);
end;

class function TX448Field.SqrtRatioVar(const AU, AV: TX448Fe; var AZ: TX448Fe): Boolean;
var
  Lu3v, Lu5v3, Lx, Lt: TX448Fe;
begin
  Sqr(AU, Lu3v);
  Mul(Lu3v, AV, Lu3v);
  Sqr(Lu3v, Lu5v3);
  Mul(Lu3v, AU, Lu3v);
  Mul(Lu5v3, AU, Lu5v3);
  Mul(Lu5v3, AV, Lu5v3);
  PowPm3d4(Lu5v3, Lx);
  Mul(Lx, Lu3v, Lx);
  Sqr(Lx, Lt);
  Mul(Lt, AV, Lt);
  Sub(AU, Lt, Lt);
  Normalize(Lt);
  if IsZeroVar(Lt) then
  begin
    AZ := Lx;
    Exit(True);
  end;
  Result := False;
end;

class function TX448Field.Decode32(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32;
begin
  Result := UInt32(ABs[AOff]) or (UInt32(ABs[AOff + 1]) shl 8) or
    (UInt32(ABs[AOff + 2]) shl 16) or (UInt32(ABs[AOff + 3]) shl 24);
end;

class procedure TX448Field.Encode32(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32);
begin
  ABs[AOff] := Byte(AN);
  ABs[AOff + 1] := Byte(AN shr 8);
  ABs[AOff + 2] := Byte(AN shr 16);
  ABs[AOff + 3] := Byte(AN shr 24);
end;

class procedure TX448Field.Decode(const ABs: TCryptoLibByteArray; AOff: Int32; var AZ: TX448Fe);
var
  LK, LI: Int32;
  LV: UInt64;
begin
  // seven bytes per 56-bit limb, little-endian.
  for LK := 0 to 7 do
  begin
    LV := 0;
    for LI := 0 to 6 do
      LV := LV or (UInt64(ABs[AOff + LK * 7 + LI]) shl (8 * LI));
    AZ.L[LK] := LV;
  end;
end;

class procedure TX448Field.Decode(const ABs: TCryptoLibByteArray; var AZ: TX448Fe);
begin
  Decode(ABs, 0, AZ);
end;

class procedure TX448Field.Encode(const AX: TX448Fe; const ABs: TCryptoLibByteArray; AOff: Int32);
var
  LH: TX448Fe;
  LK, LI: Int32;
  LV: UInt64;
begin
  LH := AX;
  Freeze(LH);
  for LK := 0 to 7 do
  begin
    LV := LH.L[LK];
    for LI := 0 to 6 do
      ABs[AOff + LK * 7 + LI] := Byte(LV shr (8 * LI));
  end;
end;

class procedure TX448Field.Encode(const AX: TX448Fe; const ABs: TCryptoLibByteArray);
begin
  Encode(AX, ABs, 0);
end;

end.
