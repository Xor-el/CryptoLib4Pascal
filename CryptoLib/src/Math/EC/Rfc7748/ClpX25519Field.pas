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

unit ClpX25519Field;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpNat,
  ClpCurveFieldSimd,
  ClpCryptoLibTypes;

type
  // radix-2^51 field element: five unsigned 64-bit limbs, each < 2^52.
  TX25519Fe = record
    L: array [0 .. 4] of UInt64;
  end;

  PX25519Fe = ^TX25519Fe;
  TX25519FeArray = array of TX25519Fe;

  TX25519Field = class sealed
  public
  const
    Size = 5;
  strict private
  const
    MASK51 = UInt64($0007FFFFFFFFFFFF);
  class var
    FRootNegOne: TX25519Fe;
    class constructor Create;
    class procedure Mul64(AX, AY: UInt64; out AHi, ALo: UInt64); static;
    class procedure MulCore(const AF, AG: TX25519Fe; var AH: TX25519Fe); static;
    class function Load8(const ABs: TCryptoLibByteArray; AOff: Int32): UInt64; static;
  public
    class function Create: TX25519Fe; static;
    class function MakeFe(A0, A1, A2, A3, A4: UInt64): TX25519Fe; static;
    class function CreateTable(AN: Int32): TX25519FeArray; static;

    class procedure Add(const AX, AY: TX25519Fe; var AZ: TX25519Fe); static;
    class procedure Apm(const AX, AY: TX25519Fe; var AZp, AZm: TX25519Fe); static;
    class procedure Sub(const AX, AY: TX25519Fe; var AZ: TX25519Fe); static;
    class procedure Negate(const AX: TX25519Fe; var AZ: TX25519Fe); static;
    class procedure Carry(var AZ: TX25519Fe); static;

    class procedure Mul(const AX, AY: TX25519Fe; var AZ: TX25519Fe); overload; static;
    class procedure Mul(const AX: TX25519Fe; AY: Int32; var AZ: TX25519Fe); overload; static;
    class procedure Sqr(const AX: TX25519Fe; var AZ: TX25519Fe); overload; static;
    class procedure Sqr(const AX: TX25519Fe; AN: Int32; var AZ: TX25519Fe); overload; static;

    class procedure CMov(ACond: Int32; const AX: TX25519Fe; var AZ: TX25519Fe); static;
    class procedure CNegate(ANegate: Int32; var AZ: TX25519Fe); static;
    class procedure CSwap(ASwap: Int32; var AA, AB: TX25519Fe); static;
    class procedure Copy(const AX: TX25519Fe; var AZ: TX25519Fe); static;

    class procedure Zero(var AZ: TX25519Fe); static;
    class procedure One(var AZ: TX25519Fe); static;
    class procedure AddOne(var AZ: TX25519Fe); static;
    class procedure SubOne(var AZ: TX25519Fe); static;
    class procedure Normalize(var AZ: TX25519Fe); static;

    class function AreEqual(const AX, AY: TX25519Fe): Int32; static;
    class function AreEqualVar(const AX, AY: TX25519Fe): Boolean; static;
    class function IsOne(const AX: TX25519Fe): Int32; static;
    class function IsOneVar(const AX: TX25519Fe): Boolean; static;
    class function IsZero(const AX: TX25519Fe): Int32; static;
    class function IsZeroVar(const AX: TX25519Fe): Boolean; static;

    class procedure Inv(const AX: TX25519Fe; var AZ: TX25519Fe); static;
    class procedure InvVar(const AX: TX25519Fe; var AZ: TX25519Fe); static;
    class procedure PowPm5d8(const AX: TX25519Fe; var ARx2, ARz: TX25519Fe); static;
    class function SqrtRatioVar(const AU, AV: TX25519Fe; var AZ: TX25519Fe): Boolean; static;

    class function Decode32(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32; static;
    class procedure Decode(const ABs: TCryptoLibByteArray; AOff: Int32; var AZ: TX25519Fe); overload; static;
    class procedure Decode(const ABs: TCryptoLibByteArray; var AZ: TX25519Fe); overload; static;
    class procedure Encode(const AX: TX25519Fe; const ABs: TCryptoLibByteArray; AOff: Int32); overload; static;
    class procedure Encode(const AX: TX25519Fe; const ABs: TCryptoLibByteArray); overload; static;
  end;

implementation

class constructor TX25519Field.Create;
var
  LRootBytes: TCryptoLibByteArray;
begin
  // sqrt(-1) mod (2^255-19), little-endian.
  LRootBytes := TCryptoLibByteArray.Create(
    $B0, $A0, $0E, $4A, $27, $1B, $EE, $C4, $78, $E4, $2F, $AD, $06, $18, $43, $2F,
    $A7, $D7, $FB, $3D, $99, $00, $4D, $2B, $0B, $DF, $C1, $4F, $80, $24, $83, $2B);
  Decode(LRootBytes, 0, FRootNegOne);
end;

class procedure TX25519Field.Mul64(AX, AY: UInt64; out AHi, ALo: UInt64);
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

class function TX25519Field.Load8(const ABs: TCryptoLibByteArray; AOff: Int32): UInt64;
var
  LI: Int32;
begin
  Result := 0;
  for LI := 7 downto 0 do
    Result := (Result shl 8) or ABs[AOff + LI];
end;

class function TX25519Field.Create: TX25519Fe;
begin
  Result.L[0] := 0;
  Result.L[1] := 0;
  Result.L[2] := 0;
  Result.L[3] := 0;
  Result.L[4] := 0;
end;

class function TX25519Field.MakeFe(A0, A1, A2, A3, A4: UInt64): TX25519Fe;
begin
  Result.L[0] := A0;
  Result.L[1] := A1;
  Result.L[2] := A2;
  Result.L[3] := A3;
  Result.L[4] := A4;
end;

class function TX25519Field.CreateTable(AN: Int32): TX25519FeArray;
begin
  System.SetLength(Result, AN);
end;

class procedure TX25519Field.Add(const AX, AY: TX25519Fe; var AZ: TX25519Fe);
begin
  AZ.L[0] := AX.L[0] + AY.L[0];
  AZ.L[1] := AX.L[1] + AY.L[1];
  AZ.L[2] := AX.L[2] + AY.L[2];
  AZ.L[3] := AX.L[3] + AY.L[3];
  AZ.L[4] := AX.L[4] + AY.L[4];
end;

class procedure TX25519Field.Sub(const AX, AY: TX25519Fe; var AZ: TX25519Fe);
begin
  // add 2p (bias) so unsigned limbs never underflow; value unchanged mod p.
  AZ.L[0] := AX.L[0] + UInt64($FFFFFFFFFFFDA) - AY.L[0];
  AZ.L[1] := AX.L[1] + UInt64($FFFFFFFFFFFFE) - AY.L[1];
  AZ.L[2] := AX.L[2] + UInt64($FFFFFFFFFFFFE) - AY.L[2];
  AZ.L[3] := AX.L[3] + UInt64($FFFFFFFFFFFFE) - AY.L[3];
  AZ.L[4] := AX.L[4] + UInt64($FFFFFFFFFFFFE) - AY.L[4];
end;

class procedure TX25519Field.Apm(const AX, AY: TX25519Fe; var AZp, AZm: TX25519Fe);
var
  LX, LY: TX25519Fe;
begin
  // copy inputs first: callers pass outputs that alias AX/AY.
  LX := AX;
  LY := AY;
  Add(LX, LY, AZp);
  Sub(LX, LY, AZm);
end;

class procedure TX25519Field.Negate(const AX: TX25519Fe; var AZ: TX25519Fe);
var
  LZero: TX25519Fe;
begin
  LZero.L[0] := 0;
  LZero.L[1] := 0;
  LZero.L[2] := 0;
  LZero.L[3] := 0;
  LZero.L[4] := 0;
  Sub(LZero, AX, AZ);
end;

class procedure TX25519Field.Carry(var AZ: TX25519Fe);
var
  Lc: UInt64;
begin
  Lc := AZ.L[0] shr 51;
  AZ.L[0] := AZ.L[0] and MASK51;
  AZ.L[1] := AZ.L[1] + Lc;
  Lc := AZ.L[1] shr 51;
  AZ.L[1] := AZ.L[1] and MASK51;
  AZ.L[2] := AZ.L[2] + Lc;
  Lc := AZ.L[2] shr 51;
  AZ.L[2] := AZ.L[2] and MASK51;
  AZ.L[3] := AZ.L[3] + Lc;
  Lc := AZ.L[3] shr 51;
  AZ.L[3] := AZ.L[3] and MASK51;
  AZ.L[4] := AZ.L[4] + Lc;
  Lc := AZ.L[4] shr 51;
  AZ.L[4] := AZ.L[4] and MASK51;
  AZ.L[0] := AZ.L[0] + Lc * 19;
  Lc := AZ.L[0] shr 51;
  AZ.L[0] := AZ.L[0] and MASK51;
  AZ.L[1] := AZ.L[1] + Lc;
end;

class procedure TX25519Field.MulCore(const AF, AG: TX25519Fe; var AH: TX25519Fe);
var
  Lg1x, Lg2x, Lg3x, Lg4x: UInt64;
  Llo0, Lhi0, Llo1, Lhi1, Llo2, Lhi2, Llo3, Lhi3, Llo4, Lhi4, Lc: UInt64;

  procedure Acc(var ALo, AHi: UInt64; AA, AB: UInt64);
  var
    LpHi, LpLo: UInt64;
  begin
    Mul64(AA, AB, LpHi, LpLo);
    ALo := ALo + LpLo;
    if ALo < LpLo then
      System.Inc(AHi);
    AHi := AHi + LpHi;
  end;

begin
  Lg1x := AG.L[1] * 19;
  Lg2x := AG.L[2] * 19;
  Lg3x := AG.L[3] * 19;
  Lg4x := AG.L[4] * 19;

  Llo0 := 0;
  Lhi0 := 0;
  Acc(Llo0, Lhi0, AF.L[0], AG.L[0]);
  Acc(Llo0, Lhi0, AF.L[1], Lg4x);
  Acc(Llo0, Lhi0, AF.L[2], Lg3x);
  Acc(Llo0, Lhi0, AF.L[3], Lg2x);
  Acc(Llo0, Lhi0, AF.L[4], Lg1x);

  Llo1 := 0;
  Lhi1 := 0;
  Acc(Llo1, Lhi1, AF.L[0], AG.L[1]);
  Acc(Llo1, Lhi1, AF.L[1], AG.L[0]);
  Acc(Llo1, Lhi1, AF.L[2], Lg4x);
  Acc(Llo1, Lhi1, AF.L[3], Lg3x);
  Acc(Llo1, Lhi1, AF.L[4], Lg2x);

  Llo2 := 0;
  Lhi2 := 0;
  Acc(Llo2, Lhi2, AF.L[0], AG.L[2]);
  Acc(Llo2, Lhi2, AF.L[1], AG.L[1]);
  Acc(Llo2, Lhi2, AF.L[2], AG.L[0]);
  Acc(Llo2, Lhi2, AF.L[3], Lg4x);
  Acc(Llo2, Lhi2, AF.L[4], Lg3x);

  Llo3 := 0;
  Lhi3 := 0;
  Acc(Llo3, Lhi3, AF.L[0], AG.L[3]);
  Acc(Llo3, Lhi3, AF.L[1], AG.L[2]);
  Acc(Llo3, Lhi3, AF.L[2], AG.L[1]);
  Acc(Llo3, Lhi3, AF.L[3], AG.L[0]);
  Acc(Llo3, Lhi3, AF.L[4], Lg4x);

  Llo4 := 0;
  Lhi4 := 0;
  Acc(Llo4, Lhi4, AF.L[0], AG.L[4]);
  Acc(Llo4, Lhi4, AF.L[1], AG.L[3]);
  Acc(Llo4, Lhi4, AF.L[2], AG.L[2]);
  Acc(Llo4, Lhi4, AF.L[3], AG.L[1]);
  Acc(Llo4, Lhi4, AF.L[4], AG.L[0]);

  Lc := (Llo0 shr 51) or (Lhi0 shl 13);
  AH.L[0] := Llo0 and MASK51;
  Llo1 := Llo1 + Lc;
  if Llo1 < Lc then
    System.Inc(Lhi1);
  Lc := (Llo1 shr 51) or (Lhi1 shl 13);
  AH.L[1] := Llo1 and MASK51;
  Llo2 := Llo2 + Lc;
  if Llo2 < Lc then
    System.Inc(Lhi2);
  Lc := (Llo2 shr 51) or (Lhi2 shl 13);
  AH.L[2] := Llo2 and MASK51;
  Llo3 := Llo3 + Lc;
  if Llo3 < Lc then
    System.Inc(Lhi3);
  Lc := (Llo3 shr 51) or (Lhi3 shl 13);
  AH.L[3] := Llo3 and MASK51;
  Llo4 := Llo4 + Lc;
  if Llo4 < Lc then
    System.Inc(Lhi4);
  Lc := (Llo4 shr 51) or (Lhi4 shl 13);
  AH.L[4] := Llo4 and MASK51;
  AH.L[0] := AH.L[0] + Lc * 19;
  Lc := AH.L[0] shr 51;
  AH.L[0] := AH.L[0] and MASK51;
  AH.L[1] := AH.L[1] + Lc;
end;

class procedure TX25519Field.Mul(const AX, AY: TX25519Fe; var AZ: TX25519Fe);
begin
  if TCurveFieldSimd.TryMul25519(@AX.L[0], @AY.L[0], @AZ.L[0]) then
    Exit;
  MulCore(AX, AY, AZ);
end;

class procedure TX25519Field.Mul(const AX: TX25519Fe; AY: Int32; var AZ: TX25519Fe);
var
  LW, LHi, LLo, LCarry: UInt64;
  LI: Int32;
begin
  LW := UInt64(AY);
  LCarry := 0;
  for LI := 0 to 4 do
  begin
    Mul64(AX.L[LI], LW, LHi, LLo);
    LLo := LLo + LCarry;
    if LLo < LCarry then
      System.Inc(LHi);
    AZ.L[LI] := LLo and MASK51;
    LCarry := (LLo shr 51) or (LHi shl 13);
  end;
  AZ.L[0] := AZ.L[0] + LCarry * 19;
  LCarry := AZ.L[0] shr 51;
  AZ.L[0] := AZ.L[0] and MASK51;
  AZ.L[1] := AZ.L[1] + LCarry;
end;

class procedure TX25519Field.Sqr(const AX: TX25519Fe; var AZ: TX25519Fe);
begin
  if TCurveFieldSimd.TrySqr25519(@AX.L[0], @AZ.L[0]) then
    Exit;
  MulCore(AX, AX, AZ);
end;

class procedure TX25519Field.Sqr(const AX: TX25519Fe; AN: Int32; var AZ: TX25519Fe);
begin
  Sqr(AX, AZ);
  while AN > 1 do
  begin
    System.Dec(AN);
    Sqr(AZ, AZ);
  end;
end;

class procedure TX25519Field.CMov(ACond: Int32; const AX: TX25519Fe; var AZ: TX25519Fe);
var
  LI: Int32;
  LMask, LT: UInt64;
begin
  LMask := UInt64(Int64(ACond));
  for LI := 0 to 4 do
  begin
    LT := (AZ.L[LI] xor AX.L[LI]) and LMask;
    AZ.L[LI] := AZ.L[LI] xor LT;
  end;
end;

class procedure TX25519Field.CNegate(ANegate: Int32; var AZ: TX25519Fe);
var
  LNeg: TX25519Fe;
  LMask, LI: Int32;
  LT: UInt64;
begin
  // carry first: Negate's 2p bias underflows on unreduced limbs (e.g. AR.U).
  Carry(AZ);
  Negate(AZ, LNeg);
  LMask := 0 - ANegate;
  for LI := 0 to 4 do
  begin
    LT := (AZ.L[LI] xor LNeg.L[LI]) and UInt64(Int64(LMask));
    AZ.L[LI] := AZ.L[LI] xor LT;
  end;
end;

class procedure TX25519Field.CSwap(ASwap: Int32; var AA, AB: TX25519Fe);
var
  LMask, LI: Int32;
  LT: UInt64;
begin
  LMask := 0 - ASwap;
  for LI := 0 to 4 do
  begin
    LT := (AA.L[LI] xor AB.L[LI]) and UInt64(Int64(LMask));
    AA.L[LI] := AA.L[LI] xor LT;
    AB.L[LI] := AB.L[LI] xor LT;
  end;
end;

class procedure TX25519Field.Copy(const AX: TX25519Fe; var AZ: TX25519Fe);
begin
  AZ := AX;
end;

class procedure TX25519Field.Zero(var AZ: TX25519Fe);
begin
  AZ.L[0] := 0;
  AZ.L[1] := 0;
  AZ.L[2] := 0;
  AZ.L[3] := 0;
  AZ.L[4] := 0;
end;

class procedure TX25519Field.One(var AZ: TX25519Fe);
begin
  AZ.L[0] := 1;
  AZ.L[1] := 0;
  AZ.L[2] := 0;
  AZ.L[3] := 0;
  AZ.L[4] := 0;
end;

class procedure TX25519Field.AddOne(var AZ: TX25519Fe);
begin
  AZ.L[0] := AZ.L[0] + 1;
end;

class procedure TX25519Field.SubOne(var AZ: TX25519Fe);
var
  LOne: TX25519Fe;
begin
  One(LOne);
  Sub(AZ, LOne, AZ);
end;

class procedure TX25519Field.Normalize(var AZ: TX25519Fe);
var
  LBs: TCryptoLibByteArray;
begin
  // freeze to the canonical rep in [0, p).
  System.SetLength(LBs, 32);
  Encode(AZ, LBs, 0);
  Decode(LBs, 0, AZ);
end;

class function TX25519Field.AreEqual(const AX, AY: TX25519Fe): Int32;
var
  LA, LB: TX25519Fe;
  Ld: UInt64;
begin
  // compare canonical forms.
  LA := AX;
  Normalize(LA);
  LB := AY;
  Normalize(LB);
  Ld := (LA.L[0] xor LB.L[0]) or (LA.L[1] xor LB.L[1]) or (LA.L[2] xor LB.L[2]) or
    (LA.L[3] xor LB.L[3]) or (LA.L[4] xor LB.L[4]);
  Result := Int32(TNat.CZero(UInt32(Ld) or UInt32(Ld shr 32)));
end;

class function TX25519Field.AreEqualVar(const AX, AY: TX25519Fe): Boolean;
begin
  Result := AreEqual(AX, AY) <> 0;
end;

class function TX25519Field.IsOne(const AX: TX25519Fe): Int32;
var
  LT: TX25519Fe;
  Ld: UInt64;
begin
  LT := AX;
  Normalize(LT);
  Ld := (LT.L[0] xor 1) or LT.L[1] or LT.L[2] or LT.L[3] or LT.L[4];
  Result := Int32(TNat.CZero(UInt32(Ld) or UInt32(Ld shr 32)));
end;

class function TX25519Field.IsOneVar(const AX: TX25519Fe): Boolean;
begin
  Result := IsOne(AX) <> 0;
end;

class function TX25519Field.IsZero(const AX: TX25519Fe): Int32;
var
  LT: TX25519Fe;
  Ld: UInt64;
begin
  LT := AX;
  Normalize(LT);
  Ld := LT.L[0] or LT.L[1] or LT.L[2] or LT.L[3] or LT.L[4];
  Result := Int32(TNat.CZero(UInt32(Ld) or UInt32(Ld shr 32)));
end;

class function TX25519Field.IsZeroVar(const AX: TX25519Fe): Boolean;
begin
  Result := IsZero(AX) <> 0;
end;

class procedure TX25519Field.Inv(const AX: TX25519Fe; var AZ: TX25519Fe);
var
  Lz2, Lz9, Lz11, Lz2_5_0, Lz2_10_0, Lz2_20_0, Lz2_50_0, Lz2_100_0, Lt: TX25519Fe;
  LI: Int32;
begin
  // x^(p-2) = x^-1 via the standard 254S+11M addition chain.
  Sqr(AX, Lz2);
  Sqr(Lz2, Lt);
  Sqr(Lt, Lt);
  Mul(Lt, AX, Lz9);
  Mul(Lz9, Lz2, Lz11);
  Sqr(Lz11, Lt);
  Mul(Lt, Lz9, Lz2_5_0);
  Sqr(Lz2_5_0, Lt);
  for LI := 1 to 4 do
    Sqr(Lt, Lt);
  Mul(Lt, Lz2_5_0, Lz2_10_0);
  Sqr(Lz2_10_0, Lt);
  for LI := 1 to 9 do
    Sqr(Lt, Lt);
  Mul(Lt, Lz2_10_0, Lz2_20_0);
  Sqr(Lz2_20_0, Lt);
  for LI := 1 to 19 do
    Sqr(Lt, Lt);
  Mul(Lt, Lz2_20_0, Lt);
  for LI := 1 to 10 do
    Sqr(Lt, Lt);
  Mul(Lt, Lz2_10_0, Lz2_50_0);
  Sqr(Lz2_50_0, Lt);
  for LI := 1 to 49 do
    Sqr(Lt, Lt);
  Mul(Lt, Lz2_50_0, Lz2_100_0);
  Sqr(Lz2_100_0, Lt);
  for LI := 1 to 99 do
    Sqr(Lt, Lt);
  Mul(Lt, Lz2_100_0, Lt);
  for LI := 1 to 50 do
    Sqr(Lt, Lt);
  Mul(Lt, Lz2_50_0, Lt);
  for LI := 1 to 5 do
    Sqr(Lt, Lt);
  Mul(Lt, Lz11, AZ);
end;

class procedure TX25519Field.InvVar(const AX: TX25519Fe; var AZ: TX25519Fe);
begin
  Inv(AX, AZ);
end;

class procedure TX25519Field.PowPm5d8(const AX: TX25519Fe; var ARx2, ARz: TX25519Fe);
var
  Lx3, Lx5, Lx10, Lx15, Lx25, Lx50, Lx75, Lx125, Lx250, Lt: TX25519Fe;
begin
  // x^((p-5)/8); ARx2 = x^2 byproduct.
  Sqr(AX, ARx2);
  Mul(AX, ARx2, ARx2);
  Sqr(ARx2, Lx3);
  Mul(AX, Lx3, Lx3);
  Sqr(Lx3, 2, Lx5);
  Mul(ARx2, Lx5, Lx5);
  Sqr(Lx5, 5, Lx10);
  Mul(Lx5, Lx10, Lx10);
  Sqr(Lx10, 5, Lx15);
  Mul(Lx5, Lx15, Lx15);
  Sqr(Lx15, 10, Lx25);
  Mul(Lx10, Lx25, Lx25);
  Sqr(Lx25, 25, Lx50);
  Mul(Lx25, Lx50, Lx50);
  Sqr(Lx50, 25, Lx75);
  Mul(Lx25, Lx75, Lx75);
  Sqr(Lx75, 50, Lx125);
  Mul(Lx50, Lx125, Lx125);
  Sqr(Lx125, 125, Lx250);
  Mul(Lx125, Lx250, Lx250);
  Sqr(Lx250, 2, Lt);
  Mul(Lt, AX, ARz);
end;

class function TX25519Field.SqrtRatioVar(const AU, AV: TX25519Fe; var AZ: TX25519Fe): Boolean;
var
  Luv3, Luv7, Lt, Lx, Lvx2: TX25519Fe;
begin
  Mul(AU, AV, Luv3);
  Sqr(AV, Luv7);
  Mul(Luv3, Luv7, Luv3);
  Sqr(Luv7, Luv7);
  Mul(Luv7, Luv3, Luv7);
  PowPm5d8(Luv7, Lt, Lx);
  Mul(Lx, Luv3, Lx);
  Sqr(Lx, Lvx2);
  Mul(Lvx2, AV, Lvx2);
  Sub(Lvx2, AU, Lt);
  Normalize(Lt);
  if IsZeroVar(Lt) then
  begin
    AZ := Lx;
    Exit(True);
  end;
  Add(Lvx2, AU, Lt);
  Normalize(Lt);
  if IsZeroVar(Lt) then
  begin
    Mul(Lx, FRootNegOne, AZ);
    Exit(True);
  end;
  Result := False;
end;

class function TX25519Field.Decode32(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32;
begin
  Result := UInt32(ABs[AOff]) or (UInt32(ABs[AOff + 1]) shl 8) or
    (UInt32(ABs[AOff + 2]) shl 16) or (UInt32(ABs[AOff + 3]) shl 24);
end;

class procedure TX25519Field.Decode(const ABs: TCryptoLibByteArray; AOff: Int32; var AZ: TX25519Fe);
begin
  AZ.L[0] := Load8(ABs, AOff + 0) and MASK51;
  AZ.L[1] := (Load8(ABs, AOff + 6) shr 3) and MASK51;
  AZ.L[2] := (Load8(ABs, AOff + 12) shr 6) and MASK51;
  AZ.L[3] := (Load8(ABs, AOff + 19) shr 1) and MASK51;
  AZ.L[4] := (Load8(ABs, AOff + 24) shr 12) and MASK51;
end;

class procedure TX25519Field.Decode(const ABs: TCryptoLibByteArray; var AZ: TX25519Fe);
begin
  Decode(ABs, 0, AZ);
end;

class procedure TX25519Field.Encode(const AX: TX25519Fe; const ABs: TCryptoLibByteArray; AOff: Int32);
var
  LH: TX25519Fe;
  Lq, Lc: UInt64;
begin
  LH := AX;
  Carry(LH);
  Carry(LH);
  Lq := (LH.L[0] + 19) shr 51;
  Lq := (LH.L[1] + Lq) shr 51;
  Lq := (LH.L[2] + Lq) shr 51;
  Lq := (LH.L[3] + Lq) shr 51;
  Lq := (LH.L[4] + Lq) shr 51;
  LH.L[0] := LH.L[0] + 19 * Lq;
  Lc := LH.L[0] shr 51;
  LH.L[0] := LH.L[0] and MASK51;
  LH.L[1] := LH.L[1] + Lc;
  Lc := LH.L[1] shr 51;
  LH.L[1] := LH.L[1] and MASK51;
  LH.L[2] := LH.L[2] + Lc;
  Lc := LH.L[2] shr 51;
  LH.L[2] := LH.L[2] and MASK51;
  LH.L[3] := LH.L[3] + Lc;
  Lc := LH.L[3] shr 51;
  LH.L[3] := LH.L[3] and MASK51;
  LH.L[4] := LH.L[4] + Lc;
  LH.L[4] := LH.L[4] and MASK51;
  ABs[AOff + 0] := Byte(LH.L[0]);
  ABs[AOff + 1] := Byte(LH.L[0] shr 8);
  ABs[AOff + 2] := Byte(LH.L[0] shr 16);
  ABs[AOff + 3] := Byte(LH.L[0] shr 24);
  ABs[AOff + 4] := Byte(LH.L[0] shr 32);
  ABs[AOff + 5] := Byte(LH.L[0] shr 40);
  ABs[AOff + 6] := Byte((LH.L[0] shr 48) or (LH.L[1] shl 3));
  ABs[AOff + 7] := Byte(LH.L[1] shr 5);
  ABs[AOff + 8] := Byte(LH.L[1] shr 13);
  ABs[AOff + 9] := Byte(LH.L[1] shr 21);
  ABs[AOff + 10] := Byte(LH.L[1] shr 29);
  ABs[AOff + 11] := Byte(LH.L[1] shr 37);
  ABs[AOff + 12] := Byte((LH.L[1] shr 45) or (LH.L[2] shl 6));
  ABs[AOff + 13] := Byte(LH.L[2] shr 2);
  ABs[AOff + 14] := Byte(LH.L[2] shr 10);
  ABs[AOff + 15] := Byte(LH.L[2] shr 18);
  ABs[AOff + 16] := Byte(LH.L[2] shr 26);
  ABs[AOff + 17] := Byte(LH.L[2] shr 34);
  ABs[AOff + 18] := Byte(LH.L[2] shr 42);
  ABs[AOff + 19] := Byte((LH.L[2] shr 50) or (LH.L[3] shl 1));
  ABs[AOff + 20] := Byte(LH.L[3] shr 7);
  ABs[AOff + 21] := Byte(LH.L[3] shr 15);
  ABs[AOff + 22] := Byte(LH.L[3] shr 23);
  ABs[AOff + 23] := Byte(LH.L[3] shr 31);
  ABs[AOff + 24] := Byte(LH.L[3] shr 39);
  ABs[AOff + 25] := Byte((LH.L[3] shr 47) or (LH.L[4] shl 4));
  ABs[AOff + 26] := Byte(LH.L[4] shr 4);
  ABs[AOff + 27] := Byte(LH.L[4] shr 12);
  ABs[AOff + 28] := Byte(LH.L[4] shr 20);
  ABs[AOff + 29] := Byte(LH.L[4] shr 28);
  ABs[AOff + 30] := Byte(LH.L[4] shr 36);
  ABs[AOff + 31] := Byte(LH.L[4] shr 44);
end;

class procedure TX25519Field.Encode(const AX: TX25519Fe; const ABs: TCryptoLibByteArray);
begin
  Encode(AX, ABs, 0);
end;

end.
