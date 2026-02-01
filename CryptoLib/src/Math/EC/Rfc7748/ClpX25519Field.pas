{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpX25519Field;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpMod,
  ClpBitUtilities,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

type
  TX25519Field = class sealed
  public
  const
    Size = 10;
  strict private
  const
    M24 = $00FFFFFF;
    M25 = $01FFFFFF;
    M26 = $03FFFFFF;
  class var
    FP32: TCryptoLibUInt32Array;
    FRootNegOne: TCryptoLibInt32Array;
  class procedure Boot; static;
  class constructor Create;
  class procedure Decode128(const AX: TCryptoLibUInt32Array; AXOff: Int32;
    const AZ: TCryptoLibInt32Array; AZOff: Int32); overload; static;
  class procedure Decode128(const ABs: TCryptoLibByteArray; AOff: Int32;
    const AZ: TCryptoLibInt32Array; AZOff: Int32); overload; static;
  class function Decode32(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32; static;
  class procedure Encode128(const AX: TCryptoLibInt32Array; AXOff: Int32;
    const AZ: TCryptoLibUInt32Array; AZOff: Int32); overload; static;
  class procedure Encode128(const AX: TCryptoLibInt32Array; AXOff: Int32;
    const ABs: TCryptoLibByteArray; AOff: Int32); overload; static;
  class procedure Encode32(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32); static;
  class procedure PowPm5d8(const AX: TCryptoLibInt32Array; const ARx2: TCryptoLibInt32Array;
    const ARz: TCryptoLibInt32Array); static;
  class procedure Reduce(AZ: TCryptoLibInt32Array; AX: Int32); static;
  public
    class procedure Add(const AX, AY, AZ: TCryptoLibInt32Array); static;
    class procedure AddOne(const AZ: TCryptoLibInt32Array); overload; static;
    class procedure AddOne(const AZ: TCryptoLibInt32Array; AZOff: Int32); overload; static;
    class procedure Apm(const AX, AY, AZp, AZm: TCryptoLibInt32Array); static;
    class function AreEqual(const AX, AY: TCryptoLibInt32Array): Int32; static;
    class function AreEqualVar(const AX, AY: TCryptoLibInt32Array): Boolean; static;
    class procedure Carry(AZ: TCryptoLibInt32Array); static;
    class procedure CMov(ACond: Int32; const AX: TCryptoLibInt32Array; AXOff: Int32;
      const AZ: TCryptoLibInt32Array; AZOff: Int32); static;
    class procedure CNegate(ANegate: Int32; AZ: TCryptoLibInt32Array); static;
    class procedure Copy(const AX: TCryptoLibInt32Array; AXOff: Int32;
      const AZ: TCryptoLibInt32Array; AZOff: Int32); static;
    class function Create: TCryptoLibInt32Array; static;
    class function CreateTable(AN: Int32): TCryptoLibInt32Array; static;
    class procedure CSwap(ASwap: Int32; AA, AB: TCryptoLibInt32Array); static;
    class procedure Decode(const AX: TCryptoLibUInt32Array; AXOff: Int32;
      AZ: TCryptoLibInt32Array); overload; static;
    class procedure Decode(const ABs: TCryptoLibByteArray; AZ: TCryptoLibInt32Array); overload; static;
    class procedure Decode(const ABs: TCryptoLibByteArray; ABsOff: Int32;
      AZ: TCryptoLibInt32Array); overload; static;
    class procedure Decode(const ABs: TCryptoLibByteArray; ABsOff: Int32;
      const AZ: TCryptoLibInt32Array; AZOff: Int32); overload; static;
    class procedure Encode(const AX: TCryptoLibInt32Array; const AZ: TCryptoLibUInt32Array;
      AZOff: Int32); overload; static;
    class procedure Encode(const AX: TCryptoLibInt32Array; const ABs: TCryptoLibByteArray); overload; static;
    class procedure Encode(const AX: TCryptoLibInt32Array; const ABs: TCryptoLibByteArray;
      ABsOff: Int32); overload; static;
    class procedure Encode(const AX: TCryptoLibInt32Array; AXOff: Int32;
      const ABs: TCryptoLibByteArray; ABsOff: Int32); overload; static;
    class procedure Inv(const AX, AZ: TCryptoLibInt32Array); static;
    class procedure InvVar(const AX, AZ: TCryptoLibInt32Array); static;
    class function IsOne(const AX: TCryptoLibInt32Array): Int32; static;
    class function IsOneVar(const AX: TCryptoLibInt32Array): Boolean; static;
    class function IsZero(const AX: TCryptoLibInt32Array): Int32; static;
    class function IsZeroVar(const AX: TCryptoLibInt32Array): Boolean; static;
    class procedure Mul(const AX: TCryptoLibInt32Array; AY: Int32; const AZ: TCryptoLibInt32Array); overload; static;
    class procedure Mul(const AX, AY, AZ: TCryptoLibInt32Array); overload; static;
    class procedure Negate(const AX, AZ: TCryptoLibInt32Array); static;
    class procedure Normalize(AZ: TCryptoLibInt32Array); static;
    class procedure One(AZ: TCryptoLibInt32Array); static;
    class procedure Sqr(const AX, AZ: TCryptoLibInt32Array); overload; static;
    class procedure Sqr(const AX: TCryptoLibInt32Array; AN: Int32; const AZ: TCryptoLibInt32Array); overload; static;
    class function SqrtRatioVar(const AU, AV, AZ: TCryptoLibInt32Array): Boolean; static;
    class procedure Sub(const AX, AY, AZ: TCryptoLibInt32Array); static;
    class procedure SubOne(AZ: TCryptoLibInt32Array); static;
    class procedure Zero(AZ: TCryptoLibInt32Array); static;
  end;

implementation

class constructor TX25519Field.Create;
begin
  Boot;
end;

class procedure TX25519Field.Boot;
begin
  FP32 := TCryptoLibUInt32Array.Create($FFFFFFED, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF,
    $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $7FFFFFFF);
  FRootNegOne := TCryptoLibInt32Array.Create(-$01F15F50, -$0079362D, $00478C4F, $0035697F,
    $005E8630, $01FBD7A7, -$00BFD9B1, -$000F4D4B, $00027E0F, $00570649);
end;

class procedure TX25519Field.Add(const AX, AY, AZ: TCryptoLibInt32Array);
var
  LI: Int32;
begin
  LI := 0;
  while LI < Size do
  begin
    AZ[LI] := AX[LI] + AY[LI];
    System.Inc(LI);
  end;
end;

class procedure TX25519Field.AddOne(const AZ: TCryptoLibInt32Array);
begin
  AZ[0] := AZ[0] + 1;
end;

class procedure TX25519Field.AddOne(const AZ: TCryptoLibInt32Array; AZOff: Int32);
begin
  AZ[AZOff] := AZ[AZOff] + 1;
end;

class procedure TX25519Field.Apm(const AX, AY, AZp, AZm: TCryptoLibInt32Array);
var
  LI: Int32;
  LXi, LYi: Int32;
begin
  LI := 0;
  while LI < Size do
  begin
    LXi := AX[LI];
    LYi := AY[LI];
    AZp[LI] := LXi + LYi;
    AZm[LI] := LXi - LYi;
    System.Inc(LI);
  end;
end;

class function TX25519Field.AreEqual(const AX, AY: TCryptoLibInt32Array): Int32;
var
  Ld: Int32;
  LI: Int32;
begin
  Ld := 0;
  LI := 0;
  while LI < Size do
  begin
    Ld := Ld or (AX[LI] xor AY[LI]);
    System.Inc(LI);
  end;
  Ld := Ld or TBitUtilities.Asr32(Ld, 16);
  Ld := Ld and $FFFF;
  Result := TBitUtilities.Asr32(Ld - 1, 31);
end;

class function TX25519Field.AreEqualVar(const AX, AY: TCryptoLibInt32Array): Boolean;
begin
  Result := AreEqual(AX, AY) <> 0;
end;

class procedure TX25519Field.Carry(AZ: TCryptoLibInt32Array);
var
  Lz0, Lz1, Lz2, Lz3, Lz4, Lz5, Lz6, Lz7, Lz8, Lz9: Int32;
begin
  Lz0 := AZ[0];
  Lz1 := AZ[1];
  Lz2 := AZ[2];
  Lz3 := AZ[3];
  Lz4 := AZ[4];
  Lz5 := AZ[5];
  Lz6 := AZ[6];
  Lz7 := AZ[7];
  Lz8 := AZ[8];
  Lz9 := AZ[9];
  Lz2 := Lz2 + TBitUtilities.Asr32(Lz1, 26);
  Lz1 := Lz1 and M26;
  Lz4 := Lz4 + TBitUtilities.Asr32(Lz3, 26);
  Lz3 := Lz3 and M26;
  Lz7 := Lz7 + TBitUtilities.Asr32(Lz6, 26);
  Lz6 := Lz6 and M26;
  Lz9 := Lz9 + TBitUtilities.Asr32(Lz8, 26);
  Lz8 := Lz8 and M26;
  Lz3 := Lz3 + TBitUtilities.Asr32(Lz2, 25);
  Lz2 := Lz2 and M25;
  Lz5 := Lz5 + TBitUtilities.Asr32(Lz4, 25);
  Lz4 := Lz4 and M25;
  Lz8 := Lz8 + TBitUtilities.Asr32(Lz7, 25);
  Lz7 := Lz7 and M25;
  Lz0 := Lz0 + TBitUtilities.Asr32(Lz9, 25) * 38;
  Lz9 := Lz9 and M25;
  Lz1 := Lz1 + TBitUtilities.Asr32(Lz0, 26);
  Lz0 := Lz0 and M26;
  Lz6 := Lz6 + TBitUtilities.Asr32(Lz5, 26);
  Lz5 := Lz5 and M26;
  Lz2 := Lz2 + TBitUtilities.Asr32(Lz1, 26);
  Lz1 := Lz1 and M26;
  Lz4 := Lz4 + TBitUtilities.Asr32(Lz3, 26);
  Lz3 := Lz3 and M26;
  Lz7 := Lz7 + TBitUtilities.Asr32(Lz6, 26);
  Lz6 := Lz6 and M26;
  Lz9 := Lz9 + TBitUtilities.Asr32(Lz8, 26);
  Lz8 := Lz8 and M26;
  AZ[0] := Lz0;
  AZ[1] := Lz1;
  AZ[2] := Lz2;
  AZ[3] := Lz3;
  AZ[4] := Lz4;
  AZ[5] := Lz5;
  AZ[6] := Lz6;
  AZ[7] := Lz7;
  AZ[8] := Lz8;
  AZ[9] := Lz9;
end;

class procedure TX25519Field.CMov(ACond: Int32; const AX: TCryptoLibInt32Array; AXOff: Int32;
  const AZ: TCryptoLibInt32Array; AZOff: Int32);
var
  LI: Int32;
  LZi, Ldiff: Int32;
begin
  LI := 0;
  while LI < Size do
  begin
    LZi := AZ[AZOff + LI];
    Ldiff := LZi xor AX[AXOff + LI];
    LZi := LZi xor (Ldiff and ACond);
    AZ[AZOff + LI] := LZi;
    System.Inc(LI);
  end;
end;

class procedure TX25519Field.CNegate(ANegate: Int32; AZ: TCryptoLibInt32Array);
var
  LMask: Int32;
  LI: Int32;
begin
  {$IFDEF DEBUG}
  System.Assert(TBitUtilities.Asr32(ANegate, 1) = 0);
  {$ENDIF}
  LMask := 0 - ANegate;
  LI := 0;
  while LI < Size do
  begin
    AZ[LI] := (AZ[LI] xor LMask) - LMask;
    System.Inc(LI);
  end;
end;

class procedure TX25519Field.Copy(const AX: TCryptoLibInt32Array; AXOff: Int32;
  const AZ: TCryptoLibInt32Array; AZOff: Int32);
begin
  System.Move(AX[AXOff], AZ[AZOff], Size * System.SizeOf(Int32));
end;

class function TX25519Field.Create: TCryptoLibInt32Array;
begin
  Result := TCryptoLibInt32Array.Create(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
end;

class function TX25519Field.CreateTable(AN: Int32): TCryptoLibInt32Array;
begin
  System.SetLength(Result, Size * AN);
end;

class procedure TX25519Field.CSwap(ASwap: Int32; AA, AB: TCryptoLibInt32Array);
var
  Lmask: Int32;
  LI: Int32;
  Lai, Lbi, Ldummy: Int32;
begin
  Lmask := 0 - ASwap;
  LI := 0;
  while LI < Size do
  begin
    Lai := AA[LI];
    Lbi := AB[LI];
    Ldummy := Lmask and (Lai xor Lbi);
    AA[LI] := Lai xor Ldummy;
    AB[LI] := Lbi xor Ldummy;
    System.Inc(LI);
  end;
end;

class function TX25519Field.Decode32(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32;
var
  LOff: Int32;
begin
  LOff := AOff;
  Result := UInt32(ABs[LOff]);
  System.Inc(LOff);
  Result := Result or (UInt32(ABs[LOff]) shl 8);
  System.Inc(LOff);
  Result := Result or (UInt32(ABs[LOff]) shl 16);
  System.Inc(LOff);
  Result := Result or (UInt32(ABs[LOff]) shl 24);
end;

class procedure TX25519Field.Decode128(const AX: TCryptoLibUInt32Array; AXOff: Int32;
  const AZ: TCryptoLibInt32Array; AZOff: Int32);
var
  Lt0, Lt1, Lt2, Lt3: UInt32;
begin
  Lt0 := AX[AXOff + 0];
  Lt1 := AX[AXOff + 1];
  Lt2 := AX[AXOff + 2];
  Lt3 := AX[AXOff + 3];
  AZ[AZOff + 0] := Int32(Lt0) and M26;
  AZ[AZOff + 1] := Int32((Lt1 shl 6) or (Lt0 shr 26)) and M26;
  AZ[AZOff + 2] := Int32((Lt2 shl 12) or (Lt1 shr 20)) and M25;
  AZ[AZOff + 3] := Int32((Lt3 shl 19) or (Lt2 shr 13)) and M26;
  AZ[AZOff + 4] := Int32(Lt3 shr 7);
end;

class procedure TX25519Field.Decode128(const ABs: TCryptoLibByteArray; AOff: Int32;
  const AZ: TCryptoLibInt32Array; AZOff: Int32);
var
  Lt0, Lt1, Lt2, Lt3: UInt32;
begin
  Lt0 := Decode32(ABs, AOff + 0);
  Lt1 := Decode32(ABs, AOff + 4);
  Lt2 := Decode32(ABs, AOff + 8);
  Lt3 := Decode32(ABs, AOff + 12);
  AZ[AZOff + 0] := Int32(Lt0) and M26;
  AZ[AZOff + 1] := Int32((Lt1 shl 6) or (Lt0 shr 26)) and M26;
  AZ[AZOff + 2] := Int32((Lt2 shl 12) or (Lt1 shr 20)) and M25;
  AZ[AZOff + 3] := Int32((Lt3 shl 19) or (Lt2 shr 13)) and M26;
  AZ[AZOff + 4] := Int32(Lt3 shr 7);
end;

class procedure TX25519Field.Decode(const AX: TCryptoLibUInt32Array; AXOff: Int32;
  AZ: TCryptoLibInt32Array);
begin
  Decode128(AX, AXOff, AZ, 0);
  Decode128(AX, AXOff + 4, AZ, 5);
  AZ[9] := AZ[9] and M24;
end;

class procedure TX25519Field.Decode(const ABs: TCryptoLibByteArray; AZ: TCryptoLibInt32Array);
begin
  Decode(ABs, 0, AZ);
end;

class procedure TX25519Field.Decode(const ABs: TCryptoLibByteArray; ABsOff: Int32;
  AZ: TCryptoLibInt32Array);
begin
  Decode128(ABs, ABsOff, AZ, 0);
  Decode128(ABs, ABsOff + 16, AZ, 5);
  AZ[9] := AZ[9] and M24;
end;

class procedure TX25519Field.Decode(const ABs: TCryptoLibByteArray; ABsOff: Int32;
  const AZ: TCryptoLibInt32Array; AZOff: Int32);
begin
  Decode128(ABs, ABsOff, AZ, AZOff);
  Decode128(ABs, ABsOff + 16, AZ, AZOff + 5);
  AZ[AZOff + 9] := AZ[AZOff + 9] and M24;
end;

class procedure TX25519Field.Encode32(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32);
var
  LOff: Int32;
begin
  LOff := AOff;
  ABs[LOff] := Byte(AN);
  System.Inc(LOff);
  ABs[LOff] := Byte(AN shr 8);
  System.Inc(LOff);
  ABs[LOff] := Byte(AN shr 16);
  System.Inc(LOff);
  ABs[LOff] := Byte(AN shr 24);
end;

class procedure TX25519Field.Encode128(const AX: TCryptoLibInt32Array; AXOff: Int32;
  const AZ: TCryptoLibUInt32Array; AZOff: Int32);
var
  Lx0, Lx1, Lx2, Lx3, Lx4: UInt32;
begin
  Lx0 := UInt32(AX[AXOff + 0]);
  Lx1 := UInt32(AX[AXOff + 1]);
  Lx2 := UInt32(AX[AXOff + 2]);
  Lx3 := UInt32(AX[AXOff + 3]);
  Lx4 := UInt32(AX[AXOff + 4]);
  AZ[AZOff + 0] := Lx0 or (Lx1 shl 26);
  AZ[AZOff + 1] := (Lx1 shr 6) or (Lx2 shl 20);
  AZ[AZOff + 2] := (Lx2 shr 12) or (Lx3 shl 13);
  AZ[AZOff + 3] := (Lx3 shr 19) or (Lx4 shl 7);
end;

class procedure TX25519Field.Encode128(const AX: TCryptoLibInt32Array; AXOff: Int32;
  const ABs: TCryptoLibByteArray; AOff: Int32);
var
  Lx0, Lx1, Lx2, Lx3, Lx4: UInt32;
  Lt0, Lt1, Lt2, Lt3: UInt32;
begin
  Lx0 := UInt32(AX[AXOff + 0]);
  Lx1 := UInt32(AX[AXOff + 1]);
  Lx2 := UInt32(AX[AXOff + 2]);
  Lx3 := UInt32(AX[AXOff + 3]);
  Lx4 := UInt32(AX[AXOff + 4]);
  Lt0 := Lx0 or (Lx1 shl 26);
  Encode32(Lt0, ABs, AOff + 0);
  Lt1 := (Lx1 shr 6) or (Lx2 shl 20);
  Encode32(Lt1, ABs, AOff + 4);
  Lt2 := (Lx2 shr 12) or (Lx3 shl 13);
  Encode32(Lt2, ABs, AOff + 8);
  Lt3 := (Lx3 shr 19) or (Lx4 shl 7);
  Encode32(Lt3, ABs, AOff + 12);
end;

class procedure TX25519Field.Encode(const AX: TCryptoLibInt32Array; const AZ: TCryptoLibUInt32Array;
  AZOff: Int32);
begin
  Encode128(AX, 0, AZ, AZOff);
  Encode128(AX, 5, AZ, AZOff + 4);
end;

class procedure TX25519Field.Encode(const AX: TCryptoLibInt32Array; const ABs: TCryptoLibByteArray);
begin
  Encode128(AX, 0, ABs, 0);
  Encode128(AX, 5, ABs, 16);
end;

class procedure TX25519Field.Encode(const AX: TCryptoLibInt32Array; const ABs: TCryptoLibByteArray;
  ABsOff: Int32);
begin
  Encode128(AX, 0, ABs, ABsOff);
  Encode128(AX, 5, ABs, ABsOff + 16);
end;

class procedure TX25519Field.Encode(const AX: TCryptoLibInt32Array; AXOff: Int32;
  const ABs: TCryptoLibByteArray; ABsOff: Int32);
begin
  Encode128(AX, AXOff, ABs, ABsOff);
  Encode128(AX, AXOff + 5, ABs, ABsOff + 16);
end;

class procedure TX25519Field.Inv(const AX, AZ: TCryptoLibInt32Array);
var
  Lt: TCryptoLibInt32Array;
  Lu: TCryptoLibUInt32Array;
begin
  Lt := Create;
  System.SetLength(Lu, 8);
  Copy(AX, 0, Lt, 0);
  Normalize(Lt);
  Encode(Lt, Lu, 0);
  TMod.ModOddInverse(FP32, Lu, Lu);
  Decode(Lu, 0, AZ);
end;

class procedure TX25519Field.InvVar(const AX, AZ: TCryptoLibInt32Array);
var
  Lt: TCryptoLibInt32Array;
  Lu: TCryptoLibUInt32Array;
begin
  Lt := Create;
  System.SetLength(Lu, 8);
  Copy(AX, 0, Lt, 0);
  Normalize(Lt);
  Encode(Lt, Lu, 0);
  TMod.ModOddInverseVar(FP32, Lu, Lu);
  Decode(Lu, 0, AZ);
end;

class function TX25519Field.IsOne(const AX: TCryptoLibInt32Array): Int32;
var
  Ld: Int32;
  LI: Int32;
begin
  Ld := AX[0] xor 1;
  LI := 1;
  while LI < Size do
  begin
    Ld := Ld or AX[LI];
    System.Inc(LI);
  end;
  Ld := Ld or TBitUtilities.Asr32(Ld, 16);
  Ld := Ld and $FFFF;
  Result := TBitUtilities.Asr32(Ld - 1, 31);
end;

class function TX25519Field.IsOneVar(const AX: TCryptoLibInt32Array): Boolean;
begin
  Result := IsOne(AX) <> 0;
end;

class function TX25519Field.IsZero(const AX: TCryptoLibInt32Array): Int32;
var
  Ld: Int32;
  LI: Int32;
begin
  Ld := 0;
  LI := 0;
  while LI < Size do
  begin
    Ld := Ld or AX[LI];
    System.Inc(LI);
  end;
  Ld := Ld or TBitUtilities.Asr32(Ld, 16);
  Ld := Ld and $FFFF;
  Result := TBitUtilities.Asr32(Ld - 1, 31);
end;

class function TX25519Field.IsZeroVar(const AX: TCryptoLibInt32Array): Boolean;
begin
  Result := IsZero(AX) <> 0;
end;

class procedure TX25519Field.Mul(const AX: TCryptoLibInt32Array; AY: Int32; const AZ: TCryptoLibInt32Array);
var
  Lx0, Lx1, Lx2, Lx3, Lx4, Lx5, Lx6, Lx7, Lx8, Lx9: Int32;
  Lc0, Lc1, Lc2, Lc3: Int64;
begin
  Lx0 := AX[0];
  Lx1 := AX[1];
  Lx2 := AX[2];
  Lx3 := AX[3];
  Lx4 := AX[4];
  Lx5 := AX[5];
  Lx6 := AX[6];
  Lx7 := AX[7];
  Lx8 := AX[8];
  Lx9 := AX[9];
  Lc0 := Int64(Lx2) * AY;
  Lx2 := Int32(Lc0) and M25;
  Lc0 := TBitUtilities.Asr64(Lc0, 25);
  Lc1 := Int64(Lx4) * AY;
  Lx4 := Int32(Lc1) and M25;
  Lc1 := TBitUtilities.Asr64(Lc1, 25);
  Lc2 := Int64(Lx7) * AY;
  Lx7 := Int32(Lc2) and M25;
  Lc2 := TBitUtilities.Asr64(Lc2, 25);
  Lc3 := Int64(Lx9) * AY;
  Lx9 := Int32(Lc3) and M25;
  Lc3 := TBitUtilities.Asr64(Lc3, 25);
  Lc3 := Lc3 * 38;
  Lc3 := Lc3 + Int64(Lx0) * AY;
  AZ[0] := Int32(Lc3) and M26;
  Lc3 := TBitUtilities.Asr64(Lc3, 26);
  Lc1 := Lc1 + Int64(Lx5) * AY;
  AZ[5] := Int32(Lc1) and M26;
  Lc1 := TBitUtilities.Asr64(Lc1, 26);
  Lc3 := Lc3 + Int64(Lx1) * AY;
  AZ[1] := Int32(Lc3) and M26;
  Lc3 := TBitUtilities.Asr64(Lc3, 26);
  Lc0 := Lc0 + Int64(Lx3) * AY;
  AZ[3] := Int32(Lc0) and M26;
  Lc0 := TBitUtilities.Asr64(Lc0, 26);
  Lc1 := Lc1 + Int64(Lx6) * AY;
  AZ[6] := Int32(Lc1) and M26;
  Lc1 := TBitUtilities.Asr64(Lc1, 26);
  Lc2 := Lc2 + Int64(Lx8) * AY;
  AZ[8] := Int32(Lc2) and M26;
  Lc2 := TBitUtilities.Asr64(Lc2, 26);
  AZ[2] := Lx2 + Int32(Lc3);
  AZ[4] := Lx4 + Int32(Lc0);
  AZ[7] := Lx7 + Int32(Lc1);
  AZ[9] := Lx9 + Int32(Lc2);
end;

class procedure TX25519Field.Mul(const AX, AY, AZ: TCryptoLibInt32Array);
var
  Lx0, Ly0, Lx1, Ly1, Lx2, Ly2, Lx3, Ly3, Lx4, Ly4: Int32;
  Lu0, Lv0, Lu1, Lv1, Lu2, Lv2, Lu3, Lv3, Lu4, Lv4: Int32;
  La0, La1, La2, La3, La4, La5, La6, La7, La8: Int64;
  Lb0, Lb1, Lb2, Lb3, Lb4, Lb5, Lb6, Lb7, Lb8: Int64;
  Lc0, Lc1, Lc2, Lc3, Lc4, Lc5, Lc6, Lc7, Lc8: Int64;
  Lt: Int64;
  Lz8, Lz9: Int32;
begin
  Lx0 := AX[0];
  Ly0 := AY[0];
  Lx1 := AX[1];
  Ly1 := AY[1];
  Lx2 := AX[2];
  Ly2 := AY[2];
  Lx3 := AX[3];
  Ly3 := AY[3];
  Lx4 := AX[4];
  Ly4 := AY[4];
  Lu0 := AX[5];
  Lv0 := AY[5];
  Lu1 := AX[6];
  Lv1 := AY[6];
  Lu2 := AX[7];
  Lv2 := AY[7];
  Lu3 := AX[8];
  Lv3 := AY[8];
  Lu4 := AX[9];
  Lv4 := AY[9];
  La0 := Int64(Lx0) * Ly0;
  La1 := Int64(Lx0) * Ly1 + Int64(Lx1) * Ly0;
  La2 := Int64(Lx0) * Ly2 + Int64(Lx1) * Ly1 + Int64(Lx2) * Ly0;
  La3 := (Int64(Lx1) * Ly2 + Int64(Lx2) * Ly1) shl 1;
  La3 := La3 + Int64(Lx0) * Ly3 + Int64(Lx3) * Ly0;
  La4 := (Int64(Lx2) * Ly2) shl 1;
  La4 := La4 + Int64(Lx0) * Ly4 + Int64(Lx1) * Ly3 + Int64(Lx3) * Ly1 + Int64(Lx4) * Ly0;
  La5 := (Int64(Lx1) * Ly4 + Int64(Lx2) * Ly3 + Int64(Lx3) * Ly2 + Int64(Lx4) * Ly1) shl 1;
  La6 := (Int64(Lx2) * Ly4 + Int64(Lx4) * Ly2) shl 1 + Int64(Lx3) * Ly3;
  La7 := Int64(Lx3) * Ly4 + Int64(Lx4) * Ly3;
  La8 := (Int64(Lx4) * Ly4) shl 1;
  Lb0 := Int64(Lu0) * Lv0;
  Lb1 := Int64(Lu0) * Lv1 + Int64(Lu1) * Lv0;
  Lb2 := Int64(Lu0) * Lv2 + Int64(Lu1) * Lv1 + Int64(Lu2) * Lv0;
  Lb3 := (Int64(Lu1) * Lv2 + Int64(Lu2) * Lv1) shl 1;
  Lb3 := Lb3 + Int64(Lu0) * Lv3 + Int64(Lu3) * Lv0;
  Lb4 := (Int64(Lu2) * Lv2) shl 1;
  Lb4 := Lb4 + Int64(Lu0) * Lv4 + Int64(Lu1) * Lv3 + Int64(Lu3) * Lv1 + Int64(Lu4) * Lv0;
  Lb5 := Int64(Lu1) * Lv4 + Int64(Lu2) * Lv3 + Int64(Lu3) * Lv2 + Int64(Lu4) * Lv1;
  Lb6 := (Int64(Lu2) * Lv4 + Int64(Lu4) * Lv2) shl 1 + Int64(Lu3) * Lv3;
  Lb7 := Int64(Lu3) * Lv4 + Int64(Lu4) * Lv3;
  Lb8 := Int64(Lu4) * Lv4;
  La0 := La0 - Lb5 * 76;
  La1 := La1 - Lb6 * 38;
  La2 := La2 - Lb7 * 38;
  La3 := La3 - Lb8 * 76;
  La5 := La5 - Lb0;
  La6 := La6 - Lb1;
  La7 := La7 - Lb2;
  La8 := La8 - Lb3;
  Lx0 := Lx0 + Lu0;
  Ly0 := Ly0 + Lv0;
  Lx1 := Lx1 + Lu1;
  Ly1 := Ly1 + Lv1;
  Lx2 := Lx2 + Lu2;
  Ly2 := Ly2 + Lv2;
  Lx3 := Lx3 + Lu3;
  Ly3 := Ly3 + Lv3;
  Lx4 := Lx4 + Lu4;
  Ly4 := Ly4 + Lv4;
  Lc0 := Int64(Lx0) * Ly0;
  Lc1 := Int64(Lx0) * Ly1 + Int64(Lx1) * Ly0;
  Lc2 := Int64(Lx0) * Ly2 + Int64(Lx1) * Ly1 + Int64(Lx2) * Ly0;
  Lc3 := (Int64(Lx1) * Ly2 + Int64(Lx2) * Ly1) shl 1;
  Lc3 := Lc3 + Int64(Lx0) * Ly3 + Int64(Lx3) * Ly0;
  Lc4 := (Int64(Lx2) * Ly2) shl 1;
  Lc4 := Lc4 + Int64(Lx0) * Ly4 + Int64(Lx1) * Ly3 + Int64(Lx3) * Ly1 + Int64(Lx4) * Ly0;
  Lc5 := (Int64(Lx1) * Ly4 + Int64(Lx2) * Ly3 + Int64(Lx3) * Ly2 + Int64(Lx4) * Ly1) shl 1;
  Lc6 := (Int64(Lx2) * Ly4 + Int64(Lx4) * Ly2) shl 1 + Int64(Lx3) * Ly3;
  Lc7 := Int64(Lx3) * Ly4 + Int64(Lx4) * Ly3;
  Lc8 := (Int64(Lx4) * Ly4) shl 1;
  Lt := La8 + (Lc3 - La3);
  Lz8 := Int32(Lt) and M26;
  Lt := TBitUtilities.Asr64(Lt, 26);
  Lt := Lt + (Lc4 - La4) - Lb4;
  Lz9 := Int32(Lt) and M25;
  Lt := TBitUtilities.Asr64(Lt, 25);
  Lt := La0 + (Lt + Lc5 - La5) * 38;
  AZ[0] := Int32(Lt) and M26;
  Lt := TBitUtilities.Asr64(Lt, 26);
  Lt := Lt + La1 + (Lc6 - La6) * 38;
  AZ[1] := Int32(Lt) and M26;
  Lt := TBitUtilities.Asr64(Lt, 26);
  Lt := Lt + La2 + (Lc7 - La7) * 38;
  AZ[2] := Int32(Lt) and M25;
  Lt := TBitUtilities.Asr64(Lt, 25);
  Lt := Lt + La3 + (Lc8 - La8) * 38;
  AZ[3] := Int32(Lt) and M26;
  Lt := TBitUtilities.Asr64(Lt, 26);
  Lt := Lt + La4 + Lb4 * 38;
  AZ[4] := Int32(Lt) and M25;
  Lt := TBitUtilities.Asr64(Lt, 25);
  Lt := Lt + La5 + (Lc0 - La0);
  AZ[5] := Int32(Lt) and M26;
  Lt := TBitUtilities.Asr64(Lt, 26);
  Lt := Lt + La6 + (Lc1 - La1);
  AZ[6] := Int32(Lt) and M26;
  Lt := TBitUtilities.Asr64(Lt, 26);
  Lt := Lt + La7 + (Lc2 - La2);
  AZ[7] := Int32(Lt) and M25;
  Lt := TBitUtilities.Asr64(Lt, 25);
  Lt := Lt + Lz8;
  AZ[8] := Int32(Lt) and M26;
  Lt := TBitUtilities.Asr64(Lt, 26);
  AZ[9] := Lz9 + Int32(Lt);
end;

class procedure TX25519Field.Negate(const AX, AZ: TCryptoLibInt32Array);
var
  LI: Int32;
begin
  LI := 0;
  while LI < Size do
  begin
    AZ[LI] := -AX[LI];
    System.Inc(LI);
  end;
end;

class procedure TX25519Field.Reduce(AZ: TCryptoLibInt32Array; AX: Int32);
var
  Lt, Lz9: Int32;
  Lcc: Int64;
begin
  Lt := AZ[9];
  Lz9 := Lt and M24;
  Lt := TBitUtilities.Asr32(Lt, 24) + AX;
  Lcc := Int64(Lt) * 19;
  Lcc := Lcc + AZ[0];
  AZ[0] := Int32(Lcc) and M26;
  Lcc := TBitUtilities.Asr64(Lcc, 26);
  Lcc := Lcc + AZ[1];
  AZ[1] := Int32(Lcc) and M26;
  Lcc := TBitUtilities.Asr64(Lcc, 26);
  Lcc := Lcc + AZ[2];
  AZ[2] := Int32(Lcc) and M25;
  Lcc := TBitUtilities.Asr64(Lcc, 25);
  Lcc := Lcc + AZ[3];
  AZ[3] := Int32(Lcc) and M26;
  Lcc := TBitUtilities.Asr64(Lcc, 26);
  Lcc := Lcc + AZ[4];
  AZ[4] := Int32(Lcc) and M25;
  Lcc := TBitUtilities.Asr64(Lcc, 25);
  Lcc := Lcc + AZ[5];
  AZ[5] := Int32(Lcc) and M26;
  Lcc := TBitUtilities.Asr64(Lcc, 26);
  Lcc := Lcc + AZ[6];
  AZ[6] := Int32(Lcc) and M26;
  Lcc := TBitUtilities.Asr64(Lcc, 26);
  Lcc := Lcc + AZ[7];
  AZ[7] := Int32(Lcc) and M25;
  Lcc := TBitUtilities.Asr64(Lcc, 25);
  Lcc := Lcc + AZ[8];
  AZ[8] := Int32(Lcc) and M26;
  Lcc := TBitUtilities.Asr64(Lcc, 26);
  AZ[9] := Lz9 + Int32(Lcc);
end;

class procedure TX25519Field.Normalize(AZ: TCryptoLibInt32Array);
var
  Lx: Int32;
begin
  Lx := TBitUtilities.Asr32(AZ[9], 23) and 1;
  Reduce(AZ, Lx);
  Reduce(AZ, -Lx);
  {$IFDEF DEBUG}
  System.Assert(TBitUtilities.Asr32(AZ[9], 24) = 0);
  {$ENDIF}
end;

class procedure TX25519Field.One(AZ: TCryptoLibInt32Array);
begin
  AZ[0] := 1;
  TArrayUtilities.Fill<Int32>(AZ, 1, Size, 0);
end;

class procedure TX25519Field.PowPm5d8(const AX: TCryptoLibInt32Array; const ARx2: TCryptoLibInt32Array;
  const ARz: TCryptoLibInt32Array);
var
  Lx2, Lx3, Lx5, Lx10, Lx15, Lx25, Lx50, Lx75, Lx125, Lx250, Lt: TCryptoLibInt32Array;
begin
  Lx2 := ARx2;
  Sqr(AX, Lx2);
  Mul(AX, Lx2, Lx2);
  Lx3 := Create;
  Sqr(Lx2, Lx3);
  Mul(AX, Lx3, Lx3);
  Lx5 := Lx3;
  Sqr(Lx3, 2, Lx5);
  Mul(Lx2, Lx5, Lx5);
  Lx10 := Create;
  Sqr(Lx5, 5, Lx10);
  Mul(Lx5, Lx10, Lx10);
  Lx15 := Create;
  Sqr(Lx10, 5, Lx15);
  Mul(Lx5, Lx15, Lx15);
  Lx25 := Lx5;
  Sqr(Lx15, 10, Lx25);
  Mul(Lx10, Lx25, Lx25);
  Lx50 := Lx10;
  Sqr(Lx25, 25, Lx50);
  Mul(Lx25, Lx50, Lx50);
  Lx75 := Lx15;
  Sqr(Lx50, 25, Lx75);
  Mul(Lx25, Lx75, Lx75);
  Lx125 := Lx25;
  Sqr(Lx75, 50, Lx125);
  Mul(Lx50, Lx125, Lx125);
  Lx250 := Lx50;
  Sqr(Lx125, 125, Lx250);
  Mul(Lx125, Lx250, Lx250);
  Lt := Lx125;
  Sqr(Lx250, 2, Lt);
  Mul(Lt, AX, ARz);
end;

class procedure TX25519Field.Sqr(const AX, AZ: TCryptoLibInt32Array);
var
  Lx0, Lx1, Lx2, Lx3, Lx4, Lu0, Lu1, Lu2, Lu3, Lu4: Int32;
  Lx1_2, Lx2_2, Lx3_2, Lx4_2, Lu1_2, Lu2_2, Lu3_2, Lu4_2: Int32;
  La0, La1, La2, La3, La4, La5, La6, La7, La8: Int64;
  Lb0, Lb1, Lb2, Lb3, Lb4, Lb5, Lb6, Lb7, Lb8: Int64;
  Lc0, Lc1, Lc2, Lc3, Lc4, Lc5, Lc6, Lc7, Lc8: Int64;
  Lt: Int64;
  Lz8, Lz9: Int32;
begin
  Lx0 := AX[0];
  Lx1 := AX[1];
  Lx2 := AX[2];
  Lx3 := AX[3];
  Lx4 := AX[4];
  Lu0 := AX[5];
  Lu1 := AX[6];
  Lu2 := AX[7];
  Lu3 := AX[8];
  Lu4 := AX[9];
  Lx1_2 := Lx1 * 2;
  Lx2_2 := Lx2 * 2;
  Lx3_2 := Lx3 * 2;
  Lx4_2 := Lx4 * 2;
  La0 := Int64(Lx0) * Lx0;
  La1 := Int64(Lx0) * Lx1_2;
  La2 := Int64(Lx0) * Lx2_2 + Int64(Lx1) * Lx1;
  La3 := Int64(Lx1_2) * Lx2_2 + Int64(Lx0) * Lx3_2;
  La4 := Int64(Lx2) * Lx2_2 + Int64(Lx0) * Lx4_2 + Int64(Lx1) * Lx3_2;
  La5 := Int64(Lx1_2) * Lx4_2 + Int64(Lx2_2) * Lx3_2;
  La6 := Int64(Lx2_2) * Lx4_2 + Int64(Lx3) * Lx3;
  La7 := Int64(Lx3) * Lx4_2;
  La8 := Int64(Lx4) * Lx4_2;
  Lu1_2 := Lu1 * 2;
  Lu2_2 := Lu2 * 2;
  Lu3_2 := Lu3 * 2;
  Lu4_2 := Lu4 * 2;
  Lb0 := Int64(Lu0) * Lu0;
  Lb1 := Int64(Lu0) * Lu1_2;
  Lb2 := Int64(Lu0) * Lu2_2 + Int64(Lu1) * Lu1;
  Lb3 := Int64(Lu1_2) * Lu2_2 + Int64(Lu0) * Lu3_2;
  Lb4 := Int64(Lu2) * Lu2_2 + Int64(Lu0) * Lu4_2 + Int64(Lu1) * Lu3_2;
  Lb5 := Int64(Lu1_2) * Lu4_2 + Int64(Lu2_2) * Lu3_2;
  Lb6 := Int64(Lu2_2) * Lu4_2 + Int64(Lu3) * Lu3;
  Lb7 := Int64(Lu3) * Lu4_2;
  Lb8 := Int64(Lu4) * Lu4_2;
  La0 := La0 - Lb5 * 38;
  La1 := La1 - Lb6 * 38;
  La2 := La2 - Lb7 * 38;
  La3 := La3 - Lb8 * 38;
  La5 := La5 - Lb0;
  La6 := La6 - Lb1;
  La7 := La7 - Lb2;
  La8 := La8 - Lb3;
  Lx0 := Lx0 + Lu0;
  Lx1 := Lx1 + Lu1;
  Lx2 := Lx2 + Lu2;
  Lx3 := Lx3 + Lu3;
  Lx4 := Lx4 + Lu4;
  Lx1_2 := Lx1 * 2;
  Lx2_2 := Lx2 * 2;
  Lx3_2 := Lx3 * 2;
  Lx4_2 := Lx4 * 2;
  Lc0 := Int64(Lx0) * Lx0;
  Lc1 := Int64(Lx0) * Lx1_2;
  Lc2 := Int64(Lx0) * Lx2_2 + Int64(Lx1) * Lx1;
  Lc3 := Int64(Lx1_2) * Lx2_2 + Int64(Lx0) * Lx3_2;
  Lc4 := Int64(Lx2) * Lx2_2 + Int64(Lx0) * Lx4_2 + Int64(Lx1) * Lx3_2;
  Lc5 := Int64(Lx1_2) * Lx4_2 + Int64(Lx2_2) * Lx3_2;
  Lc6 := Int64(Lx2_2) * Lx4_2 + Int64(Lx3) * Lx3;
  Lc7 := Int64(Lx3) * Lx4_2;
  Lc8 := Int64(Lx4) * Lx4_2;
  Lt := La8 + (Lc3 - La3);
  Lz8 := Int32(Lt) and M26;
  Lt := TBitUtilities.Asr64(Lt, 26);
  Lt := Lt + (Lc4 - La4) - Lb4;
  Lz9 := Int32(Lt) and M25;
  Lt := TBitUtilities.Asr64(Lt, 25);
  Lt := La0 + (Lt + Lc5 - La5) * 38;
  AZ[0] := Int32(Lt) and M26;
  Lt := TBitUtilities.Asr64(Lt, 26);
  Lt := Lt + La1 + (Lc6 - La6) * 38;
  AZ[1] := Int32(Lt) and M26;
  Lt := TBitUtilities.Asr64(Lt, 26);
  Lt := Lt + La2 + (Lc7 - La7) * 38;
  AZ[2] := Int32(Lt) and M25;
  Lt := TBitUtilities.Asr64(Lt, 25);
  Lt := Lt + La3 + (Lc8 - La8) * 38;
  AZ[3] := Int32(Lt) and M26;
  Lt := TBitUtilities.Asr64(Lt, 26);
  Lt := Lt + La4 + Lb4 * 38;
  AZ[4] := Int32(Lt) and M25;
  Lt := TBitUtilities.Asr64(Lt, 25);
  Lt := Lt + La5 + (Lc0 - La0);
  AZ[5] := Int32(Lt) and M26;
  Lt := TBitUtilities.Asr64(Lt, 26);
  Lt := Lt + La6 + (Lc1 - La1);
  AZ[6] := Int32(Lt) and M26;
  Lt := TBitUtilities.Asr64(Lt, 26);
  Lt := Lt + La7 + (Lc2 - La2);
  AZ[7] := Int32(Lt) and M25;
  Lt := TBitUtilities.Asr64(Lt, 25);
  Lt := Lt + Lz8;
  AZ[8] := Int32(Lt) and M26;
  Lt := TBitUtilities.Asr64(Lt, 26);
  AZ[9] := Lz9 + Int32(Lt);
end;

class procedure TX25519Field.Sqr(const AX: TCryptoLibInt32Array; AN: Int32; const AZ: TCryptoLibInt32Array);
begin
  {$IFDEF DEBUG}
  System.Assert(AN > 0);
  {$ENDIF}
  Sqr(AX, AZ);
  while AN > 1 do
  begin
    System.Dec(AN);
    Sqr(AZ, AZ);
  end;
end;

class function TX25519Field.SqrtRatioVar(const AU, AV, AZ: TCryptoLibInt32Array): Boolean;
var
  Luv3, Luv7, Lt, Lx, Lvx2: TCryptoLibInt32Array;
begin
  Luv3 := Create;
  Luv7 := Create;
  Mul(AU, AV, Luv3);
  Sqr(AV, Luv7);
  Mul(Luv3, Luv7, Luv3);
  Sqr(Luv7, Luv7);
  Mul(Luv7, Luv3, Luv7);
  Lt := Create;
  Lx := Create;
  PowPm5d8(Luv7, Lt, Lx);
  Mul(Lx, Luv3, Lx);
  Lvx2 := Create;
  Sqr(Lx, Lvx2);
  Mul(Lvx2, AV, Lvx2);
  Sub(Lvx2, AU, Lt);
  Normalize(Lt);
  if IsZeroVar(Lt) then
  begin
    Copy(Lx, 0, AZ, 0);
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

class procedure TX25519Field.Sub(const AX, AY, AZ: TCryptoLibInt32Array);
var
  LI: Int32;
begin
  LI := 0;
  while LI < Size do
  begin
    AZ[LI] := AX[LI] - AY[LI];
    System.Inc(LI);
  end;
end;

class procedure TX25519Field.SubOne(AZ: TCryptoLibInt32Array);
begin
  AZ[0] := AZ[0] - 1;
end;

class procedure TX25519Field.Zero(AZ: TCryptoLibInt32Array);
begin
  TArrayUtilities.Fill<Int32>(AZ, 0, Size, 0);
end;

end.

