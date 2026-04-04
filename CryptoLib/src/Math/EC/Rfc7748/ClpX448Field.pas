{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpX448Field;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpMod,
  ClpBitOperations,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

type
  TX448Field = class sealed
  public
  const
    Size = Int32(16);
  strict private
  const
    M28 = UInt32($0FFFFFFF);
  class var
    FP32: TCryptoLibUInt32Array;
  class procedure Boot; static;
  class constructor Create;
  class procedure Decode224(const AX: TCryptoLibUInt32Array; AXOff: Int32;
    const AZ: TCryptoLibUInt32Array; AZOff: Int32); static;
  class function Decode24(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32; static;
  class function Decode32(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32; static;
  class procedure Decode56(const ABs: TCryptoLibByteArray; AOff: Int32;
    const AZ: TCryptoLibUInt32Array; AZOff: Int32); static;
  class procedure Encode224(const AX: TCryptoLibUInt32Array; AXOff: Int32;
    const AZ: TCryptoLibUInt32Array; AZOff: Int32); static;
  class procedure Encode24(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32); static;
  class procedure Encode32(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32); static;
  class procedure Encode56(const AX: TCryptoLibUInt32Array; AXOff: Int32;
    const ABs: TCryptoLibByteArray; AOff: Int32); static;
  class procedure PowPm3d4(const AX, AZ: TCryptoLibUInt32Array); static;
  class procedure Reduce(AZ: TCryptoLibUInt32Array; AX: Int32); static;
  public
    class procedure Add(const AX, AY, AZ: TCryptoLibUInt32Array); static;
    class procedure AddOne(const AZ: TCryptoLibUInt32Array); overload; static;
    class procedure AddOne(const AZ: TCryptoLibUInt32Array; AZOff: Int32); overload; static;
    class function AreEqual(const AX, AY: TCryptoLibUInt32Array): Int32; static;
    class function AreEqualVar(const AX, AY: TCryptoLibUInt32Array): Boolean; static;
    class procedure Carry(AZ: TCryptoLibUInt32Array); static;
    class procedure CMov(ACond: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32;
      const AZ: TCryptoLibUInt32Array; AZOff: Int32); static;
    class procedure CNegate(ANegate: Int32; AZ: TCryptoLibUInt32Array); static;
    class procedure Copy(const AX: TCryptoLibUInt32Array; AXOff: Int32;
      const AZ: TCryptoLibUInt32Array; AZOff: Int32); static;
    class function Create: TCryptoLibUInt32Array; static;
    class function CreateTable(AN: Int32): TCryptoLibUInt32Array; static;
    class procedure CSwap(ASwap: Int32; AA, AB: TCryptoLibUInt32Array); static;
    class procedure Decode(const AX: TCryptoLibUInt32Array; AXOff: Int32;
      const AZ: TCryptoLibUInt32Array); overload; static;
    class procedure Decode(const AX: TCryptoLibByteArray;
      const AZ: TCryptoLibUInt32Array); overload; static;
    class procedure Decode(const AX: TCryptoLibByteArray; AXOff: Int32;
      const AZ: TCryptoLibUInt32Array); overload; static;
    class procedure Decode(const AX: TCryptoLibByteArray; AXOff: Int32;
      const AZ: TCryptoLibUInt32Array; AZOff: Int32); overload; static;
    class procedure Encode(const AX: TCryptoLibUInt32Array;
      const AZ: TCryptoLibUInt32Array; AZOff: Int32); overload; static;
    class procedure Encode(const AX: TCryptoLibUInt32Array;
      const AZ: TCryptoLibByteArray); overload; static;
    class procedure Encode(const AX: TCryptoLibUInt32Array;
      const AZ: TCryptoLibByteArray; AZOff: Int32); overload; static;
    class procedure Encode(const AX: TCryptoLibUInt32Array; AXOff: Int32;
      const AZ: TCryptoLibByteArray; AZOff: Int32); overload; static;
    class procedure Inv(const AX, AZ: TCryptoLibUInt32Array); static;
    class procedure InvVar(const AX, AZ: TCryptoLibUInt32Array); static;
    class function IsOne(const AX: TCryptoLibUInt32Array): Int32; static;
    class function IsOneVar(const AX: TCryptoLibUInt32Array): Boolean; static;
    class function IsZero(const AX: TCryptoLibUInt32Array): Int32; static;
    class function IsZeroVar(const AX: TCryptoLibUInt32Array): Boolean; static;
    class procedure Mul(const AX: TCryptoLibUInt32Array; AY: UInt32;
      const AZ: TCryptoLibUInt32Array); overload; static;
    class procedure Mul(const AX, AY, AZ: TCryptoLibUInt32Array); overload; static;
    class procedure Negate(const AX, AZ: TCryptoLibUInt32Array); static;
    class procedure Normalize(AZ: TCryptoLibUInt32Array); static;
    class procedure One(AZ: TCryptoLibUInt32Array); static;
    class procedure Sqr(const AX, AZ: TCryptoLibUInt32Array); overload; static;
    class procedure Sqr(const AX: TCryptoLibUInt32Array; AN: Int32;
      const AZ: TCryptoLibUInt32Array); overload; static;
    class function SqrtRatioVar(const AU, AV, AZ: TCryptoLibUInt32Array): Boolean; static;
    class procedure Sub(const AX, AY, AZ: TCryptoLibUInt32Array); static;
    class procedure SubOne(AZ: TCryptoLibUInt32Array); static;
    class procedure Zero(AZ: TCryptoLibUInt32Array); static;
  end;

implementation

class constructor TX448Field.Create;
begin
  Boot;
end;

class procedure TX448Field.Boot;
begin
  FP32 := TCryptoLibUInt32Array.Create($FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF,
    $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFE, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF,
    $FFFFFFFF, $FFFFFFFF, $FFFFFFFF);
end;

class procedure TX448Field.Add(const AX, AY, AZ: TCryptoLibUInt32Array);
var
  LI: Int32;
begin
  for LI := 0 to Size - 1 do
  begin
    AZ[LI] := AX[LI] + AY[LI];
  end;
end;

class procedure TX448Field.AddOne(const AZ: TCryptoLibUInt32Array);
begin
  AZ[0] := AZ[0] + 1;
end;

class procedure TX448Field.AddOne(const AZ: TCryptoLibUInt32Array; AZOff: Int32);
begin
  AZ[AZOff] := AZ[AZOff] + 1;
end;

class function TX448Field.AreEqual(const AX, AY: TCryptoLibUInt32Array): Int32;
var
  LI: Int32;
  LD: UInt32;
begin
  LD := 0;
  for LI := 0 to Size - 1 do
  begin
    LD := LD or (AX[LI] xor AY[LI]);
  end;
  LD := LD or (LD shr 16);
  LD := LD and $FFFF;
  Result := TBitOperations.Asr32(Int32(LD) - 1, 31);
end;

class function TX448Field.AreEqualVar(const AX, AY: TCryptoLibUInt32Array): Boolean;
begin
  Result := 0 <> AreEqual(AX, AY);
end;

class procedure TX448Field.Carry(AZ: TCryptoLibUInt32Array);
var
  LZ0, LZ1, LZ2, LZ3, LZ4, LZ5, LZ6, LZ7: UInt32;
  LZ8, LZ9, LZ10, LZ11, LZ12, LZ13, LZ14, LZ15: UInt32;
  LT: UInt32;
begin
  LZ0 := AZ[0]; LZ1 := AZ[1]; LZ2 := AZ[2]; LZ3 := AZ[3];
  LZ4 := AZ[4]; LZ5 := AZ[5]; LZ6 := AZ[6]; LZ7 := AZ[7];
  LZ8 := AZ[8]; LZ9 := AZ[9]; LZ10 := AZ[10]; LZ11 := AZ[11];
  LZ12 := AZ[12]; LZ13 := AZ[13]; LZ14 := AZ[14]; LZ15 := AZ[15];

  LZ1  := LZ1 + (LZ0 shr 28);  LZ0  := LZ0 and M28;
  LZ5  := LZ5 + (LZ4 shr 28);  LZ4  := LZ4 and M28;
  LZ9  := LZ9 + (LZ8 shr 28);  LZ8  := LZ8 and M28;
  LZ13 := LZ13 + (LZ12 shr 28); LZ12 := LZ12 and M28;

  LZ2  := LZ2 + (LZ1 shr 28);  LZ1  := LZ1 and M28;
  LZ6  := LZ6 + (LZ5 shr 28);  LZ5  := LZ5 and M28;
  LZ10 := LZ10 + (LZ9 shr 28);  LZ9  := LZ9 and M28;
  LZ14 := LZ14 + (LZ13 shr 28); LZ13 := LZ13 and M28;

  LZ3  := LZ3 + (LZ2 shr 28);  LZ2  := LZ2 and M28;
  LZ7  := LZ7 + (LZ6 shr 28);  LZ6  := LZ6 and M28;
  LZ11 := LZ11 + (LZ10 shr 28); LZ10 := LZ10 and M28;
  LZ15 := LZ15 + (LZ14 shr 28); LZ14 := LZ14 and M28;

  LT := LZ15 shr 28; LZ15 := LZ15 and M28;
  LZ0 := LZ0 + LT;
  LZ8 := LZ8 + LT;

  LZ4  := LZ4 + (LZ3 shr 28);  LZ3  := LZ3 and M28;
  LZ8  := LZ8 + (LZ7 shr 28);  LZ7  := LZ7 and M28;
  LZ12 := LZ12 + (LZ11 shr 28); LZ11 := LZ11 and M28;

  LZ1  := LZ1 + (LZ0 shr 28);  LZ0  := LZ0 and M28;
  LZ5  := LZ5 + (LZ4 shr 28);  LZ4  := LZ4 and M28;
  LZ9  := LZ9 + (LZ8 shr 28);  LZ8  := LZ8 and M28;
  LZ13 := LZ13 + (LZ12 shr 28); LZ12 := LZ12 and M28;

  AZ[0] := LZ0; AZ[1] := LZ1; AZ[2] := LZ2; AZ[3] := LZ3;
  AZ[4] := LZ4; AZ[5] := LZ5; AZ[6] := LZ6; AZ[7] := LZ7;
  AZ[8] := LZ8; AZ[9] := LZ9; AZ[10] := LZ10; AZ[11] := LZ11;
  AZ[12] := LZ12; AZ[13] := LZ13; AZ[14] := LZ14; AZ[15] := LZ15;
end;

class procedure TX448Field.CMov(ACond: Int32; const AX: TCryptoLibUInt32Array;
  AXOff: Int32; const AZ: TCryptoLibUInt32Array; AZOff: Int32);
var
  LI: Int32;
  LMask, LZ_I, LDiff: UInt32;
begin
  LMask := UInt32(ACond);
  for LI := 0 to Size - 1 do
  begin
    LZ_I := AZ[AZOff + LI];
    LDiff := LZ_I xor AX[AXOff + LI];
    LZ_I := LZ_I xor (LDiff and LMask);
    AZ[AZOff + LI] := LZ_I;
  end;
end;

class procedure TX448Field.CNegate(ANegate: Int32; AZ: TCryptoLibUInt32Array);
var
  LT: TCryptoLibUInt32Array;
begin
  LT := TX448Field.Create;
  Sub(LT, AZ, LT);
  CMov(-ANegate, LT, 0, AZ, 0);
end;

class procedure TX448Field.Copy(const AX: TCryptoLibUInt32Array; AXOff: Int32;
  const AZ: TCryptoLibUInt32Array; AZOff: Int32);
begin
  System.Move(AX[AXOff], AZ[AZOff], Size * System.SizeOf(UInt32));
end;

class function TX448Field.Create: TCryptoLibUInt32Array;
begin
  System.SetLength(Result, Size);
end;

class function TX448Field.CreateTable(AN: Int32): TCryptoLibUInt32Array;
begin
  System.SetLength(Result, Size * AN);
end;

class procedure TX448Field.CSwap(ASwap: Int32; AA, AB: TCryptoLibUInt32Array);
var
  LI: Int32;
  LMask, LAi, LBi, LDummy: UInt32;
begin
  LMask := UInt32(0 - ASwap);
  for LI := 0 to Size - 1 do
  begin
    LAi := AA[LI];
    LBi := AB[LI];
    LDummy := LMask and (LAi xor LBi);
    AA[LI] := LAi xor LDummy;
    AB[LI] := LBi xor LDummy;
  end;
end;

class procedure TX448Field.Decode(const AX: TCryptoLibUInt32Array; AXOff: Int32;
  const AZ: TCryptoLibUInt32Array);
begin
  Decode224(AX, AXOff, AZ, 0);
  Decode224(AX, AXOff + 7, AZ, 8);
end;

class procedure TX448Field.Decode(const AX: TCryptoLibByteArray;
  const AZ: TCryptoLibUInt32Array);
begin
  Decode56(AX, 0, AZ, 0);
  Decode56(AX, 7, AZ, 2);
  Decode56(AX, 14, AZ, 4);
  Decode56(AX, 21, AZ, 6);
  Decode56(AX, 28, AZ, 8);
  Decode56(AX, 35, AZ, 10);
  Decode56(AX, 42, AZ, 12);
  Decode56(AX, 49, AZ, 14);
end;

class procedure TX448Field.Decode(const AX: TCryptoLibByteArray; AXOff: Int32;
  const AZ: TCryptoLibUInt32Array);
begin
  Decode56(AX, AXOff, AZ, 0);
  Decode56(AX, AXOff + 7, AZ, 2);
  Decode56(AX, AXOff + 14, AZ, 4);
  Decode56(AX, AXOff + 21, AZ, 6);
  Decode56(AX, AXOff + 28, AZ, 8);
  Decode56(AX, AXOff + 35, AZ, 10);
  Decode56(AX, AXOff + 42, AZ, 12);
  Decode56(AX, AXOff + 49, AZ, 14);
end;

class procedure TX448Field.Decode(const AX: TCryptoLibByteArray; AXOff: Int32;
  const AZ: TCryptoLibUInt32Array; AZOff: Int32);
begin
  Decode56(AX, AXOff, AZ, AZOff);
  Decode56(AX, AXOff + 7, AZ, AZOff + 2);
  Decode56(AX, AXOff + 14, AZ, AZOff + 4);
  Decode56(AX, AXOff + 21, AZ, AZOff + 6);
  Decode56(AX, AXOff + 28, AZ, AZOff + 8);
  Decode56(AX, AXOff + 35, AZ, AZOff + 10);
  Decode56(AX, AXOff + 42, AZ, AZOff + 12);
  Decode56(AX, AXOff + 49, AZ, AZOff + 14);
end;

class procedure TX448Field.Decode224(const AX: TCryptoLibUInt32Array; AXOff: Int32;
  const AZ: TCryptoLibUInt32Array; AZOff: Int32);
var
  LX0, LX1, LX2, LX3, LX4, LX5, LX6: UInt32;
begin
  LX0 := AX[AXOff + 0]; LX1 := AX[AXOff + 1]; LX2 := AX[AXOff + 2]; LX3 := AX[AXOff + 3];
  LX4 := AX[AXOff + 4]; LX5 := AX[AXOff + 5]; LX6 := AX[AXOff + 6];

  AZ[AZOff + 0] := LX0 and M28;
  AZ[AZOff + 1] := ((LX0 shr 28) or (LX1 shl 4)) and M28;
  AZ[AZOff + 2] := ((LX1 shr 24) or (LX2 shl 8)) and M28;
  AZ[AZOff + 3] := ((LX2 shr 20) or (LX3 shl 12)) and M28;
  AZ[AZOff + 4] := ((LX3 shr 16) or (LX4 shl 16)) and M28;
  AZ[AZOff + 5] := ((LX4 shr 12) or (LX5 shl 20)) and M28;
  AZ[AZOff + 6] := ((LX5 shr 8) or (LX6 shl 24)) and M28;
  AZ[AZOff + 7] := LX6 shr 4;
end;

class function TX448Field.Decode24(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32;
var
  LN: UInt32;
begin
  LN := ABs[AOff];
  Inc(AOff);
  LN := LN or (UInt32(ABs[AOff]) shl 8);
  Inc(AOff);
  LN := LN or (UInt32(ABs[AOff]) shl 16);
  Result := LN;
end;

class function TX448Field.Decode32(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32;
var
  LN: UInt32;
begin
  LN := ABs[AOff];
  Inc(AOff);
  LN := LN or (UInt32(ABs[AOff]) shl 8);
  Inc(AOff);
  LN := LN or (UInt32(ABs[AOff]) shl 16);
  Inc(AOff);
  LN := LN or (UInt32(ABs[AOff]) shl 24);
  Result := LN;
end;

class procedure TX448Field.Decode56(const ABs: TCryptoLibByteArray; AOff: Int32;
  const AZ: TCryptoLibUInt32Array; AZOff: Int32);
var
  LLo, LHi: UInt32;
begin
  LLo := Decode32(ABs, AOff);
  LHi := Decode24(ABs, AOff + 4);
  AZ[AZOff] := LLo and M28;
  AZ[AZOff + 1] := (LLo shr 28) or (LHi shl 4);
end;

class procedure TX448Field.Encode(const AX: TCryptoLibUInt32Array;
  const AZ: TCryptoLibUInt32Array; AZOff: Int32);
begin
  Encode224(AX, 0, AZ, AZOff);
  Encode224(AX, 8, AZ, AZOff + 7);
end;

class procedure TX448Field.Encode(const AX: TCryptoLibUInt32Array;
  const AZ: TCryptoLibByteArray);
begin
  Encode56(AX, 0, AZ, 0);
  Encode56(AX, 2, AZ, 7);
  Encode56(AX, 4, AZ, 14);
  Encode56(AX, 6, AZ, 21);
  Encode56(AX, 8, AZ, 28);
  Encode56(AX, 10, AZ, 35);
  Encode56(AX, 12, AZ, 42);
  Encode56(AX, 14, AZ, 49);
end;

class procedure TX448Field.Encode(const AX: TCryptoLibUInt32Array;
  const AZ: TCryptoLibByteArray; AZOff: Int32);
begin
  Encode56(AX, 0, AZ, AZOff);
  Encode56(AX, 2, AZ, AZOff + 7);
  Encode56(AX, 4, AZ, AZOff + 14);
  Encode56(AX, 6, AZ, AZOff + 21);
  Encode56(AX, 8, AZ, AZOff + 28);
  Encode56(AX, 10, AZ, AZOff + 35);
  Encode56(AX, 12, AZ, AZOff + 42);
  Encode56(AX, 14, AZ, AZOff + 49);
end;

class procedure TX448Field.Encode(const AX: TCryptoLibUInt32Array; AXOff: Int32;
  const AZ: TCryptoLibByteArray; AZOff: Int32);
begin
  Encode56(AX, AXOff, AZ, AZOff);
  Encode56(AX, AXOff + 2, AZ, AZOff + 7);
  Encode56(AX, AXOff + 4, AZ, AZOff + 14);
  Encode56(AX, AXOff + 6, AZ, AZOff + 21);
  Encode56(AX, AXOff + 8, AZ, AZOff + 28);
  Encode56(AX, AXOff + 10, AZ, AZOff + 35);
  Encode56(AX, AXOff + 12, AZ, AZOff + 42);
  Encode56(AX, AXOff + 14, AZ, AZOff + 49);
end;

class procedure TX448Field.Encode224(const AX: TCryptoLibUInt32Array; AXOff: Int32;
  const AZ: TCryptoLibUInt32Array; AZOff: Int32);
var
  LX0, LX1, LX2, LX3, LX4, LX5, LX6, LX7: UInt32;
begin
  LX0 := AX[AXOff + 0]; LX1 := AX[AXOff + 1]; LX2 := AX[AXOff + 2]; LX3 := AX[AXOff + 3];
  LX4 := AX[AXOff + 4]; LX5 := AX[AXOff + 5]; LX6 := AX[AXOff + 6]; LX7 := AX[AXOff + 7];

  AZ[AZOff + 0] :=  LX0        or (LX1 shl 28);
  AZ[AZOff + 1] := (LX1 shr 4) or (LX2 shl 24);
  AZ[AZOff + 2] := (LX2 shr 8) or (LX3 shl 20);
  AZ[AZOff + 3] := (LX3 shr 12) or (LX4 shl 16);
  AZ[AZOff + 4] := (LX4 shr 16) or (LX5 shl 12);
  AZ[AZOff + 5] := (LX5 shr 20) or (LX6 shl 8);
  AZ[AZOff + 6] := (LX6 shr 24) or (LX7 shl 4);
end;

class procedure TX448Field.Encode24(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32);
begin
  ABs[AOff] := Byte(AN);
  Inc(AOff);
  ABs[AOff] := Byte(AN shr 8);
  Inc(AOff);
  ABs[AOff] := Byte(AN shr 16);
end;

class procedure TX448Field.Encode32(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32);
begin
  ABs[AOff] := Byte(AN);
  Inc(AOff);
  ABs[AOff] := Byte(AN shr 8);
  Inc(AOff);
  ABs[AOff] := Byte(AN shr 16);
  Inc(AOff);
  ABs[AOff] := Byte(AN shr 24);
end;

class procedure TX448Field.Encode56(const AX: TCryptoLibUInt32Array; AXOff: Int32;
  const ABs: TCryptoLibByteArray; AOff: Int32);
var
  LLo, LHi: UInt32;
begin
  LLo := AX[AXOff];
  LHi := AX[AXOff + 1];
  Encode32(LLo or (LHi shl 28), ABs, AOff);
  Encode24(LHi shr 4, ABs, AOff + 4);
end;

class procedure TX448Field.Inv(const AX, AZ: TCryptoLibUInt32Array);
var
  LT: TCryptoLibUInt32Array;
  LU: TCryptoLibUInt32Array;
begin
  LT := TX448Field.Create;
  System.SetLength(LU, 14);

  Copy(AX, 0, LT, 0);
  Normalize(LT);
  Encode(LT, LU, 0);

  TMod.ModOddInverse(FP32, LU, LU);

  Decode(LU, 0, AZ);
end;

class procedure TX448Field.InvVar(const AX, AZ: TCryptoLibUInt32Array);
var
  LT: TCryptoLibUInt32Array;
  LU: TCryptoLibUInt32Array;
begin
  LT := TX448Field.Create;
  System.SetLength(LU, 14);

  Copy(AX, 0, LT, 0);
  Normalize(LT);
  Encode(LT, LU, 0);

  TMod.ModOddInverseVar(FP32, LU, LU);

  Decode(LU, 0, AZ);
end;

class function TX448Field.IsOne(const AX: TCryptoLibUInt32Array): Int32;
var
  LI: Int32;
  LD: UInt32;
begin
  LD := AX[0] xor 1;
  for LI := 1 to Size - 1 do
  begin
    LD := LD or AX[LI];
  end;
  LD := LD or (LD shr 16);
  LD := LD and $FFFF;
  Result := TBitOperations.Asr32(Int32(LD) - 1, 31);
end;

class function TX448Field.IsOneVar(const AX: TCryptoLibUInt32Array): Boolean;
begin
  Result := 0 <> IsOne(AX);
end;

class function TX448Field.IsZero(const AX: TCryptoLibUInt32Array): Int32;
var
  LI: Int32;
  LD: UInt32;
begin
  LD := 0;
  for LI := 0 to Size - 1 do
  begin
    LD := LD or AX[LI];
  end;
  LD := LD or (LD shr 16);
  LD := LD and $FFFF;
  Result := TBitOperations.Asr32(Int32(LD) - 1, 31);
end;

class function TX448Field.IsZeroVar(const AX: TCryptoLibUInt32Array): Boolean;
begin
  Result := UInt32(0) <> UInt32(IsZero(AX));
end;

class procedure TX448Field.Mul(const AX: TCryptoLibUInt32Array; AY: UInt32;
  const AZ: TCryptoLibUInt32Array);
var
  LX0, LX1, LX2, LX3, LX4, LX5, LX6, LX7: UInt32;
  LX8, LX9, LX10, LX11, LX12, LX13, LX14, LX15: UInt32;
  LZ1, LZ5, LZ9, LZ13: UInt32;
  LC, LD, LE, LF: UInt64;
begin
  LX0 := AX[0]; LX1 := AX[1]; LX2 := AX[2]; LX3 := AX[3];
  LX4 := AX[4]; LX5 := AX[5]; LX6 := AX[6]; LX7 := AX[7];
  LX8 := AX[8]; LX9 := AX[9]; LX10 := AX[10]; LX11 := AX[11];
  LX12 := AX[12]; LX13 := AX[13]; LX14 := AX[14]; LX15 := AX[15];

  LC    := UInt64(LX1) * AY;
  LZ1   := UInt32(LC) and M28; LC := LC shr 28;
  LD    := UInt64(LX5) * AY;
  LZ5   := UInt32(LD) and M28; LD := LD shr 28;
  LE    := UInt64(LX9) * AY;
  LZ9   := UInt32(LE) and M28; LE := LE shr 28;
  LF    := UInt64(LX13) * AY;
  LZ13  := UInt32(LF) and M28; LF := LF shr 28;

  LC    := LC + UInt64(LX2) * AY;
  AZ[2] := UInt32(LC) and M28; LC := LC shr 28;
  LD    := LD + UInt64(LX6) * AY;
  AZ[6] := UInt32(LD) and M28; LD := LD shr 28;
  LE    := LE + UInt64(LX10) * AY;
  AZ[10] := UInt32(LE) and M28; LE := LE shr 28;
  LF    := LF + UInt64(LX14) * AY;
  AZ[14] := UInt32(LF) and M28; LF := LF shr 28;

  LC    := LC + UInt64(LX3) * AY;
  AZ[3] := UInt32(LC) and M28; LC := LC shr 28;
  LD    := LD + UInt64(LX7) * AY;
  AZ[7] := UInt32(LD) and M28; LD := LD shr 28;
  LE    := LE + UInt64(LX11) * AY;
  AZ[11] := UInt32(LE) and M28; LE := LE shr 28;
  LF    := LF + UInt64(LX15) * AY;
  AZ[15] := UInt32(LF) and M28; LF := LF shr 28;

  LD    := LD + LF;

  LC    := LC + UInt64(LX4) * AY;
  AZ[4] := UInt32(LC) and M28; LC := LC shr 28;
  LD    := LD + UInt64(LX8) * AY;
  AZ[8] := UInt32(LD) and M28; LD := LD shr 28;
  LE    := LE + UInt64(LX12) * AY;
  AZ[12] := UInt32(LE) and M28; LE := LE shr 28;
  LF    := LF + UInt64(LX0) * AY;
  AZ[0] := UInt32(LF) and M28; LF := LF shr 28;

  AZ[1]  := LZ1 + UInt32(LF);
  AZ[5]  := LZ5 + UInt32(LC);
  AZ[9]  := LZ9 + UInt32(LD);
  AZ[13] := LZ13 + UInt32(LE);
end;

class procedure TX448Field.Mul(const AX, AY, AZ: TCryptoLibUInt32Array);
var
  LX0, LX1, LX2, LX3, LX4, LX5, LX6, LX7: UInt32;
  LU0, LU1, LU2, LU3, LU4, LU5, LU6, LU7: UInt32;
  LY0, LY1, LY2, LY3, LY4, LY5, LY6, LY7: UInt32;
  LV0, LV1, LV2, LV3, LV4, LV5, LV6, LV7: UInt32;
  LS0, LS1, LS2, LS3, LS4, LS5, LS6, LS7: UInt32;
  LT0, LT1, LT2, LT3, LT4, LT5, LT6, LT7: UInt32;
  LZ0, LZ1, LZ2, LZ3, LZ4, LZ5, LZ6, LZ7: UInt32;
  LZ8, LZ9, LZ10, LZ11, LZ12, LZ13, LZ14, LZ15: UInt32;
  LC, LD: UInt64;
  LF0, LF1, LF2, LF3, LF4, LF5, LF6, LF7: UInt64;
  LF8, LF9, LF10, LF11, LF12, LF13, LF14: UInt64;
  LG0, LG1, LG2, LG3, LG4, LG5, LG6, LG7: UInt64;
  LG8, LG9, LG10, LG11, LG12, LG13, LG14: UInt64;
  LH0, LH1, LH2, LH3, LH4, LH5, LH6, LH7: UInt64;
  LH8, LH9, LH10, LH11, LH12, LH13, LH14: UInt64;
begin
  LX0 := AX[0]; LX1 := AX[1]; LX2 := AX[2]; LX3 := AX[3];
  LX4 := AX[4]; LX5 := AX[5]; LX6 := AX[6]; LX7 := AX[7];
  LU0 := AX[8]; LU1 := AX[9]; LU2 := AX[10]; LU3 := AX[11];
  LU4 := AX[12]; LU5 := AX[13]; LU6 := AX[14]; LU7 := AX[15];

  LY0 := AY[0]; LY1 := AY[1]; LY2 := AY[2]; LY3 := AY[3];
  LY4 := AY[4]; LY5 := AY[5]; LY6 := AY[6]; LY7 := AY[7];
  LV0 := AY[8]; LV1 := AY[9]; LV2 := AY[10]; LV3 := AY[11];
  LV4 := AY[12]; LV5 := AY[13]; LV6 := AY[14]; LV7 := AY[15];

  LS0 := LX0 + LU0; LS1 := LX1 + LU1; LS2 := LX2 + LU2; LS3 := LX3 + LU3;
  LS4 := LX4 + LU4; LS5 := LX5 + LU5; LS6 := LX6 + LU6; LS7 := LX7 + LU7;

  LT0 := LY0 + LV0; LT1 := LY1 + LV1; LT2 := LY2 + LV2; LT3 := LY3 + LV3;
  LT4 := LY4 + LV4; LT5 := LY5 + LV5; LT6 := LY6 + LV6; LT7 := LY7 + LV7;

  LF0  := UInt64(LX0) * LY0;
  LF8  := UInt64(LX7) * LY1 + UInt64(LX6) * LY2 + UInt64(LX5) * LY3
         + UInt64(LX4) * LY4 + UInt64(LX3) * LY5 + UInt64(LX2) * LY6
         + UInt64(LX1) * LY7;
  LG0  := UInt64(LU0) * LV0;
  LG8  := UInt64(LU7) * LV1 + UInt64(LU6) * LV2 + UInt64(LU5) * LV3
         + UInt64(LU4) * LV4 + UInt64(LU3) * LV5 + UInt64(LU2) * LV6
         + UInt64(LU1) * LV7;
  LH0  := UInt64(LS0) * LT0;
  LH8  := UInt64(LS7) * LT1 + UInt64(LS6) * LT2 + UInt64(LS5) * LT3
         + UInt64(LS4) * LT4 + UInt64(LS3) * LT5 + UInt64(LS2) * LT6
         + UInt64(LS1) * LT7;

  LC   := LF0 + LG0 + LH8 - LF8;
  LZ0  := UInt32(LC) and M28; LC := LC shr 28;
  LD   := LG8 + LH0 - LF0 + LH8;
  LZ8  := UInt32(LD) and M28; LD := LD shr 28;

  LF1  := UInt64(LX1) * LY0 + UInt64(LX0) * LY1;
  LF9  := UInt64(LX7) * LY2 + UInt64(LX6) * LY3 + UInt64(LX5) * LY4
         + UInt64(LX4) * LY5 + UInt64(LX3) * LY6 + UInt64(LX2) * LY7;
  LG1  := UInt64(LU1) * LV0 + UInt64(LU0) * LV1;
  LG9  := UInt64(LU7) * LV2 + UInt64(LU6) * LV3 + UInt64(LU5) * LV4
         + UInt64(LU4) * LV5 + UInt64(LU3) * LV6 + UInt64(LU2) * LV7;
  LH1  := UInt64(LS1) * LT0 + UInt64(LS0) * LT1;
  LH9  := UInt64(LS7) * LT2 + UInt64(LS6) * LT3 + UInt64(LS5) * LT4
         + UInt64(LS4) * LT5 + UInt64(LS3) * LT6 + UInt64(LS2) * LT7;

  LC   := LC + LF1 + LG1 + LH9 - LF9;
  LZ1  := UInt32(LC) and M28; LC := LC shr 28;
  LD   := LD + LG9 + LH1 - LF1 + LH9;
  LZ9  := UInt32(LD) and M28; LD := LD shr 28;

  LF2  := UInt64(LX2) * LY0 + UInt64(LX1) * LY1 + UInt64(LX0) * LY2;
  LF10 := UInt64(LX7) * LY3 + UInt64(LX6) * LY4 + UInt64(LX5) * LY5
         + UInt64(LX4) * LY6 + UInt64(LX3) * LY7;
  LG2  := UInt64(LU2) * LV0 + UInt64(LU1) * LV1 + UInt64(LU0) * LV2;
  LG10 := UInt64(LU7) * LV3 + UInt64(LU6) * LV4 + UInt64(LU5) * LV5
         + UInt64(LU4) * LV6 + UInt64(LU3) * LV7;
  LH2  := UInt64(LS2) * LT0 + UInt64(LS1) * LT1 + UInt64(LS0) * LT2;
  LH10 := UInt64(LS7) * LT3 + UInt64(LS6) * LT4 + UInt64(LS5) * LT5
         + UInt64(LS4) * LT6 + UInt64(LS3) * LT7;

  LC   := LC + LF2 + LG2 + LH10 - LF10;
  LZ2  := UInt32(LC) and M28; LC := LC shr 28;
  LD   := LD + LG10 + LH2 - LF2 + LH10;
  LZ10 := UInt32(LD) and M28; LD := LD shr 28;

  LF3  := UInt64(LX3) * LY0 + UInt64(LX2) * LY1 + UInt64(LX1) * LY2
         + UInt64(LX0) * LY3;
  LF11 := UInt64(LX7) * LY4 + UInt64(LX6) * LY5 + UInt64(LX5) * LY6
         + UInt64(LX4) * LY7;
  LG3  := UInt64(LU3) * LV0 + UInt64(LU2) * LV1 + UInt64(LU1) * LV2
         + UInt64(LU0) * LV3;
  LG11 := UInt64(LU7) * LV4 + UInt64(LU6) * LV5 + UInt64(LU5) * LV6
         + UInt64(LU4) * LV7;
  LH3  := UInt64(LS3) * LT0 + UInt64(LS2) * LT1 + UInt64(LS1) * LT2
         + UInt64(LS0) * LT3;
  LH11 := UInt64(LS7) * LT4 + UInt64(LS6) * LT5 + UInt64(LS5) * LT6
         + UInt64(LS4) * LT7;

  LC   := LC + LF3 + LG3 + LH11 - LF11;
  LZ3  := UInt32(LC) and M28; LC := LC shr 28;
  LD   := LD + LG11 + LH3 - LF3 + LH11;
  LZ11 := UInt32(LD) and M28; LD := LD shr 28;

  LF4  := UInt64(LX4) * LY0 + UInt64(LX3) * LY1 + UInt64(LX2) * LY2
         + UInt64(LX1) * LY3 + UInt64(LX0) * LY4;
  LF12 := UInt64(LX7) * LY5 + UInt64(LX6) * LY6 + UInt64(LX5) * LY7;
  LG4  := UInt64(LU4) * LV0 + UInt64(LU3) * LV1 + UInt64(LU2) * LV2
         + UInt64(LU1) * LV3 + UInt64(LU0) * LV4;
  LG12 := UInt64(LU7) * LV5 + UInt64(LU6) * LV6 + UInt64(LU5) * LV7;
  LH4  := UInt64(LS4) * LT0 + UInt64(LS3) * LT1 + UInt64(LS2) * LT2
         + UInt64(LS1) * LT3 + UInt64(LS0) * LT4;
  LH12 := UInt64(LS7) * LT5 + UInt64(LS6) * LT6 + UInt64(LS5) * LT7;

  LC   := LC + LF4 + LG4 + LH12 - LF12;
  LZ4  := UInt32(LC) and M28; LC := LC shr 28;
  LD   := LD + LG12 + LH4 - LF4 + LH12;
  LZ12 := UInt32(LD) and M28; LD := LD shr 28;

  LF5  := UInt64(LX5) * LY0 + UInt64(LX4) * LY1 + UInt64(LX3) * LY2
         + UInt64(LX2) * LY3 + UInt64(LX1) * LY4 + UInt64(LX0) * LY5;
  LF13 := UInt64(LX7) * LY6 + UInt64(LX6) * LY7;
  LG5  := UInt64(LU5) * LV0 + UInt64(LU4) * LV1 + UInt64(LU3) * LV2
         + UInt64(LU2) * LV3 + UInt64(LU1) * LV4 + UInt64(LU0) * LV5;
  LG13 := UInt64(LU7) * LV6 + UInt64(LU6) * LV7;
  LH5  := UInt64(LS5) * LT0 + UInt64(LS4) * LT1 + UInt64(LS3) * LT2
         + UInt64(LS2) * LT3 + UInt64(LS1) * LT4 + UInt64(LS0) * LT5;
  LH13 := UInt64(LS7) * LT6 + UInt64(LS6) * LT7;

  LC   := LC + LF5 + LG5 + LH13 - LF13;
  LZ5  := UInt32(LC) and M28; LC := LC shr 28;
  LD   := LD + LG13 + LH5 - LF5 + LH13;
  LZ13 := UInt32(LD) and M28; LD := LD shr 28;

  LF6  := UInt64(LX6) * LY0 + UInt64(LX5) * LY1 + UInt64(LX4) * LY2
         + UInt64(LX3) * LY3 + UInt64(LX2) * LY4 + UInt64(LX1) * LY5
         + UInt64(LX0) * LY6;
  LF14 := UInt64(LX7) * LY7;
  LG6  := UInt64(LU6) * LV0 + UInt64(LU5) * LV1 + UInt64(LU4) * LV2
         + UInt64(LU3) * LV3 + UInt64(LU2) * LV4 + UInt64(LU1) * LV5
         + UInt64(LU0) * LV6;
  LG14 := UInt64(LU7) * LV7;
  LH6  := UInt64(LS6) * LT0 + UInt64(LS5) * LT1 + UInt64(LS4) * LT2
         + UInt64(LS3) * LT3 + UInt64(LS2) * LT4 + UInt64(LS1) * LT5
         + UInt64(LS0) * LT6;
  LH14 := UInt64(LS7) * LT7;

  LC   := LC + LF6 + LG6 + LH14 - LF14;
  LZ6  := UInt32(LC) and M28; LC := LC shr 28;
  LD   := LD + LG14 + LH6 - LF6 + LH14;
  LZ14 := UInt32(LD) and M28; LD := LD shr 28;

  LF7  := UInt64(LX7) * LY0 + UInt64(LX6) * LY1 + UInt64(LX5) * LY2
         + UInt64(LX4) * LY3 + UInt64(LX3) * LY4 + UInt64(LX2) * LY5
         + UInt64(LX1) * LY6 + UInt64(LX0) * LY7;
  LG7  := UInt64(LU7) * LV0 + UInt64(LU6) * LV1 + UInt64(LU5) * LV2
         + UInt64(LU4) * LV3 + UInt64(LU3) * LV4 + UInt64(LU2) * LV5
         + UInt64(LU1) * LV6 + UInt64(LU0) * LV7;
  LH7  := UInt64(LS7) * LT0 + UInt64(LS6) * LT1 + UInt64(LS5) * LT2
         + UInt64(LS4) * LT3 + UInt64(LS3) * LT4 + UInt64(LS2) * LT5
         + UInt64(LS1) * LT6 + UInt64(LS0) * LT7;

  LC   := LC + LF7 + LG7;
  LZ7  := UInt32(LC) and M28; LC := LC shr 28;
  LD   := LD + LH7 - LF7;
  LZ15 := UInt32(LD) and M28; LD := LD shr 28;

  LC   := LC + LD;

  LC   := LC + LZ8;
  LZ8  := UInt32(LC) and M28; LC := LC shr 28;
  LD   := LD + LZ0;
  LZ0  := UInt32(LD) and M28; LD := LD shr 28;
  LZ9  := LZ9 + UInt32(LC);
  LZ1  := LZ1 + UInt32(LD);

  AZ[0] := LZ0; AZ[1] := LZ1; AZ[2] := LZ2; AZ[3] := LZ3;
  AZ[4] := LZ4; AZ[5] := LZ5; AZ[6] := LZ6; AZ[7] := LZ7;
  AZ[8] := LZ8; AZ[9] := LZ9; AZ[10] := LZ10; AZ[11] := LZ11;
  AZ[12] := LZ12; AZ[13] := LZ13; AZ[14] := LZ14; AZ[15] := LZ15;
end;

class procedure TX448Field.Negate(const AX, AZ: TCryptoLibUInt32Array);
var
  LZero: TCryptoLibUInt32Array;
begin
  LZero := TX448Field.Create;
  Sub(LZero, AX, AZ);
end;

class procedure TX448Field.Normalize(AZ: TCryptoLibUInt32Array);
begin
  Reduce(AZ, 1);
  Reduce(AZ, -1);
end;

class procedure TX448Field.One(AZ: TCryptoLibUInt32Array);
var
  LI: Int32;
begin
  AZ[0] := 1;
  for LI := 1 to Size - 1 do
  begin
    AZ[LI] := 0;
  end;
end;

class procedure TX448Field.PowPm3d4(const AX, AZ: TCryptoLibUInt32Array);
var
  LX2, LX3, LX6, LX9, LX18, LX19, LX37, LX74, LX111, LX222, LX223, LT: TCryptoLibUInt32Array;
begin
  LX2 := TX448Field.Create;   Sqr(AX, LX2);           Mul(AX, LX2, LX2);
  LX3 := TX448Field.Create;   Sqr(LX2, LX3);          Mul(AX, LX3, LX3);
  LX6 := TX448Field.Create;   Sqr(LX3, 3, LX6);       Mul(LX3, LX6, LX6);
  LX9 := TX448Field.Create;   Sqr(LX6, 3, LX9);       Mul(LX3, LX9, LX9);
  LX18 := TX448Field.Create;  Sqr(LX9, 9, LX18);      Mul(LX9, LX18, LX18);
  LX19 := TX448Field.Create;  Sqr(LX18, LX19);        Mul(AX, LX19, LX19);
  LX37 := TX448Field.Create;  Sqr(LX19, 18, LX37);    Mul(LX18, LX37, LX37);
  LX74 := TX448Field.Create;  Sqr(LX37, 37, LX74);    Mul(LX37, LX74, LX74);
  LX111 := TX448Field.Create; Sqr(LX74, 37, LX111);   Mul(LX37, LX111, LX111);
  LX222 := TX448Field.Create; Sqr(LX111, 111, LX222); Mul(LX111, LX222, LX222);
  LX223 := TX448Field.Create; Sqr(LX222, LX223);      Mul(AX, LX223, LX223);

  LT := TX448Field.Create;
  Sqr(LX223, 223, LT);
  Mul(LT, LX222, AZ);
end;

class procedure TX448Field.Reduce(AZ: TCryptoLibUInt32Array; AX: Int32);
var
  LU, LZ15: UInt32;
  LT: Int32;
  LCC: Int64;
  LI: Int32;
begin
  LU := AZ[15];
  LZ15 := LU and M28;
  LT := Int32(LU shr 28) + AX;

  LCC := LT;
  for LI := 0 to 7 do
  begin
    LCC := LCC + AZ[LI];
    AZ[LI] := UInt32(LCC) and M28;
    LCC := TBitOperations.Asr64(LCC, 28);
  end;
  LCC := LCC + LT;
  for LI := 8 to 14 do
  begin
    LCC := LCC + AZ[LI];
    AZ[LI] := UInt32(LCC) and M28;
    LCC := TBitOperations.Asr64(LCC, 28);
  end;
  AZ[15] := LZ15 + UInt32(LCC);
end;

class procedure TX448Field.Sqr(const AX, AZ: TCryptoLibUInt32Array);
var
  LX0, LX1, LX2, LX3, LX4, LX5, LX6, LX7: UInt32;
  LU0, LU1, LU2, LU3, LU4, LU5, LU6, LU7: UInt32;
  LX0_2, LX1_2, LX2_2, LX3_2, LX4_2, LX5_2, LX6_2: UInt32;
  LU0_2, LU1_2, LU2_2, LU3_2, LU4_2, LU5_2, LU6_2: UInt32;
  LS0, LS1, LS2, LS3, LS4, LS5, LS6, LS7: UInt32;
  LS0_2, LS1_2, LS2_2, LS3_2, LS4_2, LS5_2, LS6_2: UInt32;
  LZ0, LZ1, LZ2, LZ3, LZ4, LZ5, LZ6, LZ7: UInt32;
  LZ8, LZ9, LZ10, LZ11, LZ12, LZ13, LZ14, LZ15: UInt32;
  LC, LD: UInt64;
  LF0, LF1, LF2, LF3, LF4, LF5, LF6, LF7: UInt64;
  LF8, LF9, LF10, LF11, LF12, LF13, LF14: UInt64;
  LG0, LG1, LG2, LG3, LG4, LG5, LG6, LG7: UInt64;
  LG8, LG9, LG10, LG11, LG12, LG13, LG14: UInt64;
  LH0, LH1, LH2, LH3, LH4, LH5, LH6, LH7: UInt64;
  LH8, LH9, LH10, LH11, LH12, LH13, LH14: UInt64;
begin
  LX0 := AX[0]; LX1 := AX[1]; LX2 := AX[2]; LX3 := AX[3];
  LX4 := AX[4]; LX5 := AX[5]; LX6 := AX[6]; LX7 := AX[7];
  LU0 := AX[8]; LU1 := AX[9]; LU2 := AX[10]; LU3 := AX[11];
  LU4 := AX[12]; LU5 := AX[13]; LU6 := AX[14]; LU7 := AX[15];

  LX0_2 := LX0 * 2; LX1_2 := LX1 * 2; LX2_2 := LX2 * 2; LX3_2 := LX3 * 2;
  LX4_2 := LX4 * 2; LX5_2 := LX5 * 2; LX6_2 := LX6 * 2;

  LU0_2 := LU0 * 2; LU1_2 := LU1 * 2; LU2_2 := LU2 * 2; LU3_2 := LU3 * 2;
  LU4_2 := LU4 * 2; LU5_2 := LU5 * 2; LU6_2 := LU6 * 2;

  LS0 := LX0 + LU0; LS1 := LX1 + LU1; LS2 := LX2 + LU2; LS3 := LX3 + LU3;
  LS4 := LX4 + LU4; LS5 := LX5 + LU5; LS6 := LX6 + LU6; LS7 := LX7 + LU7;

  LS0_2 := LS0 * 2; LS1_2 := LS1 * 2; LS2_2 := LS2 * 2; LS3_2 := LS3 * 2;
  LS4_2 := LS4 * 2; LS5_2 := LS5 * 2; LS6_2 := LS6 * 2;

  LF0  := UInt64(LX0) * LX0;
  LF8  := UInt64(LX7) * LX1_2 + UInt64(LX6) * LX2_2 + UInt64(LX5) * LX3_2
         + UInt64(LX4) * LX4;
  LG0  := UInt64(LU0) * LU0;
  LG8  := UInt64(LU7) * LU1_2 + UInt64(LU6) * LU2_2 + UInt64(LU5) * LU3_2
         + UInt64(LU4) * LU4;
  LH0  := UInt64(LS0) * LS0;
  LH8  := UInt64(LS7) * LS1_2 + UInt64(LS6) * LS2_2 + UInt64(LS5) * LS3_2
         + UInt64(LS4) * LS4;

  LC   := LF0 + LG0 + LH8 - LF8;
  LZ0  := UInt32(LC) and M28; LC := LC shr 28;
  LD   := LG8 + LH0 - LF0 + LH8;
  LZ8  := UInt32(LD) and M28; LD := LD shr 28;

  LF1  := UInt64(LX1) * LX0_2;
  LF9  := UInt64(LX7) * LX2_2 + UInt64(LX6) * LX3_2 + UInt64(LX5) * LX4_2;
  LG1  := UInt64(LU1) * LU0_2;
  LG9  := UInt64(LU7) * LU2_2 + UInt64(LU6) * LU3_2 + UInt64(LU5) * LU4_2;
  LH1  := UInt64(LS1) * LS0_2;
  LH9  := UInt64(LS7) * LS2_2 + UInt64(LS6) * LS3_2 + UInt64(LS5) * LS4_2;

  LC   := LC + LF1 + LG1 + LH9 - LF9;
  LZ1  := UInt32(LC) and M28; LC := LC shr 28;
  LD   := LD + LG9 + LH1 - LF1 + LH9;
  LZ9  := UInt32(LD) and M28; LD := LD shr 28;

  LF2  := UInt64(LX2) * LX0_2 + UInt64(LX1) * LX1;
  LF10 := UInt64(LX7) * LX3_2 + UInt64(LX6) * LX4_2 + UInt64(LX5) * LX5;
  LG2  := UInt64(LU2) * LU0_2 + UInt64(LU1) * LU1;
  LG10 := UInt64(LU7) * LU3_2 + UInt64(LU6) * LU4_2 + UInt64(LU5) * LU5;
  LH2  := UInt64(LS2) * LS0_2 + UInt64(LS1) * LS1;
  LH10 := UInt64(LS7) * LS3_2 + UInt64(LS6) * LS4_2 + UInt64(LS5) * LS5;

  LC   := LC + LF2 + LG2 + LH10 - LF10;
  LZ2  := UInt32(LC) and M28; LC := LC shr 28;
  LD   := LD + LG10 + LH2 - LF2 + LH10;
  LZ10 := UInt32(LD) and M28; LD := LD shr 28;

  LF3  := UInt64(LX3) * LX0_2 + UInt64(LX2) * LX1_2;
  LF11 := UInt64(LX7) * LX4_2 + UInt64(LX6) * LX5_2;
  LG3  := UInt64(LU3) * LU0_2 + UInt64(LU2) * LU1_2;
  LG11 := UInt64(LU7) * LU4_2 + UInt64(LU6) * LU5_2;
  LH3  := UInt64(LS3) * LS0_2 + UInt64(LS2) * LS1_2;
  LH11 := UInt64(LS7) * LS4_2 + UInt64(LS6) * LS5_2;

  LC   := LC + LF3 + LG3 + LH11 - LF11;
  LZ3  := UInt32(LC) and M28; LC := LC shr 28;
  LD   := LD + LG11 + LH3 - LF3 + LH11;
  LZ11 := UInt32(LD) and M28; LD := LD shr 28;

  LF4  := UInt64(LX4) * LX0_2 + UInt64(LX3) * LX1_2 + UInt64(LX2) * LX2;
  LF12 := UInt64(LX7) * LX5_2 + UInt64(LX6) * LX6;
  LG4  := UInt64(LU4) * LU0_2 + UInt64(LU3) * LU1_2 + UInt64(LU2) * LU2;
  LG12 := UInt64(LU7) * LU5_2 + UInt64(LU6) * LU6;
  LH4  := UInt64(LS4) * LS0_2 + UInt64(LS3) * LS1_2 + UInt64(LS2) * LS2;
  LH12 := UInt64(LS7) * LS5_2 + UInt64(LS6) * LS6;

  LC   := LC + LF4 + LG4 + LH12 - LF12;
  LZ4  := UInt32(LC) and M28; LC := LC shr 28;
  LD   := LD + LG12 + LH4 - LF4 + LH12;
  LZ12 := UInt32(LD) and M28; LD := LD shr 28;

  LF5  := UInt64(LX5) * LX0_2 + UInt64(LX4) * LX1_2 + UInt64(LX3) * LX2_2;
  LF13 := UInt64(LX7) * LX6_2;
  LG5  := UInt64(LU5) * LU0_2 + UInt64(LU4) * LU1_2 + UInt64(LU3) * LU2_2;
  LG13 := UInt64(LU7) * LU6_2;
  LH5  := UInt64(LS5) * LS0_2 + UInt64(LS4) * LS1_2 + UInt64(LS3) * LS2_2;
  LH13 := UInt64(LS7) * LS6_2;

  LC   := LC + LF5 + LG5 + LH13 - LF13;
  LZ5  := UInt32(LC) and M28; LC := LC shr 28;
  LD   := LD + LG13 + LH5 - LF5 + LH13;
  LZ13 := UInt32(LD) and M28; LD := LD shr 28;

  LF6  := UInt64(LX6) * LX0_2 + UInt64(LX5) * LX1_2 + UInt64(LX4) * LX2_2
         + UInt64(LX3) * LX3;
  LF14 := UInt64(LX7) * LX7;
  LG6  := UInt64(LU6) * LU0_2 + UInt64(LU5) * LU1_2 + UInt64(LU4) * LU2_2
         + UInt64(LU3) * LU3;
  LG14 := UInt64(LU7) * LU7;
  LH6  := UInt64(LS6) * LS0_2 + UInt64(LS5) * LS1_2 + UInt64(LS4) * LS2_2
         + UInt64(LS3) * LS3;
  LH14 := UInt64(LS7) * LS7;

  LC   := LC + LF6 + LG6 + LH14 - LF14;
  LZ6  := UInt32(LC) and M28; LC := LC shr 28;
  LD   := LD + LG14 + LH6 - LF6 + LH14;
  LZ14 := UInt32(LD) and M28; LD := LD shr 28;

  LF7  := UInt64(LX7) * LX0_2 + UInt64(LX6) * LX1_2 + UInt64(LX5) * LX2_2
         + UInt64(LX4) * LX3_2;
  LG7  := UInt64(LU7) * LU0_2 + UInt64(LU6) * LU1_2 + UInt64(LU5) * LU2_2
         + UInt64(LU4) * LU3_2;
  LH7  := UInt64(LS7) * LS0_2 + UInt64(LS6) * LS1_2 + UInt64(LS5) * LS2_2
         + UInt64(LS4) * LS3_2;

  LC   := LC + LF7 + LG7;
  LZ7  := UInt32(LC) and M28; LC := LC shr 28;
  LD   := LD + LH7 - LF7;
  LZ15 := UInt32(LD) and M28; LD := LD shr 28;

  LC   := LC + LD;

  LC   := LC + LZ8;
  LZ8  := UInt32(LC) and M28; LC := LC shr 28;
  LD   := LD + LZ0;
  LZ0  := UInt32(LD) and M28; LD := LD shr 28;
  LZ9  := LZ9 + UInt32(LC);
  LZ1  := LZ1 + UInt32(LD);

  AZ[0] := LZ0; AZ[1] := LZ1; AZ[2] := LZ2; AZ[3] := LZ3;
  AZ[4] := LZ4; AZ[5] := LZ5; AZ[6] := LZ6; AZ[7] := LZ7;
  AZ[8] := LZ8; AZ[9] := LZ9; AZ[10] := LZ10; AZ[11] := LZ11;
  AZ[12] := LZ12; AZ[13] := LZ13; AZ[14] := LZ14; AZ[15] := LZ15;
end;

class procedure TX448Field.Sqr(const AX: TCryptoLibUInt32Array; AN: Int32;
  const AZ: TCryptoLibUInt32Array);
begin
  Sqr(AX, AZ);
  while AN > 1 do
  begin
    Dec(AN);
    Sqr(AZ, AZ);
  end;
end;

class function TX448Field.SqrtRatioVar(const AU, AV, AZ: TCryptoLibUInt32Array): Boolean;
var
  LU3V, LU5V3, LX, LT: TCryptoLibUInt32Array;
begin
  LU3V := TX448Field.Create;
  LU5V3 := TX448Field.Create;

  Sqr(AU, LU3V);
  Mul(LU3V, AV, LU3V);
  Sqr(LU3V, LU5V3);
  Mul(LU3V, AU, LU3V);
  Mul(LU5V3, AU, LU5V3);
  Mul(LU5V3, AV, LU5V3);

  LX := TX448Field.Create;
  PowPm3d4(LU5V3, LX);
  Mul(LX, LU3V, LX);

  LT := TX448Field.Create;
  Sqr(LX, LT);
  Mul(LT, AV, LT);

  Sub(AU, LT, LT);
  Normalize(LT);

  if IsZeroVar(LT) then
  begin
    Copy(LX, 0, AZ, 0);
    Result := True;
    Exit;
  end;

  Result := False;
end;

class procedure TX448Field.Sub(const AX, AY, AZ: TCryptoLibUInt32Array);
var
  LX0, LX1, LX2, LX3, LX4, LX5, LX6, LX7: UInt32;
  LX8, LX9, LX10, LX11, LX12, LX13, LX14, LX15: UInt32;
  LY0, LY1, LY2, LY3, LY4, LY5, LY6, LY7: UInt32;
  LY8, LY9, LY10, LY11, LY12, LY13, LY14, LY15: UInt32;
  LZ0, LZ1, LZ2, LZ3, LZ4, LZ5, LZ6, LZ7: UInt32;
  LZ8, LZ9, LZ10, LZ11, LZ12, LZ13, LZ14, LZ15: UInt32;
  LT: UInt32;
begin
  LX0 := AX[0]; LX1 := AX[1]; LX2 := AX[2]; LX3 := AX[3];
  LX4 := AX[4]; LX5 := AX[5]; LX6 := AX[6]; LX7 := AX[7];
  LX8 := AX[8]; LX9 := AX[9]; LX10 := AX[10]; LX11 := AX[11];
  LX12 := AX[12]; LX13 := AX[13]; LX14 := AX[14]; LX15 := AX[15];
  LY0 := AY[0]; LY1 := AY[1]; LY2 := AY[2]; LY3 := AY[3];
  LY4 := AY[4]; LY5 := AY[5]; LY6 := AY[6]; LY7 := AY[7];
  LY8 := AY[8]; LY9 := AY[9]; LY10 := AY[10]; LY11 := AY[11];
  LY12 := AY[12]; LY13 := AY[13]; LY14 := AY[14]; LY15 := AY[15];

  LZ0  := LX0  + $1FFFFFFE - LY0;
  LZ1  := LX1  + $1FFFFFFE - LY1;
  LZ2  := LX2  + $1FFFFFFE - LY2;
  LZ3  := LX3  + $1FFFFFFE - LY3;
  LZ4  := LX4  + $1FFFFFFE - LY4;
  LZ5  := LX5  + $1FFFFFFE - LY5;
  LZ6  := LX6  + $1FFFFFFE - LY6;
  LZ7  := LX7  + $1FFFFFFE - LY7;
  LZ8  := LX8  + $1FFFFFFC - LY8;
  LZ9  := LX9  + $1FFFFFFE - LY9;
  LZ10 := LX10 + $1FFFFFFE - LY10;
  LZ11 := LX11 + $1FFFFFFE - LY11;
  LZ12 := LX12 + $1FFFFFFE - LY12;
  LZ13 := LX13 + $1FFFFFFE - LY13;
  LZ14 := LX14 + $1FFFFFFE - LY14;
  LZ15 := LX15 + $1FFFFFFE - LY15;

  LZ2  := LZ2  + (LZ1 shr 28);  LZ1  := LZ1 and M28;
  LZ6  := LZ6  + (LZ5 shr 28);  LZ5  := LZ5 and M28;
  LZ10 := LZ10 + (LZ9 shr 28);  LZ9  := LZ9 and M28;
  LZ14 := LZ14 + (LZ13 shr 28); LZ13 := LZ13 and M28;

  LZ3  := LZ3  + (LZ2 shr 28);  LZ2  := LZ2 and M28;
  LZ7  := LZ7  + (LZ6 shr 28);  LZ6  := LZ6 and M28;
  LZ11 := LZ11 + (LZ10 shr 28); LZ10 := LZ10 and M28;
  LZ15 := LZ15 + (LZ14 shr 28); LZ14 := LZ14 and M28;

  LT := LZ15 shr 28; LZ15 := LZ15 and M28;
  LZ0 := LZ0 + LT;
  LZ8 := LZ8 + LT;

  LZ4  := LZ4  + (LZ3 shr 28);  LZ3  := LZ3 and M28;
  LZ8  := LZ8  + (LZ7 shr 28);  LZ7  := LZ7 and M28;
  LZ12 := LZ12 + (LZ11 shr 28); LZ11 := LZ11 and M28;

  LZ1  := LZ1  + (LZ0 shr 28);  LZ0  := LZ0 and M28;
  LZ5  := LZ5  + (LZ4 shr 28);  LZ4  := LZ4 and M28;
  LZ9  := LZ9  + (LZ8 shr 28);  LZ8  := LZ8 and M28;
  LZ13 := LZ13 + (LZ12 shr 28); LZ12 := LZ12 and M28;

  AZ[0] := LZ0; AZ[1] := LZ1; AZ[2] := LZ2; AZ[3] := LZ3;
  AZ[4] := LZ4; AZ[5] := LZ5; AZ[6] := LZ6; AZ[7] := LZ7;
  AZ[8] := LZ8; AZ[9] := LZ9; AZ[10] := LZ10; AZ[11] := LZ11;
  AZ[12] := LZ12; AZ[13] := LZ13; AZ[14] := LZ14; AZ[15] := LZ15;
end;

class procedure TX448Field.SubOne(AZ: TCryptoLibUInt32Array);
var
  LOne: TCryptoLibUInt32Array;
begin
  LOne := TX448Field.Create;
  LOne[0] := 1;
  Sub(AZ, LOne, AZ);
end;

class procedure TX448Field.Zero(AZ: TCryptoLibUInt32Array);
begin
  TArrayUtilities.Fill<UInt32>(AZ, 0, Size, 0);
end;

end.
