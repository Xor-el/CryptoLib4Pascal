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

unit ClpLongArray;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Math,
  ClpCryptoLibTypes,
  ClpBitOperations,
  ClpNat,
  ClpInterleave,
  ClpArrayUtilities,
  ClpBigInteger,
  ClpBigIntegerUtilities;

resourcestring
  SInvalidF2mFieldValue = 'invalid F2m field value';

type
  TLongArray = record
  private
    FData: TCryptoLibUInt64Array;

    class function BitLength(AW: UInt64): Int32; overload; static;
    class function ShiftUp(const AX: TCryptoLibUInt64Array; AXOff, ACount, AShift: Int32): UInt64; overload; static;
    class function ShiftUp(const AX: TCryptoLibUInt64Array; AXOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff, ACount, AShift: Int32): UInt64; overload; static;
    class function AddShiftedUp(const AX: TCryptoLibUInt64Array; AXOff: Int32; const AY: TCryptoLibUInt64Array; AYOff, ACount, AShift: Int32): UInt64; static;
    class function AddShiftedDown(const AX: TCryptoLibUInt64Array; AXOff: Int32; const AY: TCryptoLibUInt64Array; AYOff, ACount, AShift: Int32): UInt64; static;
    class procedure Add(const AX: TCryptoLibUInt64Array; AXOff: Int32; const AY: TCryptoLibUInt64Array; AYOff, ACount: Int32); overload; static;
    class procedure Add(const AX: TCryptoLibUInt64Array; AXOff: Int32; const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff, ACount: Int32); overload; static;
    class procedure AddBoth(const AX: TCryptoLibUInt64Array; AXOff: Int32; const AY1: TCryptoLibUInt64Array; AY1Off: Int32; const AY2: TCryptoLibUInt64Array; AY2Off, ACount: Int32); static;
    class procedure FlipWord(ABuf: TCryptoLibUInt64Array; AOff, ABit: Int32; AWord: UInt64); static;
    class function TestBit(const ABuf: TCryptoLibUInt64Array; AOff, AN: Int32): Boolean; static;
    class procedure FlipBit(ABuf: TCryptoLibUInt64Array; AOff, AN: Int32); static;
    class procedure MultiplyWord(AA: UInt64; const AB: TCryptoLibUInt64Array; ABLen: Int32; AC: TCryptoLibUInt64Array; ACOff: Int32); static;
    function DegreeFrom(ALimit: Int32): Int32;
    function ResizedData(ANewLen: Int32): TCryptoLibUInt64Array;
    procedure AddShiftedByBitsSafe(const AOther: TLongArray; AOtherDegree, ABits: Int32);
    class function ReduceResult(const ABuf: TCryptoLibUInt64Array; AOff, ALen, AM: Int32; const AKs: TCryptoLibInt32Array): TLongArray; static;
    class function ReduceInPlace(ABuf: TCryptoLibUInt64Array; AOff, ALen, AM: Int32; const AKs: TCryptoLibInt32Array): Int32; static;
    class procedure ReduceBitWise(ABuf: TCryptoLibUInt64Array; AOff, ABitLength, AM: Int32; const AKs: TCryptoLibInt32Array); static;
    class procedure ReduceBit(ABuf: TCryptoLibUInt64Array; AOff, ABit, AM: Int32; const AKs: TCryptoLibInt32Array); static;
    class procedure ReduceWordWise(ABuf: TCryptoLibUInt64Array; AOff, ALen, AToBit, AM: Int32; const AKs: TCryptoLibInt32Array); static;
    class procedure ReduceWord(ABuf: TCryptoLibUInt64Array; AOff, ABit: Int32; AWord: UInt64; AM: Int32; const AKs: TCryptoLibInt32Array); static;
    class procedure ReduceVectorWise(ABuf: TCryptoLibUInt64Array; AOff, ALen, AWords, AM: Int32; const AKs: TCryptoLibInt32Array); static;
    class procedure FlipVector(const AX: TCryptoLibUInt64Array; AXOff: Int32; const AY: TCryptoLibUInt64Array; AYOff, AYLen, ABits: Int32); static;
  public
    class function AreAliased(const A, B: TLongArray): Boolean; static;
    constructor Create(AIntLen: Int32); overload;
    constructor Create(const AData: TCryptoLibUInt64Array); overload;
    constructor Create(const AData: TCryptoLibUInt64Array; AOff, ALen: Int32); overload;
    constructor Create(const ABigInt: TBigInteger); overload;

    procedure CopyTo(const AZ: TCryptoLibUInt64Array; AZOff: Int32);
    function IsOne(): Boolean;
    function IsZero(): Boolean;
    function GetUsedLength(): Int32;
    function GetUsedLengthFrom(AFrom: Int32): Int32;
    function Degree(): Int32;
    function BitLength(): Int32; overload; inline;
    function ToBigInteger(): TBigInteger;
    function AddOne(): TLongArray;
    procedure AddShiftedByWords(const AOther: TLongArray; AWords: Int32);
    function TestBitZero(): Boolean;
    function ModMultiplyLD(const AOther: TLongArray; AM: Int32; const AKs: TCryptoLibInt32Array): TLongArray;
    function ModMultiply(const AOther: TLongArray; AM: Int32; const AKs: TCryptoLibInt32Array): TLongArray;
    function Multiply(const AOther: TLongArray): TLongArray; overload;
    function Multiply(const AOther: TLongArray; AM: Int32; const AKs: TCryptoLibInt32Array): TLongArray; overload;
    procedure Reduce(AM: Int32; const AKs: TCryptoLibInt32Array);
    function ModSquare(AM: Int32; const AKs: TCryptoLibInt32Array): TLongArray;
    function ModSquareN(AN, AM: Int32; const AKs: TCryptoLibInt32Array): TLongArray;
    function Square(AM: Int32; const AKs: TCryptoLibInt32Array): TLongArray;
    function ModInverse(AM: Int32; const AKs: TCryptoLibInt32Array): TLongArray;
    function Copy(): TLongArray;
    function Equals(const AOther: TLongArray): Boolean;
    function GetHashCode(): Int32;
    function ToString(): String;
  end;

implementation

{ TLongArray }

class function TLongArray.AreAliased(const A, B: TLongArray): Boolean;
begin
  Result := A.FData = B.FData;
end;

constructor TLongArray.Create(AIntLen: Int32);
begin
  System.SetLength(Self.FData, AIntLen);
end;

constructor TLongArray.Create(const AData: TCryptoLibUInt64Array);
begin
  Self.FData := AData;
end;

constructor TLongArray.Create(const AData: TCryptoLibUInt64Array; AOff, ALen: Int32);
var
  LData: TCryptoLibUInt64Array;
begin
  if (AOff = 0) and (ALen = System.Length(AData)) then
    Self.FData := AData
  else
  begin
    LData := System.Copy(AData, AOff, ALen);
    Self.FData := LData;
  end;
end;

constructor TLongArray.Create(const ABigInt: TBigInteger);
var
  LBarr: TCryptoLibByteArray;
  LBarrLen, LBarrStart, LIntLen, LIarrJ, LRem, LBarrI, I: Int32;
  LTemp: UInt64;
begin
  if (not ABigInt.IsInitialized) or (ABigInt.SignValue < 0) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidF2mFieldValue);

  if ABigInt.SignValue = 0 then
  begin
    System.SetLength(Self.FData, 1);
    Self.FData[0] := 0;
    Exit;
  end;

  LBarr := ABigInt.ToByteArray();
  LBarrLen := System.Length(LBarr);
  LBarrStart := 0;
  if LBarr[0] = 0 then
  begin
    System.Dec(LBarrLen);
    LBarrStart := 1;
  end;
  LIntLen := (LBarrLen + 7) div 8;
  System.SetLength(Self.FData, LIntLen);

  LIarrJ := LIntLen - 1;
  LRem := (LBarrLen mod 8) + LBarrStart;
  LTemp := 0;
  LBarrI := LBarrStart;
  if LBarrStart < LRem then
  begin
    while LBarrI < LRem do
    begin
      LTemp := (LTemp shl 8) or UInt64(LBarr[LBarrI]);
      System.Inc(LBarrI);
    end;
    Self.FData[LIarrJ] := LTemp;
    System.Dec(LIarrJ);
  end;

  while LIarrJ >= 0 do
  begin
    LTemp := 0;
    for I := 0 to 7 do
    begin
      LTemp := (LTemp shl 8) or UInt64(LBarr[LBarrI]);
      System.Inc(LBarrI);
    end;
    Self.FData[LIarrJ] := LTemp;
    System.Dec(LIarrJ);
  end;
end;

procedure TLongArray.CopyTo(const AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  LLen: Int32;
begin
  LLen := System.Length(FData);
  if LLen > 0 then
    System.Move(FData[0], AZ[AZOff], LLen * SizeOf(UInt64));
end;

function TLongArray.IsOne(): Boolean;
var
  LA: TCryptoLibUInt64Array;
  LALen, I: Int32;
begin
  LA := FData;
  LALen := System.Length(LA);
  if (LALen < 1) or (LA[0] <> 1) then
    Exit(False);
  for I := 1 to LALen - 1 do
    if LA[I] <> 0 then
      Exit(False);
  Result := True;
end;

function TLongArray.IsZero(): Boolean;
var
  LA: TCryptoLibUInt64Array;
  I: Int32;
begin
  LA := FData;
  for I := 0 to System.Length(LA) - 1 do
    if LA[I] <> 0 then
      Exit(False);
  Result := True;
end;

function TLongArray.GetUsedLength(): Int32;
begin
  Result := GetUsedLengthFrom(System.Length(FData));
end;

function TLongArray.GetUsedLengthFrom(AFrom: Int32): Int32;
var
  LA: TCryptoLibUInt64Array;
begin
  LA := FData;
  AFrom := Min(AFrom, System.Length(LA));
  if AFrom < 1 then
    Exit(0);

  if LA[0] <> 0 then
  begin
    repeat
      System.Dec(AFrom);
      if LA[AFrom] <> 0 then
        Break;
    until False;
    Exit(AFrom + 1);
  end;

  repeat
    System.Dec(AFrom);
    if LA[AFrom] <> 0 then
      Exit(AFrom + 1);
  until AFrom <= 0;
  Result := 0;
end;

class function TLongArray.BitLength(AW: UInt64): Int32;
begin
  Result := 64 - TBitOperations.NumberOfLeadingZeros64(AW);
end;

function TLongArray.Degree(): Int32;
var
  I: Int32;
  LW: UInt64;
begin
  I := System.Length(FData);
  repeat
    if I = 0 then
      Exit(0);
    System.Dec(I);
    LW := FData[I];
  until LW <> 0;
  Result := (I shl 6) + BitLength(LW);
end;

function TLongArray.DegreeFrom(ALimit: Int32): Int32;
var
  I: Int32;
  LW: UInt64;
begin
  I := Int32((UInt32(ALimit) + 62) shr 6);
  repeat
    if I = 0 then
      Exit(0);
    System.Dec(I);
    LW := FData[I];
  until LW <> 0;
  Result := (I shl 6) + BitLength(LW);
end;

function TLongArray.ResizedData(ANewLen: Int32): TCryptoLibUInt64Array;
var
  LCount: Int32;
begin
  System.SetLength(Result, ANewLen);
  LCount := Min(System.Length(FData), ANewLen);
  if LCount > 0 then
    System.Move(FData[0], Result[0], LCount * SizeOf(UInt64));
end;

function TLongArray.ToBigInteger(): TBigInteger;
var
  LUsedLen, LBarrI, LBarrLen, LJ, LIarrJ: Int32;
  LHighestInt: UInt64;
  LTemp: TCryptoLibByteArray;
  LTrailingZeroBytesDone: Boolean;
  LThisByte: Byte;
  LBarr: TCryptoLibByteArray;
  LMI: UInt64;
begin
  LUsedLen := GetUsedLength();
  if LUsedLen = 0 then
    Exit(TBigIntegerUtilities.Zero);

  LHighestInt := FData[LUsedLen - 1];
  System.SetLength(LTemp, 8);
  LBarrI := 0;
  LTrailingZeroBytesDone := False;
  for LJ := 7 downto 0 do
  begin
    LThisByte := Byte(LHighestInt shr (8 * LJ));
    if LTrailingZeroBytesDone or (LThisByte <> 0) then
    begin
      LTrailingZeroBytesDone := True;
      LTemp[LBarrI] := LThisByte;
      System.Inc(LBarrI);
    end;
  end;

  LBarrLen := 8 * (LUsedLen - 1) + LBarrI;
  System.SetLength(LBarr, LBarrLen);
  for LJ := 0 to LBarrI - 1 do
    LBarr[LJ] := LTemp[LJ];

  for LIarrJ := LUsedLen - 2 downto 0 do
  begin
    LMI := FData[LIarrJ];
    for LJ := 7 downto 0 do
    begin
      LBarr[LBarrI] := Byte(LMI shr (8 * LJ));
      System.Inc(LBarrI);
    end;
  end;
  Result := TBigInteger.Create(1, LBarr);
end;

class function TLongArray.ShiftUp(const AX: TCryptoLibUInt64Array; AXOff, ACount, AShift: Int32): UInt64;
var
  LShiftInv: Int32;
  LPrev: UInt64;
  I: Int32;
  LNext: UInt64;
begin
  LShiftInv := 64 - AShift;
  LPrev := 0;
  for I := 0 to ACount - 1 do
  begin
    LNext := AX[AXOff + I];
    AX[AXOff + I] := (LNext shl AShift) or LPrev;
    LPrev := LNext shr LShiftInv;
  end;
  Result := LPrev;
end;

class function TLongArray.ShiftUp(const AX: TCryptoLibUInt64Array; AXOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff, ACount, AShift: Int32): UInt64;
var
  LShiftInv: Int32;
  LPrev: UInt64;
  I: Int32;
  LNext: UInt64;
begin
  LShiftInv := 64 - AShift;
  LPrev := 0;
  for I := 0 to ACount - 1 do
  begin
    LNext := AX[AXOff + I];
    AZ[AZOff + I] := (LNext shl AShift) or LPrev;
    LPrev := LNext shr LShiftInv;
  end;
  Result := LPrev;
end;

class function TLongArray.AddShiftedUp(const AX: TCryptoLibUInt64Array; AXOff: Int32; const AY: TCryptoLibUInt64Array; AYOff, ACount, AShift: Int32): UInt64;
var
  LShiftInv: Int32;
  LPrev: UInt64;
  I: Int32;
  LNext: UInt64;
begin
  LShiftInv := 64 - AShift;
  LPrev := 0;
  for I := 0 to ACount - 1 do
  begin
    LNext := AY[AYOff + I];
    AX[AXOff + I] := AX[AXOff + I] xor ((LNext shl AShift) or LPrev);
    LPrev := LNext shr LShiftInv;
  end;
  Result := LPrev;
end;

class function TLongArray.AddShiftedDown(const AX: TCryptoLibUInt64Array; AXOff: Int32; const AY: TCryptoLibUInt64Array; AYOff, ACount, AShift: Int32): UInt64;
var
  LShiftInv: Int32;
  LPrev: UInt64;
  I: Int32;
  LNext: UInt64;
begin
  LShiftInv := 64 - AShift;
  LPrev := 0;
  I := ACount;
  while True do
  begin
    System.Dec(I);
    if I < 0 then
      Break;
    LNext := AY[AYOff + I];
    AX[AXOff + I] := AX[AXOff + I] xor ((LNext shr AShift) or LPrev);
    LPrev := LNext shl LShiftInv;
  end;
  Result := LPrev;
end;

class procedure TLongArray.Add(const AX: TCryptoLibUInt64Array; AXOff: Int32; const AY: TCryptoLibUInt64Array; AYOff, ACount: Int32);
begin
  TNat.XorTo64(ACount, AY, AYOff, AX, AXOff);
end;

class procedure TLongArray.Add(const AX: TCryptoLibUInt64Array; AXOff: Int32; const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff, ACount: Int32);
begin
  TNat.Xor64(ACount, AX, AXOff, AY, AYOff, AZ, AZOff);
end;

class procedure TLongArray.AddBoth(const AX: TCryptoLibUInt64Array; AXOff: Int32; const AY1: TCryptoLibUInt64Array; AY1Off: Int32; const AY2: TCryptoLibUInt64Array; AY2Off, ACount: Int32);
var
  I: Int32;
begin
  for I := 0 to ACount - 1 do
    AX[AXOff + I] := AX[AXOff + I] xor (AY1[AY1Off + I] xor AY2[AY2Off + I]);
end;

procedure TLongArray.AddShiftedByBitsSafe(const AOther: TLongArray; AOtherDegree, ABits: Int32);
var
  LOtherLen, LWords, LShift: Int32;
  LCarry: UInt64;
begin
  LOtherLen := Int32((UInt32(AOtherDegree + 63) shr 6));
  LWords := Int32(UInt32(ABits) shr 6);
  LShift := ABits and $3F;
  if LShift = 0 then
    Add(FData, LWords, AOther.FData, 0, LOtherLen)
  else
  begin
    LCarry := AddShiftedUp(FData, LWords, AOther.FData, 0, LOtherLen, LShift);
    if LCarry <> 0 then
      FData[LOtherLen + LWords] := FData[LOtherLen + LWords] xor LCarry;
  end;
end;

procedure TLongArray.AddShiftedByWords(const AOther: TLongArray; AWords: Int32);
var
  LOtherUsedLen, LMinLen: Int32;
begin
  LOtherUsedLen := AOther.GetUsedLength();
  if LOtherUsedLen = 0 then
    Exit;
  LMinLen := LOtherUsedLen + AWords;
  if LMinLen > System.Length(FData) then
    FData := ResizedData(LMinLen);
  Add(FData, AWords, AOther.FData, 0, LOtherUsedLen);
end;

class procedure TLongArray.FlipWord(ABuf: TCryptoLibUInt64Array; AOff, ABit: Int32; AWord: UInt64);
var
  LN: Int32;
  LShift: Int32;
begin
  LN := AOff + Int32(UInt32(ABit) shr 6);
  LShift := ABit and $3F;
  if LShift = 0 then
    ABuf[LN] := ABuf[LN] xor AWord
  else
  begin
    ABuf[LN] := ABuf[LN] xor (AWord shl LShift);
    AWord := AWord shr (64 - LShift);
    if AWord <> 0 then
    begin
      System.Inc(LN);
      ABuf[LN] := ABuf[LN] xor AWord;
    end;
  end;
end;

function TLongArray.TestBitZero(): Boolean;
begin
  Result := (System.Length(FData) > 0) and ((FData[0] and 1) <> 0);
end;

class function TLongArray.TestBit(const ABuf: TCryptoLibUInt64Array; AOff, AN: Int32): Boolean;
var
  LTheInt: Int32;
  LTheBit: Int32;
  LTester: UInt64;
begin
  LTheInt := Int32(UInt32(AN) shr 6);
  LTheBit := AN and $3F;
  LTester := UInt64(1) shl LTheBit;
  Result := (ABuf[AOff + LTheInt] and LTester) <> 0;
end;

class procedure TLongArray.FlipBit(ABuf: TCryptoLibUInt64Array; AOff, AN: Int32);
var
  LTheInt: Int32;
  LTheBit: Int32;
  LFlipper: UInt64;
begin
  LTheInt := Int32(UInt32(AN) shr 6);
  LTheBit := AN and $3F;
  LFlipper := UInt64(1) shl LTheBit;
  ABuf[AOff + LTheInt] := ABuf[AOff + LTheInt] xor LFlipper;
end;

class procedure TLongArray.MultiplyWord(AA: UInt64; const AB: TCryptoLibUInt64Array; ABLen: Int32; AC: TCryptoLibUInt64Array; ACOff: Int32);
var
  LK: Int32;
  LCarry: UInt64;
begin
  if (AA and 1) <> 0 then
    Add(AC, ACOff, AB, 0, ABLen);
  LK := 1;
  AA := AA shr 1;
  while AA <> 0 do
  begin
    if (AA and 1) <> 0 then
    begin
      LCarry := AddShiftedUp(AC, ACOff, AB, 0, ABLen, LK);
      if LCarry <> 0 then
        AC[ACOff + ABLen] := AC[ACOff + ABLen] xor LCarry;
    end;
    System.Inc(LK);
    AA := AA shr 1;
  end;
end;

class procedure TLongArray.ReduceBit(ABuf: TCryptoLibUInt64Array; AOff, ABit, AM: Int32; const AKs: TCryptoLibInt32Array);
var
  LN: Int32;
  LJ: Int32;
begin
  FlipBit(ABuf, AOff, ABit);
  LN := ABit - AM;
  LJ := System.Length(AKs);
  while True do
  begin
    System.Dec(LJ);
    if LJ < 0 then
      Break;
    FlipBit(ABuf, AOff, AKs[LJ] + LN);
  end;
  FlipBit(ABuf, AOff, LN);
end;

class procedure TLongArray.ReduceBitWise(ABuf: TCryptoLibUInt64Array; AOff, ABitLength, AM: Int32; const AKs: TCryptoLibInt32Array);
begin
  while True do
  begin
    System.Dec(ABitLength);
    if ABitLength < AM then
      Break;
    if TestBit(ABuf, AOff, ABitLength) then
      ReduceBit(ABuf, AOff, ABitLength, AM, AKs);
  end;
end;

class procedure TLongArray.ReduceWord(ABuf: TCryptoLibUInt64Array; AOff, ABit: Int32; AWord: UInt64; AM: Int32; const AKs: TCryptoLibInt32Array);
var
  LOffset: Int32;
  LJ: Int32;
begin
  LOffset := ABit - AM;
  LJ := System.Length(AKs);
  while True do
  begin
    System.Dec(LJ);
    if LJ < 0 then
      Break;
    FlipWord(ABuf, AOff, LOffset + AKs[LJ], AWord);
  end;
  FlipWord(ABuf, AOff, LOffset, AWord);
end;

class procedure TLongArray.ReduceWordWise(ABuf: TCryptoLibUInt64Array; AOff, ALen, AToBit, AM: Int32; const AKs: TCryptoLibInt32Array);
var
  LToPos: Int32;
  LPartial: Int32;
  LWord: UInt64;
begin
  LToPos := Int32(UInt32(AToBit) shr 6);
  while True do
  begin
    System.Dec(ALen);
    if ALen <= LToPos then
      Break;
    LWord := ABuf[AOff + ALen];
    if LWord <> 0 then
    begin
      ABuf[AOff + ALen] := 0;
      ReduceWord(ABuf, AOff, ALen shl 6, LWord, AM, AKs);
    end;
  end;
  LPartial := AToBit and $3F;
  LWord := ABuf[AOff + LToPos] shr LPartial;
  if LWord <> 0 then
  begin
    ABuf[AOff + LToPos] := ABuf[AOff + LToPos] xor (LWord shl LPartial);
    ReduceWord(ABuf, AOff, AToBit, LWord, AM, AKs);
  end;
end;

class procedure TLongArray.FlipVector(const AX: TCryptoLibUInt64Array; AXOff: Int32; const AY: TCryptoLibUInt64Array; AYOff, AYLen, ABits: Int32);
var
  LCarry: UInt64;
begin
  AXOff := AXOff + Int32(UInt32(ABits) shr 6);
  ABits := ABits and $3F;
  if ABits = 0 then
    Add(AX, AXOff, AY, AYOff, AYLen)
  else
  begin
    LCarry := AddShiftedDown(AX, AXOff + 1, AY, AYOff, AYLen, 64 - ABits);
    AX[AXOff] := AX[AXOff] xor LCarry;
  end;
end;

class procedure TLongArray.ReduceVectorWise(ABuf: TCryptoLibUInt64Array; AOff, ALen, AWords, AM: Int32; const AKs: TCryptoLibInt32Array);
var
  LBaseBit: Int32;
  LJ: Int32;
begin
  LBaseBit := (AWords shl 6) - AM;
  LJ := System.Length(AKs);
  while True do
  begin
    System.Dec(LJ);
    if LJ < 0 then
      Break;
    FlipVector(ABuf, AOff, ABuf, AOff + AWords, ALen - AWords, LBaseBit + AKs[LJ]);
  end;
  FlipVector(ABuf, AOff, ABuf, AOff + AWords, ALen - AWords, LBaseBit);
end;

class function TLongArray.ReduceInPlace(ABuf: TCryptoLibUInt64Array; AOff, ALen, AM: Int32; const AKs: TCryptoLibInt32Array): Int32;
var
  LMLen: Int32;
  LNumBits: Int32;
  LExcessBits: Int32;
  LKLen, LKMax, LKNext: Int32;
  LWordWiseLimit: Int32;
  LVectorableWords: Int32;
  LVectorWiseWords: Int32;
begin
  LMLen := TBitOperations.Asr32(AM + 63, 6);
  if ALen < LMLen then
    Exit(ALen);

  LNumBits := Min(ALen shl 6, (AM shl 1) - 1);
  LExcessBits := (ALen shl 6) - LNumBits;
  while LExcessBits >= 64 do
  begin
    System.Dec(ALen);
    LExcessBits := LExcessBits - 64;
  end;

  LKLen := System.Length(AKs);
  LKMax := AKs[LKLen - 1];
  if LKLen > 1 then
    LKNext := AKs[LKLen - 2]
  else
    LKNext := 0;
  LWordWiseLimit := Max(AM, LKMax + 64);
  LVectorableWords := TBitOperations.Asr32(LExcessBits + Min(LNumBits - LWordWiseLimit, AM - LKNext), 6);
  if LVectorableWords > 1 then
  begin
    LVectorWiseWords := ALen - LVectorableWords;
    ReduceVectorWise(ABuf, AOff, ALen, LVectorWiseWords, AM, AKs);
    while ALen > LVectorWiseWords do
    begin
      System.Dec(ALen);
      ABuf[AOff + ALen] := 0;
    end;
    LNumBits := LVectorWiseWords shl 6;
  end;

  if LNumBits > LWordWiseLimit then
  begin
    ReduceWordWise(ABuf, AOff, ALen, LWordWiseLimit, AM, AKs);
    LNumBits := LWordWiseLimit;
  end;

  if LNumBits > AM then
    ReduceBitWise(ABuf, AOff, LNumBits, AM, AKs);

  Result := LMLen;
end;

class function TLongArray.ReduceResult(const ABuf: TCryptoLibUInt64Array; AOff, ALen, AM: Int32; const AKs: TCryptoLibInt32Array): TLongArray;
var
  RLen: Int32;
begin
  RLen := ReduceInPlace(ABuf, AOff, ALen, AM, AKs);
  Result := TLongArray.Create(ABuf, AOff, RLen);
end;

function TLongArray.AddOne(): TLongArray;
var
  LResultLen: Int32;
  LData: TCryptoLibUInt64Array;
begin
  if System.Length(FData) = 0 then
    Exit(TLongArray.Create(TCryptoLibUInt64Array.Create(1)));
  LResultLen := Max(1, GetUsedLength());
  LData := ResizedData(LResultLen);
  LData[0] := LData[0] xor 1;
  Result := TLongArray.Create(LData);
end;

function TLongArray.ModMultiplyLD(const AOther: TLongArray; AM: Int32; const AKs: TCryptoLibInt32Array): TLongArray;
var
  LADeg, LBDeg, LALen, LBLen, LCLen: Int32;
  LA, LB: TLongArray;
  LA0: UInt64;
  LC0: TCryptoLibUInt64Array;
  LBMax, LTOff, I: Int32;
  LTi: TCryptoLibInt32Array;
  LT0, LT1: TCryptoLibUInt64Array;
  LAArr: TCryptoLibUInt64Array;
  LC: TCryptoLibUInt64Array;
  LMask: UInt32;
  LK, LJ: Int32;
  LAVal: UInt32;
  LU, LV: UInt32;
begin
  LADeg := Degree();
  if LADeg = 0 then
    Exit(Self);
  LBDeg := AOther.Degree();
  if LBDeg = 0 then
    Exit(AOther);

  LA := Self;
  LB := AOther;
  if LADeg > LBDeg then
  begin
    LA := AOther;
    LB := Self;
    LADeg := LBDeg;
    LBDeg := Degree();
  end;

  LALen := Int32((UInt32(LADeg + 63) shr 6));
  LBLen := Int32((UInt32(LBDeg + 63) shr 6));
  LCLen := Int32((UInt32(LADeg + LBDeg + 62) shr 6));

  if LALen = 1 then
  begin
    LA0 := LA.FData[0];
    if LA0 = 1 then
      Exit(LB);
    System.SetLength(LC0, LCLen);
    MultiplyWord(LA0, LB.FData, LBLen, LC0, 0);
    Result := ReduceResult(LC0, 0, LCLen, AM, AKs);
    Exit;
  end;

  LBMax := Int32((UInt32(LBDeg + 7 + 63) shr 6));
  System.SetLength(LTi, 16);
  System.SetLength(LT0, LBMax shl 4);
  LTOff := LBMax;
  LTi[1] := LTOff;
  for I := 0 to LBLen - 1 do
    LT0[LTOff + I] := LB.FData[I];
  for I := 2 to 15 do
  begin
    LTOff := LTOff + LBMax;
    LTi[I] := LTOff;
    if (I and 1) = 0 then
      ShiftUp(LT0, Int32(UInt32(LTOff) shr 1), LT0, LTOff, LBMax, 1)
    else
      Add(LT0, LBMax, LT0, LTOff - LBMax, LT0, LTOff, LBMax);
  end;

  System.SetLength(LT1, System.Length(LT0));
  ShiftUp(LT0, 0, LT1, 0, System.Length(LT0), 4);

  LAArr := LA.FData;
  System.SetLength(LC, LCLen);
  LMask := $F;

  LK := 56;
  while LK >= 0 do
  begin
    LJ := 1;
    while LJ < LALen do
    begin
      LAVal := UInt32(LAArr[LJ] shr LK);
      LU := LAVal and LMask;
      LV := (LAVal shr 4) and LMask;
      AddBoth(LC, LJ - 1, LT0, LTi[LU], LT1, LTi[LV], LBMax);
      LJ := LJ + 2;
    end;
    ShiftUp(LC, 0, LCLen, 8);
    LK := LK - 8;
  end;

  LK := 56;
  while LK >= 0 do
  begin
    LJ := 0;
    while LJ < LALen do
    begin
      LAVal := UInt32(LAArr[LJ] shr LK);
      LU := LAVal and LMask;
      LV := (LAVal shr 4) and LMask;
      AddBoth(LC, LJ, LT0, LTi[LU], LT1, LTi[LV], LBMax);
      LJ := LJ + 2;
    end;
    if LK > 0 then
      ShiftUp(LC, 0, LCLen, 8);
    LK := LK - 8;
  end;

  Result := ReduceResult(LC, 0, LCLen, AM, AKs);
end;

function TLongArray.ModMultiply(const AOther: TLongArray; AM: Int32; const AKs: TCryptoLibInt32Array): TLongArray;
var
  LADeg, LBDeg, LALen, LBLen, LCLen: Int32;
  LA, LB: TLongArray;
  LA0: UInt64;
  LC0: TCryptoLibUInt64Array;
  LBMax, LTOff, I: Int32;
  LTi: TCryptoLibInt32Array;
  LT0, LT1: TCryptoLibUInt64Array;
  LAArr: TCryptoLibUInt64Array;
  LC: TCryptoLibUInt64Array;
  LMask: UInt32;
  LAPos: Int32;
  LAVal: UInt64;
  LCOff: Int32;
  LU, LV: UInt32;
  LCOff2: Int32;
begin
  LADeg := Degree();
  if LADeg = 0 then
    Exit(Self);
  LBDeg := AOther.Degree();
  if LBDeg = 0 then
    Exit(AOther);

  LA := Self;
  LB := AOther;
  if LADeg > LBDeg then
  begin
    LA := AOther;
    LB := Self;
    LADeg := LBDeg;
    LBDeg := Degree();
  end;

  LALen := Int32((UInt32(LADeg + 63) shr 6));
  LBLen := Int32((UInt32(LBDeg + 63) shr 6));
  LCLen := Int32((UInt32(LADeg + LBDeg + 62) shr 6));

  if LALen = 1 then
  begin
    LA0 := LA.FData[0];
    if LA0 = 1 then
      Exit(LB);
    System.SetLength(LC0, LCLen);
    MultiplyWord(LA0, LB.FData, LBLen, LC0, 0);
    Exit(ReduceResult(LC0, 0, LCLen, AM, AKs));
  end;

  LBMax := Int32((UInt32(LBDeg + 7 + 63) shr 6));
  System.SetLength(LTi, 16);
  System.SetLength(LT0, LBMax shl 4);
  LTOff := LBMax;
  LTi[1] := LTOff;
  for I := 0 to LBLen - 1 do
    LT0[LTOff + I] := LB.FData[I];
  for I := 2 to 15 do
  begin
    LTOff := LTOff + LBMax;
    LTi[I] := LTOff;
    if (I and 1) = 0 then
      ShiftUp(LT0, Int32(UInt32(LTOff) shr 1), LT0, LTOff, LBMax, 1)
    else
      Add(LT0, LBMax, LT0, LTOff - LBMax, LT0, LTOff, LBMax);
  end;

  System.SetLength(LT1, System.Length(LT0));
  ShiftUp(LT0, 0, LT1, 0, System.Length(LT0), 4);

  LAArr := LA.FData;
  System.SetLength(LC, LCLen shl 3);
  LMask := $F;

  for LAPos := 0 to LALen - 1 do
  begin
    LAVal := LAArr[LAPos];
    LCOff := LAPos;
    while True do
    begin
      LU := UInt32(LAVal) and LMask;
      LAVal := LAVal shr 4;
      LV := UInt32(LAVal) and LMask;
      LAVal := LAVal shr 4;
      AddBoth(LC, LCOff, LT0, LTi[LU], LT1, LTi[LV], LBMax);
      if LAVal = 0 then
        Break;
      LCOff := LCOff + LCLen;
    end;
  end;

  LCOff2 := System.Length(LC);
  while True do
  begin
    LCOff2 := LCOff2 - LCLen;
    if LCOff2 <= 0 then
      Break;
    AddShiftedUp(LC, LCOff2 - LCLen, LC, LCOff2, LCLen, 8);
  end;

  Result := ReduceResult(LC, 0, LCLen, AM, AKs);
end;

function TLongArray.Multiply(const AOther: TLongArray): TLongArray;
begin
  Result := Multiply(AOther, 0, nil);
end;

function TLongArray.Multiply(const AOther: TLongArray; AM: Int32; const AKs: TCryptoLibInt32Array): TLongArray;
var
  LADeg, LBDeg, LALen, LBLen, LCLen: Int32;
  LA, LB: TLongArray;
  LA0: UInt64;
  LC0: TCryptoLibUInt64Array;
  LBMax, LTOff, I: Int32;
  LTi: TCryptoLibInt32Array;
  LT0, LT1: TCryptoLibUInt64Array;
  LAArr: TCryptoLibUInt64Array;
  LC: TCryptoLibUInt64Array;
  LMask: UInt32;
  LAPos: Int32;
  LAVal: UInt64;
  LCOff: Int32;
  LU, LV: UInt32;
  LCOff2: Int32;
begin
  LADeg := Degree();
  if LADeg = 0 then
    Exit(Self);
  LBDeg := AOther.Degree();
  if LBDeg = 0 then
    Exit(AOther);

  LA := Self;
  LB := AOther;
  if LADeg > LBDeg then
  begin
    LA := AOther;
    LB := Self;
    LADeg := LBDeg;
    LBDeg := Degree();
  end;

  LALen := Int32((UInt32(LADeg + 63) shr 6));
  LBLen := Int32((UInt32(LBDeg + 63) shr 6));
  LCLen := Int32((UInt32(LADeg + LBDeg + 62) shr 6));

  if LALen = 1 then
  begin
    LA0 := LA.FData[0];
    if LA0 = 1 then
      Exit(LB);
    System.SetLength(LC0, LCLen);
    MultiplyWord(LA0, LB.FData, LBLen, LC0, 0);
    Exit(TLongArray.Create(LC0, 0, LCLen));
  end;

  LBMax := Int32((UInt32(LBDeg + 7 + 63) shr 6));
  System.SetLength(LTi, 16);
  System.SetLength(LT0, LBMax shl 4);
  LTOff := LBMax;
  LTi[1] := LTOff;
  for I := 0 to LBLen - 1 do
    LT0[LTOff + I] := LB.FData[I];
  for I := 2 to 15 do
  begin
    LTOff := LTOff + LBMax;
    LTi[I] := LTOff;
    if (I and 1) = 0 then
      ShiftUp(LT0, Int32(UInt32(LTOff) shr 1), LT0, LTOff, LBMax, 1)
    else
      Add(LT0, LBMax, LT0, LTOff - LBMax, LT0, LTOff, LBMax);
  end;

  System.SetLength(LT1, System.Length(LT0));
  ShiftUp(LT0, 0, LT1, 0, System.Length(LT0), 4);

  LAArr := LA.FData;
  System.SetLength(LC, LCLen shl 3);
  LMask := $F;

  for LAPos := 0 to LALen - 1 do
  begin
    LAVal := LAArr[LAPos];
    LCOff := LAPos;
    while True do
    begin
      LU := UInt32(LAVal) and LMask;
      LAVal := LAVal shr 4;
      LV := UInt32(LAVal) and LMask;
      LAVal := LAVal shr 4;
      AddBoth(LC, LCOff, LT0, LTi[LU], LT1, LTi[LV], LBMax);
      if LAVal = 0 then
        Break;
      LCOff := LCOff + LCLen;
    end;
  end;

  LCOff2 := System.Length(LC);
  while True do
  begin
    LCOff2 := LCOff2 - LCLen;
    if LCOff2 <= 0 then
      Break;
    AddShiftedUp(LC, LCOff2 - LCLen, LC, LCOff2, LCLen, 8);
  end;

  Result := TLongArray.Create(LC, 0, LCLen);
end;

procedure TLongArray.Reduce(AM: Int32; const AKs: TCryptoLibInt32Array);
var
  LBuf: TCryptoLibUInt64Array;
  RLen: Int32;
  LNewData: TCryptoLibUInt64Array;
begin
  LBuf := FData;
  RLen := ReduceInPlace(LBuf, 0, System.Length(LBuf), AM, AKs);
  if RLen < System.Length(LBuf) then
  begin
    System.SetLength(LNewData, RLen);
    if RLen > 0 then
      System.Move(LBuf[0], LNewData[0], RLen * SizeOf(UInt64));
    FData := LNewData;
  end;
end;

function TLongArray.ModSquare(AM: Int32; const AKs: TCryptoLibInt32Array): TLongArray;
var
  LLen: Int32;
  LR: TCryptoLibUInt64Array;
  RLen: Int32;
begin
  LLen := GetUsedLength();
  if LLen = 0 then
    Exit(Self);
  System.SetLength(LR, LLen shl 1);
  TInterleave.Expand64To128(FData, 0, LLen, LR, 0);
  RLen := ReduceInPlace(LR, 0, System.Length(LR), AM, AKs);
  Result := TLongArray.Create(LR, 0, RLen);
end;

function TLongArray.ModSquareN(AN, AM: Int32; const AKs: TCryptoLibInt32Array): TLongArray;
var
  LLen: Int32;
  LMLen: Int32;
  LR: TCryptoLibUInt64Array;
  I: Int32;
begin
  LLen := GetUsedLength();
  if LLen = 0 then
    Exit(Self);
  LMLen := TBitOperations.Asr32(AM + 63, 6);
  System.SetLength(LR, LMLen shl 1);
  if LLen > 0 then
    System.Move(FData[0], LR[0], LLen * SizeOf(UInt64));
  for I := AN - 1 downto 0 do
  begin
    TInterleave.Expand64To128(LR, 0, LLen, LR, 0);
    LLen := ReduceInPlace(LR, 0, System.Length(LR), AM, AKs);
  end;
  Result := TLongArray.Create(LR, 0, LLen);
end;

function TLongArray.Square(AM: Int32; const AKs: TCryptoLibInt32Array): TLongArray;
var
  LLen: Int32;
  LR: TCryptoLibUInt64Array;
begin
  LLen := GetUsedLength();
  if LLen = 0 then
    Exit(Self);
  System.SetLength(LR, LLen shl 1);
  TInterleave.Expand64To128(FData, 0, LLen, LR, 0);
  Result := TLongArray.Create(LR, 0, System.Length(LR));
end;

function TLongArray.ModInverse(AM: Int32; const AKs: TCryptoLibInt32Array): TLongArray;
var
  LUzDegree: Int32;
  LT: Int32;
  LUz: TLongArray;
  LVz: TLongArray;
  LG1z: TLongArray;
  LG2z: TLongArray;
  LUvDeg: TCryptoLibInt32Array;
  LUv: array [0 .. 1] of TLongArray;
  LGgDeg: TCryptoLibInt32Array;
  LGg: array [0 .. 1] of TLongArray;
  LB, LDuv1, LDgg1, LJ, LDuv2, LDgg2: Int32;
begin
  LUzDegree := Degree();
  if LUzDegree = 0 then
    raise EArgumentCryptoLibException.Create('');
  if LUzDegree = 1 then
    Exit(Self);

  LUz := Copy();
  LT := TBitOperations.Asr32(AM + 63, 6);

  LVz := TLongArray.Create(LT);
  ReduceBit(LVz.FData, 0, AM, AM, AKs);

  LG1z := TLongArray.Create(LT);
  LG1z.FData[0] := 1;
  LG2z := TLongArray.Create(LT);

  LUvDeg := TCryptoLibInt32Array.Create(LUzDegree, AM + 1);
  LUv[0] := LUz;
  LUv[1] := LVz;

  LGgDeg := TCryptoLibInt32Array.Create(1, 0);
  LGg[0] := LG1z;
  LGg[1] := LG2z;

  LB := 1;
  LDuv1 := LUvDeg[LB];
  LDgg1 := LGgDeg[LB];
  LJ := LDuv1 - LUvDeg[1 - LB];

  while True do
  begin
    if LJ < 0 then
    begin
      LJ := -LJ;
      LUvDeg[LB] := LDuv1;
      LGgDeg[LB] := LDgg1;
      LB := 1 - LB;
      LDuv1 := LUvDeg[LB];
      LDgg1 := LGgDeg[LB];
    end;

    LUv[LB].AddShiftedByBitsSafe(LUv[1 - LB], LUvDeg[1 - LB], LJ);

    LDuv2 := LUv[LB].DegreeFrom(LDuv1);
    if LDuv2 = 0 then
      Exit(LGg[1 - LB]);

    LDgg2 := LGgDeg[1 - LB];
    LGg[LB].AddShiftedByBitsSafe(LGg[1 - LB], LDgg2, LJ);
    LDgg2 := LDgg2 + LJ;

    if LDgg2 > LDgg1 then
      LDgg1 := LDgg2
    else if LDgg2 = LDgg1 then
      LDgg1 := LGg[LB].DegreeFrom(LDgg1);

    LJ := LJ + (LDuv2 - LDuv1);
    LDuv1 := LDuv2;
  end;
end;

function TLongArray.Copy(): TLongArray;
var
  LCloned: TCryptoLibUInt64Array;
begin
  LCloned := System.Copy(FData, 0, System.Length(FData));
  Result := TLongArray.Create(LCloned);
end;

function TLongArray.Equals(const AOther: TLongArray): Boolean;
var
  LUsedLen, I: Int32;
begin
  if AreAliased(Self, AOther) then
    Exit(True);
  LUsedLen := GetUsedLength();
  if AOther.GetUsedLength() <> LUsedLen then
    Exit(False);
  for I := 0 to LUsedLen - 1 do
    if FData[I] <> AOther.FData[I] then
      Exit(False);
  Result := True;
end;

function TLongArray.GetHashCode(): Int32;
begin
  Result := TArrayUtilities.GetArrayHashCode(FData, 0, GetUsedLength());
end;

function TLongArray.ToString(): String;
var
  I: Int32;
  LS: String;
  LW: UInt64;
  LB: Int32;
begin
  I := GetUsedLength();
  if I = 0 then
    Exit('0');
  System.Dec(I);
  LW := FData[I];
  Result := '';
  for LB := 63 downto 0 do
    if (LW shr LB) and 1 <> 0 then
      Result := Result + '1'
    else if System.Length(Result) > 0 then
      Result := Result + '0';
  if Result = '' then
    Result := '0';
  while I > 0 do
  begin
    System.Dec(I);
    LW := FData[I];
    LS := '';
    for LB := 63 downto 0 do
      if (LW shr LB) and 1 <> 0 then
        LS := LS + '1'
      else
        LS := LS + '0';
    Result := Result + LS;
  end;
end;

function TLongArray.BitLength(): Int32;
var
  I: Int32;
  LW: UInt64;
begin
  I := System.Length(FData);
  repeat
    if I = 0 then
      Exit(0);
    System.Dec(I);
    LW := FData[I];
  until LW <> 0;
  Result := (I shl 6) + BitLength(LW);
end;

end.
