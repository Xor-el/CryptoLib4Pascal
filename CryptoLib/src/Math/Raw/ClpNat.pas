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

unit ClpNat;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpArrayUtilities,
  ClpPack,
  ClpBitUtilities,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  TNat = class sealed
  private
    const M: UInt64 = UInt64($FFFFFFFF);
  public
    class function Add(ALen: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): UInt32; static;
    class function Add33At(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array; AZPos: Int32): UInt32; overload; static;
    class function Add33At(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32; AZPos: Int32): UInt32; overload; static;
    class function Add33To(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array): UInt32; overload; static;
    class function Add33To(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; overload; static;
    class function AddBothTo(ALen: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): UInt32; overload; static;
    class function AddBothTo(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; overload; static;
    class function AddDWordAt(ALen: Int32; AX: UInt64; AZ: TCryptoLibUInt32Array; AZPos: Int32): UInt32; overload; static;
    class function AddDWordAt(ALen: Int32; AX: UInt64; AZ: TCryptoLibUInt32Array; AZOff: Int32; AZPos: Int32): UInt32; overload; static;
    class function AddDWordTo(ALen: Int32; AX: UInt64; AZ: TCryptoLibUInt32Array): UInt32; overload; static;
    class function AddDWordTo(ALen: Int32; AX: UInt64; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; overload; static;
    class function AddTo(ALen: Int32; const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): UInt32; overload; static;
    class function AddTo(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; overload; static;
    class function AddTo(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32; ACIn: UInt32): UInt32; overload; static;
    class function AddToEachOther(ALen: Int32; AU: TCryptoLibUInt32Array; AUOff: Int32; AV: TCryptoLibUInt32Array; AVOff: Int32): UInt32; static;
    class function AddWordAt(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array; AZPos: Int32): UInt32; overload; static;
    class function AddWordAt(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32; AZPos: Int32): UInt32; overload; static;
    class function AddWordTo(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array): UInt32; overload; static;
    class function AddWordTo(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; overload; static;
    class function CAdd(ALen: Int32; AMask: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): UInt32; static;
    class function CAddTo(ALen: Int32; AMask: Int32; const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): UInt32; static;
    class procedure CMov(ALen: Int32; AMask: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32); static;
    class function Compare(ALen: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array): Int32; overload; static;
    class function Compare(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32): Int32; overload; static;
    class function Copy(ALen: Int32; const AX: TCryptoLibUInt32Array): TCryptoLibUInt32Array; overload; static;
    class procedure Copy(ALen: Int32; const AX: TCryptoLibUInt32Array; const AZ: TCryptoLibUInt32Array); overload; static;
    class procedure Copy(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AZ: TCryptoLibUInt32Array; AZOff: Int32); overload; static;
    class function Copy64(ALen: Int32; const AX: TCryptoLibUInt64Array): TCryptoLibUInt64Array; overload; static;
    class procedure Copy64(ALen: Int32; const AX: TCryptoLibUInt64Array; const AZ: TCryptoLibUInt64Array); overload; static;
    class procedure Copy64(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32); overload; static;
    class function Create(ALen: Int32): TCryptoLibUInt32Array; static;
    class function Create64(ALen: Int32): TCryptoLibUInt64Array; static;
    class function CSub(ALen: Int32; AMask: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): Int32; overload; static;
    class function CSub(ALen: Int32; AMask: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): Int32; overload; static;
    class function Dec(ALen: Int32; const AZ: TCryptoLibUInt32Array): Int32; overload; static;
    class function Dec(ALen: Int32; const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): Int32; overload; static;
    class function DecAt(ALen: Int32; const AZ: TCryptoLibUInt32Array; AZPos: Int32): Int32; overload; static;
    class function DecAt(ALen: Int32; const AZ: TCryptoLibUInt32Array; AZOff: Int32; AZPos: Int32): Int32; overload; static;
    class function Eq(ALen: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array): Boolean; static;
    class function EqualTo(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; AY: UInt32): UInt32; overload; static;
    class function EqualTo(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32): UInt32; overload; static;
    class function EqualToZero(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32): UInt32; static;
    class function FromBigInteger(ABits: Int32; AX: TBigInteger): TCryptoLibUInt32Array; static;
    class function FromBigInteger64(ABits: Int32; AX: TBigInteger): TCryptoLibUInt64Array; static;
    class function GetBit(const AX: TCryptoLibUInt32Array; ABit: Int32): UInt32; static;
    class function GetBitLength(ALen: Int32; const AX: TCryptoLibUInt32Array): Int32; overload; static;
    class function GetBitLength(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32): Int32; overload; static;
    class function GetLengthForBits(ABits: Int32): Int32; static;
    class function GetLengthForBits64(ABits: Int32): Int32; static;
    class function Gte(ALen: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array): Boolean; static;
    class function Inc(ALen: Int32; const AZ: TCryptoLibUInt32Array): UInt32; overload; static;
    class function Inc(ALen: Int32; const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): UInt32; overload; static;
    class function IncAt(ALen: Int32; const AZ: TCryptoLibUInt32Array; AZPos: Int32): UInt32; overload; static;
    class function IncAt(ALen: Int32; const AZ: TCryptoLibUInt32Array; AZOff: Int32; AZPos: Int32): UInt32; overload; static;
    class function IsOne(ALen: Int32; const AX: TCryptoLibUInt32Array): Boolean; static;
    class function IsZero(ALen: Int32; const AX: TCryptoLibUInt32Array): Boolean; static;
    class function LessThan(ALen: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array): Int32; overload; static;
    class function LessThan(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32): Int32; overload; static;
    class procedure Mul(ALen: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array); overload; static;
    class procedure Mul(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZz: TCryptoLibUInt32Array; AZzOff: Int32); overload; static;
    class procedure Mul(const AX: TCryptoLibUInt32Array; AXOff: Int32; AXLen: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AYLen: Int32; AZz: TCryptoLibUInt32Array; AZzOff: Int32); overload; static;
    class function MulAddTo(ALen: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array): UInt32; overload; static;
    class function MulAddTo(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZz: TCryptoLibUInt32Array; AZzOff: Int32): UInt32; overload; static;
    class function Mul31BothAdd(ALen: Int32; AA: UInt32; const AX: TCryptoLibUInt32Array; AB: UInt32; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; static;
    class function MulWord(ALen: Int32; AX: UInt32; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): UInt32; overload; static;
    class function MulWord(ALen: Int32; AX: UInt32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; overload; static;
    class function MulWordAddTo(ALen: Int32; AX: UInt32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; static;
    class function MulWordDwordAddAt(ALen: Int32; AX: UInt32; AY: UInt64; AZ: TCryptoLibUInt32Array; AZPos: Int32): UInt32; static;
    class function Negate(ALen: Int32; const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): Int32; static;
    class function ShiftDownBit(ALen: Int32; AZ: TCryptoLibUInt32Array; AC: UInt32): UInt32; overload; static;
    class function ShiftDownBit(ALen: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32; AC: UInt32): UInt32; overload; static;
    class function ShiftDownBit(ALen: Int32; const AX: TCryptoLibUInt32Array; AC: UInt32; AZ: TCryptoLibUInt32Array): UInt32; overload; static;
    class function ShiftDownBit(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; AC: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; overload; static;
    class function ShiftDownBits(ALen: Int32; AZ: TCryptoLibUInt32Array; ABits: Int32; AC: UInt32): UInt32; overload; static;
    class function ShiftDownBits(ALen: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32; ABits: Int32; AC: UInt32): UInt32; overload; static;
    class function ShiftDownBits(ALen: Int32; const AX: TCryptoLibUInt32Array; ABits: Int32; AC: UInt32; AZ: TCryptoLibUInt32Array): UInt32; overload; static;
    class function ShiftDownBits(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; ABits: Int32; AC: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; overload; static;
    class function ShiftDownBits64(ALen: Int32; AZ: TCryptoLibUInt64Array; AZOff: Int32; ABits: Int32; AC: UInt64): UInt64; static;
    class function ShiftDownWord(ALen: Int32; AZ: TCryptoLibUInt32Array; AC: UInt32): UInt32; static;
    class function ShiftUpBit(ALen: Int32; AZ: TCryptoLibUInt32Array; AC: UInt32): UInt32; overload; static;
    class function ShiftUpBit(ALen: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32; AC: UInt32): UInt32; overload; static;
    class function ShiftUpBit(ALen: Int32; const AX: TCryptoLibUInt32Array; AC: UInt32; AZ: TCryptoLibUInt32Array): UInt32; overload; static;
    class function ShiftUpBit(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; AC: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; overload; static;
    class function ShiftUpBit64(ALen: Int32; const AX: TCryptoLibUInt64Array; AC: UInt64; AZ: TCryptoLibUInt64Array): UInt64; overload; static;
    class function ShiftUpBit64(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32; AC: UInt64; AZ: TCryptoLibUInt64Array; AZOff: Int32): UInt64; overload; static;
    class function ShiftUpBits(ALen: Int32; AZ: TCryptoLibUInt32Array; ABits: Int32; AC: UInt32): UInt32; overload; static;
    class function ShiftUpBits(ALen: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32; ABits: Int32; AC: UInt32): UInt32; overload; static;
    class function ShiftUpBits(ALen: Int32; const AX: TCryptoLibUInt32Array; ABits: Int32; AC: UInt32; AZ: TCryptoLibUInt32Array): UInt32; overload; static;
    class function ShiftUpBits(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; ABits: Int32; AC: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; overload; static;
    class function ShiftUpBits64(ALen: Int32; AZ: TCryptoLibUInt64Array; ABits: Int32; AC: UInt64): UInt64; overload; static;
    class function ShiftUpBits64(ALen: Int32; AZ: TCryptoLibUInt64Array; AZOff: Int32; ABits: Int32; AC: UInt64): UInt64; overload; static;
    class function ShiftUpBits64(ALen: Int32; const AX: TCryptoLibUInt64Array; ABits: Int32; AC: UInt64; AZ: TCryptoLibUInt64Array): UInt64; overload; static;
    class function ShiftUpBits64(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32; ABits: Int32; AC: UInt64; AZ: TCryptoLibUInt64Array; AZOff: Int32): UInt64; overload; static;
    class procedure Square(ALen: Int32; const AX: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array); overload; static;
    class procedure Square(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; AZz: TCryptoLibUInt32Array; AZzOff: Int32); overload; static;
    class function SquareWordAddTo(const AX: TCryptoLibUInt32Array; AXPos: Int32; AZ: TCryptoLibUInt32Array): UInt32; overload; static;
    class function SquareWordAddTo(const AX: TCryptoLibUInt32Array; AXOff: Int32; AXPos: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; overload; static;
    class function Sub(ALen: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): Int32; overload; static;
    class function Sub(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): Int32; overload; static;
    class function Sub33At(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array; AZPos: Int32): Int32; overload; static;
    class function Sub33At(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32; AZPos: Int32): Int32; overload; static;
    class function Sub33From(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array): Int32; overload; static;
    class function Sub33From(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32): Int32; overload; static;
    class function SubBothFrom(ALen: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): Int32; overload; static;
    class function SubBothFrom(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): Int32; overload; static;
    class function SubDWordAt(ALen: Int32; AX: UInt64; AZ: TCryptoLibUInt32Array; AZPos: Int32): Int32; overload; static;
    class function SubDWordAt(ALen: Int32; AX: UInt64; AZ: TCryptoLibUInt32Array; AZOff: Int32; AZPos: Int32): Int32; overload; static;
    class function SubDWordFrom(ALen: Int32; AX: UInt64; AZ: TCryptoLibUInt32Array): Int32; overload; static;
    class function SubDWordFrom(ALen: Int32; AX: UInt64; AZ: TCryptoLibUInt32Array; AZOff: Int32): Int32; overload; static;
    class function SubFrom(ALen: Int32; const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): Int32; overload; static;
    class function SubFrom(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): Int32; overload; static;
    class function SubWordAt(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array; AZPos: Int32): Int32; overload; static;
    class function SubWordAt(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32; AZPos: Int32): Int32; overload; static;
    class function SubWordFrom(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array): Int32; overload; static;
    class function SubWordFrom(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32): Int32; overload; static;
    class function ToBigInteger(ALen: Int32; const AX: TCryptoLibUInt32Array): TBigInteger; static;
    class procedure &Xor(ALen: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array); overload; static;
    class procedure &Xor(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32); overload; static;
    class procedure Xor64(ALen: Int32; const AX: TCryptoLibUInt64Array; AY: UInt64; AZ: TCryptoLibUInt64Array); overload; static;
    class procedure Xor64(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32; AY: UInt64; AZ: TCryptoLibUInt64Array; AZOff: Int32); overload; static;
    class procedure Xor64(ALen: Int32; const AX: TCryptoLibUInt64Array; const AY: TCryptoLibUInt64Array; AZ: TCryptoLibUInt64Array); overload; static;
    class procedure Xor64(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32; const AY: TCryptoLibUInt64Array; AYOff: Int32; AZ: TCryptoLibUInt64Array; AZOff: Int32); overload; static;
    class procedure XorBothTo(ALen: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; const AZ: TCryptoLibUInt32Array); overload; static;
    class procedure XorBothTo(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; const AZ: TCryptoLibUInt32Array; AZOff: Int32); overload; static;
    class procedure XorBothTo64(ALen: Int32; const AX: TCryptoLibUInt64Array; const AY: TCryptoLibUInt64Array; const AZ: TCryptoLibUInt64Array); overload; static;
    class procedure XorBothTo64(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32; const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32); overload; static;
    class procedure XorTo(ALen: Int32; const AX: TCryptoLibUInt32Array; const AZ: TCryptoLibUInt32Array); overload; static;
    class procedure XorTo(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AZ: TCryptoLibUInt32Array; AZOff: Int32); overload; static;
    class procedure XorTo64(ALen: Int32; const AX: TCryptoLibUInt64Array; const AZ: TCryptoLibUInt64Array); overload; static;
    class procedure XorTo64(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32); overload; static;
    class procedure Zero(ALen: Int32; AZ: TCryptoLibUInt32Array); static;
    class procedure Zero64(ALen: Int32; AZ: TCryptoLibUInt64Array); static;
  end;

implementation

class function TNat.Add(ALen: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): UInt32;
var
  LC: UInt64;
  LI: Int32;
begin
  LC := UInt64(0);
  for LI := 0 to ALen - 1 do
  begin
    LC := LC + UInt64(AX[LI]) + AY[LI];
    AZ[LI] := UInt32(LC);
    LC := LC shr 32;
  end;
  Result := UInt32(LC);
end;

class function TNat.Add33At(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array; AZPos: Int32): UInt32;
var
  LC: UInt64;
begin
  LC := UInt64(AZ[AZPos + 0]) + AX;
  {$IFDEF DEBUG}
  System.Assert(AZPos <= (ALen - 2));
  {$ENDIF}
  AZ[AZPos + 0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AZ[AZPos + 1]) + 1;
  AZ[AZPos + 1] := UInt32(LC);
  LC := LC shr 32;
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := IncAt(ALen, AZ, AZPos + 2);
  end;
end;

class function TNat.Add33At(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32; AZPos: Int32): UInt32;
var
  LC: UInt64;
begin
  LC := UInt64(AZ[AZOff + AZPos]) + AX;
  {$IFDEF DEBUG}
  System.Assert(AZPos <= (ALen - 2));
  {$ENDIF}
  AZ[AZOff + AZPos] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AZ[AZOff + AZPos + 1]) + 1;
  AZ[AZOff + AZPos + 1] := UInt32(LC);
  LC := LC shr 32;
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := IncAt(ALen, AZ, AZOff, AZPos + 2);
  end;
end;

class function TNat.Add33To(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array): UInt32;
var
  LC: UInt64;
begin
  LC := UInt64(AZ[0]) + AX;
  AZ[0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AZ[1]) + 1;
  AZ[1] := UInt32(LC);
  LC := LC shr 32;
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := IncAt(ALen, AZ, 2);
  end;
end;

class function TNat.Add33To(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LC: UInt64;
begin
  LC := UInt64(AZ[AZOff + 0]) + AX;
  AZ[AZOff + 0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AZ[AZOff + 1]) + 1;
  AZ[AZOff + 1] := UInt32(LC);
  LC := LC shr 32;
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := IncAt(ALen, AZ, AZOff, 2);
  end;
end;

class function TNat.AddBothTo(ALen: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): UInt32;
var
  LC: UInt64;
  LI: Int32;
begin
  LC := 0;
  for LI := 0 to ALen - 1 do
  begin
    LC := LC + UInt64(AX[LI]) + AY[LI] + AZ[LI];
    AZ[LI] := UInt32(LC);
    LC := LC shr 32;
  end;
  Result := UInt32(LC);
end;

class function TNat.AddBothTo(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LC: UInt64;
  LI: Int32;
begin
  LC := 0;
  for LI := 0 to ALen - 1 do
  begin
    LC := LC + UInt64(AX[AXOff + LI]) + AY[AYOff + LI] + AZ[AZOff + LI];
    AZ[AZOff + LI] := UInt32(LC);
    LC := LC shr 32;
  end;
  Result := UInt32(LC);
end;

class function TNat.AddDWordAt(ALen: Int32; AX: UInt64; AZ: TCryptoLibUInt32Array; AZPos: Int32): UInt32;
var
  LC: UInt64;
begin
  LC := UInt64(AZ[AZPos + 0]) + (AX and M);
  {$IFDEF DEBUG}
  System.Assert(AZPos <= (ALen - 2));
  {$ENDIF}
  AZ[AZPos + 0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AZ[AZPos + 1]) + (AX shr 32);
  AZ[AZPos + 1] := UInt32(LC);
  LC := LC shr 32;
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := IncAt(ALen, AZ, AZPos + 2);
  end;
end;

class function TNat.AddDWordAt(ALen: Int32; AX: UInt64; AZ: TCryptoLibUInt32Array; AZOff: Int32; AZPos: Int32): UInt32;
var
  LC: UInt64;
begin
  LC := UInt64(AZ[AZOff + AZPos]) + (AX and M);
  {$IFDEF DEBUG}
  System.Assert(AZPos <= (ALen - 2));
  {$ENDIF}
  AZ[AZOff + AZPos] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AZ[AZOff + AZPos + 1]) + (AX shr 32);
  AZ[AZOff + AZPos + 1] := UInt32(LC);
  LC := LC shr 32;
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := IncAt(ALen, AZ, AZOff, AZPos + 2);
  end;
end;

class function TNat.AddDWordTo(ALen: Int32; AX: UInt64; AZ: TCryptoLibUInt32Array): UInt32;
var
  LC: UInt64;
begin
  LC := UInt64(AZ[0]) + (AX and M);
  AZ[0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AZ[1]) + (AX shr 32);
  AZ[1] := UInt32(LC);
  LC := LC shr 32;
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := IncAt(ALen, AZ, 2);
  end;
end;

class function TNat.AddDWordTo(ALen: Int32; AX: UInt64; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LC: UInt64;
begin
  LC := UInt64(AZ[AZOff + 0]) + (AX and M);
  AZ[AZOff + 0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AZ[AZOff + 1]) + (AX shr 32);
  AZ[AZOff + 1] := UInt32(LC);
  LC := LC shr 32;
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := IncAt(ALen, AZ, AZOff, 2);
  end;
end;

class function TNat.AddTo(ALen: Int32; const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): UInt32;
var
  LC: UInt64;
  LI: Int32;
begin
  LC := 0;
  for LI := 0 to ALen - 1 do
  begin
    LC := LC + UInt64(AX[LI]) + AZ[LI];
    AZ[LI] := UInt32(LC);
    LC := LC shr 32;
  end;
  Result := UInt32(LC);
end;

class function TNat.AddTo(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LC: UInt64;
  LI: Int32;
begin
  LC := 0;
  for LI := 0 to ALen - 1 do
  begin
    LC := LC + UInt64(AX[AXOff + LI]) + AZ[AZOff + LI];
    AZ[AZOff + LI] := UInt32(LC);
    LC := LC shr 32;
  end;
  Result := UInt32(LC);
end;

class function TNat.AddTo(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32; ACIn: UInt32): UInt32;
var
  LC: UInt64;
  LI: Int32;
begin
  LC := ACIn;
  for LI := 0 to ALen - 1 do
  begin
    LC := LC + UInt64(AX[AXOff + LI]) + AZ[AZOff + LI];
    AZ[AZOff + LI] := UInt32(LC);
    LC := LC shr 32;
  end;
  Result := UInt32(LC);
end;

class function TNat.AddToEachOther(ALen: Int32; AU: TCryptoLibUInt32Array; AUOff: Int32; AV: TCryptoLibUInt32Array; AVOff: Int32): UInt32;
var
  LC: UInt64;
  LI: Int32;
begin
  LC := 0;
  for LI := 0 to ALen - 1 do
  begin
    LC := LC + UInt64(AU[AUOff + LI]) + AV[AVOff + LI];
    AU[AUOff + LI] := UInt32(LC);
    AV[AVOff + LI] := UInt32(LC);
    LC := LC shr 32;
  end;
  Result := UInt32(LC);
end;

class function TNat.AddWordAt(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array; AZPos: Int32): UInt32;
var
  LC: UInt64;
begin
  LC := UInt64(AX) + AZ[AZPos];
  {$IFDEF DEBUG}
  System.Assert(AZPos <= (ALen - 1));
  {$ENDIF}
  AZ[AZPos] := UInt32(LC);
  LC := LC shr 32;
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := IncAt(ALen, AZ, AZPos + 1);
  end;
end;

class function TNat.AddWordAt(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32; AZPos: Int32): UInt32;
var
  LC: UInt64;
begin
  LC := UInt64(AX) + AZ[AZOff + AZPos];
  {$IFDEF DEBUG}
  System.Assert(AZPos <= (ALen - 1));
  {$ENDIF}
  AZ[AZOff + AZPos] := UInt32(LC);
  LC := LC shr 32;
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := IncAt(ALen, AZ, AZOff, AZPos + 1);
  end;
end;

class function TNat.AddWordTo(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array): UInt32;
var
  LC: UInt64;
begin
  LC := UInt64(AX) + AZ[0];
  AZ[0] := UInt32(LC);
  LC := LC shr 32;
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := IncAt(ALen, AZ, 1);
  end;
end;

class function TNat.AddWordTo(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LC: UInt64;
begin
  LC := UInt64(AX) + AZ[AZOff];
  AZ[AZOff] := UInt32(LC);
  LC := LC shr 32;
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := IncAt(ALen, AZ, AZOff, 1);
  end;
end;

class function TNat.CAdd(ALen: Int32; AMask: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): UInt32;
var
  LMASK: UInt32;
  LC: UInt64;
  LI: Int32;
begin
  LMASK := UInt32(-(AMask ) and 1);
  LC := 0;
  for LI := 0 to ALen - 1 do
  begin
    LC := LC + UInt64(AX[LI]) + (AY[LI] and LMASK);
    AZ[LI] := UInt32(LC);
    LC := LC shr 32;
  end;
  Result := UInt32(LC);
end;

class function TNat.CAddTo(ALen: Int32; AMask: Int32; const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): UInt32;
var
  LMASK: UInt32;
  LC: UInt64;
  LI: Int32;
begin
  LMASK := UInt32(-(AMask ) and 1);
  LC := 0;
  for LI := 0 to ALen - 1 do
  begin
    LC := LC + UInt64(AZ[LI]) + (AX[LI] and LMASK);
    AZ[LI] := UInt32(LC);
    LC := LC shr 32;
  end;
  Result := UInt32(LC);
end;

class procedure TNat.CMov(ALen: Int32; AMask: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32);
var
  LMASK: UInt32;
  LI: Int32;
  LZI: UInt32;
  LDiff: UInt32;
begin
  LMASK := UInt32(-(AMask ) and 1);
  LZI := AZ[AZOff + LI];
  LDiff := LZI xor AX[AXOff + LI];
  for LI := 0 to ALen - 1 do
  begin
    LZI := LZI xor (LDiff and LMASK);
    AZ[AZOff + LI] := LZI;
  end;
end;

class function TNat.Compare(ALen: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array): Int32;
var
  LI: Int32;
  LXI: UInt32;
  LYI: UInt32;
begin
  for LI := ALen - 1 downto 0 do
  begin
    LXI := AX[LI];
    LYI := AY[LI];
    if LXI < LYI then
    begin
      Result := -1;
      Exit;
    end;
    if LXI > LYI then
    begin
      Result := 1;
      Exit;
    end;
  end;
  Result := 0;
end;

class function TNat.Compare(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32): Int32;
var
  LI: Int32;
  LXI: UInt32;
  LYI: UInt32;
begin
  for LI := ALen - 1 downto 0 do
  begin
    LXI := AX[AXOff + LI];
    LYI := AY[AYOff + LI];
    if LXI < LYI then
    begin
      Result := -1;
      Exit;
    end;
    if LXI > LYI then
    begin
      Result := 1;
      Exit;
    end;
  end;
  Result := 0;
end;

class function TNat.Copy(ALen: Int32; const AX: TCryptoLibUInt32Array): TCryptoLibUInt32Array;
var
  LZ: TCryptoLibUInt32Array;
begin
  SetLength(LZ, ALen);
  System.Move(AX[0], LZ[0], ALen * System.SizeOf(UInt32));
  Result := LZ;
end;

class procedure TNat.Copy(ALen: Int32; const AX: TCryptoLibUInt32Array; const AZ: TCryptoLibUInt32Array);
begin
  System.Move(AX[0], AZ[0], ALen * System.SizeOf(UInt32));
end;

class procedure TNat.Copy(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AZ: TCryptoLibUInt32Array; AZOff: Int32);
begin
  System.Move(AX[AXOff], AZ[AZOff], ALen * System.SizeOf(UInt32));
end;

class function TNat.Copy64(ALen: Int32; const AX: TCryptoLibUInt64Array): TCryptoLibUInt64Array;
var
  LZ: TCryptoLibUInt64Array;
begin
  SetLength(LZ, ALen);
  System.Move(AX[0], LZ[0], ALen * System.SizeOf(UInt64));
  Result := LZ;
end;

class procedure TNat.Copy64(ALen: Int32; const AX: TCryptoLibUInt64Array; const AZ: TCryptoLibUInt64Array);
begin
  System.Move(AX[0], AZ[0], ALen * System.SizeOf(UInt64));
end;

class procedure TNat.Copy64(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  System.Move(AX[AXOff], AZ[AZOff], ALen * System.SizeOf(UInt64));
end;

class function TNat.Create(ALen: Int32): TCryptoLibUInt32Array;
begin
  SetLength(Result, ALen);
  Exit;
end;

class function TNat.Create64(ALen: Int32): TCryptoLibUInt64Array;
begin
  SetLength(Result, ALen);
  Exit;
end;

class function TNat.CSub(ALen: Int32; AMask: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): Int32;
var
  LMASK: Int64;
  LC: Int64;
  LI: Int32;
begin
  LMASK := UInt32(-(AMask ) and 1);
  LC := 0;
  for LI := 0 to ALen - 1 do
  begin
    LC := LC + (AX[LI] - (AY[LI] and LMASK));
    AZ[LI] := UInt32(LC);
    LC := TBitUtilities.Asr64(LC, 32);
  end;
  Result := Int32(LC);
end;

class function TNat.CSub(ALen: Int32; AMask: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): Int32;
var
  LMASK: Int64;
  LC: Int64;
  LI: Int32;
begin
  LMASK := UInt32(-(AMask ) and 1);
  LC := 0;
  for LI := 0 to ALen - 1 do
  begin
    LC := LC + (AX[AXOff + LI] - (AY[AYOff + LI] and LMASK));
    AZ[AZOff + LI] := UInt32(LC);
    LC := TBitUtilities.Asr64(LC, 32);
  end;
  Result := Int32(LC);
end;

class function TNat.Dec(ALen: Int32; const AZ: TCryptoLibUInt32Array): Int32;
var
  LI: Int32;
begin
  for LI := 0 to ALen - 1 do
  begin
    System.Dec(AZ[LI]);
    if AZ[LI] <> UInt32.MaxValue then
    begin
      Result := 0;
      Exit;
    end;
  end;
  Result := -1;
end;

class function TNat.Dec(ALen: Int32; const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): Int32;
var
  LI: Int32;
  LC: UInt32;
begin
  LI := 0;
  LC := AX[LI] - 1;
  while LI < ALen do
  begin
    AZ[LI] := LC;
    System.Inc(LI);
    if LC <> UInt32.MaxValue then
    begin
      System.Move(AX[LI], AZ[LI], (ALen - LI) * System.SizeOf(UInt32));
      Result := 0;
      Exit;
    end;
  end;
  Result := -1;
end;

class function TNat.DecAt(ALen: Int32; const AZ: TCryptoLibUInt32Array; AZPos: Int32): Int32;
var
  LI: Int32;
begin
  {$IFDEF DEBUG}
  System.Assert(AZPos <= ALen);
  {$ENDIF}
  for LI := AZPos to ALen - 1 do
  begin
    System.Dec(AZ[LI]);
    if AZ[LI] <> UInt32.MaxValue then
    begin
      Result := 0;
      Exit;
    end;
  end;
  Result := -1;
end;

class function TNat.DecAt(ALen: Int32; const AZ: TCryptoLibUInt32Array; AZOff: Int32; AZPos: Int32): Int32;
var
  LI: Int32;
begin
  {$IFDEF DEBUG}
  System.Assert(AZPos <= ALen);
  {$ENDIF}
  for LI := AZPos to ALen - 1 do
  begin
    System.Dec(AZ[AZOff + LI]);
    if AZ[AZOff + LI] <> UInt32.MaxValue then
    begin
      Result := 0;
      Exit;
    end;
  end;
  Result := -1;
end;

class function TNat.Eq(ALen: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array): Boolean;
var
  LI: Int32;
begin
  for LI := ALen - 1 downto 0 do
  begin
    if AX[LI] <> AY[LI] then
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := True;
end;

class function TNat.EqualTo(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; AY: UInt32): UInt32;
var
  LD: UInt32;
  LI: Int32;
begin
  LD := AX[AXOff] xor AY;
  for LI := 1 to ALen - 1 do
  begin
    LD := LD or (AX[AXOff + LI]);
  end;
  LD := ((LD shr 1)) or (LD and 1);
  Result := UInt32(TBitUtilities.Asr32(Int32(LD - 1), 31));
end;

class function TNat.EqualTo(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32): UInt32;
var
  LD: UInt32;
  LI: Int32;
begin
  LD := 0;
  for LI := 0 to ALen - 1 do
  begin
    LD := LD or (AX[AXOff + LI] xor AY[AYOff + LI]);
  end;
  LD := ((LD shr 1)) or (LD and 1);
  Result := UInt32(TBitUtilities.Asr32(Int32(LD - 1), 31));
end;

class function TNat.EqualToZero(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32): UInt32;
var
  LD: UInt32;
  LI: Int32;
begin
  LD := 0;
  for LI := 0 to ALen - 1 do
  begin
    LD := LD or (AX[AXOff + LI]);
  end;
  LD := ((LD shr 1)) or (LD and 1);
  Result := UInt32(TBitUtilities.Asr32(Int32(LD - 1), 31));
end;

class function TNat.FromBigInteger(ABits: Int32; AX: TBigInteger): TCryptoLibUInt32Array;
var
  LLen: Int32;
  LZ: TCryptoLibUInt32Array;
  LI: Int32;
begin
  LLen := GetLengthForBits(ABits);
  LZ := Create(LLen);
  if ((AX.SignValue < 0) or (AX.BitLength > ABits)) then
  raise EArgumentCryptoLibException.Create('');
  LZ[0] := UInt32(AX.Int32Value);
  for LI := 1 to LLen - 1 do
  begin
    AX := AX.ShiftRight(32);
    LZ[LI] := UInt32(AX.Int32Value);
  end;
  Result := LZ;
end;

class function TNat.FromBigInteger64(ABits: Int32; AX: TBigInteger): TCryptoLibUInt64Array;
var
  LLen: Int32;
  LZ: TCryptoLibUInt64Array;
  LI: Int32;
begin
  LLen := GetLengthForBits64(ABits);
  LZ := Create64(LLen);
  if ((AX.SignValue < 0) or (AX.BitLength > ABits)) then
  raise EArgumentCryptoLibException.Create('');
  LZ[0] := UInt64(AX.Int64Value);
  for LI := 1 to LLen - 1 do
  begin
    AX := AX.ShiftRight(64);
    LZ[LI] := UInt64(AX.Int64Value);
  end;
  Result := LZ;
end;

class function TNat.GetBit(const AX: TCryptoLibUInt32Array; ABit: Int32): UInt32;
var
  LW: Int32;
  LB: Int32;
begin
  if ABit = 0 then
  begin
    Result := AX[0] and 1;
    Exit;
  end;
  LW := TBitUtilities.Asr32(ABit, 5);
  LB := ABit and 31;
  if (LW < 0) or (LW >= System.Length(AX)) then
  begin
    Result := 0;
    Exit;
  end;
  Result := (AX[LW] shr LB) and 1;
end;

class function TNat.GetBitLength(ALen: Int32; const AX: TCryptoLibUInt32Array): Int32;
var
  LI: Int32;
  LXI: UInt32;
begin
  for LI := ALen - 1 downto 0 do
  begin
    LXI := AX[LI];
    if LXI <> 0 then
    begin
      Result := LI * 32 + 32 - TBitUtilities.NumberOfLeadingZeros(LXI);
      Exit;
    end;
  end;
  Result := 0;
end;

class function TNat.GetBitLength(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32): Int32;
var
  LI: Int32;
  LXI: UInt32;
begin
  for LI := ALen - 1 downto 0 do
  begin
    LXI := AX[AXOff + LI];
    if LXI <> 0 then
    begin
      Result := LI * 32 + 32 - TBitUtilities.NumberOfLeadingZeros(LXI);
      Exit;
    end;
  end;
  Result := 0;
end;

class function TNat.GetLengthForBits(ABits: Int32): Int32;
begin
  if ABits < 1 then
  raise EArgumentCryptoLibException.Create('');
  Result := Int32((UInt32(ABits) + 31) shr 5);
end;

class function TNat.GetLengthForBits64(ABits: Int32): Int32;
begin
  if ABits < 1 then
  raise EArgumentCryptoLibException.Create('');
  Result := Int32((UInt32(ABits) + 63) shr 6);
end;

class function TNat.Gte(ALen: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array): Boolean;
var
  LI: Int32;
  LXI: UInt32;
  LYI: UInt32;
begin
  for LI := ALen - 1 downto 0 do
  begin
    LXI := AX[LI];
    LYI := AY[LI];
    if LXI < LYI then
    begin
      Result := False;
      Exit;
    end;
    if LXI > LYI then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := True;
end;

class function TNat.Inc(ALen: Int32; const AZ: TCryptoLibUInt32Array): UInt32;
var
  LI: Int32;
begin
  for LI := 0 to ALen - 1 do
  begin
    System.Inc(AZ[LI]);
    if AZ[LI] <> UInt32(0) then
    begin
      Result := 0;
      Exit;
    end;
  end;
  Result := 1;
end;

class function TNat.Inc(ALen: Int32; const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): UInt32;
var
  LI: Int32;
  LC: UInt32;
begin
  LI := 0;
  LC := AX[LI] + 1;
  while LI < ALen do
  begin
    AZ[LI] := LC;
    System.Inc(LI);
    if LC <> 0 then
    begin
      System.Move(AX[LI], AZ[LI], (ALen - LI) * System.SizeOf(UInt32));
      Result := 0;
      Exit;
    end;
  end;
  Result := 1;
end;

class function TNat.IncAt(ALen: Int32; const AZ: TCryptoLibUInt32Array; AZPos: Int32): UInt32;
var
  LI: Int32;
begin
  {$IFDEF DEBUG}
  System.Assert(AZPos <= ALen);
  {$ENDIF}
  for LI := AZPos to ALen - 1 do
  begin
    System.Inc(AZ[LI]);
    if AZ[LI] <> UInt32(0) then
    begin
      Result := 0;
      Exit;
    end;
  end;
  Result := 1;
end;

class function TNat.IncAt(ALen: Int32; const AZ: TCryptoLibUInt32Array; AZOff: Int32; AZPos: Int32): UInt32;
var
  LI: Int32;
begin
  {$IFDEF DEBUG}
  System.Assert(AZPos <= ALen);
  {$ENDIF}
  for LI := AZPos to ALen - 1 do
  begin
    System.Inc(AZ[AZOff + LI]);
    if AZ[AZOff + LI] <> UInt32(0) then
    begin
      Result := 0;
      Exit;
    end;
  end;
  Result := 1;
end;

class function TNat.IsOne(ALen: Int32; const AX: TCryptoLibUInt32Array): Boolean;
var
  LI: Int32;
begin
  if AX[0] <> 1 then
  begin
    Result := False;
    Exit;
  end;
  for LI := 1 to ALen - 1 do
  begin
    if AX[LI] <> 0 then
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := True;
end;

class function TNat.IsZero(ALen: Int32; const AX: TCryptoLibUInt32Array): Boolean;
var
  LI: Int32;
begin
  if AX[0] <> 0 then
  begin
    Result := False;
    Exit;
  end;
  for LI := 1 to ALen - 1 do
  begin
    if AX[LI] <> 0 then
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := True;
end;

class function TNat.LessThan(ALen: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array): Int32;
var
  LC: Int64;
  LI: Int32;
begin
  LC := 0;
  for LI := 0 to ALen - 1 do
  begin
    LC := LC + (Int64(AX[LI]) - AY[LI]);
    LC := TBitUtilities.Asr64(LC, 32);
  end;
  System.Assert((LC = Int64(0)) or (LC = -Int64(1)));
  Result := Int32(LC);
end;

class function TNat.LessThan(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32): Int32;
var
  LC: Int64;
  LI: Int32;
begin
  LC := 0;
  for LI := 0 to ALen - 1 do
  begin
    LC := LC + (Int64(AX[AXOff + LI]) - Int64(AY[AYOff + LI]));
    LC := TBitUtilities.Asr64(LC, 32);
  end;
  {$IFDEF DEBUG}
  System.Assert((LC = Int64(0)) or (LC = -Int64(1)));
  {$ENDIF}
  Result := Int32(LC);
end;

class procedure TNat.Mul(ALen: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array);
var
  LI: Int32;
begin
  AZz[ALen] := MulWord(ALen, AX[0], AY, AZz);
  for LI := 1 to ALen - 1 do
  begin
    AZz[LI + ALen] := MulWordAddTo(ALen, AX[LI], AY, 0, AZz, LI);
  end;
end;

class procedure TNat.Mul(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZz: TCryptoLibUInt32Array; AZzOff: Int32);
var
  LI: Int32;
begin
  AZz[AZzOff + ALen] := MulWord(ALen, AX[AXOff], AY, AYOff, AZz, AZzOff);
  for LI := 1 to ALen - 1 do
  begin
    AZz[AZzOff + LI + ALen] := MulWordAddTo(ALen, AX[AXOff + LI], AY, AYOff, AZz, AZzOff + LI);
  end;
end;

class procedure TNat.Mul(const AX: TCryptoLibUInt32Array; AXOff: Int32; AXLen: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AYLen: Int32; AZz: TCryptoLibUInt32Array; AZzOff: Int32);
var
  LI: Int32;
begin
  AZz[AZzOff + AYLen] := MulWord(AYLen, AX[AXOff], AY, AYOff, AZz, AZzOff);
  for LI := 1 to AXLen - 1 do
  begin
    AZz[AZzOff + LI + AYLen] := MulWordAddTo(AYLen, AX[AXOff + LI], AY, AYOff, AZz, AZzOff + LI);
  end;
end;

class function TNat.MulAddTo(ALen: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array): UInt32;
var
  LZc: UInt64;
  LI: Int32;
begin
  LZc := 0;
  for LI := 0 to ALen - 1 do
  begin
    LZc := LZc + (MulWordAddTo(ALen, AX[LI], AY, 0, AZz, LI) and M);
    LZc := LZc + (AZz[LI + ALen] and M);
    AZz[LI + ALen] := UInt32(LZc);
    LZc := LZc shr 32;
  end;
  Result := UInt32(LZc);
end;

class function TNat.MulAddTo(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZz: TCryptoLibUInt32Array; AZzOff: Int32): UInt32;
var
  LZc: UInt64;
  LI: Int32;
begin
  LZc := 0;
  for LI := 0 to ALen - 1 do
  begin
    LZc := LZc + (MulWordAddTo(ALen, AX[AXOff + LI], AY, AYOff, AZz, AZzOff) and M);
    LZc := LZc + (AZz[AZzOff + ALen] and M);
    AZz[AZzOff + ALen] := UInt32(LZc);
    LZc := LZc shr 32;
    System.Inc(AZzOff);
  end;
  Result := UInt32(LZc);
end;

class function TNat.Mul31BothAdd(ALen: Int32; AA: UInt32; const AX: TCryptoLibUInt32Array; AB: UInt32; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LC: UInt64;
  LAVal: UInt64;
  LBVal: UInt64;
  LI: Int32;
begin
  LC := 0;
  LAVal := AA;
  LBVal := AB;
  LI := 0;
  repeat
    LC := LC + (LAVal * AX[LI] + LBVal * AY[LI] + AZ[AZOff + LI]);
    AZ[AZOff + LI] := UInt32(LC);
    LC := LC shr 32;
    System.Inc(LI);
  until (not (LI < ALen));
  Result := UInt32(LC);
end;

class function TNat.MulWord(ALen: Int32; AX: UInt32; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): UInt32;
var
  LC: UInt64;
  LXVal: UInt64;
  LI: Int32;
begin
  LC := 0;
  LXVal := AX;
  LI := 0;
  repeat
    LC := LC + (LXVal * AY[LI]);
    AZ[LI] := UInt32(LC);
    LC := LC shr 32;
    System.Inc(LI);
  until (not (LI < ALen));
  Result := UInt32(LC);
end;

class function TNat.MulWord(ALen: Int32; AX: UInt32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LC: UInt64;
  LXVal: UInt64;
  LI: Int32;
begin
  LC := 0;
  LXVal := AX;
  for LI := 0 to ALen - 1 do
  begin
    LC := LC + (LXVal * AY[AYOff + LI]);
    AZ[AZOff + LI] := UInt32(LC);
    LC := LC shr 32;
  end;
  Result := UInt32(LC);
end;

class function TNat.MulWordAddTo(ALen: Int32; AX: UInt32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LC: UInt64;
  LXVal: UInt64;
  LI: Int32;
begin
  LC := 0;
  LXVal := AX;
  for LI := 0 to ALen - 1 do
  begin
    LC := LC + (LXVal * AY[AYOff + LI] + AZ[AZOff + LI]);
    AZ[AZOff + LI] := UInt32(LC);
    LC := LC shr 32;
  end;
  Result := UInt32(LC);
end;

class function TNat.MulWordDwordAddAt(ALen: Int32; AX: UInt32; AY: UInt64; AZ: TCryptoLibUInt32Array; AZPos: Int32): UInt32;
var
  LC: UInt64;
  LXVal: UInt64;
begin
  LC := 0;
  LXVal := AX;
  {$IFDEF DEBUG}
  System.Assert(AZPos <= (ALen - 3));
  {$ENDIF}
  LC := LC + (LXVal * UInt32(AY) + AZ[AZPos + 0]);
  AZ[AZPos + 0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * (AY shr 32) + AZ[AZPos + 1]);
  AZ[AZPos + 1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (AZ[AZPos + 2]);
  AZ[AZPos + 2] := UInt32(LC);
  LC := LC shr 32;
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := IncAt(ALen, AZ, AZPos + 3);
  end;
end;

class function TNat.Negate(ALen: Int32; const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): Int32;
var
  LC: Int64;
  LI: Int32;
begin
  LC := Int64(0);
  for LI := 0 to ALen - 1 do
  begin
    LC := LC - (AX[LI]);
    AZ[LI] := UInt32(LC);
    LC := TBitUtilities.Asr64(LC, 32);
  end;
  Result := Int32(LC);
end;

class function TNat.ShiftDownBit(ALen: Int32; AZ: TCryptoLibUInt32Array; AC: UInt32): UInt32;
var
  LI: Int32;
  LNext: UInt32;
begin
  LI := ALen;
  while LI > 0 do
  begin
    System.Dec(LI);
    LNext := AZ[LI];
    AZ[LI] := ((LNext shr 1)) or ((AC shl 31));
    AC := LNext;
  end;
  Result := (AC shl 31);
end;

class function TNat.ShiftDownBit(ALen: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32; AC: UInt32): UInt32;
var
  LI: Int32;
  LNext: UInt32;
begin
  LI := ALen;
  while LI > 0 do
  begin
    System.Dec(LI);
    LNext := AZ[AZOff + LI];
    AZ[AZOff + LI] := ((LNext shr 1)) or ((AC shl 31));
    AC := LNext;
  end;
  Result := (AC shl 31);
end;

class function TNat.ShiftDownBit(ALen: Int32; const AX: TCryptoLibUInt32Array; AC: UInt32; AZ: TCryptoLibUInt32Array): UInt32;
var
  LI: Int32;
  LNext: UInt32;
begin
  LI := ALen;
  while LI > 0 do
  begin
    System.Dec(LI);
    LNext := AX[LI];
    AZ[LI] := ((LNext shr 1)) or ((AC shl 31));
    AC := LNext;
  end;
  Result := (AC shl 31);
end;

class function TNat.ShiftDownBit(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; AC: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LI: Int32;
  LNext: UInt32;
begin
  LI := ALen;
  while LI > 0 do
  begin
    System.Dec(LI);
    LNext := AX[AXOff + LI];
    AZ[AZOff + LI] := ((LNext shr 1)) or ((AC shl 31));
    AC := LNext;
  end;
  Result := (AC shl 31);
end;

class function TNat.ShiftDownBits(ALen: Int32; AZ: TCryptoLibUInt32Array; ABits: Int32; AC: UInt32): UInt32;
var
  LI: Int32;
  LNext: UInt32;
begin
  {$IFDEF DEBUG}
  System.Assert((ABits > 0) and (ABits < 32));
  {$ENDIF}
  LI := ALen;
  while LI > 0 do
  begin
    System.Dec(LI);
    LNext := AZ[LI];
    AZ[LI] := ((LNext shr ABits)) or (TBitUtilities.NegativeLeftShift32(AC, -ABits));
    AC := LNext;
  end;
  Result := TBitUtilities.NegativeLeftShift32(AC, -ABits);
end;

class function TNat.ShiftDownBits(ALen: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32; ABits: Int32; AC: UInt32): UInt32;
var
  LI: Int32;
  LNext: UInt32;
begin
  {$IFDEF DEBUG}
  System.Assert((ABits > 0) and (ABits < 32));
  {$ENDIF}
  LI := ALen;
  while LI > 0 do
  begin
    System.Dec(LI);
    LNext := AZ[AZOff + LI];
    AZ[AZOff + LI] := ((LNext shr ABits)) or (TBitUtilities.NegativeLeftShift32(AC, -ABits));
    AC := LNext;
  end;
  Result := TBitUtilities.NegativeLeftShift32(AC, -ABits);
end;

class function TNat.ShiftDownBits(ALen: Int32; const AX: TCryptoLibUInt32Array; ABits: Int32; AC: UInt32; AZ: TCryptoLibUInt32Array): UInt32;
var
  LI: Int32;
  LNext: UInt32;
begin
  {$IFDEF DEBUG}
  System.Assert((ABits > 0) and (ABits < 32));
  {$ENDIF}
  LI := ALen;
  while LI > 0 do
  begin
    System.Dec(LI);
    LNext := AX[LI];
    AZ[LI] := ((LNext shr ABits)) or (TBitUtilities.NegativeLeftShift32(AC, -ABits));
    AC := LNext;
  end;
  Result := TBitUtilities.NegativeLeftShift32(AC, -ABits);
end;

class function TNat.ShiftDownBits(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; ABits: Int32; AC: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LI: Int32;
  LNext: UInt32;
begin
  {$IFDEF DEBUG}
  System.Assert((ABits > 0) and (ABits < 32));
  {$ENDIF}
  LI := ALen;
  while LI > 0 do
  begin
    System.Dec(LI);
    LNext := AX[AXOff + LI];
    AZ[AZOff + LI] := ((LNext shr ABits)) or (TBitUtilities.NegativeLeftShift32(AC, -ABits));
    AC := LNext;
  end;
  Result := TBitUtilities.NegativeLeftShift32(AC, -ABits);
end;

class function TNat.ShiftDownBits64(ALen: Int32; AZ: TCryptoLibUInt64Array; AZOff: Int32; ABits: Int32; AC: UInt64): UInt64;
var
  LI: Int32;
  LNext: UInt64;
begin
  {$IFDEF DEBUG}
  System.Assert((ABits > 0) and (ABits < 64));
  {$ENDIF}
  LI := ALen;
  while LI > 0 do
  begin
    System.Dec(LI);
    LNext := AZ[AZOff + LI];
    AZ[AZOff + LI] := ((LNext shr ABits)) or (TBitUtilities.NegativeLeftShift64(AC, -ABits));
    AC := LNext;
  end;
  Result := TBitUtilities.NegativeLeftShift64(AC, -ABits);
end;

class function TNat.ShiftDownWord(ALen: Int32; AZ: TCryptoLibUInt32Array; AC: UInt32): UInt32;
var
  LI: Int32;
  LNext: UInt32;
begin
  LI := ALen;
  while LI > 0 do
  begin
    System.Dec(LI);
    LNext := AZ[LI];
    AZ[LI] := AC;
    AC := LNext;
  end;
  Result := AC;
end;

class function TNat.ShiftUpBit(ALen: Int32; AZ: TCryptoLibUInt32Array; AC: UInt32): UInt32;
var
  LI: Int32;
  LLimit4: Int32;
  LNext0: UInt32;
  LNext1: UInt32;
  LNext2: UInt32;
  LNext3: UInt32;
  LNext: UInt32;
begin
  LI := 0;
  LLimit4 := ALen - 4;
  while LI <= LLimit4 do
  begin
    LNext0 := AZ[LI + 0];
    LNext1 := AZ[LI + 1];
    LNext2 := AZ[LI + 2];
    LNext3 := AZ[LI + 3];
    AZ[LI + 0] := ((LNext0 shl 1)) or ((AC shr 31));
    AZ[LI + 1] := ((LNext1 shl 1)) or ((LNext0 shr 31));
    AZ[LI + 2] := ((LNext2 shl 1)) or ((LNext1 shr 31));
    AZ[LI + 3] := ((LNext3 shl 1)) or ((LNext2 shr 31));
    AC := LNext3;
    LI := LI + (4);
  end;
  while LI < ALen do
  begin
    LNext := AZ[LI];
    AZ[LI] := ((LNext shl 1)) or ((AC shr 31));
    AC := LNext;
    System.Inc(LI);
  end;
  Result := (AC shr 31);
end;

class function TNat.ShiftUpBit(ALen: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32; AC: UInt32): UInt32;
var
  LI: Int32;
  LLimit4: Int32;
  LNext0: UInt32;
  LNext1: UInt32;
  LNext2: UInt32;
  LNext3: UInt32;
  LNext: UInt32;
begin
  LI := 0;
  LLimit4 := ALen - 4;
  while LI <= LLimit4 do
  begin
    LNext0 := AZ[AZOff + LI + 0];
    LNext1 := AZ[AZOff + LI + 1];
    LNext2 := AZ[AZOff + LI + 2];
    LNext3 := AZ[AZOff + LI + 3];
    AZ[AZOff + LI + 0] := ((LNext0 shl 1)) or ((AC shr 31));
    AZ[AZOff + LI + 1] := ((LNext1 shl 1)) or ((LNext0 shr 31));
    AZ[AZOff + LI + 2] := ((LNext2 shl 1)) or ((LNext1 shr 31));
    AZ[AZOff + LI + 3] := ((LNext3 shl 1)) or ((LNext2 shr 31));
    AC := LNext3;
    LI := LI + (4);
  end;
  while LI < ALen do
  begin
    LNext := AZ[AZOff + LI];
    AZ[AZOff + LI] := ((LNext shl 1)) or ((AC shr 31));
    AC := LNext;
    System.Inc(LI);
  end;
  Result := (AC shr 31);
end;

class function TNat.ShiftUpBit(ALen: Int32; const AX: TCryptoLibUInt32Array; AC: UInt32; AZ: TCryptoLibUInt32Array): UInt32;
var
  LI: Int32;
  LLimit4: Int32;
  LNext0: UInt32;
  LNext1: UInt32;
  LNext2: UInt32;
  LNext3: UInt32;
  LNext: UInt32;
begin
  LI := 0;
  LLimit4 := ALen - 4;
  while LI <= LLimit4 do
  begin
    LNext0 := AX[LI + 0];
    LNext1 := AX[LI + 1];
    LNext2 := AX[LI + 2];
    LNext3 := AX[LI + 3];
    AZ[LI + 0] := ((LNext0 shl 1)) or ((AC shr 31));
    AZ[LI + 1] := ((LNext1 shl 1)) or ((LNext0 shr 31));
    AZ[LI + 2] := ((LNext2 shl 1)) or ((LNext1 shr 31));
    AZ[LI + 3] := ((LNext3 shl 1)) or ((LNext2 shr 31));
    AC := LNext3;
    LI := LI + (4);
  end;
  while LI < ALen do
  begin
    LNext := AX[LI];
    AZ[LI] := ((LNext shl 1)) or ((AC shr 31));
    AC := LNext;
    System.Inc(LI);
  end;
  Result := (AC shr 31);
end;

class function TNat.ShiftUpBit(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; AC: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LI: Int32;
  LLimit4: Int32;
  LNext0: UInt32;
  LNext1: UInt32;
  LNext2: UInt32;
  LNext3: UInt32;
  LNext: UInt32;
begin
  LI := 0;
  LLimit4 := ALen - 4;
  while LI <= LLimit4 do
  begin
    LNext0 := AX[AXOff + LI + 0];
    LNext1 := AX[AXOff + LI + 1];
    LNext2 := AX[AXOff + LI + 2];
    LNext3 := AX[AXOff + LI + 3];
    AZ[AZOff + LI + 0] := ((LNext0 shl 1)) or ((AC shr 31));
    AZ[AZOff + LI + 1] := ((LNext1 shl 1)) or ((LNext0 shr 31));
    AZ[AZOff + LI + 2] := ((LNext2 shl 1)) or ((LNext1 shr 31));
    AZ[AZOff + LI + 3] := ((LNext3 shl 1)) or ((LNext2 shr 31));
    AC := LNext3;
    LI := LI + (4);
  end;
  while LI < ALen do
  begin
    LNext := AX[AXOff + LI];
    AZ[AZOff + LI] := ((LNext shl 1)) or ((AC shr 31));
    AC := LNext;
    System.Inc(LI);
  end;
  Result := (AC shr 31);
end;

class function TNat.ShiftUpBit64(ALen: Int32; const AX: TCryptoLibUInt64Array; AC: UInt64; AZ: TCryptoLibUInt64Array): UInt64;
var
  LI: Int32;
  LLimit4: Int32;
  LNext0: UInt64;
  LNext1: UInt64;
  LNext2: UInt64;
  LNext3: UInt64;
  LNext: UInt64;
begin
  LI := 0;
  LLimit4 := ALen - 4;
  while LI <= LLimit4 do
  begin
    LNext0 := AX[LI + 0];
    LNext1 := AX[LI + 1];
    LNext2 := AX[LI + 2];
    LNext3 := AX[LI + 3];
    AZ[LI + 0] := ((LNext0 shl 1)) or ((AC shr 63));
    AZ[LI + 1] := ((LNext1 shl 1)) or ((LNext0 shr 63));
    AZ[LI + 2] := ((LNext2 shl 1)) or ((LNext1 shr 63));
    AZ[LI + 3] := ((LNext3 shl 1)) or ((LNext2 shr 63));
    AC := LNext3;
    LI := LI + (4);
  end;
  while LI < ALen do
  begin
    LNext := AX[LI];
    AZ[LI] := ((LNext shl 1)) or ((AC shr 63));
    AC := LNext;
    System.Inc(LI);
  end;
  Result := (AC shr 63);
end;

class function TNat.ShiftUpBit64(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32; AC: UInt64; AZ: TCryptoLibUInt64Array; AZOff: Int32): UInt64;
var
  LI: Int32;
  LLimit4: Int32;
  LNext0: UInt64;
  LNext1: UInt64;
  LNext2: UInt64;
  LNext3: UInt64;
  LNext: UInt64;
begin
  LI := 0;
  LLimit4 := ALen - 4;
  while LI <= LLimit4 do
  begin
    LNext0 := AX[AXOff + LI + 0];
    LNext1 := AX[AXOff + LI + 1];
    LNext2 := AX[AXOff + LI + 2];
    LNext3 := AX[AXOff + LI + 3];
    AZ[AZOff + LI + 0] := ((LNext0 shl 1)) or ((AC shr 63));
    AZ[AZOff + LI + 1] := ((LNext1 shl 1)) or ((LNext0 shr 63));
    AZ[AZOff + LI + 2] := ((LNext2 shl 1)) or ((LNext1 shr 63));
    AZ[AZOff + LI + 3] := ((LNext3 shl 1)) or ((LNext2 shr 63));
    AC := LNext3;
    LI := LI + (4);
  end;
  while LI < ALen do
  begin
    LNext := AX[AXOff + LI];
    AZ[AZOff + LI] := ((LNext shl 1)) or ((AC shr 63));
    AC := LNext;
    System.Inc(LI);
  end;
  Result := (AC shr 63);
end;

class function TNat.ShiftUpBits(ALen: Int32; AZ: TCryptoLibUInt32Array; ABits: Int32; AC: UInt32): UInt32;
var
  LI: Int32;
  LLimit4: Int32;
  LNext0: UInt32;
  LNext1: UInt32;
  LNext2: UInt32;
  LNext3: UInt32;
  LNext: UInt32;
begin
  LI := 0;
  LLimit4 := ALen - 4;
  {$IFDEF DEBUG}
  System.Assert((ABits > 0) and (ABits < 32));
  {$ENDIF}
  while LI <= LLimit4 do
  begin
    LNext0 := AZ[LI + 0];
    LNext1 := AZ[LI + 1];
    LNext2 := AZ[LI + 2];
    LNext3 := AZ[LI + 3];
    AZ[LI + 0] := ((LNext0 shl ABits)) or (TBitUtilities.NegativeRightShift32(AC, -ABits));
    AZ[LI + 1] := ((LNext1 shl ABits)) or (TBitUtilities.NegativeRightShift32(LNext0, -ABits));
    AZ[LI + 2] := ((LNext2 shl ABits)) or (TBitUtilities.NegativeRightShift32(LNext1, -ABits));
    AZ[LI + 3] := ((LNext3 shl ABits)) or (TBitUtilities.NegativeRightShift32(LNext2, -ABits));
    AC := LNext3;
    LI := LI + 4;
  end;
  while LI < ALen do
  begin
    LNext := AZ[LI];
    AZ[LI] := ((LNext shl ABits)) or (TBitUtilities.NegativeRightShift32(AC, -ABits));
    AC := LNext;
    System.Inc(LI);
  end;
  Result := TBitUtilities.NegativeRightShift32(AC, -ABits);
end;

class function TNat.ShiftUpBits(ALen: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32; ABits: Int32; AC: UInt32): UInt32;
var
  LI: Int32;
  LLimit4: Int32;
  LNext0: UInt32;
  LNext1: UInt32;
  LNext2: UInt32;
  LNext3: UInt32;
  LNext: UInt32;
begin
  LI := 0;
  LLimit4 := ALen - 4;
  {$IFDEF DEBUG}
  System.Assert((ABits > 0) and (ABits < 32));
  {$ENDIF}
  while LI <= LLimit4 do
  begin
    LNext0 := AZ[AZOff + LI + 0];
    LNext1 := AZ[AZOff + LI + 1];
    LNext2 := AZ[AZOff + LI + 2];
    LNext3 := AZ[AZOff + LI + 3];
    AZ[AZOff + LI + 0] := ((LNext0 shl ABits)) or (TBitUtilities.NegativeRightShift32(AC, -ABits));
    AZ[AZOff + LI + 1] := ((LNext1 shl ABits)) or (TBitUtilities.NegativeRightShift32(LNext0, -ABits));
    AZ[AZOff + LI + 2] := ((LNext2 shl ABits)) or (TBitUtilities.NegativeRightShift32(LNext1, -ABits));
    AZ[AZOff + LI + 3] := ((LNext3 shl ABits)) or (TBitUtilities.NegativeRightShift32(LNext2, -ABits));
    AC := LNext3;
    LI := LI + 4;
  end;
  while LI < ALen do
  begin
    LNext := AZ[AZOff + LI];
    AZ[AZOff + LI] := ((LNext shl ABits)) or (TBitUtilities.NegativeRightShift32(AC, -ABits));
    AC := LNext;
    System.Inc(LI);
  end;
  Result := TBitUtilities.NegativeRightShift32(AC, -ABits);
end;

class function TNat.ShiftUpBits(ALen: Int32; const AX: TCryptoLibUInt32Array; ABits: Int32; AC: UInt32; AZ: TCryptoLibUInt32Array): UInt32;
var
  LI: Int32;
  LLimit4: Int32;
  LNext0: UInt32;
  LNext1: UInt32;
  LNext2: UInt32;
  LNext3: UInt32;
  LNext: UInt32;
begin
  LI := 0;
  LLimit4 := ALen - 4;
  {$IFDEF DEBUG}
  System.Assert((ABits > 0) and (ABits < 32));
  {$ENDIF}
  while LI <= LLimit4 do
  begin
    LNext0 := AX[LI + 0];
    LNext1 := AX[LI + 1];
    LNext2 := AX[LI + 2];
    LNext3 := AX[LI + 3];
    AZ[LI + 0] := ((LNext0 shl ABits)) or (TBitUtilities.NegativeRightShift32(AC, -ABits));
    AZ[LI + 1] := ((LNext1 shl ABits)) or (TBitUtilities.NegativeRightShift32(LNext0, -ABits));
    AZ[LI + 2] := ((LNext2 shl ABits)) or (TBitUtilities.NegativeRightShift32(LNext1, -ABits));
    AZ[LI + 3] := ((LNext3 shl ABits)) or (TBitUtilities.NegativeRightShift32(LNext2, -ABits));
    AC := LNext3;
    LI := LI + 4;
  end;
  while LI < ALen do
  begin
    LNext := AX[LI];
    AZ[LI] := ((LNext shl ABits)) or (TBitUtilities.NegativeRightShift32(AC, -ABits));
    AC := LNext;
    System.Inc(LI);
  end;
  Result := TBitUtilities.NegativeRightShift32(AC, -ABits);
end;

class function TNat.ShiftUpBits(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; ABits: Int32; AC: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LI: Int32;
  LLimit4: Int32;
  LNext0: UInt32;
  LNext1: UInt32;
  LNext2: UInt32;
  LNext3: UInt32;
  LNext: UInt32;
begin
  LI := 0;
  LLimit4 := ALen - 4;
  {$IFDEF DEBUG}
  System.Assert((ABits > 0) and (ABits < 32));
  {$ENDIF}
  while LI <= LLimit4 do
  begin
    LNext0 := AX[AXOff + LI + 0];
    LNext1 := AX[AXOff + LI + 1];
    LNext2 := AX[AXOff + LI + 2];
    LNext3 := AX[AXOff + LI + 3];
    AZ[AZOff + LI + 0] := ((LNext0 shl ABits)) or (TBitUtilities.NegativeRightShift32(AC, -ABits));
    AZ[AZOff + LI + 1] := ((LNext1 shl ABits)) or (TBitUtilities.NegativeRightShift32(LNext0, -ABits));
    AZ[AZOff + LI + 2] := ((LNext2 shl ABits)) or (TBitUtilities.NegativeRightShift32(LNext1, -ABits));
    AZ[AZOff + LI + 3] := ((LNext3 shl ABits)) or (TBitUtilities.NegativeRightShift32(LNext2, -ABits));
    AC := LNext3;
    LI := LI + 4;
  end;
  while LI < ALen do
  begin
    LNext := AX[AXOff + LI];
    AZ[AZOff + LI] := ((LNext shl ABits)) or (TBitUtilities.NegativeRightShift32(AC, -ABits));
    AC := LNext;
    System.Inc(LI);
  end;
  Result := TBitUtilities.NegativeRightShift32(AC, -ABits);
end;

class function TNat.ShiftUpBits64(ALen: Int32; AZ: TCryptoLibUInt64Array; ABits: Int32; AC: UInt64): UInt64;
var
  LI: Int32;
  LLimit4: Int32;
  LNext0: UInt64;
  LNext1: UInt64;
  LNext2: UInt64;
  LNext3: UInt64;
  LNext: UInt64;
begin
  LI := 0;
  LLimit4 := ALen - 4;
  {$IFDEF DEBUG}
  System.Assert((ABits > 0) and (ABits < 64));
  {$ENDIF}
  while LI <= LLimit4 do
  begin
    LNext0 := AZ[LI + 0];
    LNext1 := AZ[LI + 1];
    LNext2 := AZ[LI + 2];
    LNext3 := AZ[LI + 3];
    AZ[LI + 0] := ((LNext0 shl ABits)) or (TBitUtilities.NegativeRightShift64(AC, -ABits));
    AZ[LI + 1] := ((LNext1 shl ABits)) or (TBitUtilities.NegativeRightShift64(LNext0, -ABits));
    AZ[LI + 2] := ((LNext2 shl ABits)) or (TBitUtilities.NegativeRightShift64(LNext1, -ABits));
    AZ[LI + 3] := ((LNext3 shl ABits)) or (TBitUtilities.NegativeRightShift64(LNext2, -ABits));
    AC := LNext3;
    LI := LI + 4;
  end;
  while LI < ALen do
  begin
    LNext := AZ[LI];
    AZ[LI] := ((LNext shl ABits)) or (TBitUtilities.NegativeRightShift64(AC, -ABits));
    AC := LNext;
    System.Inc(LI);
  end;
  Result := TBitUtilities.NegativeRightShift64(AC, -ABits);
end;

class function TNat.ShiftUpBits64(ALen: Int32; AZ: TCryptoLibUInt64Array; AZOff: Int32; ABits: Int32; AC: UInt64): UInt64;
var
  LI: Int32;
  LLimit4: Int32;
  LNext0: UInt64;
  LNext1: UInt64;
  LNext2: UInt64;
  LNext3: UInt64;
  LNext: UInt64;
begin
  LI := 0;
  LLimit4 := ALen - 4;
  {$IFDEF DEBUG}
  System.Assert((ABits > 0) and (ABits < 64));
  {$ENDIF}
  while LI <= LLimit4 do
  begin
    LNext0 := AZ[AZOff + LI + 0];
    LNext1 := AZ[AZOff + LI + 1];
    LNext2 := AZ[AZOff + LI + 2];
    LNext3 := AZ[AZOff + LI + 3];
    AZ[AZOff + LI + 0] := ((LNext0 shl ABits)) or (TBitUtilities.NegativeRightShift64(AC, -ABits));
    AZ[AZOff + LI + 1] := ((LNext1 shl ABits)) or (TBitUtilities.NegativeRightShift64(LNext0, -ABits));
    AZ[AZOff + LI + 2] := ((LNext2 shl ABits)) or (TBitUtilities.NegativeRightShift64(LNext1, -ABits));
    AZ[AZOff + LI + 3] := ((LNext3 shl ABits)) or (TBitUtilities.NegativeRightShift64(LNext2, -ABits));
    AC := LNext3;
    LI := LI + 4;
  end;
  while LI < ALen do
  begin
    LNext := AZ[AZOff + LI];
    AZ[AZOff + LI] := ((LNext shl ABits)) or (TBitUtilities.NegativeRightShift64(AC, -ABits));
    AC := LNext;
    System.Inc(LI);
  end;
  Result := TBitUtilities.NegativeRightShift64(AC, -ABits);
end;

class function TNat.ShiftUpBits64(ALen: Int32; const AX: TCryptoLibUInt64Array; ABits: Int32; AC: UInt64; AZ: TCryptoLibUInt64Array): UInt64;
var
  LI: Int32;
  LLimit4: Int32;
  LNext0: UInt64;
  LNext1: UInt64;
  LNext2: UInt64;
  LNext3: UInt64;
  LNext: UInt64;
begin
  LI := 0;
  LLimit4 := ALen - 4;
  {$IFDEF DEBUG}
  System.Assert((ABits > 0) and (ABits < 64));
  {$ENDIF}
  while LI <= LLimit4 do
  begin
    LNext0 := AX[LI + 0];
    LNext1 := AX[LI + 1];
    LNext2 := AX[LI + 2];
    LNext3 := AX[LI + 3];
    AZ[LI + 0] := ((LNext0 shl ABits)) or (TBitUtilities.NegativeRightShift64(AC, -ABits));
    AZ[LI + 1] := ((LNext1 shl ABits)) or (TBitUtilities.NegativeRightShift64(LNext0, -ABits));
    AZ[LI + 2] := ((LNext2 shl ABits)) or (TBitUtilities.NegativeRightShift64(LNext1, -ABits));
    AZ[LI + 3] := ((LNext3 shl ABits)) or (TBitUtilities.NegativeRightShift64(LNext2, -ABits));
    AC := LNext3;
    LI := LI + 4;
  end;
  while LI < ALen do
  begin
    LNext := AX[LI];
    AZ[LI] := ((LNext shl ABits)) or (TBitUtilities.NegativeRightShift64(AC, -ABits));
    AC := LNext;
    System.Inc(LI);
  end;
  Result := TBitUtilities.NegativeRightShift64(AC, -ABits);
end;

class function TNat.ShiftUpBits64(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32; ABits: Int32; AC: UInt64; AZ: TCryptoLibUInt64Array; AZOff: Int32): UInt64;
var
  LI: Int32;
  LLimit4: Int32;
  LNext0: UInt64;
  LNext1: UInt64;
  LNext2: UInt64;
  LNext3: UInt64;
  LNext: UInt64;
begin
  LI := 0;
  LLimit4 := ALen - 4;
  {$IFDEF DEBUG}
  System.Assert((ABits > 0) and (ABits < 64));
  {$ENDIF}
  while LI <= LLimit4 do
  begin
    LNext0 := AX[AXOff + LI + 0];
    LNext1 := AX[AXOff + LI + 1];
    LNext2 := AX[AXOff + LI + 2];
    LNext3 := AX[AXOff + LI + 3];
    AZ[AZOff + LI + 0] := ((LNext0 shl ABits)) or (TBitUtilities.NegativeRightShift64(AC, -ABits));
    AZ[AZOff + LI + 1] := ((LNext1 shl ABits)) or (TBitUtilities.NegativeRightShift64(LNext0, -ABits));
    AZ[AZOff + LI + 2] := ((LNext2 shl ABits)) or (TBitUtilities.NegativeRightShift64(LNext1, -ABits));
    AZ[AZOff + LI + 3] := ((LNext3 shl ABits)) or (TBitUtilities.NegativeRightShift64(LNext2, -ABits));
    AC := LNext3;
    LI := LI + 4;
  end;
  while LI < ALen do
  begin
    LNext := AX[AXOff + LI];
    AZ[AZOff + LI] := ((LNext shl ABits)) or (TBitUtilities.NegativeRightShift64(AC, -ABits));
    AC := LNext;
    System.Inc(LI);
  end;
  Result := TBitUtilities.NegativeRightShift64(AC, -ABits);
end;

class procedure TNat.Square(ALen: Int32; const AX: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array);
var
  LExtLen: Int32;
  LC: UInt32;
  LJ: Int32;
  LK: Int32;
  LXVal: UInt64;
  LP: UInt64;
  LD: UInt64;
  LZzPos: Int32;
  LI: Int32;
begin
  LExtLen := (ALen shl 1);
  LC := 0;
  LJ := ALen;
  LK := LExtLen;

  repeat
    System.Dec(LJ);
    LXVal := UInt64(AX[LJ]);
    LP := LXVal * LXVal;

    System.Dec(LK);
    AZz[LK] := (LC shl 31) or UInt32(LP shr 33);
    System.Dec(LK);
    AZz[LK] := UInt32(LP shr 1);

    LC := UInt32(LP);
  until not (LJ > 0);

  LD := UInt64(0);
  LZzPos := 2;

  for LI := 1 to ALen - 1 do
  begin
    LD := LD + SquareWordAddTo(AX, LI, AZz);

    LD := LD + AZz[LZzPos];
    AZz[LZzPos] := UInt32(LD);
    System.Inc(LZzPos);
    LD := LD shr 32;

    LD := LD + AZz[LZzPos];
    AZz[LZzPos] := UInt32(LD);
    System.Inc(LZzPos);
    LD := LD shr 32;
  end;

  {$IFDEF DEBUG}
  System.Assert(UInt64(0) = LD);
  {$ENDIF}

  ShiftUpBit(LExtLen, AZz, (AX[0] shl 31));
end;

class procedure TNat.Square(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; AZz: TCryptoLibUInt32Array; AZzOff: Int32);
var
  LExtLen: Int32;
  LC: UInt32;
  LJ: Int32;
  LK: Int32;
  LXVal: UInt64;
  LP: UInt64;
  LD: UInt64;
  LZzPos: Int32;
  LI: Int32;
begin
  LExtLen := (ALen shl 1);
  LC := 0;
  LJ := ALen;
  LK := LExtLen;

  repeat
    System.Dec(LJ);
    LXVal := UInt64(AX[AXOff + LJ]);
    LP := LXVal * LXVal;

    System.Dec(LK);
    AZz[AZzOff + LK] := (LC shl 31) or UInt32(LP shr 33);
   System.Dec(LK);
    AZz[AZzOff + LK] := UInt32(LP shr 1);

    LC := UInt32(LP);
  until not (LJ > 0);

  LD := UInt64(0);
  LZzPos := AZzOff + 2;

  for LI := 1 to ALen - 1 do
  begin
    LD := LD + SquareWordAddTo(AX, AXOff, LI, AZz, AZzOff);

    LD := LD + AZz[LZzPos];
    AZz[LZzPos] := UInt32(LD);
    System.Inc(LZzPos);
    LD := LD shr 32;

    LD := LD + AZz[LZzPos];
    AZz[LZzPos] := UInt32(LD);
    System.Inc(LZzPos);
    LD := LD shr 32;
  end;

  {$IFDEF DEBUG}
  System.Assert(UInt64(0) = LD);
  {$ENDIF}

  ShiftUpBit(LExtLen, AZz, AZzOff, (AX[AXOff] shl 31));
end;

class function TNat.SquareWordAddTo(const AX: TCryptoLibUInt32Array; AXPos: Int32; AZ: TCryptoLibUInt32Array): UInt32;
var
  LC: UInt64;
  LXVal: UInt64;
  LI: Int32;
begin
  LC := 0;
  LXVal := UInt64(AX[AXPos]);
  LI := 0;

  repeat
    LC := LC + (LXVal * UInt64(AX[LI]) + UInt64(AZ[AXPos + LI]));
    AZ[AXPos + LI] := UInt32(LC);
    LC := LC shr 32;
    System.Inc(LI);
  until not (LI < AXPos);

  Result := UInt32(LC);
end;

class function TNat.SquareWordAddTo(const AX: TCryptoLibUInt32Array; AXOff: Int32; AXPos: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LC: UInt64;
  LXVal: UInt64;
  LI: Int32;
  LZOff: Int32;
begin
  LC := 0;
  LXVal := UInt64(AX[AXOff + AXPos]);
  LI := 0;
  LZOff := AZOff;

  repeat
    LC := LC + (LXVal * (UInt64(AX[AXOff + LI]) and M) + (UInt64(AZ[AXPos + LZOff]) and M));
    AZ[AXPos + LZOff] := UInt32(LC);
    LC := LC shr 32;
    System.Inc(LZOff);
    System.Inc(LI);
  until not (LI < AXPos);

  Result := UInt32(LC);
end;

class function TNat.Sub(ALen: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): Int32;
var
  LC: Int64;
  LI: Int32;
begin
  LC := 0;
  for LI := 0 to ALen - 1 do
  begin
    LC := LC + (Int64(AX[LI]) - Int64(AY[LI]));
    AZ[LI] := UInt32(LC);
    LC := TBitUtilities.Asr64(LC, 32);
  end;
  Result := Int32(LC);
end;

class function TNat.Sub(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): Int32;
var
  LC: Int64;
  LI: Int32;
begin
  LC := 0;
  for LI := 0 to ALen - 1 do
  begin
    LC := LC + (Int64(AX[AXOff + LI]) - Int64(AY[AYOff + LI]));
    AZ[AZOff + LI] := UInt32(LC);
    LC := TBitUtilities.Asr64(LC, 32);
  end;
  Result := Int32(LC);
end;

class function TNat.Sub33At(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array; AZPos: Int32): Int32;
var
  LC: Int64;
begin
  LC := Int64(AZ[AZPos + 0] - AX);
  {$IFDEF DEBUG}
  System.Assert(AZPos <= (ALen - 2));
  {$ENDIF}
  AZ[AZPos + 0] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AZ[AZPos + 1] - 1));
  AZ[AZPos + 1] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := DecAt(ALen, AZ, AZPos + 2);
  end;
end;

class function TNat.Sub33At(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32; AZPos: Int32): Int32;
var
  LC: Int64;
begin
  LC := Int64(AZ[AZOff + AZPos] - AX);
  {$IFDEF DEBUG}
  System.Assert(AZPos <= (ALen - 2));
  {$ENDIF}
  AZ[AZOff + AZPos] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AZ[AZOff + AZPos + 1] - 1));
  AZ[AZOff + AZPos + 1] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := DecAt(ALen, AZ, AZOff, AZPos + 2);
  end;
end;

class function TNat.Sub33From(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array): Int32;
var
  LC: Int64;
begin
  LC := Int64(AZ[0] - AX);
  AZ[0] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AZ[1] - 1));
  AZ[1] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := DecAt(ALen, AZ, 2);
  end;
end;

class function TNat.Sub33From(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32): Int32;
var
  LC: Int64;
begin
  LC := Int64(AZ[AZOff + 0] - AX);
  AZ[AZOff + 0] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AZ[AZOff + 1] - 1));
  AZ[AZOff + 1] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := DecAt(ALen, AZ, AZOff, 2);
  end;
end;

class function TNat.SubBothFrom(ALen: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): Int32;
var
  LC: Int64;
  LI: Int32;
begin
  LC := 0;
  for LI := 0 to ALen - 1 do
  begin
    LC := LC + (Int64(AZ[LI]) - Int64(AX[LI]) - Int64(AY[LI]));
    AZ[LI] := UInt32(LC);
    LC := TBitUtilities.Asr64(LC, 32);
  end;
  Result := Int32(LC);
end;

class function TNat.SubBothFrom(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): Int32;
var
  LC: Int64;
  LI: Int32;
begin
  LC := 0;
  for LI := 0 to ALen - 1 do
  begin
    LC := LC + (Int64(AZ[AZOff + LI]) - Int64(AX[AXOff + LI]) - Int64(AY[AYOff + LI]));
    AZ[AZOff + LI] := UInt32(LC);
    LC := TBitUtilities.Asr64(LC, 32);
  end;
  Result := Int32(LC);
end;

class function TNat.SubDWordAt(ALen: Int32; AX: UInt64; AZ: TCryptoLibUInt32Array; AZPos: Int32): Int32;
var
  LC: Int64;
begin
  LC := AZ[AZPos + 0] - Int64(AX and M);
  {$IFDEF DEBUG}
  System.Assert(AZPos <= (ALen - 2));
  {$ENDIF}
  AZ[AZPos + 0] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (AZ[AZPos + 1] - Int64(AX shr 32));
  AZ[AZPos + 1] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := DecAt(ALen, AZ, AZPos + 2);
  end;
end;

class function TNat.SubDWordAt(ALen: Int32; AX: UInt64; AZ: TCryptoLibUInt32Array; AZOff: Int32; AZPos: Int32): Int32;
var
  LC: Int64;
begin
  LC := AZ[AZOff + AZPos] - Int64(AX and M);
  {$IFDEF DEBUG}
  System.Assert(AZPos <= (ALen - 2));
  {$ENDIF}
  AZ[AZOff + AZPos] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (AZ[AZOff + AZPos + 1] - Int64(AX shr 32));
  AZ[AZOff + AZPos + 1] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := DecAt(ALen, AZ, AZOff, AZPos + 2);
  end;
end;

class function TNat.SubDWordFrom(ALen: Int32; AX: UInt64; AZ: TCryptoLibUInt32Array): Int32;
var
  LC: Int64;
begin
  LC := AZ[0] - Int64(AX and M);
  AZ[0] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (AZ[1] - Int64(AX shr 32));
  AZ[1] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := DecAt(ALen, AZ, 2);
  end;
end;

class function TNat.SubDWordFrom(ALen: Int32; AX: UInt64; AZ: TCryptoLibUInt32Array; AZOff: Int32): Int32;
var
  LC: Int64;
begin
  LC := AZ[AZOff + 0] - Int64(AX and M);
  AZ[AZOff + 0] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (AZ[AZOff + 1] - Int64(AX shr 32));
  AZ[AZOff + 1] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := DecAt(ALen, AZ, AZOff, 2);
  end;
end;

class function TNat.SubFrom(ALen: Int32; const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): Int32;
var
  LC: Int64;
  LI: Int32;
begin
  LC := 0;
  for LI := 0 to ALen - 1 do
  begin
    LC := LC + (Int64(AZ[LI]) - Int64(AX[LI]));
    AZ[LI] := UInt32(LC);
    LC := TBitUtilities.Asr64(LC, 32);
  end;
  Result := Int32(LC);
end;

class function TNat.SubFrom(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): Int32;
var
  LC: Int64;
  LI: Int32;
begin
  LC := 0;
  for LI := 0 to ALen - 1 do
  begin
    LC := LC + (Int64(AZ[AZOff + LI]) - Int64(AX[AXOff + LI]));
    AZ[AZOff + LI] := UInt32(LC);
    LC := TBitUtilities.Asr64(LC, 32);
  end;
  Result := Int32(LC);
end;

class function TNat.SubWordAt(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array; AZPos: Int32): Int32;
var
  LC: Int64;
begin
  LC := Int64(AZ[AZPos] - AX);
  {$IFDEF DEBUG}
  System.Assert(AZPos <= (ALen - 1));
  {$ENDIF}
  AZ[AZPos] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := DecAt(ALen, AZ, AZPos + 1);
  end;
end;

class function TNat.SubWordAt(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32; AZPos: Int32): Int32;
var
  LC: Int64;
begin
  LC := Int64(AZ[AZOff + AZPos] - AX);
  {$IFDEF DEBUG}
  System.Assert(AZPos <= (ALen - 1));
  {$ENDIF}
  AZ[AZOff + AZPos] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := DecAt(ALen, AZ, AZOff, AZPos + 1);
  end;
end;

class function TNat.SubWordFrom(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array): Int32;
var
  LC: Int64;
begin
  LC := Int64(AZ[0] - AX);
  AZ[0] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := DecAt(ALen, AZ, 1);
  end;
end;

class function TNat.SubWordFrom(ALen: Int32; AX: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32): Int32;
var
  LC: Int64;
begin
  LC := Int64(AZ[AZOff + 0] - AX);
  AZ[AZOff + 0] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := DecAt(ALen, AZ, AZOff, 1);
  end;
end;

class function TNat.ToBigInteger(ALen: Int32; const AX: TCryptoLibUInt32Array): TBigInteger;
var
  LBs: TCryptoLibByteArray;
  LXPos: Int32;
  LBsPos: Int32;
begin
  SetLength(LBs, (ALen shl 2));
  LXPos := ALen - 1;
  LBsPos := 0;
  while LXPos >= 0 do
  begin
    TPack.UInt32_To_BE(AX[LXPos], LBs, LBsPos);
    LBsPos := LBsPos + 4;
    System.Dec(LXPos);
  end;
  Result := TBigInteger.Create(1, LBs);
end;

class procedure TNat.&Xor(ALen: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array);
var
  LI: Int32;
begin
  for LI := 0 to ALen - 1 do
  begin
    AZ[LI] := AX[LI] xor AY[LI];
  end;
end;

class procedure TNat.&Xor(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32);
var
  LI: Int32;
begin
  for LI := 0 to ALen - 1 do
  begin
    AZ[AZOff + LI] := AX[AXOff + LI] xor AY[AYOff + LI];
  end;
end;

class procedure TNat.Xor64(ALen: Int32; const AX: TCryptoLibUInt64Array; AY: UInt64; AZ: TCryptoLibUInt64Array);
var
  LI: Int32;
begin
  for LI := 0 to ALen - 1 do
  begin
    AZ[LI] := AX[LI] xor AY;
  end;
end;

class procedure TNat.Xor64(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32; AY: UInt64; AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  LI: Int32;
begin
  for LI := 0 to ALen - 1 do
  begin
    AZ[AZOff + LI] := AX[AXOff + LI] xor AY;
  end;
end;

class procedure TNat.Xor64(ALen: Int32; const AX: TCryptoLibUInt64Array; const AY: TCryptoLibUInt64Array; AZ: TCryptoLibUInt64Array);
var
  LI: Int32;
begin
  for LI := 0 to ALen - 1 do
  begin
    AZ[LI] := AX[LI] xor AY[LI];
  end;
end;

class procedure TNat.Xor64(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32; const AY: TCryptoLibUInt64Array; AYOff: Int32; AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  LI: Int32;
begin
  for LI := 0 to ALen - 1 do
  begin
    AZ[AZOff + LI] := AX[AXOff + LI] xor AY[AYOff + LI];
  end;
end;

class procedure TNat.XorBothTo(ALen: Int32; const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; const AZ: TCryptoLibUInt32Array);
var
  LI: Int32;
begin
  for LI := 0 to ALen - 1 do
  begin
    AZ[LI] := AZ[LI] xor (AX[LI] xor AY[LI]);
  end;
end;

class procedure TNat.XorBothTo(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; const AZ: TCryptoLibUInt32Array; AZOff: Int32);
var
  LI: Int32;
begin
  for LI := 0 to ALen - 1 do
  begin
    AZ[AZOff + LI] := AZ[AZOff + LI] xor (AX[AXOff + LI] xor AY[AYOff + LI]);
  end;
end;

class procedure TNat.XorBothTo64(ALen: Int32; const AX: TCryptoLibUInt64Array; const AY: TCryptoLibUInt64Array; const AZ: TCryptoLibUInt64Array);
var
  LI: Int32;
begin
  for LI := 0 to ALen - 1 do
  begin
    AZ[LI] := AZ[LI] xor (AX[LI] xor AY[LI]);
  end;
end;

class procedure TNat.XorBothTo64(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32; const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  LI: Int32;
begin
  for LI := 0 to ALen - 1 do
  begin
    AZ[AZOff + LI] := AZ[AZOff + LI] xor (AX[AXOff + LI] xor AY[AYOff + LI]);
  end;
end;

class procedure TNat.XorTo(ALen: Int32; const AX: TCryptoLibUInt32Array; const AZ: TCryptoLibUInt32Array);
var
  LI: Int32;
begin
  for LI := 0 to ALen - 1 do
  begin
    AZ[LI] := AZ[LI] xor (AX[LI]);
  end;
end;

class procedure TNat.XorTo(ALen: Int32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AZ: TCryptoLibUInt32Array; AZOff: Int32);
var
  LI: Int32;
begin
  for LI := 0 to ALen - 1 do
  begin
    AZ[AZOff + LI] := AZ[AZOff + LI] xor (AX[AXOff + LI]);
  end;
end;

class procedure TNat.XorTo64(ALen: Int32; const AX: TCryptoLibUInt64Array; const AZ: TCryptoLibUInt64Array);
var
  LI: Int32;
begin
  for LI := 0 to ALen - 1 do
  begin
    AZ[LI] := AZ[LI] xor (AX[LI]);
  end;
end;

class procedure TNat.XorTo64(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  LI: Int32;
begin
  for LI := 0 to ALen - 1 do
  begin
    AZ[AZOff + LI] := AZ[AZOff + LI] xor (AX[AXOff + LI]);
  end;
end;

class procedure TNat.Zero(ALen: Int32; AZ: TCryptoLibUInt32Array);
begin
  TArrayUtilities.Fill<UInt32>(AZ, 0, ALen, UInt32(0));
end;

class procedure TNat.Zero64(ALen: Int32; AZ: TCryptoLibUInt64Array);
begin
  TArrayUtilities.Fill<UInt64>(AZ, 0, ALen, UInt64(0));
end;

end.
