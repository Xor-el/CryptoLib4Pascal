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

unit ClpX448;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpArrayUtilities,
  ClpBitOperations,
  ClpCryptoLibTypes,
  ClpEd448,
  ClpISecureRandom,
  ClpX448Field;

resourcestring
  SInvalidKeyLength = 'Invalid key length';

type
  TX448 = class sealed
  strict private
  const
    C_A = UInt32(156326);
    C_A24 = UInt32((156326 + 2) div 4);
  class function Decode32(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32; static;
  class procedure DecodeScalar(const AK: TCryptoLibByteArray; AKOff: Int32;
    AN: TCryptoLibUInt32Array); static;
  class procedure PointDouble(AX, AZ: TCryptoLibUInt32Array); static;
  public
  const
    PointSize = Int32(56);
    ScalarSize = Int32(56);

    class function CalculateAgreement(const AK: TCryptoLibByteArray; AKOff: Int32;
      const AU: TCryptoLibByteArray; AUOff: Int32; AR: TCryptoLibByteArray;
      AROff: Int32): Boolean; static;

    class procedure ClampPrivateKey(AK: TCryptoLibByteArray); static;

    class procedure GeneratePrivateKey(const ARandom: ISecureRandom;
      const AK: TCryptoLibByteArray); static;

    class procedure GeneratePublicKey(const AK: TCryptoLibByteArray; AKOff: Int32;
      AR: TCryptoLibByteArray; AROff: Int32); static;

    class procedure Precompute; static;

    class procedure ScalarMult(const AK: TCryptoLibByteArray; AKOff: Int32;
      const AU: TCryptoLibByteArray; AUOff: Int32; AR: TCryptoLibByteArray;
      AROff: Int32); static;

    class procedure ScalarMultBase(const AK: TCryptoLibByteArray; AKOff: Int32;
      AR: TCryptoLibByteArray; AROff: Int32); static;
  end;

implementation

{ TX448 }

class function TX448.CalculateAgreement(const AK: TCryptoLibByteArray; AKOff: Int32;
  const AU: TCryptoLibByteArray; AUOff: Int32; AR: TCryptoLibByteArray;
  AROff: Int32): Boolean;
begin
  ScalarMult(AK, AKOff, AU, AUOff, AR, AROff);
  Result := not TArrayUtilities.AreAllZeroes(AR, AROff, PointSize);
end;

class procedure TX448.ClampPrivateKey(AK: TCryptoLibByteArray);
begin
  if System.Length(AK) <> ScalarSize then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidKeyLength);
  AK[0] := AK[0] and $FC;
  AK[ScalarSize - 1] := AK[ScalarSize - 1] or $80;
end;

class function TX448.Decode32(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32;
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

class procedure TX448.DecodeScalar(const AK: TCryptoLibByteArray; AKOff: Int32;
  AN: TCryptoLibUInt32Array);
var
  LI: Int32;
begin
  for LI := 0 to 13 do
  begin
    AN[LI] := Decode32(AK, AKOff + LI * 4);
  end;
  AN[0] := AN[0] and $FFFFFFFC;
  AN[13] := AN[13] or $80000000;
end;

class procedure TX448.GeneratePrivateKey(const ARandom: ISecureRandom;
  const AK: TCryptoLibByteArray);
begin
  if System.Length(AK) <> ScalarSize then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidKeyLength);
  ARandom.NextBytes(AK);
  ClampPrivateKey(AK);
end;

class procedure TX448.GeneratePublicKey(const AK: TCryptoLibByteArray; AKOff: Int32;
  AR: TCryptoLibByteArray; AROff: Int32);
begin
  ScalarMultBase(AK, AKOff, AR, AROff);
end;

class procedure TX448.PointDouble(AX, AZ: TCryptoLibUInt32Array);
var
  LA, LB: TCryptoLibUInt32Array;
begin
  LA := TX448Field.Create;
  LB := TX448Field.Create;

  TX448Field.Add(AX, AZ, LA);
  TX448Field.Sub(AX, AZ, LB);
  TX448Field.Sqr(LA, LA);
  TX448Field.Sqr(LB, LB);
  TX448Field.Mul(LA, LB, AX);
  TX448Field.Sub(LA, LB, LA);
  TX448Field.Mul(LA, C_A24, AZ);
  TX448Field.Add(AZ, LB, AZ);
  TX448Field.Mul(AZ, LA, AZ);
end;

class procedure TX448.Precompute;
begin
  TEd448.Precompute;
end;

class procedure TX448.ScalarMult(const AK: TCryptoLibByteArray; AKOff: Int32;
  const AU: TCryptoLibByteArray; AUOff: Int32; AR: TCryptoLibByteArray;
  AROff: Int32);
var
  LN: TCryptoLibUInt32Array;
  LX1, LX2, LZ2, LX3, LZ3: TCryptoLibUInt32Array;
  LT1, LT2: TCryptoLibUInt32Array;
  LBit, LSwap, LWord, LShift, LKt, LI: Int32;
begin
  System.SetLength(LN, 14);
  DecodeScalar(AK, AKOff, LN);

  LX1 := TX448Field.Create; TX448Field.Decode(AU, AUOff, LX1);
  LX2 := TX448Field.Create; TX448Field.Copy(LX1, 0, LX2, 0);
  LZ2 := TX448Field.Create; LZ2[0] := 1;
  LX3 := TX448Field.Create; LX3[0] := 1;
  LZ3 := TX448Field.Create;

  LT1 := TX448Field.Create;
  LT2 := TX448Field.Create;

  LBit := 447;
  LSwap := 1;
  repeat
    TX448Field.Add(LX3, LZ3, LT1);
    TX448Field.Sub(LX3, LZ3, LX3);
    TX448Field.Add(LX2, LZ2, LZ3);
    TX448Field.Sub(LX2, LZ2, LX2);

    TX448Field.Mul(LT1, LX2, LT1);
    TX448Field.Mul(LX3, LZ3, LX3);
    TX448Field.Sqr(LZ3, LZ3);
    TX448Field.Sqr(LX2, LX2);

    TX448Field.Sub(LZ3, LX2, LT2);
    TX448Field.Mul(LT2, C_A24, LZ2);
    TX448Field.Add(LZ2, LX2, LZ2);
    TX448Field.Mul(LZ2, LT2, LZ2);
    TX448Field.Mul(LX2, LZ3, LX2);

    TX448Field.Sub(LT1, LX3, LZ3);
    TX448Field.Add(LT1, LX3, LX3);
    TX448Field.Sqr(LX3, LX3);
    TX448Field.Sqr(LZ3, LZ3);
    TX448Field.Mul(LZ3, LX1, LZ3);

    Dec(LBit);

    LWord := TBitOperations.Asr32(LBit, 5);
    LShift := LBit and $1F;
    LKt := Int32(LN[LWord] shr LShift) and 1;
    LSwap := LSwap xor LKt;
    TX448Field.CSwap(LSwap, LX2, LX3);
    TX448Field.CSwap(LSwap, LZ2, LZ3);
    LSwap := LKt;
  until LBit < 2;

  for LI := 0 to 1 do
  begin
    PointDouble(LX2, LZ2);
  end;

  TX448Field.Inv(LZ2, LZ2);
  TX448Field.Mul(LX2, LZ2, LX2);

  TX448Field.Normalize(LX2);
  TX448Field.Encode(LX2, AR, AROff);
end;

class procedure TX448.ScalarMultBase(const AK: TCryptoLibByteArray; AKOff: Int32;
  AR: TCryptoLibByteArray; AROff: Int32);
var
  LX, LY: TCryptoLibUInt32Array;
begin
  LX := TX448Field.Create;
  LY := TX448Field.Create;

  TEd448.ScalarMultBaseXY(AK, AKOff, LX, LY);

  TX448Field.Inv(LX, LX);
  TX448Field.Mul(LX, LY, LX);
  TX448Field.Sqr(LX, LX);

  TX448Field.Normalize(LX);
  TX448Field.Encode(LX, AR, AROff);
end;

end.
