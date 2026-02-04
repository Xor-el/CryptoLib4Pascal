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

unit ClpX25519;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpArrayUtilities,
  ClpBitOperations,
  ClpCryptoLibTypes,
  ClpEd25519,
  ClpISecureRandom,
  ClpX25519Field;


resourcestring
  SInvalidKeyLength = 'Invalid key length';

type
  TX25519 = class sealed
  strict private
  const
    C_A = 486662;
    C_A24 = (C_A + 2) div 4;
  class function Decode32(const Abs: TCryptoLibByteArray; AOff: Int32): UInt32; static;
  class procedure DecodeScalar(const AK: TCryptoLibByteArray; AKOff: Int32;
    AN: TCryptoLibUInt32Array); static;
  class procedure PointDouble(AX, AZ: TCryptoLibInt32Array); static;
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

    class procedure Precompute; static;

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
  if System.Length(AK) <> ScalarSize then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidKeyLength);
  AK[0] := AK[0] and $F8;
  AK[ScalarSize - 1] := AK[ScalarSize - 1] and $7F;
  AK[ScalarSize - 1] := AK[ScalarSize - 1] or $40;
end;

class function TX25519.Decode32(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32;
var
  LN: UInt32;
begin
  LN := ABs[AOff];
  LN := LN or (UInt32(ABs[AOff + 1]) shl 8);
  LN := LN or (UInt32(ABs[AOff + 2]) shl 16);
  LN := LN or (UInt32(ABs[AOff + 3]) shl 24);
  Result := LN;
end;

class procedure TX25519.DecodeScalar(const AK: TCryptoLibByteArray; AKOff: Int32;
  AN: TCryptoLibUInt32Array);
var
  LI: Int32;
begin
  LI := 0;
  while LI < 8 do
  begin
    AN[LI] := Decode32(AK, AKOff + LI * 4);
    System.Inc(LI);
  end;
  AN[0] := AN[0] and $FFFFFFF8;
  AN[7] := AN[7] and $7FFFFFFF;
  AN[7] := AN[7] or $40000000;
end;

class procedure TX25519.GeneratePrivateKey(const ARandom: ISecureRandom; const AK: TCryptoLibByteArray);
begin
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

class procedure TX25519.PointDouble(AX, AZ: TCryptoLibInt32Array);
var
  LA, LB: TCryptoLibInt32Array;
begin
  LA := TX25519Field.Create();
  LB := TX25519Field.Create();
  TX25519Field.Apm(AX, AZ, LA, LB);
  TX25519Field.Sqr(LA, LA);
  TX25519Field.Sqr(LB, LB);
  TX25519Field.Mul(LA, LB, AX);
  TX25519Field.Sub(LA, LB, LA);
  TX25519Field.Mul(LA, C_A24, AZ);
  TX25519Field.Add(AZ, LB, AZ);
  TX25519Field.Mul(AZ, LA, AZ);
end;

class procedure TX25519.Precompute;
begin
  TEd25519.Precompute();
end;

class procedure TX25519.ScalarMult(const AK: TCryptoLibByteArray; AKOff: Int32;
  const AU: TCryptoLibByteArray; AUOff: Int32; AR: TCryptoLibByteArray; AROff: Int32);
var
  LN: TCryptoLibUInt32Array;
  LX1, LX2, LZ2, LX3, LZ3: TCryptoLibInt32Array;
  LT1, LT2: TCryptoLibInt32Array;
  LBit, LSwap, LWord, LShift, LKt: Int32;
  LI: Int32;
begin
  System.SetLength(LN, 8);
  DecodeScalar(AK, AKOff, LN);
  LX1 := TX25519Field.Create();
  TX25519Field.Decode(AU, AUOff, LX1);
  LX2 := TX25519Field.Create();
  TX25519Field.Copy(LX1, 0, LX2, 0);
  LZ2 := TX25519Field.Create();
  LZ2[0] := 1;
  LX3 := TX25519Field.Create();
  LX3[0] := 1;
  LZ3 := TX25519Field.Create();
  LT1 := TX25519Field.Create();
  LT2 := TX25519Field.Create();
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

class procedure TX25519.ScalarMultBase(const AK: TCryptoLibByteArray; AKOff: Int32;
  AR: TCryptoLibByteArray; AROff: Int32);
var
  LY, LZ: TCryptoLibInt32Array;
begin
  LY := TX25519Field.Create();
  LZ := TX25519Field.Create();
  TEd25519.ScalarMultBaseYZ(AK, AKOff, LY, LZ);
  TX25519Field.Apm(LZ, LY, LY, LZ);
  TX25519Field.Inv(LZ, LZ);
  TX25519Field.Mul(LY, LZ, LY);
  TX25519Field.Normalize(LY);
  TX25519Field.Encode(LY, AR, AROff);
end;

end.
