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

unit ClpGcmUtilities;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBitOperations,
  ClpInt64Utilities,
  ClpPack,
  ClpInterleave,
  ClpCryptoLibTypes;

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
begin
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

end.
