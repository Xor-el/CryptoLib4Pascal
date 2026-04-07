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

unit ClpByteUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpNat,
  ClpCryptoLibTypes;

type
  TByteUtilities = class sealed(TObject)
  public
    const
      NumBits: Int32 = 8;
      NumBytes: Int32 = 1;

    class procedure &Xor(ALen: Int32; const AX, AY, AZ: TCryptoLibByteArray); overload; static;
    class procedure &Xor(ALen: Int32; const AX: TCryptoLibByteArray; AXOff: Int32;
      const AY: TCryptoLibByteArray; AYOff: Int32;
      const AZ: TCryptoLibByteArray; AZOff: Int32); overload; static;

    class procedure XorTo(ALen: Int32; const AX, AZ: TCryptoLibByteArray); overload; static;
    class procedure XorTo(ALen: Int32; const AX: TCryptoLibByteArray; AXOff: Int32;
      const AZ: TCryptoLibByteArray; AZOff: Int32); overload; static;

    class procedure CMov(ALen: Int32; ACond: Int32; const AX, AZ: TCryptoLibByteArray); overload; static;
    class procedure CMov(ALen: Int32; ACond: Int32; const AX: TCryptoLibByteArray; AXOff: Int32;
      const AZ: TCryptoLibByteArray; AZOff: Int32); overload; static;
  end;

implementation

{ TByteUtilities }

class procedure TByteUtilities.&Xor(ALen: Int32; const AX, AY, AZ: TCryptoLibByteArray);
var
  LI: Int32;
begin
  for LI := 0 to ALen - 1 do
  begin
    AZ[LI] := Byte(AX[LI] xor AY[LI]);
  end;
end;

class procedure TByteUtilities.&Xor(ALen: Int32; const AX: TCryptoLibByteArray; AXOff: Int32;
  const AY: TCryptoLibByteArray; AYOff: Int32;
  const AZ: TCryptoLibByteArray; AZOff: Int32);
var
  LI: Int32;
begin
  for LI := 0 to ALen - 1 do
  begin
    AZ[AZOff + LI] := Byte(AX[AXOff + LI] xor AY[AYOff + LI]);
  end;
end;

class procedure TByteUtilities.XorTo(ALen: Int32; const AX, AZ: TCryptoLibByteArray);
var
  LI: Int32;
begin
  for LI := 0 to ALen - 1 do
  begin
    AZ[LI] := AZ[LI] xor AX[LI];
  end;
end;

class procedure TByteUtilities.XorTo(ALen: Int32; const AX: TCryptoLibByteArray; AXOff: Int32;
  const AZ: TCryptoLibByteArray; AZOff: Int32);
var
  LI: Int32;
begin
  for LI := 0 to ALen - 1 do
  begin
    AZ[AZOff + LI] := AZ[AZOff + LI] xor AX[AXOff + LI];
  end;
end;

class procedure TByteUtilities.CMov(ALen: Int32; ACond: Int32; const AX, AZ: TCryptoLibByteArray);
var
  LM0, LM1, LXI, LZI: UInt32;
  LI: Int32;
begin
  LM0 := TNat.CZero(UInt32(ACond));
  LM1 := not LM0;
  for LI := 0 to ALen - 1 do
  begin
    LXI := AX[LI];
    LZI := AZ[LI];
    AZ[LI] := Byte((LZI and LM0) or (LXI and LM1));
  end;
end;

class procedure TByteUtilities.CMov(ALen: Int32; ACond: Int32; const AX: TCryptoLibByteArray; AXOff: Int32;
  const AZ: TCryptoLibByteArray; AZOff: Int32);
var
  LM0, LM1, LXI, LZI: UInt32;
  LI: Int32;
begin
  LM0 := TNat.CZero(UInt32(ACond));
  LM1 := not LM0;
  for LI := 0 to ALen - 1 do
  begin
    LXI := AX[AXOff + LI];
    LZI := AZ[AZOff + LI];
    AZ[AZOff + LI] := Byte((LZI and LM0) or (LXI and LM1));
  end;
end;

end.
