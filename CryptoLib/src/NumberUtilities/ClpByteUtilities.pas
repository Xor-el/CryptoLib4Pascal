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

unit ClpByteUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpNat,
  ClpBinaryPrimitives,
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
    /// <summary>
    ///   Triple-XOR: AZ := AX xor AY. Intentionally NOT inline: FPC 3.2 for
    ///   i386 miscompiles the equivalent loop when inlined inside pipelined
    ///   GCM steps at -O3, so the CALL boundary is load-bearing.
    /// </summary>
    class procedure &Xor(ALen: Int32; AX, AY, AZ: PByte); overload; static;
    class procedure &Xor(ALen: Int32; AX, AY, AZ: PByte; AXOff, AYOff, AZOff: Integer); overload; static;

    class procedure XorTo(ALen: Int32; const AX, AZ: TCryptoLibByteArray); overload; static;
    class procedure XorTo(ALen: Int32; const AX: TCryptoLibByteArray; AXOff: Int32;
      const AZ: TCryptoLibByteArray; AZOff: Int32); overload; static;
    class procedure XorTo(ALen: Int32; AX, AZ: PByte); overload; static;
    class procedure XorTo(ALen: Int32; AX, AZ: PByte; AXOff, AZOff: Integer); overload; static;

    class procedure CMov(ALen: Int32; ACond: Int32; const AX, AZ: TCryptoLibByteArray); overload; static;
    class procedure CMov(ALen: Int32; ACond: Int32; const AX: TCryptoLibByteArray; AXOff: Int32;
      const AZ: TCryptoLibByteArray; AZOff: Int32); overload; static;
  end;

implementation

{ TByteUtilities }

class procedure TByteUtilities.&Xor(ALen: Int32; AX, AY, AZ: PByte);
var
  LI, LQwords: Int32;
  PSrcA, PSrcB, PDst: PByte;
begin
  if ALen <= 0 then
    Exit;

  PSrcA := AX;
  PSrcB := AY;
  PDst := AZ;

  if (ALen >= 8) and
    ((NativeUInt(PSrcA) or NativeUInt(PSrcB) or NativeUInt(PDst) or NativeUInt(ALen)) and 7 = 0) then
  begin
    LQwords := ALen shr 3;
    for LI := 0 to LQwords - 1 do
      TBinaryPrimitives.StoreUInt64(PUInt64(PDst + (LI * 8)),
        TBinaryPrimitives.LoadUInt64(PUInt64(PSrcA + (LI * 8))) xor
        TBinaryPrimitives.LoadUInt64(PUInt64(PSrcB + (LI * 8))));
    Exit;
  end;

  for LI := 0 to ALen - 1 do
    PDst[LI] := Byte(PSrcA[LI] xor PSrcB[LI]);
end;

class procedure TByteUtilities.&Xor(ALen: Int32; AX, AY, AZ: PByte;
  AXOff, AYOff, AZOff: Integer);
begin
  &Xor(ALen, AX + AXOff, AY + AYOff, AZ + AZOff);
end;

class procedure TByteUtilities.&Xor(ALen: Int32; const AX, AY, AZ: TCryptoLibByteArray);
begin
  &Xor(ALen, PByte(AX), PByte(AY), PByte(AZ));
end;

class procedure TByteUtilities.&Xor(ALen: Int32; const AX: TCryptoLibByteArray; AXOff: Int32;
  const AY: TCryptoLibByteArray; AYOff: Int32;
  const AZ: TCryptoLibByteArray; AZOff: Int32);
begin
  &Xor(ALen, PByte(AX), PByte(AY), PByte(AZ), AXOff, AYOff, AZOff);
end;

class procedure TByteUtilities.XorTo(ALen: Int32; AX, AZ: PByte);
var
  LI, LQwords: Int32;
  PSrc, PDst: PByte;
begin
  if ALen <= 0 then
    Exit;

  PSrc := AX;
  PDst := AZ;

  if (ALen >= 8) and
    ((NativeUInt(PSrc) or NativeUInt(PDst) or NativeUInt(ALen)) and 7 = 0) then
  begin
    LQwords := ALen shr 3;
    for LI := 0 to LQwords - 1 do
      TBinaryPrimitives.StoreUInt64(PUInt64(PDst + (LI * 8)),
        TBinaryPrimitives.LoadUInt64(PUInt64(PDst + (LI * 8))) xor
        TBinaryPrimitives.LoadUInt64(PUInt64(PSrc + (LI * 8))));
    Exit;
  end;

  for LI := 0 to ALen - 1 do
    PDst[LI] := PDst[LI] xor PSrc[LI];
end;

class procedure TByteUtilities.XorTo(ALen: Int32; AX, AZ: PByte; AXOff, AZOff: Integer);
begin
  XorTo(ALen, AX + AXOff, AZ + AZOff);
end;

class procedure TByteUtilities.XorTo(ALen: Int32; const AX, AZ: TCryptoLibByteArray);
begin
  XorTo(ALen, PByte(AX), PByte(AZ));
end;

class procedure TByteUtilities.XorTo(ALen: Int32; const AX: TCryptoLibByteArray; AXOff: Int32;
  const AZ: TCryptoLibByteArray; AZOff: Int32);
begin
  XorTo(ALen, PByte(AX), PByte(AZ), AXOff, AZOff);
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
