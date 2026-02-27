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

unit ClpTables8kGcmMultiplier;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIGcmMultiplier,
  ClpGcmUtilities,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

type
  TTables8kGcmMultiplier = class(TInterfacedObject, IGcmMultiplier)
  strict private
    FH: TCryptoLibByteArray;
    FT: TCryptoLibMatrixGenericArray<TFieldElement>;
  public
    procedure Init(const AH: TCryptoLibByteArray);
    procedure MultiplyH(const AX: TCryptoLibByteArray);
  end;

implementation

{ TTables8kGcmMultiplier }

procedure TTables8kGcmMultiplier.Init(const AH: TCryptoLibByteArray);
var
  LI, LN: Int32;
  LT: TCryptoLibGenericArray<TFieldElement>;
begin
  if FT = nil then
  begin
    System.SetLength(FT, 2);
  end
  else if TArrayUtilities.AreEqual(FH, AH) then
  begin
    Exit;
  end;

  FH := System.Copy(AH);

  for LI := 0 to 1 do
  begin
    System.SetLength(FT[LI], 256);
    LT := FT[LI];

    if LI = 0 then
    begin
      TGcmUtilities.AsFieldElement(FH, LT[1]);
      TGcmUtilities.MultiplyP7(LT[1]);
    end
    else
    begin
      TGcmUtilities.MultiplyP8(FT[LI - 1][1], LT[1]);
    end;

    for LN := 1 to 127 do
    begin
      TGcmUtilities.DivideP(LT[LN], LT[LN shl 1]);
      TGcmUtilities.&Xor(LT[LN shl 1], LT[1], LT[(LN shl 1) + 1]);
    end;
  end;
end;

procedure TTables8kGcmMultiplier.MultiplyH(const AX: TCryptoLibByteArray);
var
  LT0, LT1: TCryptoLibGenericArray<TFieldElement>;
  LVPos, LUPos, LI: Int32;
  LZ0, LZ1, LC: UInt64;
begin
  LT0 := FT[0];
  LT1 := FT[1];

  LVPos := AX[15];
  LUPos := AX[14];
  LZ1 := LT0[LUPos].N1 xor LT1[LVPos].N1;
  LZ0 := LT0[LUPos].N0 xor LT1[LVPos].N0;

  LI := 12;
  while LI >= 0 do
  begin
    LVPos := AX[LI + 1];
    LUPos := AX[LI];

    LC := LZ1 shl 48;
    LZ1 := LT0[LUPos].N1 xor LT1[LVPos].N1 xor ((LZ1 shr 16) or (LZ0 shl 48));
    LZ0 := LT0[LUPos].N0 xor LT1[LVPos].N0 xor (LZ0 shr 16) xor LC xor (LC shr 1) xor (LC shr 2) xor (LC shr 7);

    System.Dec(LI, 2);
  end;

  TGcmUtilities.AsBytes(LZ0, LZ1, AX);
end;

end.
