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

unit ClpTables64kGcmMultiplier;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIGcmMultiplier,
  ClpGcmUtilities,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

type
  TTables64kGcmMultiplier = class(TInterfacedObject, IGcmMultiplier)
  strict private
    FH: TCryptoLibByteArray;
    FT: TCryptoLibMatrixGenericArray<TFieldElement>;
  public
    procedure Init(const AH: TCryptoLibByteArray);
    procedure MultiplyH(const AX: TCryptoLibByteArray);
  end;

implementation

{ TTables64kGcmMultiplier }

procedure TTables64kGcmMultiplier.Init(const AH: TCryptoLibByteArray);
var
  LI, LN: Int32;
  LT: TCryptoLibGenericArray<TFieldElement>;
begin
  if FT = nil then
  begin
    System.SetLength(FT, 16);
  end
  else if TArrayUtilities.AreEqual(FH, AH) then
  begin
    Exit;
  end;

  FH := System.Copy(AH);

  for LI := 0 to 15 do
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

procedure TTables64kGcmMultiplier.MultiplyH(const AX: TCryptoLibByteArray);
var
  LT: TCryptoLibGenericArray<TFieldElement>;
  LTPos, LI: Int32;
  LZ0, LZ1: UInt64;
begin
  LT := FT[15];
  LTPos := AX[15];
  LZ0 := LT[LTPos].N0;
  LZ1 := LT[LTPos].N1;

  for LI := 14 downto 0 do
  begin
    LT := FT[LI];
    LTPos := AX[LI];
    LZ0 := LZ0 xor LT[LTPos].N0;
    LZ1 := LZ1 xor LT[LTPos].N1;
  end;

  TGcmUtilities.AsBytes(LZ0, LZ1, AX);
end;

end.
