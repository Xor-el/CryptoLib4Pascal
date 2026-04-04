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

unit ClpTables4kGcmMultiplier;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIGcmMultiplier,
  ClpGcmUtilities,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

type
  TTables4kGcmMultiplier = class(TInterfacedObject, IGcmMultiplier)
  strict private
    FH: TCryptoLibByteArray;
    FT: TCryptoLibGenericArray<TFieldElement>;
  public
    procedure Init(const AH: TCryptoLibByteArray);
    procedure MultiplyH(const AX: TCryptoLibByteArray);
  end;

implementation

{ TTables4kGcmMultiplier }

procedure TTables4kGcmMultiplier.Init(const AH: TCryptoLibByteArray);
var
  LN: Int32;
begin
  if FT = nil then
  begin
    System.SetLength(FT, 256);
  end
  else if TArrayUtilities.AreEqual(FH, AH) then
  begin
    Exit;
  end;

  FH := System.Copy(AH);

  TGcmUtilities.AsFieldElement(FH, FT[1]);
  TGcmUtilities.MultiplyP7(FT[1]);

  for LN := 1 to 127 do
  begin
    TGcmUtilities.DivideP(FT[LN], FT[LN shl 1]);
    TGcmUtilities.&Xor(FT[LN shl 1], FT[1], FT[(LN shl 1) + 1]);
  end;
end;

procedure TTables4kGcmMultiplier.MultiplyH(const AX: TCryptoLibByteArray);
var
  LPos, LI: Int32;
  LZ0, LZ1, LC: UInt64;
begin
  LPos := AX[15];
  LZ0 := FT[LPos].N0;
  LZ1 := FT[LPos].N1;

  for LI := 14 downto 0 do
  begin
    LPos := AX[LI];

    LC := LZ1 shl 56;
    LZ1 := FT[LPos].N1 xor ((LZ1 shr 8) or (LZ0 shl 56));
    LZ0 := FT[LPos].N0 xor (LZ0 shr 8) xor LC xor (LC shr 1) xor (LC shr 2) xor (LC shr 7);
  end;

  TGcmUtilities.AsBytes(LZ0, LZ1, AX);
end;

end.
