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

unit ClpTBCPadding;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipherPadding,
  ClpITBCPadding,
  ClpISecureRandom,
  ClpCryptoLibTypes;

type
  TTBCPadding = class sealed(TInterfacedObject, ITBCPadding,
    IBlockCipherPadding)
  strict private
    function GetPaddingName: String; inline;
  public
    procedure Init(const ARandom: ISecureRandom);
    function AddPadding(const AInput: TCryptoLibByteArray; AInOff: Int32): Int32;
    function PadCount(const AInput: TCryptoLibByteArray): Int32;
    property PaddingName: String read GetPaddingName;
  end;

implementation

function TTBCPadding.AddPadding(const AInput: TCryptoLibByteArray;
  AInOff: Int32): Int32;
var
  LCount: Int32;
  LCode: Byte;
begin
  LCount := System.Length(AInput) - AInOff;
  if (AInOff > 0) then
  begin
    if (AInput[AInOff - 1] and $01) = 0 then
      LCode := Byte($FF)
    else
      LCode := Byte($00);
  end
  else
  begin
    if (AInput[System.Length(AInput) - 1] and $01) = 0 then
      LCode := Byte($FF)
    else
      LCode := Byte($00);
  end;
  while (AInOff < System.Length(AInput)) do
  begin
    AInput[AInOff] := LCode;
    System.Inc(AInOff);
  end;
  Result := LCount;
end;

function TTBCPadding.GetPaddingName: String;
begin
  Result := 'TBC';
end;

{$IFNDEF _FIXINSIGHT_}
procedure TTBCPadding.Init(const ARandom: ISecureRandom);
begin
end;
{$ENDIF}

function TTBCPadding.PadCount(const AInput: TCryptoLibByteArray): Int32;
var
  LCode: Byte;
  LIndex: Int32;
begin
  LCode := AInput[System.Length(AInput) - 1];
  LIndex := System.Length(AInput) - 1;
  while ((LIndex > 0) and (AInput[LIndex - 1] = LCode)) do
    System.Dec(LIndex);
  Result := System.Length(AInput) - LIndex;
end;

end.
