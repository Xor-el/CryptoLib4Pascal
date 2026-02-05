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

unit ClpZeroBytePadding;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipherPadding,
  ClpIZeroBytePadding,
  ClpISecureRandom,
  ClpCryptoLibTypes;

type
  TZeroBytePadding = class sealed(TInterfacedObject, IZeroBytePadding,
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

function TZeroBytePadding.AddPadding(const AInput: TCryptoLibByteArray;
  AInOff: Int32): Int32;
var
  LAdded: Int32;
begin
  LAdded := System.Length(AInput) - AInOff;

  while (AInOff < System.Length(AInput)) do
  begin
    AInput[AInOff] := Byte(0);
    System.Inc(AInOff);
  end;

  Result := LAdded;
end;

function TZeroBytePadding.GetPaddingName: String;
begin
  Result := 'ZeroBytePadding';
end;

{$IFNDEF _FIXINSIGHT_}
procedure TZeroBytePadding.Init(const ARandom: ISecureRandom);
begin
  // nothing to do.
end;
{$ENDIF}

function TZeroBytePadding.PadCount(const AInput: TCryptoLibByteArray): Int32;
var
  LCount: Int32;
begin
  LCount := System.Length(AInput);
  while (LCount > 0) do
  begin
    if (AInput[LCount - 1] <> 0) then
      break;
    System.Dec(LCount);
  end;

  Result := System.Length(AInput) - LCount;
end;

end.
