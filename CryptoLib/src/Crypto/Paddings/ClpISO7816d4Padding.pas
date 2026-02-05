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

unit ClpISO7816d4Padding;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipherPadding,
  ClpIISO7816d4Padding,
  ClpISecureRandom,
  ClpCryptoLibTypes;

resourcestring
  SCorruptedPadBlock = 'Pad Block Corrupted';

type
  TISO7816d4Padding = class sealed(TInterfacedObject, IISO7816d4Padding,
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

function TISO7816d4Padding.AddPadding(const AInput: TCryptoLibByteArray;
  AInOff: Int32): Int32;
var
  LAdded: Int32;
begin
  LAdded := (System.Length(AInput) - AInOff);
  AInput[AInOff] := Byte($80);
  System.Inc(AInOff);
  while (AInOff < System.Length(AInput)) do
  begin
    AInput[AInOff] := Byte(0);
    System.Inc(AInOff);
  end;
  Result := LAdded;
end;

function TISO7816d4Padding.GetPaddingName: String;
begin
  Result := 'ISO7816-4';
end;

{$IFNDEF _FIXINSIGHT_}
procedure TISO7816d4Padding.Init(const ARandom: ISecureRandom);
begin
end;
{$ENDIF}

function TISO7816d4Padding.PadCount(const AInput: TCryptoLibByteArray): Int32;
var
  LCount: Int32;
begin
  LCount := System.Length(AInput) - 1;
  while ((LCount > 0) and (AInput[LCount] = 0)) do
    System.Dec(LCount);
  if (AInput[LCount] <> Byte($80)) then
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SCorruptedPadBlock);
  Result := System.Length(AInput) - LCount;
end;

end.
