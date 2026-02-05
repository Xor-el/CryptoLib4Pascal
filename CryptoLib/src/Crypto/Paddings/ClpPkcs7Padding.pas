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

unit ClpPkcs7Padding;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipherPadding,
  ClpIPkcs7Padding,
  ClpISecureRandom,
  ClpCryptoLibTypes;

resourcestring
  SCorruptedPadBlock = 'Pad Block Corrupted';

type
  TPkcs7Padding = class sealed(TInterfacedObject, IPkcs7Padding,
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

function TPkcs7Padding.AddPadding(const AInput: TCryptoLibByteArray;
  AInOff: Int32): Int32;
var
  LCode: Byte;
begin
  LCode := Byte(System.Length(AInput) - AInOff);
  while (AInOff < System.Length(AInput)) do
  begin
    AInput[AInOff] := LCode;
    System.Inc(AInOff);
  end;
  Result := LCode;
end;

function TPkcs7Padding.GetPaddingName: String;
begin
  Result := 'PKCS7';
end;

{$IFNDEF _FIXINSIGHT_}
procedure TPkcs7Padding.Init(const ARandom: ISecureRandom);
begin
end;
{$ENDIF}

function TPkcs7Padding.PadCount(const AInput: TCryptoLibByteArray): Int32;
var
  LCountAsByte: Byte;
  LCount, LI: Int32;
  LFailed: Boolean;
begin
  LCount := AInput[System.Length(AInput) - 1] and $FF;
  LCountAsByte := Byte(LCount);
  LFailed := ((LCount > System.Length(AInput)) or (LCount = 0));
  for LI := 0 to System.Pred(System.Length(AInput)) do
    LFailed := LFailed or ((System.Length(AInput) - LI <= LCount) and
      (AInput[LI] <> LCountAsByte));
  if (LFailed) then
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SCorruptedPadBlock);
  Result := LCount;
end;

end.
