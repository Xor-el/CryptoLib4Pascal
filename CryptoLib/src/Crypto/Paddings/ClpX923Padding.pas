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

unit ClpX923Padding;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipherPadding,
  ClpIX923Padding,
  ClpISecureRandom,
  ClpCryptoLibTypes;

resourcestring
  SCorruptedPadBlock = 'Pad Block Corrupted';

type
  TX923Padding = class sealed(TInterfacedObject, IX923Padding,
    IBlockCipherPadding)
  strict private
    FRandom: ISecureRandom;
    function GetPaddingName: String; inline;
  public
    procedure Init(const ARandom: ISecureRandom);
    function AddPadding(const AInput: TCryptoLibByteArray; AInOff: Int32): Int32;
    function PadCount(const AInput: TCryptoLibByteArray): Int32;
    property PaddingName: String read GetPaddingName;
  end;

implementation

function TX923Padding.AddPadding(const AInput: TCryptoLibByteArray;
  AInOff: Int32): Int32;
var
  LCode: Byte;
begin
  LCode := Byte(System.Length(AInput) - AInOff);
  while (AInOff < (System.Length(AInput) - 1)) do
  begin
    if (FRandom = nil) then
      AInput[AInOff] := 0
    else
      AInput[AInOff] := Byte(FRandom.NextInt32);
    System.Inc(AInOff);
  end;
  AInput[AInOff] := LCode;
  Result := LCode;
end;

function TX923Padding.GetPaddingName: String;
begin
  Result := 'X9.23';
end;

procedure TX923Padding.Init(const ARandom: ISecureRandom);
begin
  FRandom := ARandom;
end;

function TX923Padding.PadCount(const AInput: TCryptoLibByteArray): Int32;
var
  LCount: Int32;
begin
  LCount := AInput[System.Length(AInput) - 1] and $FF;
  if (LCount > System.Length(AInput)) then
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SCorruptedPadBlock);
  Result := LCount;
end;

end.
