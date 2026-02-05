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

unit ClpISO10126d2Padding;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipherPadding,
  ClpIISO10126d2Padding,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpCryptoLibTypes;

resourcestring
  SCorruptedPadBlock = 'Pad Block Corrupted';

type
  TISO10126d2Padding = class sealed(TInterfacedObject, IISO10126d2Padding,
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

function TISO10126d2Padding.AddPadding(const AInput: TCryptoLibByteArray;
  AInOff: Int32): Int32;
var
  LCode: Byte;
begin
  LCode := Byte(System.Length(AInput) - AInOff);
  while (AInOff < (System.Length(AInput) - 1)) do
  begin
    AInput[AInOff] := Byte(FRandom.NextInt32);
    System.Inc(AInOff);
  end;
  AInput[AInOff] := LCode;
  Result := LCode;
end;

function TISO10126d2Padding.GetPaddingName: String;
begin
  Result := 'ISO10126-2';
end;

procedure TISO10126d2Padding.Init(const ARandom: ISecureRandom);
begin
  if ARandom <> nil then
    FRandom := ARandom
  else
    FRandom := TSecureRandom.Create();
end;

function TISO10126d2Padding.PadCount(const AInput: TCryptoLibByteArray): Int32;
var
  LCount: Int32;
begin
  LCount := AInput[System.Length(AInput) - 1] and $FF;
  if (LCount > System.Length(AInput)) then
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SCorruptedPadBlock);
  Result := LCount;
end;

end.
