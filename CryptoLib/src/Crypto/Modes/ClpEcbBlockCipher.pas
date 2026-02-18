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

unit ClpEcbBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIBlockCipherMode,
  ClpIEcbBlockCipher,
  ClpICipherParameters,
  ClpCryptoLibTypes;

type
  TEcbBlockCipher = class(TInterfacedObject, IEcbBlockCipher,
    IBlockCipherMode, IBlockCipher)

  strict private
  var
    FCipher: IBlockCipher;

    function GetAlgorithmName: String;
    function GetIsPartialBlockOkay: Boolean;

  public
    class function GetBlockCipherMode(const ABlockCipher: IBlockCipher)
      : IBlockCipherMode; static;

    constructor Create(const ACipher: IBlockCipher);

    function GetBlockSize(): Int32;

    function GetUnderlyingCipher: IBlockCipher;

    procedure Init(AForEncryption: Boolean;
      const AParameters: ICipherParameters);

    function ProcessBlock(const AInBuf: TCryptoLibByteArray; AInOff: Int32;
      const AOutBuf: TCryptoLibByteArray; AOutOff: Int32): Int32;

    procedure Reset();

    property AlgorithmName: String read GetAlgorithmName;
    property IsPartialBlockOkay: Boolean read GetIsPartialBlockOkay;
    property UnderlyingCipher: IBlockCipher read GetUnderlyingCipher;
  end;

implementation

{ TEcbBlockCipher }

class function TEcbBlockCipher.GetBlockCipherMode(
  const ABlockCipher: IBlockCipher): IBlockCipherMode;
var
  LBlockCipherMode: IBlockCipherMode;
begin
  if Supports(ABlockCipher, IBlockCipherMode, LBlockCipherMode) then
    Result := LBlockCipherMode
  else
    Result := TEcbBlockCipher.Create(ABlockCipher);
end;

constructor TEcbBlockCipher.Create(const ACipher: IBlockCipher);
begin
  inherited Create();
  if ACipher = nil then
    raise EArgumentNilCryptoLibException.Create('ACipher');
  FCipher := ACipher;
end;

function TEcbBlockCipher.GetAlgorithmName: String;
begin
  Result := FCipher.AlgorithmName + '/ECB';
end;

function TEcbBlockCipher.GetBlockSize: Int32;
begin
  Result := FCipher.GetBlockSize();
end;

function TEcbBlockCipher.GetIsPartialBlockOkay: Boolean;
begin
  Result := False;
end;

function TEcbBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  Result := FCipher;
end;

procedure TEcbBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
begin
  FCipher.Init(AForEncryption, AParameters);
end;

function TEcbBlockCipher.ProcessBlock(const AInBuf: TCryptoLibByteArray;
  AInOff: Int32; const AOutBuf: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  Result := FCipher.ProcessBlock(AInBuf, AInOff, AOutBuf, AOutOff);
end;

procedure TEcbBlockCipher.Reset;
begin
  // no-op
end;

end.
