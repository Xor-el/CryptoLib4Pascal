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

unit ClpCbcBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpICbcBlockCipher,
  ClpICipherParameters,
  ClpIParametersWithIV,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SInvalidIVLength =
    'Initialisation Vector Must be the Same Length as Block Size';
  SInvalidChangeState = 'Cannot Change Encrypting State Without Providing Key.';
  SInputBufferTooShort = 'Input Buffer too Short';
  SOutputBufferTooShort = 'Output Buffer too Short';

type
  TCbcBlockCipher = class sealed(TInterfacedObject, ICbcBlockCipher,
    IBlockCipher)

  strict private
  var
    FIV, FCbcV, FCbcNextV: TCryptoLibByteArray;
    FBlockSize: Int32;
    FCipher: IBlockCipher;
    FEncrypting: Boolean;

    function GetAlgorithmName: String; inline;
    function GetIsPartialBlockOkay: Boolean; inline;
    function EncryptBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;
    function DecryptBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;

  public
    constructor Create(const ACipher: IBlockCipher);
    function GetUnderlyingCipher(): IBlockCipher;
    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters);
    function GetBlockSize(): Int32; inline;
    function ProcessBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
    procedure Reset(); inline;
    property AlgorithmName: String read GetAlgorithmName;
    property IsPartialBlockOkay: Boolean read GetIsPartialBlockOkay;
  end;

implementation

{ TCbcBlockCipher }

constructor TCbcBlockCipher.Create(const ACipher: IBlockCipher);
begin
  inherited Create();
  FCipher := ACipher;
  FBlockSize := ACipher.GetBlockSize();
  System.SetLength(FIV, FBlockSize);
  System.SetLength(FCbcV, FBlockSize);
  System.SetLength(FCbcNextV, FBlockSize);
end;

function TCbcBlockCipher.DecryptBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LLength, LI: Int32;
  LTmp: TCryptoLibByteArray;
begin
  if ((AInOff + FBlockSize) > System.Length(AInput)) then
    raise EDataLengthCryptoLibException.CreateRes(@SInputBufferTooShort);
  System.Move(AInput[AInOff], FCbcNextV[0], FBlockSize * System.SizeOf(Byte));
  LLength := FCipher.ProcessBlock(AInput, AInOff, AOutBytes, AOutOff);
  for LI := 0 to System.Pred(FBlockSize) do
    AOutBytes[AOutOff + LI] := AOutBytes[AOutOff + LI] xor FCbcV[LI];
  LTmp := FCbcV;
  FCbcV := FCbcNextV;
  FCbcNextV := LTmp;
  Result := LLength;
end;

function TCbcBlockCipher.EncryptBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LI, LLen: Int32;
begin
  if ((AInOff + FBlockSize) > System.Length(AInput)) then
    raise EDataLengthCryptoLibException.CreateRes(@SInputBufferTooShort);
  for LI := 0 to System.Pred(FBlockSize) do
    FCbcV[LI] := FCbcV[LI] xor AInput[AInOff + LI];
  LLen := FCipher.ProcessBlock(FCbcV, 0, AOutBytes, AOutOff);
  System.Move(AOutBytes[AOutOff], FCbcV[0], System.Length(FCbcV) * System.SizeOf(Byte));
  Result := LLen;
end;

procedure TCbcBlockCipher.Reset;
begin
  System.Move(FIV[0], FCbcV[0], System.Length(FIV));
  TArrayUtilities.Fill<Byte>(FCbcNextV, 0, System.Length(FCbcNextV), Byte(0));
  FCipher.Reset();
end;

function TCbcBlockCipher.GetAlgorithmName: String;
begin
  Result := FCipher.AlgorithmName + '/CBC';
end;

function TCbcBlockCipher.GetBlockSize: Int32;
begin
  Result := FCipher.GetBlockSize();
end;

function TCbcBlockCipher.GetIsPartialBlockOkay: Boolean;
begin
  Result := False;
end;

function TCbcBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  Result := FCipher;
end;

procedure TCbcBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LOldEncrypting: Boolean;
  LIvParam: IParametersWithIV;
  LIv: TCryptoLibByteArray;
  LParameters: ICipherParameters;
begin
  LOldEncrypting := FEncrypting;
  FEncrypting := AForEncryption;
  LParameters := AParameters;
  if Supports(LParameters, IParametersWithIV, LIvParam) then
  begin
    LIv := LIvParam.GetIV();
    if (System.Length(LIv) <> FBlockSize) then
      raise EArgumentCryptoLibException.CreateRes(@SInvalidIVLength);
    System.Move(LIv[0], FIV[0], System.Length(LIv) * System.SizeOf(Byte));
    LParameters := LIvParam.Parameters;
  end;
  Reset();
  if (LParameters <> nil) then
    FCipher.Init(FEncrypting, LParameters)
  else if (LOldEncrypting <> FEncrypting) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidChangeState);
end;

function TCbcBlockCipher.ProcessBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  if FEncrypting then
    Result := EncryptBlock(AInput, AInOff, AOutput, AOutOff)
  else
    Result := DecryptBlock(AInput, AInOff, AOutput, AOutOff);
end;

end.
