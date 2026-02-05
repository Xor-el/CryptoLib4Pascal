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

unit ClpCfbBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpICfbBlockCipher,
  ClpICipherParameters,
  ClpIParametersWithIV,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SInputBufferTooShort = 'Input Buffer too Short';
  SOutputBufferTooShort = 'Output Buffer too Short';

type
  TCfbBlockCipher = class sealed(TInterfacedObject, ICfbBlockCipher,
    IBlockCipher)

  strict private
  var
    FIV, FCfbV, FCfbOutV: TCryptoLibByteArray;
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
    constructor Create(const ACipher: IBlockCipher; ABitBlockSize: Int32);
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

{ TCfbBlockCipher }

constructor TCfbBlockCipher.Create(const ACipher: IBlockCipher;
  ABitBlockSize: Int32);
begin
  inherited Create();
  FCipher := ACipher;
  FBlockSize := ABitBlockSize div 8;

  System.SetLength(FIV, FCipher.GetBlockSize());
  System.SetLength(FCfbV, FCipher.GetBlockSize());
  System.SetLength(FCfbOutV, FCipher.GetBlockSize());
end;

function TCfbBlockCipher.DecryptBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LI, LCount: Int32;
begin
  if ((AInOff + FBlockSize) > System.Length(AInput)) then
    raise EDataLengthCryptoLibException.CreateRes(@SInputBufferTooShort);

  if ((AOutOff + FBlockSize) > System.Length(AOutBytes)) then
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooShort);

  FCipher.ProcessBlock(FCfbV, 0, FCfbOutV, 0);

  LCount := (System.Length(FCfbV) - FBlockSize) * System.SizeOf(Byte);
  if LCount > 0 then
    System.Move(FCfbV[FBlockSize], FCfbV[0], LCount);

  System.Move(AInput[AInOff], FCfbV[(System.Length(FCfbV) - FBlockSize)],
    FBlockSize * System.SizeOf(Byte));

  for LI := 0 to System.Pred(FBlockSize) do
    AOutBytes[AOutOff + LI] := Byte(FCfbOutV[LI] xor AInput[AInOff + LI]);

  Result := FBlockSize;
end;

function TCfbBlockCipher.EncryptBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LI, LCount: Int32;
begin
  if ((AInOff + FBlockSize) > System.Length(AInput)) then
    raise EDataLengthCryptoLibException.CreateRes(@SInputBufferTooShort);

  if ((AOutOff + FBlockSize) > System.Length(AOutBytes)) then
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooShort);

  FCipher.ProcessBlock(FCfbV, 0, FCfbOutV, 0);

  for LI := 0 to System.Pred(FBlockSize) do
    AOutBytes[AOutOff + LI] := Byte(FCfbOutV[LI] xor AInput[AInOff + LI]);

  LCount := (System.Length(FCfbV) - FBlockSize) * System.SizeOf(Byte);
  if LCount > 0 then
    System.Move(FCfbV[FBlockSize], FCfbV[0], LCount);

  System.Move(AOutBytes[AOutOff], FCfbV[(System.Length(FCfbV) - FBlockSize)],
    FBlockSize * System.SizeOf(Byte));

  Result := FBlockSize;
end;

procedure TCfbBlockCipher.Reset;
begin
  System.Move(FIV[0], FCfbV[0], System.Length(FIV));
  FCipher.Reset();
end;

function TCfbBlockCipher.GetAlgorithmName: String;
begin
  Result := FCipher.AlgorithmName + '/CFB' + IntToStr(FBlockSize * 8);
end;

function TCfbBlockCipher.GetBlockSize: Int32;
begin
  Result := FBlockSize;
end;

function TCfbBlockCipher.GetIsPartialBlockOkay: Boolean;
begin
  Result := True;
end;

function TCfbBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  Result := FCipher;
end;

procedure TCfbBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LIvParam: IParametersWithIV;
  LIv: TCryptoLibByteArray;
  LParameters: ICipherParameters;
  LDiff: Int32;
begin
  FEncrypting := AForEncryption;
  LParameters := AParameters;

  if Supports(LParameters, IParametersWithIV, LIvParam) then
  begin
    LIv := LIvParam.GetIV();
    LDiff := System.Length(FIV) - System.Length(LIv);
    System.Move(LIv[0], FIV[LDiff], System.Length(LIv) * System.SizeOf(Byte));
    TArrayUtilities.Fill<Byte>(FIV, 0, LDiff, Byte(0));
    LParameters := LIvParam.Parameters;
  end;

  Reset();
  if (LParameters <> nil) then
    FCipher.Init(True, LParameters);
end;

function TCfbBlockCipher.ProcessBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  if FEncrypting then
    Result := EncryptBlock(AInput, AInOff, AOutput, AOutOff)
  else
    Result := DecryptBlock(AInput, AInOff, AOutput, AOutOff);
end;

end.
