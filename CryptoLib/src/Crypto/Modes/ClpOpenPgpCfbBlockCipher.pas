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

unit ClpOpenPgpCfbBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIBlockCipherMode,
  ClpIOpenPgpCfbBlockCipher,
  ClpICipherParameters,
  ClpIParametersWithIV,
  ClpCheck,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SInputBufferTooShort = 'Input Buffer too Short';
  SOutputBufferTooShort = 'Output Buffer too Short';

type
  TOpenPgpCfbBlockCipher = class sealed(TInterfacedObject,
    IOpenPgpCfbBlockCipher, IBlockCipherMode, IBlockCipher)

  strict private
  var
    FIV, FFR, FFRE: TCryptoLibByteArray;
    FBlockSize: Int32;
    FCipher: IBlockCipher;
    FCount: Int32;
    FForEncryption: Boolean;

    function GetAlgorithmName: String; inline;
    function GetIsPartialBlockOkay: Boolean; inline;

    function EncryptByte(AData: Byte; ABlockOff: Int32): Byte; inline;

    function EncryptBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;
    function DecryptBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;

  public
    constructor Create(const ACipher: IBlockCipher);
    function GetUnderlyingCipher(): IBlockCipher;
    procedure Init(AForEncryption: Boolean;
      const AParameters: ICipherParameters);
    function GetBlockSize(): Int32; inline;
    function ProcessBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
    procedure Reset(); inline;
    property AlgorithmName: String read GetAlgorithmName;
    property IsPartialBlockOkay: Boolean read GetIsPartialBlockOkay;
  end;

implementation

{ TOpenPgpCfbBlockCipher }

constructor TOpenPgpCfbBlockCipher.Create(const ACipher: IBlockCipher);
begin
  inherited Create();
  FCipher := ACipher;
  FBlockSize := ACipher.GetBlockSize();

  System.SetLength(FIV, FBlockSize);
  System.SetLength(FFR, FBlockSize);
  System.SetLength(FFRE, FBlockSize);
end;

function TOpenPgpCfbBlockCipher.EncryptByte(AData: Byte;
  ABlockOff: Int32): Byte;
begin
  Result := Byte(FFRE[ABlockOff] xor AData);
end;

function TOpenPgpCfbBlockCipher.EncryptBlock(
  const AInput: TCryptoLibByteArray; AInOff: Int32;
  const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LN: Int32;
begin
  TCheck.DataLength(AInput, AInOff, FBlockSize, SInputBufferTooShort);
  TCheck.OutputLength(AOutBytes, AOutOff, FBlockSize, SOutputBufferTooShort);

  if (FCount > FBlockSize) then
  begin
    FFR[FBlockSize - 2] := EncryptByte(AInput[AInOff], FBlockSize - 2);
    AOutBytes[AOutOff] := FFR[FBlockSize - 2];

    FFR[FBlockSize - 1] := EncryptByte(AInput[AInOff + 1], FBlockSize - 1);
    AOutBytes[AOutOff + 1] := FFR[FBlockSize - 1];

    FCipher.ProcessBlock(FFR, 0, FFRE, 0);

    for LN := 2 to System.Pred(FBlockSize) do
    begin
      FFR[LN - 2] := EncryptByte(AInput[AInOff + LN], LN - 2);
      AOutBytes[AOutOff + LN] := FFR[LN - 2];
    end;
  end
  else if (FCount = 0) then
  begin
    FCipher.ProcessBlock(FFR, 0, FFRE, 0);

    for LN := 0 to System.Pred(FBlockSize) do
    begin
      FFR[LN] := EncryptByte(AInput[AInOff + LN], LN);
      AOutBytes[AOutOff + LN] := FFR[LN];
    end;

    FCount := FCount + FBlockSize;
  end
  else if (FCount = FBlockSize) then
  begin
    FCipher.ProcessBlock(FFR, 0, FFRE, 0);

    AOutBytes[AOutOff] := EncryptByte(AInput[AInOff], 0);
    AOutBytes[AOutOff + 1] := EncryptByte(AInput[AInOff + 1], 1);

    System.Move(FFR[2], FFR[0], (FBlockSize - 2) * System.SizeOf(Byte));
    System.Move(AOutBytes[AOutOff], FFR[FBlockSize - 2],
      2 * System.SizeOf(Byte));

    FCipher.ProcessBlock(FFR, 0, FFRE, 0);

    for LN := 2 to System.Pred(FBlockSize) do
    begin
      FFR[LN - 2] := EncryptByte(AInput[AInOff + LN], LN - 2);
      AOutBytes[AOutOff + LN] := FFR[LN - 2];
    end;

    FCount := FCount + FBlockSize;
  end;

  Result := FBlockSize;
end;

function TOpenPgpCfbBlockCipher.DecryptBlock(
  const AInput: TCryptoLibByteArray; AInOff: Int32;
  const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LN: Int32;
  LInVal, LInVal1, LInVal2: Byte;
begin
  TCheck.DataLength(AInput, AInOff, FBlockSize, SInputBufferTooShort);
  TCheck.OutputLength(AOutBytes, AOutOff, FBlockSize, SOutputBufferTooShort);

  if (FCount > FBlockSize) then
  begin
    LInVal := AInput[AInOff];
    FFR[FBlockSize - 2] := LInVal;
    AOutBytes[AOutOff] := EncryptByte(LInVal, FBlockSize - 2);

    LInVal := AInput[AInOff + 1];
    FFR[FBlockSize - 1] := LInVal;
    AOutBytes[AOutOff + 1] := EncryptByte(LInVal, FBlockSize - 1);

    FCipher.ProcessBlock(FFR, 0, FFRE, 0);

    for LN := 2 to System.Pred(FBlockSize) do
    begin
      LInVal := AInput[AInOff + LN];
      FFR[LN - 2] := LInVal;
      AOutBytes[AOutOff + LN] := EncryptByte(LInVal, LN - 2);
    end;
  end
  else if (FCount = 0) then
  begin
    FCipher.ProcessBlock(FFR, 0, FFRE, 0);

    for LN := 0 to System.Pred(FBlockSize) do
    begin
      FFR[LN] := AInput[AInOff + LN];
      AOutBytes[AOutOff + LN] := EncryptByte(AInput[AInOff + LN], LN);
    end;

    FCount := FCount + FBlockSize;
  end
  else if (FCount = FBlockSize) then
  begin
    FCipher.ProcessBlock(FFR, 0, FFRE, 0);

    LInVal1 := AInput[AInOff];
    LInVal2 := AInput[AInOff + 1];
    AOutBytes[AOutOff] := EncryptByte(LInVal1, 0);
    AOutBytes[AOutOff + 1] := EncryptByte(LInVal2, 1);

    System.Move(FFR[2], FFR[0], (FBlockSize - 2) * System.SizeOf(Byte));
    FFR[FBlockSize - 2] := LInVal1;
    FFR[FBlockSize - 1] := LInVal2;

    FCipher.ProcessBlock(FFR, 0, FFRE, 0);

    for LN := 2 to System.Pred(FBlockSize) do
    begin
      LInVal := AInput[AInOff + LN];
      FFR[LN - 2] := LInVal;
      AOutBytes[AOutOff + LN] := EncryptByte(LInVal, LN - 2);
    end;

    FCount := FCount + FBlockSize;
  end;

  Result := FBlockSize;
end;

procedure TOpenPgpCfbBlockCipher.Reset;
begin
  FCount := 0;
  System.Move(FIV[0], FFR[0], System.Length(FFR) * System.SizeOf(Byte));
end;

function TOpenPgpCfbBlockCipher.GetAlgorithmName: String;
begin
  Result := FCipher.AlgorithmName + '/OpenPGPCFB';
end;

function TOpenPgpCfbBlockCipher.GetBlockSize: Int32;
begin
  Result := FCipher.GetBlockSize();
end;

function TOpenPgpCfbBlockCipher.GetIsPartialBlockOkay: Boolean;
begin
  Result := True;
end;

function TOpenPgpCfbBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  Result := FCipher;
end;

procedure TOpenPgpCfbBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LIvParam: IParametersWithIV;
  LIv: TCryptoLibByteArray;
  LParameters: ICipherParameters;
begin
  FForEncryption := AForEncryption;
  LParameters := AParameters;

  if Supports(LParameters, IParametersWithIV, LIvParam) then
  begin
    LIv := LIvParam.GetIV();
    if (System.Length(LIv) < System.Length(FIV)) then
    begin
      System.Move(LIv[0], FIV[System.Length(FIV) - System.Length(LIv)],
        System.Length(LIv) * System.SizeOf(Byte));
      TArrayUtilities.Fill<Byte>(FIV, 0,
        System.Length(FIV) - System.Length(LIv), Byte(0));
    end
    else
    begin
      System.Move(LIv[0], FIV[0], System.Length(FIV) * System.SizeOf(Byte));
    end;
    LParameters := LIvParam.Parameters;
  end;

  Reset();
  FCipher.Init(True, LParameters);
end;

function TOpenPgpCfbBlockCipher.ProcessBlock(
  const AInput: TCryptoLibByteArray; AInOff: Int32;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  if FForEncryption then
    Result := EncryptBlock(AInput, AInOff, AOutput, AOutOff)
  else
    Result := DecryptBlock(AInput, AInOff, AOutput, AOutOff);
end;

end.
