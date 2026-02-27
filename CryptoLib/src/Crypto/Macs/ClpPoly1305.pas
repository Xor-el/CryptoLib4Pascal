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

unit ClpPoly1305;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIPoly1305,
  ClpIMac,
  ClpMac,
  ClpIBlockCipher,
  ClpICipherParameters,
  ClpIParametersWithIV,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpCheck,
  ClpPack,
  ClpBitOperations,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SCipherBlockSizeMismatch =
    'Poly1305 requires a 128-bit block cipher.';
  SParametersWithIVRequired =
    'Poly1305 requires parameters of type IParametersWithIV when used with a cipher.';
  SKeyParameterRequired =
    'Poly1305 requires a key parameter.';
  SInvalidKeyLength =
    'Poly1305 key must be 256 bits.';
  SInvalidNonce =
    'Poly1305 requires a 128-bit IV when used with a cipher.';

type
  TPoly1305 = class sealed(TMac, IPoly1305, IMac)

  strict private
  const
    BlockSize = Int32(16);

  var
    FCipher: IBlockCipher;
    FR0, FR1, FR2, FR3, FR4: UInt32;
    FS1, FS2, FS3, FS4: UInt32;
    FK0, FK1, FK2, FK3: UInt32;
    FCurrentBlock: TCryptoLibByteArray;
    FCurrentBlockOffset: Int32;
    FH0, FH1, FH2, FH3, FH4: UInt32;

    procedure SetKey(const AKeyParameter: IKeyParameter;
      const ANonce: TCryptoLibByteArray);
    procedure ProcessBlock(const ABuf: TCryptoLibByteArray; AOff: Int32);

  strict protected
    function GetAlgorithmName: String; override;

  public
    constructor Create(); overload;
    constructor Create(const ACipher: IBlockCipher); overload;

    function GetMacSize: Int32; override;

    procedure Update(AInput: Byte); override;
    procedure BlockUpdate(const AInput: TCryptoLibByteArray;
      AInOff, ALen: Int32); override;
    procedure Init(const AParameters: ICipherParameters); override;
    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32)
      : Int32; overload; override;

    procedure Reset(); override;

    property AlgorithmName: String read GetAlgorithmName;

  end;

implementation

{ TPoly1305 }

constructor TPoly1305.Create();
begin
  inherited Create();
  FCipher := nil;
  System.SetLength(FCurrentBlock, BlockSize);
end;

constructor TPoly1305.Create(const ACipher: IBlockCipher);
begin
  inherited Create();
  if ACipher.GetBlockSize() <> BlockSize then
    raise EArgumentCryptoLibException.CreateRes(@SCipherBlockSizeMismatch);
  FCipher := ACipher;
  System.SetLength(FCurrentBlock, BlockSize);
end;

procedure TPoly1305.Init(const AParameters: ICipherParameters);
var
  LNonce: TCryptoLibByteArray;
  LIvParams: IParametersWithIV;
  LKeyParameter: IKeyParameter;
  LParams: ICipherParameters;
begin
  LNonce := nil;
  LParams := AParameters;

  if FCipher <> nil then
  begin
    if not Supports(LParams, IParametersWithIV, LIvParams) then
      raise EArgumentCryptoLibException.CreateRes(@SParametersWithIVRequired);
    LNonce := LIvParams.GetIV();
    LParams := LIvParams.Parameters;
  end;

  if not Supports(LParams, IKeyParameter, LKeyParameter) then
    raise EArgumentCryptoLibException.CreateRes(@SKeyParameterRequired);

  SetKey(LKeyParameter, LNonce);
  Reset();
end;

procedure TPoly1305.SetKey(const AKeyParameter: IKeyParameter;
  const ANonce: TCryptoLibByteArray);
var
  LKey, LKBytes: TCryptoLibByteArray;
  LT0, LT1, LT2, LT3: UInt32;
begin
  LKey := AKeyParameter.GetKey();
  if System.Length(LKey) <> 32 then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidKeyLength);

  if (FCipher <> nil) and
    ((ANonce = nil) or (System.Length(ANonce) <> BlockSize)) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidNonce);

  LT0 := TPack.LE_To_UInt32(LKey, 0);
  LT1 := TPack.LE_To_UInt32(LKey, 4);
  LT2 := TPack.LE_To_UInt32(LKey, 8);
  LT3 := TPack.LE_To_UInt32(LKey, 12);

  FR0 := LT0 and $03FFFFFF;
  FR1 := ((LT0 shr 26) or (LT1 shl 6)) and $03FFFF03;
  FR2 := ((LT1 shr 20) or (LT2 shl 12)) and $03FFC0FF;
  FR3 := ((LT2 shr 14) or (LT3 shl 18)) and $03F03FFF;
  FR4 := (LT3 shr 8) and $000FFFFF;

  FS1 := FR1 * 5;
  FS2 := FR2 * 5;
  FS3 := FR3 * 5;
  FS4 := FR4 * 5;

  if FCipher = nil then
  begin
    FK0 := TPack.LE_To_UInt32(LKey, BlockSize + 0);
    FK1 := TPack.LE_To_UInt32(LKey, BlockSize + 4);
    FK2 := TPack.LE_To_UInt32(LKey, BlockSize + 8);
    FK3 := TPack.LE_To_UInt32(LKey, BlockSize + 12);
  end
  else
  begin
    System.SetLength(LKBytes, BlockSize);
    FCipher.Init(True, TKeyParameter.Create(LKey, BlockSize, BlockSize)
      as IKeyParameter);
    FCipher.ProcessBlock(ANonce, 0, LKBytes, 0);
    FK0 := TPack.LE_To_UInt32(LKBytes, 0);
    FK1 := TPack.LE_To_UInt32(LKBytes, 4);
    FK2 := TPack.LE_To_UInt32(LKBytes, 8);
    FK3 := TPack.LE_To_UInt32(LKBytes, 12);
  end;
end;

function TPoly1305.GetAlgorithmName: String;
begin
  if FCipher = nil then
    Result := 'Poly1305'
  else
    Result := 'Poly1305-' + FCipher.AlgorithmName;
end;

function TPoly1305.GetMacSize: Int32;
begin
  Result := BlockSize;
end;

procedure TPoly1305.Update(AInput: Byte);
begin
  FCurrentBlock[FCurrentBlockOffset] := AInput;
  System.Inc(FCurrentBlockOffset);
  if FCurrentBlockOffset = BlockSize then
  begin
    ProcessBlock(FCurrentBlock, 0);
    FCurrentBlockOffset := 0;
  end;
end;

procedure TPoly1305.BlockUpdate(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32);
var
  LAvailable, LPos, LRemaining: Int32;
begin
  TCheck.DataLength(AInput, AInOff, ALen, 'input buffer too short');

  LAvailable := BlockSize - FCurrentBlockOffset;
  if ALen < LAvailable then
  begin
    System.Move(AInput[AInOff], FCurrentBlock[FCurrentBlockOffset],
      ALen * System.SizeOf(Byte));
    FCurrentBlockOffset := FCurrentBlockOffset + ALen;
    Exit;
  end;

  LPos := 0;
  if FCurrentBlockOffset > 0 then
  begin
    System.Move(AInput[AInOff], FCurrentBlock[FCurrentBlockOffset],
      LAvailable * System.SizeOf(Byte));
    LPos := LAvailable;
    ProcessBlock(FCurrentBlock, 0);
  end;

  LRemaining := ALen - LPos;
  while LRemaining >= BlockSize do
  begin
    ProcessBlock(AInput, AInOff + LPos);
    LPos := LPos + BlockSize;
    LRemaining := ALen - LPos;
  end;

  System.Move(AInput[AInOff + LPos], FCurrentBlock[0],
    LRemaining * System.SizeOf(Byte));
  FCurrentBlockOffset := LRemaining;
end;

procedure TPoly1305.ProcessBlock(const ABuf: TCryptoLibByteArray; AOff: Int32);
var
  LT0, LT1, LT2, LT3: UInt32;
  LTp0, LTp1, LTp2, LTp3, LTp4: UInt64;
begin
  LT0 := TPack.LE_To_UInt32(ABuf, AOff + 0);
  LT1 := TPack.LE_To_UInt32(ABuf, AOff + 4);
  LT2 := TPack.LE_To_UInt32(ABuf, AOff + 8);
  LT3 := TPack.LE_To_UInt32(ABuf, AOff + 12);

  FH0 := FH0 + (LT0 and $3FFFFFF);
  FH1 := FH1 + (((LT1 shl 6) or (LT0 shr 26)) and $3FFFFFF);
  FH2 := FH2 + (((LT2 shl 12) or (LT1 shr 20)) and $3FFFFFF);
  FH3 := FH3 + (((LT3 shl 18) or (LT2 shr 14)) and $3FFFFFF);
  FH4 := FH4 + ((UInt32(1) shl 24) or (LT3 shr 8));

  LTp0 := UInt64(FH0) * FR0 + UInt64(FH1) * FS4 + UInt64(FH2) * FS3 +
    UInt64(FH3) * FS2 + UInt64(FH4) * FS1;
  LTp1 := UInt64(FH0) * FR1 + UInt64(FH1) * FR0 + UInt64(FH2) * FS4 +
    UInt64(FH3) * FS3 + UInt64(FH4) * FS2;
  LTp2 := UInt64(FH0) * FR2 + UInt64(FH1) * FR1 + UInt64(FH2) * FR0 +
    UInt64(FH3) * FS4 + UInt64(FH4) * FS3;
  LTp3 := UInt64(FH0) * FR3 + UInt64(FH1) * FR2 + UInt64(FH2) * FR1 +
    UInt64(FH3) * FR0 + UInt64(FH4) * FS4;
  LTp4 := UInt64(FH0) * FR4 + UInt64(FH1) * FR3 + UInt64(FH2) * FR2 +
    UInt64(FH3) * FR1 + UInt64(FH4) * FR0;

  FH0 := UInt32(LTp0) and $3FFFFFF;
  LTp1 := LTp1 + (LTp0 shr 26);
  FH1 := UInt32(LTp1) and $3FFFFFF;
  LTp2 := LTp2 + (LTp1 shr 26);
  FH2 := UInt32(LTp2) and $3FFFFFF;
  LTp3 := LTp3 + (LTp2 shr 26);
  FH3 := UInt32(LTp3) and $3FFFFFF;
  LTp4 := LTp4 + (LTp3 shr 26);
  FH4 := UInt32(LTp4) and $3FFFFFF;
  FH0 := FH0 + UInt32(LTp4 shr 26) * 5;
  FH1 := FH1 + (FH0 shr 26);
  FH0 := FH0 and $3FFFFFF;
end;

function TPoly1305.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LC: Int64;
begin
  TCheck.OutputLength(AOutput, AOutOff, BlockSize, 'output buffer too short');

  if FCurrentBlockOffset > 0 then
  begin
    if FCurrentBlockOffset < BlockSize then
    begin
      FCurrentBlock[FCurrentBlockOffset] := 1;
      System.Inc(FCurrentBlockOffset);
      while FCurrentBlockOffset < BlockSize do
      begin
        FCurrentBlock[FCurrentBlockOffset] := 0;
        System.Inc(FCurrentBlockOffset);
      end;
      FH4 := FH4 - (UInt32(1) shl 24);
    end;
    ProcessBlock(FCurrentBlock, 0);
  end;

  FH0 := FH0 + 5;
  FH1 := FH1 + (FH0 shr 26);
  FH0 := FH0 and $3FFFFFF;
  FH2 := FH2 + (FH1 shr 26);
  FH1 := FH1 and $3FFFFFF;
  FH3 := FH3 + (FH2 shr 26);
  FH2 := FH2 and $3FFFFFF;
  FH4 := FH4 + (FH3 shr 26);
  FH3 := FH3 and $3FFFFFF;

  LC := Int64(Int32(FH4 shr 26) - 1) * 5;
  LC := LC + Int64(FK0) + Int64(FH0 or (FH1 shl 26));
  TPack.UInt32_To_LE(UInt32(LC), AOutput, AOutOff);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(FK1) + Int64((FH1 shr 6) or (FH2 shl 20));
  TPack.UInt32_To_LE(UInt32(LC), AOutput, AOutOff + 4);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(FK2) + Int64((FH2 shr 12) or (FH3 shl 14));
  TPack.UInt32_To_LE(UInt32(LC), AOutput, AOutOff + 8);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(FK3) + Int64((FH3 shr 18) or (FH4 shl 8));
  TPack.UInt32_To_LE(UInt32(LC), AOutput, AOutOff + 12);

  Reset();
  Result := BlockSize;
end;

procedure TPoly1305.Reset();
begin
  FCurrentBlockOffset := 0;
  TArrayUtilities.Fill<Byte>(FCurrentBlock, 0, System.Length(FCurrentBlock), Byte(0));
  FH0 := 0;
  FH1 := 0;
  FH2 := 0;
  FH3 := 0;
  FH4 := 0;
end;

end.
