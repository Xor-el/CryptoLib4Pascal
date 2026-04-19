{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpCcmBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  ClpIBlockCipher,
  ClpIBlockCipherMode,
  ClpICcmBlockCipher,
  ClpIAeadBlockCipher,
  ClpIAeadCipher,
  ClpICipherParameters,
  ClpIParametersWithIV,
  ClpSicBlockCipher,
  ClpISicBlockCipher,
  ClpIBulkBlockCipherMode,
  ClpBlockCipherBulkUtilities,
  ClpCipherModeParameterUtilities,
  ClpCbcBlockCipherMac,
  ClpIMac,
  ClpParametersWithIV,
  ClpCheck,
  ClpArrayUtilities,
  ClpStreamUtilities,
  ClpCryptoLibTypes;

resourcestring
  SCipherRequired = 'cipher required with a block size of %d.';
  SInvalidParametersCCM = 'invalid parameters passed to CCM';
  SNonceLengthRange = 'nonce must have length from 7 to 13 octets';
  SCcmUninitialised = 'CCM cipher unitialized.';
  SCcmPacketTooLarge = 'CCM packet too large for choice of q.';
  SDataTooShort = 'data too short';
  SMacCheckFailed = 'mac check in CCM failed';
  STagLengthOctets = 'tag length in octets must be one of {4,6,8,10,12,14,16}';
  SInputBufferTooShort = 'Input Buffer Too Short';
  SOutputBufferTooShort = 'Output Buffer Too Short';

type
  TCcmBlockCipher = class(TInterfacedObject, ICcmBlockCipher,
    IAeadBlockCipher, IAeadCipher)

  strict private
  const
    BlockSize: Int32 = 16;

  var
    FCipher: IBlockCipher;
    FMacBlock: TCryptoLibByteArray;
    FForEncryption: Boolean;
    FNonce: TCryptoLibByteArray;
    FInitialAssociatedText: TCryptoLibByteArray;
    FMacSize: Int32;
    FKeyParam: ICipherParameters;
    FAssociatedText: TMemoryStream;
    FData: TMemoryStream;

    function GetMacSize(AForEncryption: Boolean; ARequestedMacBits: Int32): Int32;
    function GetAssociatedTextLength(): Int32;
    function HasAssociatedText(): Boolean;
    function CalculateMac(const AData: TCryptoLibByteArray; ADataOff, ADataLen: Int32;
      const AMacBlock: TCryptoLibByteArray): Int32;

  strict protected
    function GetAlgorithmName: String; virtual;
    function GetUnderlyingCipher(): IBlockCipher; virtual;

  public
    constructor Create(const ACipher: IBlockCipher);
    destructor Destroy; override;

    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters); virtual;
    function GetBlockSize(): Int32; virtual;

    procedure ProcessAadByte(AInput: Byte); virtual;
    procedure ProcessAadBytes(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32); virtual;

    function ProcessByte(AInput: Byte; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual;
    function ProcessBytes(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual;

    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual;

    procedure Reset(); virtual;

    function GetMac(): TCryptoLibByteArray; virtual;
    function GetUpdateOutputSize(ALen: Int32): Int32; virtual;
    function GetOutputSize(ALen: Int32): Int32; virtual;

    function ProcessPacket(const AInput: TCryptoLibByteArray; AInOff, AInLen: Int32): TCryptoLibByteArray; overload; virtual;
    function ProcessPacket(const AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload; virtual;

    property UnderlyingCipher: IBlockCipher read GetUnderlyingCipher;
    property AlgorithmName: String read GetAlgorithmName;
  end;

implementation

{ TCcmBlockCipher }

constructor TCcmBlockCipher.Create(const ACipher: IBlockCipher);
begin
  inherited Create();
  FCipher := ACipher;
  System.SetLength(FMacBlock, BlockSize);
  FAssociatedText := TMemoryStream.Create;
  FData := TMemoryStream.Create;

  if (ACipher.GetBlockSize() <> BlockSize) then
    raise EArgumentCryptoLibException.CreateResFmt(@SCipherRequired, [BlockSize]);
end;

destructor TCcmBlockCipher.Destroy;
begin
  FAssociatedText.Free;
  FData.Free;
  inherited Destroy;
end;

function TCcmBlockCipher.GetAlgorithmName: String;
begin
  Result := FCipher.AlgorithmName + '/CCM';
end;

function TCcmBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  Result := FCipher;
end;

procedure TCcmBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LChoice: TCipherAeadChoice;
  LRequestedMacSizeBits: Int32;
begin
  FForEncryption := AForEncryption;

  if not TCipherModeParameterUtilities.TryResolveAeadOrIv(AParameters, LChoice)
  then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidParametersCCM);

  FNonce := LChoice.Nonce;
  FInitialAssociatedText := LChoice.AssociatedText;
  if LChoice.IsAead then
    LRequestedMacSizeBits := LChoice.MacSizeBits
  else
    LRequestedMacSizeBits := 64;
  FMacSize := GetMacSize(AForEncryption, LRequestedMacSizeBits);

  if (LChoice.CipherKey <> nil) then
    FKeyParam := LChoice.CipherKey;

  if (System.Length(FNonce) < 7) or (System.Length(FNonce) > 13) then
    raise EArgumentCryptoLibException.CreateRes(@SNonceLengthRange);

  Reset();
end;

function TCcmBlockCipher.GetBlockSize: Int32;
begin
  Result := FCipher.GetBlockSize();
end;

procedure TCcmBlockCipher.ProcessAadByte(AInput: Byte);
begin
  FAssociatedText.WriteByte(AInput);
end;

procedure TCcmBlockCipher.ProcessAadBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32);
begin
  FAssociatedText.WriteBuffer(AInput[AInOff], ALen);
end;

function TCcmBlockCipher.ProcessByte(AInput: Byte;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  FData.WriteByte(AInput);
  Result := 0;
end;

function TCcmBlockCipher.ProcessBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  TCheck.DataLength(AInput, AInOff, ALen, SInputBufferTooShort);
  FData.WriteBuffer(AInput[AInOff], ALen);
  Result := 0;
end;

function TCcmBlockCipher.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LInput: TCryptoLibByteArray;
  LInLen: Int32;
begin
  LInLen := Int32(FData.Size);
  System.SetLength(LInput, LInLen);
  if LInLen > 0 then
  begin
    FData.Position := 0;
    FData.ReadBuffer(LInput[0], LInLen);
  end;

  Result := ProcessPacket(LInput, 0, LInLen, AOutput, AOutOff);

  Reset();
end;

procedure TCcmBlockCipher.Reset;
begin
  FAssociatedText.Size := 0;
  FData.Size := 0;
end;

function TCcmBlockCipher.GetMac: TCryptoLibByteArray;
begin
  Result := TArrayUtilities.CopyOfRange<Byte>(FMacBlock, 0, FMacSize);
end;

function TCcmBlockCipher.GetUpdateOutputSize(ALen: Int32): Int32;
begin
  Result := 0;
end;

function TCcmBlockCipher.GetOutputSize(ALen: Int32): Int32;
var
  LTotalData: Int32;
begin
  LTotalData := Int32(FData.Size) + ALen;

  if FForEncryption then
  begin
    Result := LTotalData + FMacSize;
    Exit;
  end;

  if LTotalData < FMacSize then
    Result := 0
  else
    Result := LTotalData - FMacSize;
end;

function TCcmBlockCipher.ProcessPacket(const AInput: TCryptoLibByteArray;
  AInOff, AInLen: Int32): TCryptoLibByteArray;
var
  LOutput: TCryptoLibByteArray;
begin
  TCheck.DataLength(AInput, AInOff, AInLen, SInputBufferTooShort);

  if FForEncryption then
  begin
    System.SetLength(LOutput, AInLen + FMacSize);
  end
  else
  begin
    if (AInLen < FMacSize) then
      raise EInvalidCipherTextCryptoLibException.CreateRes(@SDataTooShort);

    System.SetLength(LOutput, AInLen - FMacSize);
  end;

  ProcessPacket(AInput, AInOff, AInLen, LOutput, 0);
  Result := LOutput;
end;

function TCcmBlockCipher.ProcessPacket(const AInput: TCryptoLibByteArray;
  AInOff, AInLen: Int32; const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LN, LQ, LLimitLen, LInputAdjustment, LOutputLen, LInIndex, LOutIndex, LI,
    LBulkBlocks, LBulkBytes: Int32;
  LIV, LEncMac, LBlock, LCalculatedMacBlock: TCryptoLibByteArray;
  LCtrCipher: ISicBlockCipher;
  // Cached IBulkBlockCipherMode view of LCtrCipher. TSicBlockCipher always
  // implements IBulkBlockCipherMode, so this is non-nil in practice; the
  // Supports() guard keeps us robust to a future SIC variant that opts out.
  LBulkCtr: IBulkBlockCipherMode;
begin
  TCheck.DataLength(AInput, AInOff, AInLen, SInputBufferTooShort);

  if (FKeyParam = nil) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SCcmUninitialised);

  LN := System.Length(FNonce);
  LQ := 15 - LN;
  if (LQ < 4) then
  begin
    LLimitLen := 1 shl (8 * LQ);

    LInputAdjustment := 0;

    if (not FForEncryption) then
    begin
      LInputAdjustment := 1 + 15;
    end;

    if ((AInLen - LInputAdjustment) >= LLimitLen) then
      raise EInvalidOperationCryptoLibException.CreateRes(@SCcmPacketTooLarge);
  end;

  System.SetLength(LIV, BlockSize);
  LIV[0] := Byte((LQ - 1) and $7);
  System.Move(FNonce[0], LIV[1], LN);

  LCtrCipher := TSicBlockCipher.Create(FCipher);
  LCtrCipher.Init(FForEncryption, TParametersWithIV.Create(FKeyParam, LIV) as IParametersWithIV);
  TBlockCipherBulkUtilities.TryResolveBulkCipherMode(LCtrCipher, LBulkCtr);

  LInIndex := AInOff;
  LOutIndex := AOutOff;

  if FForEncryption then
  begin
    LOutputLen := AInLen + FMacSize;
    TCheck.OutputLength(AOutput, AOutOff, LOutputLen, SOutputBufferTooShort);

    CalculateMac(AInput, AInOff, AInLen, FMacBlock);

    System.SetLength(LEncMac, BlockSize);
    LCtrCipher.ProcessBlock(FMacBlock, 0, LEncMac, 0);

    // Number of whole 16-byte blocks that the classic loop would have
    // consumed. The tail (1..BlockSize bytes) is always handled via the
    // LBlock scratch path below, so we intentionally hold back the last
    // (possibly full) block and let the per-block tail finish it. This
    // preserves byte-identical behaviour with the pre-bulk code.
    LBulkBlocks := (AInLen - 1) div BlockSize;
    if (LBulkCtr <> nil) and (LBulkBlocks > 0) then
    begin
      LBulkBytes := LBulkCtr.ProcessBlocks(AInput, LInIndex, LBulkBlocks,
        AOutput, LOutIndex);
      LInIndex := LInIndex + LBulkBytes;
      LOutIndex := LOutIndex + LBulkBytes;
    end
    else
    begin
      while (LInIndex < (AInOff + AInLen - BlockSize)) do
      begin
        LCtrCipher.ProcessBlock(AInput, LInIndex, AOutput, LOutIndex);
        LOutIndex := LOutIndex + BlockSize;
        LInIndex := LInIndex + BlockSize;
      end;
    end;

    System.SetLength(LBlock, BlockSize);

    System.Move(AInput[LInIndex], LBlock[0], AInLen + AInOff - LInIndex);

    LCtrCipher.ProcessBlock(LBlock, 0, LBlock, 0);

    System.Move(LBlock[0], AOutput[LOutIndex], AInLen + AInOff - LInIndex);

    System.Move(LEncMac[0], AOutput[AOutOff + AInLen], FMacSize);
  end
  else
  begin
    if (AInLen < FMacSize) then
      raise EInvalidCipherTextCryptoLibException.CreateRes(@SDataTooShort);

    LOutputLen := AInLen - FMacSize;
    TCheck.OutputLength(AOutput, AOutOff, LOutputLen, SOutputBufferTooShort);

    System.Move(AInput[AInOff + LOutputLen], FMacBlock[0], FMacSize);

    LCtrCipher.ProcessBlock(FMacBlock, 0, FMacBlock, 0);

    for LI := FMacSize to System.Pred(System.Length(FMacBlock)) do
    begin
      FMacBlock[LI] := 0;
    end;

    // Same LBulkBlocks / tail split as encrypt, but over LOutputLen
    // (ciphertext minus trailing tag) rather than AInLen. The last
    // (possibly full) 16-byte block is held back for the LBlock scratch
    // path so behaviour matches the pre-bulk loop byte-for-byte.
    LBulkBlocks := (LOutputLen - 1) div BlockSize;
    if (LBulkCtr <> nil) and (LBulkBlocks > 0) then
    begin
      LBulkBytes := LBulkCtr.ProcessBlocks(AInput, LInIndex, LBulkBlocks,
        AOutput, LOutIndex);
      LInIndex := LInIndex + LBulkBytes;
      LOutIndex := LOutIndex + LBulkBytes;
    end
    else
    begin
      while (LInIndex < (AInOff + LOutputLen - BlockSize)) do
      begin
        LCtrCipher.ProcessBlock(AInput, LInIndex, AOutput, LOutIndex);
        LOutIndex := LOutIndex + BlockSize;
        LInIndex := LInIndex + BlockSize;
      end;
    end;

    System.SetLength(LBlock, BlockSize);

    System.Move(AInput[LInIndex], LBlock[0], LOutputLen - (LInIndex - AInOff));

    LCtrCipher.ProcessBlock(LBlock, 0, LBlock, 0);

    System.Move(LBlock[0], AOutput[LOutIndex], LOutputLen - (LInIndex - AInOff));

    System.SetLength(LCalculatedMacBlock, BlockSize);

    CalculateMac(AOutput, AOutOff, LOutputLen, LCalculatedMacBlock);

    if (not TArrayUtilities.FixedTimeEquals(FMacBlock, LCalculatedMacBlock)) then
      raise EInvalidCipherTextCryptoLibException.CreateRes(@SMacCheckFailed);
  end;

  Result := LOutputLen;
end;

function TCcmBlockCipher.CalculateMac(const AData: TCryptoLibByteArray;
  ADataOff, ADataLen: Int32; const AMacBlock: TCryptoLibByteArray): Int32;
var
  LCMac: IMac;
  LB0: TCryptoLibByteArray;
  LQ, LCount, LExtra, LTextLength, LLen: Int32;
  LInput: TCryptoLibByteArray;
begin
  LCMac := TCbcBlockCipherMac.Create(FCipher, FMacSize * 8);
  LCMac.Init(FKeyParam);

  System.SetLength(LB0, 16);

  if HasAssociatedText() then
  begin
    LB0[0] := LB0[0] or $40;
  end;

  LB0[0] := LB0[0] or Byte((((LCMac.GetMacSize() - 2) div 2) and $7) shl 3);

  LB0[0] := LB0[0] or Byte(((15 - System.Length(FNonce)) - 1) and $7);

  System.Move(FNonce[0], LB0[1], System.Length(FNonce));

  LQ := ADataLen;
  LCount := 1;
  while (LQ > 0) do
  begin
    LB0[System.Length(LB0) - LCount] := Byte(LQ and $FF);
    LQ := LQ shr 8;
    System.Inc(LCount);
  end;

  LCMac.BlockUpdate(LB0, 0, System.Length(LB0));

  if HasAssociatedText() then
  begin
    LTextLength := GetAssociatedTextLength();
    if (LTextLength < ((1 shl 16) - (1 shl 8))) then
    begin
      LCMac.Update(Byte(LTextLength shr 8));
      LCMac.Update(Byte(LTextLength));
      LExtra := 2;
    end
    else
    begin
      LCMac.Update(Byte($FF));
      LCMac.Update(Byte($FE));
      LCMac.Update(Byte(LTextLength shr 24));
      LCMac.Update(Byte(LTextLength shr 16));
      LCMac.Update(Byte(LTextLength shr 8));
      LCMac.Update(Byte(LTextLength));
      LExtra := 6;
    end;

    if (FInitialAssociatedText <> nil) then
    begin
      LCMac.BlockUpdate(FInitialAssociatedText, 0, System.Length(FInitialAssociatedText));
    end;

    if (FAssociatedText.Size > 0) then
    begin
      LLen := Int32(FAssociatedText.Size);
      System.SetLength(LInput, LLen);
      FAssociatedText.Position := 0;
      FAssociatedText.ReadBuffer(LInput[0], LLen);
      LCMac.BlockUpdate(LInput, 0, LLen);
    end;

    LExtra := (LExtra + LTextLength) mod 16;
    if (LExtra <> 0) then
    begin
      while LExtra < 16 do
      begin
        LCMac.Update(Byte($00));
        System.Inc(LExtra);
      end;
    end;
  end;

  LCMac.BlockUpdate(AData, ADataOff, ADataLen);

  Result := LCMac.DoFinal(AMacBlock, 0);
end;

function TCcmBlockCipher.GetMacSize(AForEncryption: Boolean;
  ARequestedMacBits: Int32): Int32;
begin
  if AForEncryption and ((ARequestedMacBits < 32) or (ARequestedMacBits > 128) or
    (0 <> (ARequestedMacBits and 15))) then
    raise EArgumentCryptoLibException.CreateRes(@STagLengthOctets);

  Result := ARequestedMacBits shr 3;
end;

function TCcmBlockCipher.GetAssociatedTextLength: Int32;
begin
  Result := Int32(FAssociatedText.Size);
  if (FInitialAssociatedText <> nil) then
    Result := Result + System.Length(FInitialAssociatedText);
end;

function TCcmBlockCipher.HasAssociatedText: Boolean;
begin
  Result := GetAssociatedTextLength() > 0;
end;

end.
