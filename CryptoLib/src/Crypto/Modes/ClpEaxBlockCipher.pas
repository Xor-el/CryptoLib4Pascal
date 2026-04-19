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

unit ClpEaxBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIBlockCipherMode,
  ClpIEaxBlockCipher,
  ClpIAeadBlockCipher,
  ClpIAeadCipher,
  ClpICipherParameters,
  ClpIParametersWithIV,
  ClpSicBlockCipher,
  ClpISicBlockCipher,
  ClpIBulkBlockCipherMode,
  ClpBlockCipherBulkUtilities,
  ClpCipherModeParameterUtilities,
  ClpCMac,
  ClpIMac,
  ClpParametersWithIV,
  ClpCheck,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SInvalidParametersEAX = 'invalid parameters passed to EAX';
  SOutputBufferTooShort = 'Output Buffer Too Short';
  SDataTooShort = 'data too short';
  SMacCheckFailed = 'mac check in EAX failed';
  SAadAfterProcessing = 'AAD data cannot be added after encryption/decryption processing has begun.';

type
  TEaxBlockCipher = class(TInterfacedObject, IEaxBlockCipher,
    IAeadBlockCipher, IAeadCipher)

  strict private
  type
    TTag = (TagN = 0, TagH = 1, TagC = 2);
  var
    FCipher: ISicBlockCipher;
    // Cached IBulkBlockCipherMode view of FCipher. TSicBlockCipher always
    // implements IBulkBlockCipherMode so this is non-nil in practice; the
    // Supports() call in the constructor keeps us robust against future
    // variants that might opt out.
    FBulkCipher: IBulkBlockCipherMode;
    FForEncryption: Boolean;
    FBlockSize: Int32;
    FMac: IMac;
    FNonceMac: TCryptoLibByteArray;
    FAssociatedTextMac: TCryptoLibByteArray;
    FMacBlock: TCryptoLibByteArray;
    FMacSize: Int32;
    FBufBlock: TCryptoLibByteArray;
    FBufOff: Int32;
    FCipherInitialized: Boolean;
    FInitialAssociatedText: TCryptoLibByteArray;

    procedure InitCipher();
    procedure CalculateMac();
    procedure Reset(AClearMac: Boolean); overload;
    function Process(AB: Byte; const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;
    function VerifyMac(const AMac: TCryptoLibByteArray; AOff: Int32): Boolean;

  strict protected
    function GetAlgorithmName: String; virtual;
    function GetUnderlyingCipher(): IBlockCipher; virtual;

  public
    constructor Create(const ACipher: IBlockCipher);

    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters); virtual;
    function GetBlockSize(): Int32; virtual;

    procedure ProcessAadByte(AInput: Byte); virtual;
    procedure ProcessAadBytes(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32); virtual;

    function ProcessByte(AInput: Byte; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual;
    function ProcessBytes(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual;

    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual;

    function GetMac(): TCryptoLibByteArray; virtual;
    function GetUpdateOutputSize(ALen: Int32): Int32; virtual;
    function GetOutputSize(ALen: Int32): Int32; virtual;
    procedure Reset(); overload; virtual;

    property UnderlyingCipher: IBlockCipher read GetUnderlyingCipher;
    property AlgorithmName: String read GetAlgorithmName;
  end;

implementation

{ TEaxBlockCipher }

constructor TEaxBlockCipher.Create(const ACipher: IBlockCipher);
begin
  inherited Create();
  FBlockSize := ACipher.GetBlockSize();
  FMac := TCMac.Create(ACipher);
  System.SetLength(FMacBlock, FBlockSize);
  System.SetLength(FAssociatedTextMac, FMac.GetMacSize());
  System.SetLength(FNonceMac, FMac.GetMacSize());
  FCipher := TSicBlockCipher.Create(ACipher);
  TBlockCipherBulkUtilities.TryResolveBulkCipherMode(FCipher, FBulkCipher);
end;

function TEaxBlockCipher.GetAlgorithmName: String;
begin
  Result := FCipher.GetUnderlyingCipher().AlgorithmName + '/EAX';
end;

function TEaxBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  Result := FCipher;
end;

function TEaxBlockCipher.GetBlockSize: Int32;
begin
  Result := FCipher.GetBlockSize();
end;

procedure TEaxBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LChoice: TCipherAeadChoice;
  LTag: TCryptoLibByteArray;
begin
  FForEncryption := AForEncryption;

  if not TCipherModeParameterUtilities.TryResolveAeadOrIv(AParameters, LChoice)
  then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidParametersEAX);

  FInitialAssociatedText := LChoice.AssociatedText;
  if LChoice.IsAead then
    FMacSize := LChoice.MacSizeBits div 8
  else
    FMacSize := FMac.GetMacSize() div 2;

  if FForEncryption then
    System.SetLength(FBufBlock, FBlockSize)
  else
    System.SetLength(FBufBlock, FBlockSize + FMacSize);

  System.SetLength(LTag, FBlockSize);

  FMac.Init(LChoice.CipherKey);

  LTag[FBlockSize - 1] := Byte(Ord(TTag.TagN));
  FMac.BlockUpdate(LTag, 0, FBlockSize);
  FMac.BlockUpdate(LChoice.Nonce, 0, System.Length(LChoice.Nonce));
  FMac.DoFinal(FNonceMac, 0);

  FCipher.Init(True, TParametersWithIV.Create(nil, FNonceMac) as IParametersWithIV);

  Reset(True);
end;

procedure TEaxBlockCipher.InitCipher;
var
  LTag: TCryptoLibByteArray;
begin
  if FCipherInitialized then
    Exit;

  FCipherInitialized := True;

  FMac.DoFinal(FAssociatedTextMac, 0);

  System.SetLength(LTag, FBlockSize);
  LTag[FBlockSize - 1] := Byte(Ord(TTag.TagC));
  FMac.BlockUpdate(LTag, 0, FBlockSize);
end;

procedure TEaxBlockCipher.CalculateMac;
var
  LOutC: TCryptoLibByteArray;
  LI: Int32;
begin
  System.SetLength(LOutC, FBlockSize);
  FMac.DoFinal(LOutC, 0);

  for LI := 0 to System.Pred(System.Length(FMacBlock)) do
  begin
    FMacBlock[LI] := Byte(FNonceMac[LI] xor FAssociatedTextMac[LI] xor LOutC[LI]);
  end;
end;

procedure TEaxBlockCipher.Reset;
begin
  Reset(True);
end;

procedure TEaxBlockCipher.Reset(AClearMac: Boolean);
var
  LTag: TCryptoLibByteArray;
begin
  FCipher.Reset();
  FMac.Reset();

  FBufOff := 0;
  TArrayUtilities.Fill<Byte>(FBufBlock, 0, System.Length(FBufBlock), Byte(0));

  if AClearMac then
  begin
    TArrayUtilities.Fill<Byte>(FMacBlock, 0, System.Length(FMacBlock), Byte(0));
  end;

  System.SetLength(LTag, FBlockSize);
  LTag[FBlockSize - 1] := Byte(Ord(TTag.TagH));
  FMac.BlockUpdate(LTag, 0, FBlockSize);

  FCipherInitialized := False;

  if (FInitialAssociatedText <> nil) then
  begin
    ProcessAadBytes(FInitialAssociatedText, 0, System.Length(FInitialAssociatedText));
  end;
end;

procedure TEaxBlockCipher.ProcessAadByte(AInput: Byte);
begin
  if FCipherInitialized then
    raise EInvalidOperationCryptoLibException.CreateRes(@SAadAfterProcessing);

  FMac.Update(AInput);
end;

procedure TEaxBlockCipher.ProcessAadBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32);
begin
  if FCipherInitialized then
    raise EInvalidOperationCryptoLibException.CreateRes(@SAadAfterProcessing);

  FMac.BlockUpdate(AInput, AInOff, ALen);
end;

function TEaxBlockCipher.ProcessByte(AInput: Byte;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  InitCipher();
  Result := Process(AInput, AOutput, AOutOff);
end;

function TEaxBlockCipher.ProcessBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LI, LResultLen, LToFill, LBulkBlocks, LBulkBytes: Int32;
  LScratch: TCryptoLibByteArray;
begin
  InitCipher();

  LResultLen := 0;

  // Bulk fast path: only activates when the underlying CTR cipher exposes
  // the generic multi-block capability. The scalar per-byte loop below
  // remains as the fallback and preserves byte-for-byte semantics with the
  // pre-bulk code; the bulk path reproduces the exact same state transitions
  // (MAC update order, FBufBlock lookahead shifts, FBufOff invariants) via
  // a direct buffer-drain + aligned-run + tail-repack sequence.
  if (FBulkCipher <> nil) and (ALen > 0) then
  begin
    if FForEncryption then
    begin
      // Drain any partial block accumulated from previous ProcessBytes
      // calls. If we can complete FBufBlock, flush it exactly as
      // Process() would.
      if FBufOff > 0 then
      begin
        LToFill := FBlockSize - FBufOff;
        if LToFill > ALen then
          LToFill := ALen;
        System.Move(AInput[AInOff], FBufBlock[FBufOff], LToFill);
        FBufOff := FBufOff + LToFill;
        AInOff := AInOff + LToFill;
        ALen := ALen - LToFill;
        if FBufOff = FBlockSize then
        begin
          TCheck.OutputLength(AOutput, AOutOff + LResultLen, FBlockSize,
            SOutputBufferTooShort);
          FCipher.ProcessBlock(FBufBlock, 0, AOutput, AOutOff + LResultLen);
          FMac.BlockUpdate(AOutput, AOutOff + LResultLen, FBlockSize);
          LResultLen := LResultLen + FBlockSize;
          FBufOff := 0;
        end;
      end;

      // Aligned full-block run directly from AInput -> AOutput. CTR
      // encrypts in place via the bulk cipher, then ciphertext is handed
      // to CMAC in one BlockUpdate call.
      if (FBufOff = 0) and (ALen >= FBlockSize) then
      begin
        LBulkBlocks := ALen div FBlockSize;
        LBulkBytes := LBulkBlocks * FBlockSize;
        TCheck.OutputLength(AOutput, AOutOff + LResultLen, LBulkBytes,
          SOutputBufferTooShort);
        FBulkCipher.ProcessBlocks(AInput, AInOff, LBulkBlocks, AOutput,
          AOutOff + LResultLen);
        FMac.BlockUpdate(AOutput, AOutOff + LResultLen, LBulkBytes);
        LResultLen := LResultLen + LBulkBytes;
        AInOff := AInOff + LBulkBytes;
        ALen := ALen - LBulkBytes;
      end;

      // Residue (< FBlockSize bytes) goes into FBufBlock; DoFinal will
      // consume it.
      if ALen > 0 then
      begin
        System.Move(AInput[AInOff], FBufBlock[FBufOff], ALen);
        FBufOff := FBufOff + ALen;
      end;

      Result := LResultLen;
      Exit;
    end
    else
    begin
      // Decrypt path. FBufBlock is (FBlockSize + FMacSize) bytes; the last
      // FMacSize bytes are a look-ahead that we do not MAC / decrypt until
      // we are certain they are payload and not the trailing tag. The
      // scalar Process() keeps this invariant by shifting the trailing
      // FMacSize bytes down after every flush.
      //
      // Drain the buffer to its canonical post-first-flush state
      // (FBufOff = FMacSize). If the first flush has not yet happened,
      // this step may trigger it. After this step either FBufOff equals
      // FMacSize and ALen may still be > 0, or we ran out of input while
      // filling.
      LToFill := (FBlockSize + FMacSize) - FBufOff;
      if LToFill > ALen then
        LToFill := ALen;
      System.Move(AInput[AInOff], FBufBlock[FBufOff], LToFill);
      FBufOff := FBufOff + LToFill;
      AInOff := AInOff + LToFill;
      ALen := ALen - LToFill;
      if FBufOff = FBlockSize + FMacSize then
      begin
        TCheck.OutputLength(AOutput, AOutOff + LResultLen, FBlockSize,
          SOutputBufferTooShort);
        FMac.BlockUpdate(FBufBlock, 0, FBlockSize);
        FCipher.ProcessBlock(FBufBlock, 0, AOutput, AOutOff + LResultLen);
        LResultLen := LResultLen + FBlockSize;
        System.Move(FBufBlock[FBlockSize], FBufBlock[0], FMacSize);
        FBufOff := FMacSize;
      end;

      // Aligned bulk run: once FBufOff = FMacSize, each subsequent flush
      // consumes exactly FBlockSize bytes of AInput. For N flushes the
      // MAC / decrypt stream is:
      //   chunk 0     = FBufBlock[0..FMacSize-1] || AInput[0..FBlockSize-FMacSize-1]
      //   chunk 1..N-1= AInput[FBlockSize-FMacSize..N*FBlockSize-FMacSize-1] (contiguous)
      //   new FBufBlock[0..FMacSize-1] = AInput[N*FBlockSize-FMacSize..N*FBlockSize-1]
      // Block 0 needs a small FBlockSize-byte scratch to stitch the
      // look-ahead to the first AInput bytes; blocks 1..N-1 reference
      // AInput directly.
      if (FBufOff = FMacSize) and (ALen >= FBlockSize) then
      begin
        LBulkBlocks := ALen div FBlockSize;
        LBulkBytes := LBulkBlocks * FBlockSize;
        TCheck.OutputLength(AOutput, AOutOff + LResultLen, LBulkBytes,
          SOutputBufferTooShort);

        System.SetLength(LScratch, FBlockSize);
        System.Move(FBufBlock[0], LScratch[0], FMacSize);
        if FBlockSize > FMacSize then
          System.Move(AInput[AInOff], LScratch[FMacSize],
            FBlockSize - FMacSize);
        FMac.BlockUpdate(LScratch, 0, FBlockSize);
        FCipher.ProcessBlock(LScratch, 0, AOutput, AOutOff + LResultLen);

        if LBulkBlocks > 1 then
        begin
          FMac.BlockUpdate(AInput, AInOff + FBlockSize - FMacSize,
            (LBulkBlocks - 1) * FBlockSize);
          FBulkCipher.ProcessBlocks(AInput, AInOff + FBlockSize - FMacSize,
            LBulkBlocks - 1, AOutput, AOutOff + LResultLen + FBlockSize);
        end;

        System.Move(AInput[AInOff + LBulkBytes - FMacSize], FBufBlock[0],
          FMacSize);

        LResultLen := LResultLen + LBulkBytes;
        AInOff := AInOff + LBulkBytes;
        ALen := ALen - LBulkBytes;
      end;

      // Pack remaining bytes (strictly less than FBlockSize on this
      // branch) into FBufBlock. No flush is possible with < FBlockSize
      // new bytes: we would not reach FBlockSize + FMacSize total.
      if ALen > 0 then
      begin
        System.Move(AInput[AInOff], FBufBlock[FBufOff], ALen);
        FBufOff := FBufOff + ALen;
      end;

      Result := LResultLen;
      Exit;
    end;
  end;

  for LI := 0 to System.Pred(ALen) do
  begin
    LResultLen := LResultLen + Process(AInput[AInOff + LI], AOutput, AOutOff + LResultLen);
  end;

  Result := LResultLen;
end;

function TEaxBlockCipher.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LExtra: Int32;
  LTmp: TCryptoLibByteArray;
begin
  InitCipher();

  LExtra := FBufOff;
  System.SetLength(LTmp, System.Length(FBufBlock));

  FBufOff := 0;

  if FForEncryption then
  begin
    TCheck.OutputLength(AOutput, AOutOff, LExtra + FMacSize, SOutputBufferTooShort);

    FCipher.ProcessBlock(FBufBlock, 0, LTmp, 0);

    System.Move(LTmp[0], AOutput[AOutOff], LExtra);

    FMac.BlockUpdate(LTmp, 0, LExtra);

    CalculateMac();

    System.Move(FMacBlock[0], AOutput[AOutOff + LExtra], FMacSize);

    Reset(False);

    Result := LExtra + FMacSize;
  end
  else
  begin
    if (LExtra < FMacSize) then
      raise EInvalidCipherTextCryptoLibException.CreateRes(@SDataTooShort);

    TCheck.OutputLength(AOutput, AOutOff, LExtra - FMacSize, SOutputBufferTooShort);

    if (LExtra > FMacSize) then
    begin
      FMac.BlockUpdate(FBufBlock, 0, LExtra - FMacSize);

      FCipher.ProcessBlock(FBufBlock, 0, LTmp, 0);

      System.Move(LTmp[0], AOutput[AOutOff], LExtra - FMacSize);
    end;

    CalculateMac();

    if (not VerifyMac(FBufBlock, LExtra - FMacSize)) then
      raise EInvalidCipherTextCryptoLibException.CreateRes(@SMacCheckFailed);

    Reset(False);

    Result := LExtra - FMacSize;
  end;
end;

function TEaxBlockCipher.GetMac: TCryptoLibByteArray;
begin
  System.SetLength(Result, FMacSize);
  System.Move(FMacBlock[0], Result[0], FMacSize);
end;

function TEaxBlockCipher.GetUpdateOutputSize(ALen: Int32): Int32;
var
  LTotalData: Int32;
begin
  LTotalData := ALen + FBufOff;
  if (not FForEncryption) then
  begin
    if (LTotalData < FMacSize) then
    begin
      Result := 0;
      Exit;
    end;
    LTotalData := LTotalData - FMacSize;
  end;
  Result := LTotalData - LTotalData mod FBlockSize;
end;

function TEaxBlockCipher.GetOutputSize(ALen: Int32): Int32;
var
  LTotalData: Int32;
begin
  LTotalData := ALen + FBufOff;

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

function TEaxBlockCipher.Process(AB: Byte; const AOutBytes: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LSize: Int32;
begin
  FBufBlock[FBufOff] := AB;
  System.Inc(FBufOff);

  if (FBufOff = System.Length(FBufBlock)) then
  begin
    TCheck.OutputLength(AOutBytes, AOutOff, FBlockSize, SOutputBufferTooShort);

    if FForEncryption then
    begin
      LSize := FCipher.ProcessBlock(FBufBlock, 0, AOutBytes, AOutOff);
      FMac.BlockUpdate(AOutBytes, AOutOff, FBlockSize);
    end
    else
    begin
      FMac.BlockUpdate(FBufBlock, 0, FBlockSize);
      LSize := FCipher.ProcessBlock(FBufBlock, 0, AOutBytes, AOutOff);
    end;

    FBufOff := 0;
    if (not FForEncryption) then
    begin
      System.Move(FBufBlock[FBlockSize], FBufBlock[0], FMacSize);
      FBufOff := FMacSize;
    end;

    Result := LSize;
    Exit;
  end;

  Result := 0;
end;

function TEaxBlockCipher.VerifyMac(const AMac: TCryptoLibByteArray;
  AOff: Int32): Boolean;
begin
  Result := TArrayUtilities.FixedTimeEquals(FMacSize, AMac, AOff, FMacBlock, 0);
end;

end.
