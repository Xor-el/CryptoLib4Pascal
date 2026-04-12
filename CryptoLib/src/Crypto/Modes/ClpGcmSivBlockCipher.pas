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

unit ClpGcmSivBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  Math,
  SysUtils,
  ClpIBlockCipher,
  ClpIGcmSivBlockCipher,
  ClpIAeadBlockCipher,
  ClpIAeadCipher,
  ClpICipherParameters,
  ClpIAeadParameters,
  ClpIParametersWithIV,
  ClpIKeyParameter,
  ClpIGcmMultiplier,
  ClpGcmBlockCipher,
  ClpKeyParameter,
  ClpAesUtilities,
  ClpInt64Utilities,
  ClpByteUtilities,
  ClpPack,
  ClpCheck,
  ClpArrayUtilities,
  ClpStreamUtilities,
  ClpCryptoLibTypes;

resourcestring
  SCipherBlockSizeRequiredSiv = 'Cipher required with a block size of %d.';
  SInvalidParametersGcmSiv = 'invalid parameters passed to GCM_SIV';
  SInvalidNonce = 'Invalid nonce';
  SInvalidKey = 'Invalid key';
  SCipherNotInitialised = 'Cipher is not initialised';
  SAeadAfterData = 'AEAD data cannot be processed after ordinary data';
  SAeadByteCountExceeded = 'AEAD byte count exceeded';
  SByteCountExceeded = 'byte count exceeded';
  SOutputBufferTooShortSiv = 'output buffer too short';
  SInputBufferTooShortSiv = 'input buffer too short';
  SDataTooShortSiv = 'Data too short';
  SMacCheckFailedSiv = 'mac check failed';

type
  TGcmSivBlockCipher = class(TInterfacedObject, IGcmSivBlockCipher,
    IAeadBlockCipher, IAeadCipher)

  strict private
  type
    TGcmSivCache = class(TMemoryStream)
    public
      constructor Create;
    end;

    TGcmSivHasher = class(TObject)
    strict private
      FBuffer: TCryptoLibByteArray;
      FSingleByte: TCryptoLibByteArray;
      FNumActive: Int32;
      FNumHashed: UInt64;
      FParent: TGcmSivBlockCipher;
    public
      constructor Create(AParent: TGcmSivBlockCipher);
      function GetBytesProcessed(): UInt64;
      procedure Reset();
      procedure UpdateHash(AByte: Byte); overload;
      procedure UpdateHash(const ABuffer: TCryptoLibByteArray; AOffset, ALen: Int32); overload;
      procedure CompleteHash();
    end;

  strict private
  const
    FBUFLEN: Int32 = 16;
    FHALFBUFLEN: Int32 = 8;
    FNONCELEN: Int32 = 12;
    FMAX_DATALEN: Int32 = Int32($7FFFFFF8) - 16;
    FMASK: Byte = $80;
    FADD: Byte = $E1;
    FINIT: Int32 = 1;
    FAEAD_COMPLETE: Int32 = 2;

  var
    FTheCipher: IBlockCipher;
    FTheMultiplier: IGcmMultiplier;
    FTheGHash: TCryptoLibByteArray;
    FTheReverse: TCryptoLibByteArray;
    FTheAEADHasher: TGcmSivHasher;
    FTheDataHasher: TGcmSivHasher;
    FThePlain: TGcmSivCache;
    FTheEncData: TGcmSivCache;
    FForEncryption: Boolean;
    FTheInitialAEAD: TCryptoLibByteArray;
    FTheNonce: TCryptoLibByteArray;
    FTheFlags: Int32;

    procedure CheckAeadStatus(ALen: Int32);
    procedure CheckStatus(ALen: Int32);
    procedure DeriveKeys(const AKey: IKeyParameter);
    function CalculateTag(): TCryptoLibByteArray;
    function EncryptPlain(const ACounter: TCryptoLibByteArray;
      const ATarget: TCryptoLibByteArray; AOffset: Int32): Int32;
    procedure DecryptPlain();
    function CompletePolyVal(): TCryptoLibByteArray;
    procedure GHashLengths();
    procedure GHASH(const ANext: TCryptoLibByteArray);
    procedure ResetStreams();

    class procedure FillReverse(const AInput: TCryptoLibByteArray;
      AOffset, ALength: Int32; const AOutput: TCryptoLibByteArray); static;
    class procedure XorBlock(const ALeft, ARight: TCryptoLibByteArray); overload; static;
    class procedure XorBlock(const ALeft, ARight: TCryptoLibByteArray;
      AOffset, ALength: Int32); overload; static;
    class procedure IncrementCounter(const ACounter: TCryptoLibByteArray); static;
    class procedure MulX(const AValue: TCryptoLibByteArray); static;

  strict protected
    function GetAlgorithmName: String; virtual;
    function GetUnderlyingCipher(): IBlockCipher; virtual;

  public
    constructor Create(); overload;
    constructor Create(const ACipher: IBlockCipher); overload;
    constructor Create(const ACipher: IBlockCipher; const AMultiplier: IGcmMultiplier); overload;
    destructor Destroy; override;

    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters); virtual;
    function GetBlockSize(): Int32; virtual;

    procedure ProcessAadByte(AInput: Byte); virtual;
    procedure ProcessAadBytes(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32); virtual;

    function ProcessByte(AInput: Byte; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual;
    function ProcessBytes(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual;

    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual;

    function GetMac(): TCryptoLibByteArray; virtual;
    function GetOutputSize(ALen: Int32): Int32; virtual;
    function GetUpdateOutputSize(ALen: Int32): Int32; virtual;

    procedure Reset(); virtual;

    property AlgorithmName: String read GetAlgorithmName;
    property UnderlyingCipher: IBlockCipher read GetUnderlyingCipher;
  end;

implementation

{ TGcmSivBlockCipher.TGcmSivCache }

constructor TGcmSivBlockCipher.TGcmSivCache.Create;
begin
  inherited Create;
end;

{ TGcmSivBlockCipher.TGcmSivHasher }

constructor TGcmSivBlockCipher.TGcmSivHasher.Create(AParent: TGcmSivBlockCipher);
begin
  inherited Create;
  FParent := AParent;
  System.SetLength(FBuffer, 16);
  System.SetLength(FSingleByte, 1);
  FNumActive := 0;
  FNumHashed := 0;
end;

function TGcmSivBlockCipher.TGcmSivHasher.GetBytesProcessed: UInt64;
begin
  Result := FNumHashed;
end;

procedure TGcmSivBlockCipher.TGcmSivHasher.Reset;
begin
  FNumActive := 0;
  FNumHashed := 0;
end;

procedure TGcmSivBlockCipher.TGcmSivHasher.UpdateHash(AByte: Byte);
begin
  FSingleByte[0] := AByte;
  UpdateHash(FSingleByte, 0, 1);
end;

procedure TGcmSivBlockCipher.TGcmSivHasher.UpdateHash(const ABuffer: TCryptoLibByteArray;
  AOffset, ALen: Int32);
var
  LMySpace, LNumProcessed, LMyRemaining: Int32;
begin
  LMySpace := 16 - FNumActive;
  LNumProcessed := 0;
  LMyRemaining := ALen;

  if (FNumActive > 0) and (ALen >= LMySpace) then
  begin
    System.Move(ABuffer[AOffset], FBuffer[FNumActive], LMySpace);
    TGcmSivBlockCipher.FillReverse(FBuffer, 0, 16, FParent.FTheReverse);
    FParent.GHASH(FParent.FTheReverse);

    LNumProcessed := LNumProcessed + LMySpace;
    LMyRemaining := LMyRemaining - LMySpace;
    FNumActive := 0;
  end;

  while LMyRemaining >= 16 do
  begin
    TGcmSivBlockCipher.FillReverse(ABuffer, AOffset + LNumProcessed, 16, FParent.FTheReverse);
    FParent.GHASH(FParent.FTheReverse);

    LNumProcessed := LNumProcessed + 16;
    LMyRemaining := LMyRemaining - 16;
  end;

  if LMyRemaining > 0 then
  begin
    System.Move(ABuffer[AOffset + LNumProcessed], FBuffer[FNumActive], LMyRemaining);
    FNumActive := FNumActive + LMyRemaining;
  end;

  FNumHashed := FNumHashed + UInt64(ALen);
end;

procedure TGcmSivBlockCipher.TGcmSivHasher.CompleteHash;
begin
  if FNumActive > 0 then
  begin
    TArrayUtilities.Fill<Byte>(FParent.FTheReverse, 0, System.Length(FParent.FTheReverse), Byte(0));
    TGcmSivBlockCipher.FillReverse(FBuffer, 0, FNumActive, FParent.FTheReverse);

    FParent.GHASH(FParent.FTheReverse);
  end;
end;

{ TGcmSivBlockCipher }

constructor TGcmSivBlockCipher.Create;
begin
  Create(TAesUtilities.CreateEngine());
end;

constructor TGcmSivBlockCipher.Create(const ACipher: IBlockCipher);
begin
  Create(ACipher, nil);
end;

constructor TGcmSivBlockCipher.Create(const ACipher: IBlockCipher;
  const AMultiplier: IGcmMultiplier);
begin
  inherited Create;
  if ACipher.GetBlockSize() <> FBUFLEN then
    raise EArgumentCryptoLibException.CreateResFmt(@SCipherBlockSizeRequiredSiv, [FBUFLEN]);

  if AMultiplier <> nil then
    FTheMultiplier := AMultiplier
  else
    FTheMultiplier := TGcmBlockCipher.CreateGcmMultiplier();

  FTheCipher := ACipher;

  System.SetLength(FTheGHash, FBUFLEN);
  System.SetLength(FTheReverse, FBUFLEN);

  FTheAEADHasher := TGcmSivHasher.Create(Self);
  FTheDataHasher := TGcmSivHasher.Create(Self);
end;

destructor TGcmSivBlockCipher.Destroy;
begin
  FTheAEADHasher.Free;
  FTheDataHasher.Free;
  FThePlain.Free;
  FTheEncData.Free;
  inherited Destroy;
end;

function TGcmSivBlockCipher.GetAlgorithmName: String;
begin
  Result := FTheCipher.AlgorithmName + '-GCM-SIV';
end;

function TGcmSivBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  Result := FTheCipher;
end;

function TGcmSivBlockCipher.GetBlockSize: Int32;
begin
  Result := FTheCipher.GetBlockSize();
end;

procedure TGcmSivBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LAeadParameters: IAeadParameters;
  LParametersWithIV: IParametersWithIV;
  LMyKey: IKeyParameter;
  LMyNonce: TCryptoLibByteArray;
  LMyInitialAEAD: TCryptoLibByteArray;
  LKeyLength: Int32;
begin
  LMyInitialAEAD := nil;

  if Supports(AParameters, IAeadParameters, LAeadParameters) then
  begin
    LMyInitialAEAD := LAeadParameters.GetAssociatedText();
    LMyNonce := LAeadParameters.GetNonce();
    LMyKey := LAeadParameters.Key;
  end
  else if Supports(AParameters, IParametersWithIV, LParametersWithIV) then
  begin
    LMyNonce := LParametersWithIV.GetIV();
    if not Supports(LParametersWithIV.Parameters, IKeyParameter, LMyKey) then
      LMyKey := nil;
  end
  else
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidParametersGcmSiv);
  end;

  if System.Length(LMyNonce) <> FNONCELEN then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidNonce);

  if LMyKey = nil then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidKey);

  LKeyLength := LMyKey.GetKeyLength();
  if (LKeyLength <> FBUFLEN) and (LKeyLength <> (FBUFLEN shl 1)) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidKey);

  FForEncryption := AForEncryption;
  FTheInitialAEAD := LMyInitialAEAD;
  FTheNonce := LMyNonce;

  DeriveKeys(LMyKey);
  ResetStreams();
end;

procedure TGcmSivBlockCipher.CheckAeadStatus(ALen: Int32);
begin
  if (FTheFlags and FINIT) = 0 then
    raise EInvalidOperationCryptoLibException.CreateRes(@SCipherNotInitialised);

  if (FTheFlags and FAEAD_COMPLETE) <> 0 then
    raise EInvalidOperationCryptoLibException.CreateRes(@SAeadAfterData);

  if FTheAEADHasher.GetBytesProcessed() > UInt64(FMAX_DATALEN - ALen) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SAeadByteCountExceeded);
end;

procedure TGcmSivBlockCipher.CheckStatus(ALen: Int32);
var
  LDataLimit: Int64;
  LCurrBytes: Int64;
begin
  if (FTheFlags and FINIT) = 0 then
    raise EInvalidOperationCryptoLibException.CreateRes(@SCipherNotInitialised);

  if (FTheFlags and FAEAD_COMPLETE) = 0 then
  begin
    FTheAEADHasher.CompleteHash();
    FTheFlags := FTheFlags or FAEAD_COMPLETE;
  end;

  LDataLimit := FMAX_DATALEN;
  LCurrBytes := FThePlain.Size;
  if not FForEncryption then
  begin
    LDataLimit := LDataLimit + FBUFLEN;
    LCurrBytes := FTheEncData.Size;
  end;

  if TInt64Utilities.CompareUnsigned(LCurrBytes, LDataLimit - ALen) > 0 then
    raise EInvalidOperationCryptoLibException.CreateRes(@SByteCountExceeded);
end;

procedure TGcmSivBlockCipher.ProcessAadByte(AInput: Byte);
begin
  CheckAeadStatus(1);
  FTheAEADHasher.UpdateHash(AInput);
end;

procedure TGcmSivBlockCipher.ProcessAadBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32);
begin
  TCheck.DataLength(AInput, AInOff, ALen, SInputBufferTooShortSiv);
  CheckAeadStatus(ALen);
  FTheAEADHasher.UpdateHash(AInput, AInOff, ALen);
end;

function TGcmSivBlockCipher.ProcessByte(AInput: Byte;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  CheckStatus(1);

  if FForEncryption then
  begin
    FThePlain.WriteByte(AInput);
    FTheDataHasher.UpdateHash(AInput);
  end
  else
  begin
    FTheEncData.WriteByte(AInput);
  end;

  Result := 0;
end;

function TGcmSivBlockCipher.ProcessBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  TCheck.DataLength(AInput, AInOff, ALen, SInputBufferTooShortSiv);
  CheckStatus(ALen);

  if FForEncryption then
  begin
    FThePlain.Write(AInput[AInOff], ALen);
    FTheDataHasher.UpdateHash(AInput, AInOff, ALen);
  end
  else
  begin
    FTheEncData.Write(AInput[AInOff], ALen);
  end;

  Result := 0;
end;

function TGcmSivBlockCipher.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LMyTag: TCryptoLibByteArray;
  LMyDataLen: Int32;
begin
  TCheck.OutputLength(AOutput, AOutOff, GetOutputSize(0), SOutputBufferTooShortSiv);
  CheckStatus(0);

  if FForEncryption then
  begin
    LMyTag := CalculateTag();

    LMyDataLen := FBUFLEN + EncryptPlain(LMyTag, AOutput, AOutOff);

    System.Move(LMyTag[0], AOutput[AOutOff + FThePlain.Size], FBUFLEN);

    ResetStreams();
    Result := LMyDataLen;
  end
  else
  begin
    DecryptPlain();

    LMyDataLen := TStreamUtilities.WriteBufTo(FThePlain, AOutput, AOutOff);

    ResetStreams();
    Result := LMyDataLen;
  end;
end;

function TGcmSivBlockCipher.GetMac: TCryptoLibByteArray;
begin
  raise EInvalidOperationCryptoLibException.Create('');
end;

function TGcmSivBlockCipher.GetUpdateOutputSize(ALen: Int32): Int32;
begin
  Result := 0;
end;

function TGcmSivBlockCipher.GetOutputSize(ALen: Int32): Int32;
var
  LMyCurr: Int32;
begin
  if FForEncryption then
  begin
    Result := ALen + Int32(FThePlain.Size) + FBUFLEN;
  end
  else
  begin
    LMyCurr := ALen + Int32(FTheEncData.Size);
    if LMyCurr > FBUFLEN then
      Result := LMyCurr - FBUFLEN
    else
      Result := 0;
  end;
end;

procedure TGcmSivBlockCipher.Reset;
begin
  ResetStreams();
end;

procedure TGcmSivBlockCipher.ResetStreams;
var
  LCount: Int32;
begin
  if FThePlain <> nil then
  begin
    LCount := Int32(FThePlain.Size);
    if LCount > 0 then
      FillChar(PByte(FThePlain.Memory)^, LCount, 0);
    FThePlain.Size := 0;
  end;

  FTheAEADHasher.Reset();
  FTheDataHasher.Reset();

  FThePlain.Free;
  FThePlain := TGcmSivCache.Create();

  FTheEncData.Free;
  if FForEncryption then
    FTheEncData := nil
  else
    FTheEncData := TGcmSivCache.Create();

  FTheFlags := FTheFlags and (not FAEAD_COMPLETE);
  TArrayUtilities.Fill<Byte>(FTheGHash, 0, System.Length(FTheGHash), Byte(0));

  if FTheInitialAEAD <> nil then
    FTheAEADHasher.UpdateHash(FTheInitialAEAD, 0, System.Length(FTheInitialAEAD));
end;

function TGcmSivBlockCipher.EncryptPlain(const ACounter: TCryptoLibByteArray;
  const ATarget: TCryptoLibByteArray; AOffset: Int32): Int32;
var
  LThePlainBuf: TCryptoLibByteArray;
  LThePlainLen: Int32;
  LMySrc, LMyCounter, LMyMask: TCryptoLibByteArray;
  LMyRemaining: Int64;
  LMyOff, LMyLen: Int32;
begin
  System.SetLength(LThePlainBuf, FThePlain.Size);
  FThePlain.Position := 0;
  FThePlain.ReadBuffer(LThePlainBuf[0], System.Length(LThePlainBuf));
  LThePlainLen := System.Length(LThePlainBuf);

  LMySrc := LThePlainBuf;
  LMyCounter := System.Copy(ACounter);
  LMyCounter[FBUFLEN - 1] := LMyCounter[FBUFLEN - 1] or FMASK;
  System.SetLength(LMyMask, FBUFLEN);
  LMyRemaining := LThePlainLen;
  LMyOff := 0;

  while LMyRemaining > 0 do
  begin
    FTheCipher.ProcessBlock(LMyCounter, 0, LMyMask, 0);

    LMyLen := Int32(Math.Min(FBUFLEN, LMyRemaining));
    XorBlock(LMyMask, LMySrc, LMyOff, LMyLen);

    System.Move(LMyMask[0], ATarget[AOffset + LMyOff], LMyLen);

    LMyRemaining := LMyRemaining - LMyLen;
    LMyOff := LMyOff + LMyLen;
    IncrementCounter(LMyCounter);
  end;

  Result := LThePlainLen;
end;

procedure TGcmSivBlockCipher.DecryptPlain;
var
  LTheEncDataBuf: TCryptoLibByteArray;
  LTheEncDataLen: Int32;
  LMySrc, LMyExpected, LMyCounter, LMyMask, LMyTag: TCryptoLibByteArray;
  LMyRemaining, LMyOff, LMyLen: Int32;
begin
  System.SetLength(LTheEncDataBuf, FTheEncData.Size);
  FTheEncData.Position := 0;
  FTheEncData.ReadBuffer(LTheEncDataBuf[0], System.Length(LTheEncDataBuf));
  LTheEncDataLen := System.Length(LTheEncDataBuf);

  LMySrc := LTheEncDataBuf;
  LMyRemaining := LTheEncDataLen - FBUFLEN;

  if LMyRemaining < 0 then
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SDataTooShortSiv);

  LMyExpected := TArrayUtilities.CopyOfRange<Byte>(LMySrc, LMyRemaining, LMyRemaining + FBUFLEN);
  LMyCounter := System.Copy(LMyExpected);
  LMyCounter[FBUFLEN - 1] := LMyCounter[FBUFLEN - 1] or FMASK;
  System.SetLength(LMyMask, FBUFLEN);
  LMyOff := 0;

  while LMyRemaining > 0 do
  begin
    FTheCipher.ProcessBlock(LMyCounter, 0, LMyMask, 0);

    LMyLen := Math.Min(FBUFLEN, LMyRemaining);
    XorBlock(LMyMask, LMySrc, LMyOff, LMyLen);

    FThePlain.Write(LMyMask[0], LMyLen);
    FTheDataHasher.UpdateHash(LMyMask, 0, LMyLen);

    LMyRemaining := LMyRemaining - LMyLen;
    LMyOff := LMyOff + LMyLen;
    IncrementCounter(LMyCounter);
  end;

  LMyTag := CalculateTag();
  if not TArrayUtilities.FixedTimeEquals(LMyTag, LMyExpected) then
  begin
    Reset();
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SMacCheckFailedSiv);
  end;
end;

function TGcmSivBlockCipher.CalculateTag: TCryptoLibByteArray;
var
  LMyPolyVal, LMyResult: TCryptoLibByteArray;
  LI: Int32;
begin
  FTheDataHasher.CompleteHash();
  LMyPolyVal := CompletePolyVal();

  System.SetLength(LMyResult, FBUFLEN);

  for LI := 0 to FNONCELEN - 1 do
    LMyPolyVal[LI] := LMyPolyVal[LI] xor FTheNonce[LI];

  LMyPolyVal[FBUFLEN - 1] := LMyPolyVal[FBUFLEN - 1] and Byte(FMASK - 1);

  FTheCipher.ProcessBlock(LMyPolyVal, 0, LMyResult, 0);
  Result := LMyResult;
end;

function TGcmSivBlockCipher.CompletePolyVal: TCryptoLibByteArray;
var
  LMyResult: TCryptoLibByteArray;
begin
  System.SetLength(LMyResult, FBUFLEN);
  GHashLengths();
  FillReverse(FTheGHash, 0, FBUFLEN, LMyResult);
  Result := LMyResult;
end;

procedure TGcmSivBlockCipher.GHashLengths;
var
  LMyIn: TCryptoLibByteArray;
begin
  System.SetLength(LMyIn, FBUFLEN);
  TPack.UInt64_To_BE(UInt64(TByteUtilities.NumBits) * FTheDataHasher.GetBytesProcessed(), LMyIn, 0);
  TPack.UInt64_To_BE(UInt64(TByteUtilities.NumBits) * FTheAEADHasher.GetBytesProcessed(), LMyIn, TInt64Utilities.NumBytes);
  GHASH(LMyIn);
end;

procedure TGcmSivBlockCipher.GHASH(const ANext: TCryptoLibByteArray);
begin
  XorBlock(FTheGHash, ANext);
  FTheMultiplier.MultiplyH(FTheGHash);
end;

class procedure TGcmSivBlockCipher.FillReverse(const AInput: TCryptoLibByteArray;
  AOffset, ALength: Int32; const AOutput: TCryptoLibByteArray);
var
  LI, LJ: Int32;
begin
  LJ := 16 - 1;
  for LI := 0 to ALength - 1 do
  begin
    AOutput[LJ] := AInput[AOffset + LI];
    System.Dec(LJ);
  end;
end;

class procedure TGcmSivBlockCipher.XorBlock(const ALeft, ARight: TCryptoLibByteArray);
var
  LI: Int32;
begin
  for LI := 0 to 15 do
    ALeft[LI] := ALeft[LI] xor ARight[LI];
end;

class procedure TGcmSivBlockCipher.XorBlock(const ALeft, ARight: TCryptoLibByteArray;
  AOffset, ALength: Int32);
var
  LI: Int32;
begin
  for LI := 0 to ALength - 1 do
    ALeft[LI] := ALeft[LI] xor ARight[LI + AOffset];
end;

class procedure TGcmSivBlockCipher.IncrementCounter(const ACounter: TCryptoLibByteArray);
var
  LI: Int32;
begin
  for LI := 0 to 3 do
  begin
    ACounter[LI] := Byte(ACounter[LI] + 1);
    if ACounter[LI] <> 0 then
      Break;
  end;
end;

class procedure TGcmSivBlockCipher.MulX(const AValue: TCryptoLibByteArray);
var
  LMyMask: Byte;
  LI: Int32;
  LMyValue: Byte;
begin
  LMyMask := Byte(0);
  for LI := 0 to 15 do
  begin
    LMyValue := AValue[LI];
    AValue[LI] := Byte(((LMyValue shr 1) and (not Byte($80))) or LMyMask);
    if (LMyValue and 1) = 0 then
      LMyMask := Byte(0)
    else
      LMyMask := Byte($80);
  end;

  if LMyMask <> 0 then
    AValue[0] := AValue[0] xor Byte($E1);
end;

procedure TGcmSivBlockCipher.DeriveKeys(const AKey: IKeyParameter);
var
  LMyIn, LMyOut, LMyResult, LMyEncKey: TCryptoLibByteArray;
  LMyOff: Int32;
begin
  System.SetLength(LMyIn, FBUFLEN);
  System.SetLength(LMyOut, FBUFLEN);
  System.SetLength(LMyResult, FBUFLEN);
  System.SetLength(LMyEncKey, AKey.GetKeyLength());

  System.Move(FTheNonce[0], LMyIn[FBUFLEN - FNONCELEN], FNONCELEN);
  FTheCipher.Init(True, AKey as ICipherParameters);

  LMyOff := 0;
  FTheCipher.ProcessBlock(LMyIn, 0, LMyOut, 0);
  System.Move(LMyOut[0], LMyResult[LMyOff], FHALFBUFLEN);
  LMyIn[0] := Byte(LMyIn[0] + 1);
  LMyOff := LMyOff + FHALFBUFLEN;
  FTheCipher.ProcessBlock(LMyIn, 0, LMyOut, 0);
  System.Move(LMyOut[0], LMyResult[LMyOff], FHALFBUFLEN);

  LMyIn[0] := Byte(LMyIn[0] + 1);
  LMyOff := 0;
  FTheCipher.ProcessBlock(LMyIn, 0, LMyOut, 0);
  System.Move(LMyOut[0], LMyEncKey[LMyOff], FHALFBUFLEN);
  LMyIn[0] := Byte(LMyIn[0] + 1);
  LMyOff := LMyOff + FHALFBUFLEN;
  FTheCipher.ProcessBlock(LMyIn, 0, LMyOut, 0);
  System.Move(LMyOut[0], LMyEncKey[LMyOff], FHALFBUFLEN);

  if System.Length(LMyEncKey) = (FBUFLEN shl 1) then
  begin
    LMyIn[0] := Byte(LMyIn[0] + 1);
    LMyOff := LMyOff + FHALFBUFLEN;
    FTheCipher.ProcessBlock(LMyIn, 0, LMyOut, 0);
    System.Move(LMyOut[0], LMyEncKey[LMyOff], FHALFBUFLEN);
    LMyIn[0] := Byte(LMyIn[0] + 1);
    LMyOff := LMyOff + FHALFBUFLEN;
    FTheCipher.ProcessBlock(LMyIn, 0, LMyOut, 0);
    System.Move(LMyOut[0], LMyEncKey[LMyOff], FHALFBUFLEN);
  end;

  FTheCipher.Init(True, TKeyParameter.Create(LMyEncKey) as ICipherParameters);

  FillReverse(LMyResult, 0, FBUFLEN, LMyOut);
  MulX(LMyOut);
  FTheMultiplier.Init(LMyOut);
  FTheFlags := FTheFlags or FINIT;
end;

end.
