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

unit ClpChaCha20Poly1305;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Math,
  ClpIChaCha20Poly1305,
  ClpIAeadCipher,
  ClpICipherParameters,
  ClpIAeadParameters,
  ClpIParametersWithIV,
  ClpIKeyParameter,
  ClpChaCha7539Engine,
  ClpIChaCha7539Engine,
  ClpPoly1305,
  ClpIPoly1305,
  ClpIMac,
  ClpKeyParameter,
  ClpParametersWithIV,
  ClpPack,
  ClpCheck,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SPoly1305Nil = 'poly1305';
  SPoly1305MustBe128 = 'must be a 128-bit MAC';
  SInvalidParameters = 'invalid parameters passed to ChaCha20Poly1305';
  SKeyMustBeSpecified = 'Key must be specified in initial init';
  SKeyMustBe256 = 'Key must be 256 bits';
  SNonceMustBe96 = 'Nonce must be 96 bits';
  SCannotReuseNonce = 'cannot reuse nonce for ChaCha20Poly1305 encryption';
  SInvalidMacSize = 'Invalid value for MAC size: %d';
  SCannotBeNegative = 'cannot be negative';
  SInputBufferTooShort = 'input buffer too short';
  SOutputBufferTooShort = 'output buffer too short';
  SDataTooShort = 'data too short';
  SMacCheckFailed = 'mac check in ChaCha20Poly1305 failed';
  SCannotReuseEncryption = ' cannot be reused for encryption';
  SNeedsInit = ' needs to be initialized';
  SLimitExceeded = 'Limit exceeded';

type
  TChaCha20Poly1305 = class(TInterfacedObject, IChaCha20Poly1305, IAeadCipher)

  strict private
  type
    TState = (
      Uninitialized = 0,
      EncInit = 1,
      EncAad = 2,
      EncData = 3,
      EncFinal = 4,
      DecInit = 5,
      DecAad = 6,
      DecData = 7,
      DecFinal = 8
    );

  const
    BufSize: Int32 = 64;
    KeySize: Int32 = 32;
    NonceSize: Int32 = 12;
    MacSize: Int32 = 16;

  class var
    FZeroes: TCryptoLibByteArray;

  const
    AadLimit: UInt64 = UInt64($FFFFFFFFFFFFFFFF);
    DataLimit: UInt64 = ((UInt64(1) shl 32) - 1) * 64;

  var
    FChaCha20: IChaCha7539Engine;
    FPoly1305: IMac;

    FKey: TCryptoLibByteArray;
    FNonce: TCryptoLibByteArray;
    FBuf: TCryptoLibByteArray;
    FMac: TCryptoLibByteArray;

    FInitialAad: TCryptoLibByteArray;

    FAadCount: UInt64;
    FDataCount: UInt64;
    FState: TState;
    FBufPos: Int32;

    procedure CheckAad();
    procedure CheckData();
    procedure FinishAad(ANextState: TState);
    procedure FinishData(ANextState: TState);
    function IncrementCount(ACount: UInt64; AIncrement: UInt32; ALimit: UInt64): UInt64;
    procedure InitMac();
    procedure PadMac(ACount: UInt64);
    procedure ProcessBlock(const AInBytes: TCryptoLibByteArray; AInOff: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32);
    procedure ProcessBlocks2(const AInBytes: TCryptoLibByteArray; AInOff: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32);
    procedure ProcessData(const AInBytes: TCryptoLibByteArray; AInOff, AInLen: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32);
    procedure Reset(AClearMac, AResetCipher: Boolean); overload;

    class constructor Create; overload;

  strict protected
    function GetAlgorithmName: String; virtual;

  public
    constructor Create(); overload;
    constructor Create(const APoly1305: IMac); overload;
    destructor Destroy; override;

    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters); virtual;

    function GetOutputSize(ALen: Int32): Int32; virtual;
    function GetUpdateOutputSize(ALen: Int32): Int32; virtual;

    procedure ProcessAadByte(AInput: Byte); virtual;
    procedure ProcessAadBytes(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32); virtual;

    function ProcessByte(AInput: Byte; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual;
    function ProcessBytes(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual;

    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual;

    function GetMac(): TCryptoLibByteArray; virtual;
    procedure Reset(); overload; virtual;

    property AlgorithmName: String read GetAlgorithmName;
  end;

implementation

{ TChaCha20Poly1305 }

class constructor TChaCha20Poly1305.Create;
begin
  System.SetLength(FZeroes, MacSize - 1);
end;

constructor TChaCha20Poly1305.Create;
begin
  Create(TPoly1305.Create() as IMac);
end;

constructor TChaCha20Poly1305.Create(const APoly1305: IMac);
begin
  inherited Create();

  if (APoly1305 = nil) then
    raise EArgumentNilCryptoLibException.CreateRes(@SPoly1305Nil);
  if (MacSize <> APoly1305.GetMacSize()) then
    raise EArgumentCryptoLibException.CreateRes(@SPoly1305MustBe128);

  FChaCha20 := TChaCha7539Engine.Create();
  FPoly1305 := APoly1305;

  System.SetLength(FKey, KeySize);
  System.SetLength(FNonce, NonceSize);
  System.SetLength(FBuf, BufSize + MacSize);
  System.SetLength(FMac, MacSize);

  FState := TState.Uninitialized;
end;

destructor TChaCha20Poly1305.Destroy;
begin
  inherited Destroy;
end;

function TChaCha20Poly1305.GetAlgorithmName: String;
begin
  Result := 'ChaCha20Poly1305';
end;

procedure TChaCha20Poly1305.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LAeadParams: IAeadParameters;
  LIvParams: IParametersWithIV;
  LInitKeyParam: IKeyParameter;
  LInitNonce: TCryptoLibByteArray;
  LChaCha20Params: ICipherParameters;
  LMacSizeBits: Int32;
begin
  if Supports(AParameters, IAeadParameters, LAeadParams) then
  begin
    LMacSizeBits := LAeadParams.MacSize;
    if ((MacSize * 8) <> LMacSizeBits) then
      raise EArgumentCryptoLibException.CreateResFmt(@SInvalidMacSize, [LMacSizeBits]);

    LInitKeyParam := LAeadParams.Key;
    LInitNonce := LAeadParams.GetNonce();
    LChaCha20Params := TParametersWithIV.Create(LInitKeyParam, LInitNonce) as IParametersWithIV;

    FInitialAad := LAeadParams.GetAssociatedText();
  end
  else if Supports(AParameters, IParametersWithIV, LIvParams) then
  begin
    LInitKeyParam := LIvParams.Parameters as IKeyParameter;
    LInitNonce := LIvParams.GetIV();
    LChaCha20Params := LIvParams;

    FInitialAad := nil;
  end
  else
    raise EArgumentCryptoLibException.CreateRes(@SInvalidParameters);

  if (LInitKeyParam = nil) then
  begin
    if (TState.Uninitialized = FState) then
      raise EArgumentCryptoLibException.CreateRes(@SKeyMustBeSpecified);
  end
  else
  begin
    if (KeySize <> LInitKeyParam.KeyLength) then
      raise EArgumentCryptoLibException.CreateRes(@SKeyMustBe256);
  end;

  if (NonceSize <> System.Length(LInitNonce)) then
    raise EArgumentCryptoLibException.CreateRes(@SNonceMustBe96);

  if (TState.Uninitialized <> FState) and AForEncryption and
    TArrayUtilities.AreEqual(FNonce, LInitNonce) then
  begin
    if (LInitKeyParam = nil) or LInitKeyParam.FixedTimeEquals(FKey) then
      raise EArgumentCryptoLibException.CreateRes(@SCannotReuseNonce);
  end;

  if (LInitKeyParam <> nil) then
  begin
    LInitKeyParam.CopyKeyTo(FKey, 0, KeySize);
  end;

  System.Move(LInitNonce[0], FNonce[0], NonceSize);

  FChaCha20.Init(True, LChaCha20Params);

  if AForEncryption then
    FState := TState.EncInit
  else
    FState := TState.DecInit;

  Reset(True, False);
end;

function TChaCha20Poly1305.GetOutputSize(ALen: Int32): Int32;
var
  LTotal: Int32;
begin
  LTotal := Math.Max(0, ALen);

  case FState of
    TState.DecInit, TState.DecAad:
      Result := Math.Max(0, LTotal - MacSize);
    TState.DecData, TState.DecFinal:
      Result := Math.Max(0, LTotal + FBufPos - MacSize);
    TState.EncData, TState.EncFinal:
      Result := LTotal + FBufPos + MacSize;
  else
    Result := LTotal + MacSize;
  end;
end;

function TChaCha20Poly1305.GetUpdateOutputSize(ALen: Int32): Int32;
var
  LTotal: Int32;
begin
  LTotal := Math.Max(0, ALen);

  case FState of
    TState.DecInit, TState.DecAad:
      LTotal := Math.Max(0, LTotal - MacSize);
    TState.DecData, TState.DecFinal:
      LTotal := Math.Max(0, LTotal + FBufPos - MacSize);
    TState.EncData, TState.EncFinal:
      LTotal := LTotal + FBufPos;
  else
    ;
  end;

  Result := LTotal - LTotal mod BufSize;
end;

procedure TChaCha20Poly1305.ProcessAadByte(AInput: Byte);
begin
  CheckAad();
  FAadCount := IncrementCount(FAadCount, 1, AadLimit);
  FPoly1305.Update(AInput);
end;

procedure TChaCha20Poly1305.ProcessAadBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32);
begin
  if (AInput = nil) then
    raise EArgumentNilCryptoLibException.Create('inBytes');
  if (AInOff < 0) then
    raise EArgumentCryptoLibException.CreateRes(@SCannotBeNegative);
  if (ALen < 0) then
    raise EArgumentCryptoLibException.CreateRes(@SCannotBeNegative);
  TCheck.DataLength(AInput, AInOff, ALen, SInputBufferTooShort);

  CheckAad();

  if (ALen > 0) then
  begin
    FAadCount := IncrementCount(FAadCount, UInt32(ALen), AadLimit);
    FPoly1305.BlockUpdate(AInput, AInOff, ALen);
  end;
end;

function TChaCha20Poly1305.ProcessByte(AInput: Byte;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  CheckData();

  case FState of
    TState.DecData:
    begin
      FBuf[FBufPos] := AInput;
      System.Inc(FBufPos);
      if (FBufPos = System.Length(FBuf)) then
      begin
        FPoly1305.BlockUpdate(FBuf, 0, BufSize);
        ProcessBlock(FBuf, 0, AOutput, AOutOff);
        System.Move(FBuf[BufSize], FBuf[0], MacSize);
        FBufPos := MacSize;
        Result := BufSize;
        Exit;
      end;
      Result := 0;
      Exit;
    end;
    TState.EncData:
    begin
      FBuf[FBufPos] := AInput;
      System.Inc(FBufPos);
      if (FBufPos = BufSize) then
      begin
        ProcessBlock(FBuf, 0, AOutput, AOutOff);
        FPoly1305.BlockUpdate(AOutput, AOutOff, BufSize);
        FBufPos := 0;
        Result := BufSize;
        Exit;
      end;
      Result := 0;
      Exit;
    end;
  else
    raise EInvalidOperationCryptoLibException.Create('');
  end;
end;

function TChaCha20Poly1305.ProcessBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LResultLen, LAvailable, LInLimit1, LInLimit2: Int32;
begin
  if (AInput = nil) then
    raise EArgumentNilCryptoLibException.Create('inBytes');
  if (AInOff < 0) then
    raise EArgumentCryptoLibException.CreateRes(@SCannotBeNegative);
  if (ALen < 0) then
    raise EArgumentCryptoLibException.CreateRes(@SCannotBeNegative);
  TCheck.DataLength(AInput, AInOff, ALen, SInputBufferTooShort);
  if (AOutOff < 0) then
    raise EArgumentCryptoLibException.CreateRes(@SCannotBeNegative);

  CheckData();

  LResultLen := 0;

  case FState of
    TState.DecData:
    begin
      LAvailable := System.Length(FBuf) - FBufPos;
      if (ALen < LAvailable) then
      begin
        System.Move(AInput[AInOff], FBuf[FBufPos], ALen);
        FBufPos := FBufPos + ALen;
        Result := 0;
        Exit;
      end;

      if (FBufPos >= BufSize) then
      begin
        FPoly1305.BlockUpdate(FBuf, 0, BufSize);
        ProcessBlock(FBuf, 0, AOutput, AOutOff);
        FBufPos := FBufPos - BufSize;
        System.Move(FBuf[BufSize], FBuf[0], FBufPos);
        LResultLen := BufSize;

        LAvailable := LAvailable + BufSize;
        if (ALen < LAvailable) then
        begin
          System.Move(AInput[AInOff], FBuf[FBufPos], ALen);
          FBufPos := FBufPos + ALen;
          Result := LResultLen;
          Exit;
        end;
      end;

      LInLimit1 := AInOff + ALen - System.Length(FBuf);
      LInLimit2 := LInLimit1 - BufSize;

      LAvailable := BufSize - FBufPos;
      System.Move(AInput[AInOff], FBuf[FBufPos], LAvailable);
      FPoly1305.BlockUpdate(FBuf, 0, BufSize);
      ProcessBlock(FBuf, 0, AOutput, AOutOff + LResultLen);
      AInOff := AInOff + LAvailable;
      LResultLen := LResultLen + BufSize;

      while (AInOff <= LInLimit2) do
      begin
        FPoly1305.BlockUpdate(AInput, AInOff, BufSize * 2);
        ProcessBlocks2(AInput, AInOff, AOutput, AOutOff + LResultLen);
        AInOff := AInOff + BufSize * 2;
        LResultLen := LResultLen + BufSize * 2;
      end;

      if (AInOff <= LInLimit1) then
      begin
        FPoly1305.BlockUpdate(AInput, AInOff, BufSize);
        ProcessBlock(AInput, AInOff, AOutput, AOutOff + LResultLen);
        AInOff := AInOff + BufSize;
        LResultLen := LResultLen + BufSize;
      end;

      FBufPos := System.Length(FBuf) + LInLimit1 - AInOff;
      System.Move(AInput[AInOff], FBuf[0], FBufPos);
    end;
    TState.EncData:
    begin
      LAvailable := BufSize - FBufPos;
      if (ALen < LAvailable) then
      begin
        System.Move(AInput[AInOff], FBuf[FBufPos], ALen);
        FBufPos := FBufPos + ALen;
        Result := 0;
        Exit;
      end;

      LInLimit1 := AInOff + ALen - BufSize;
      LInLimit2 := LInLimit1 - BufSize;

      if (FBufPos > 0) then
      begin
        System.Move(AInput[AInOff], FBuf[FBufPos], LAvailable);
        ProcessBlock(FBuf, 0, AOutput, AOutOff);
        AInOff := AInOff + LAvailable;
        LResultLen := BufSize;
      end;

      while (AInOff <= LInLimit2) do
      begin
        ProcessBlocks2(AInput, AInOff, AOutput, AOutOff + LResultLen);
        AInOff := AInOff + BufSize * 2;
        LResultLen := LResultLen + BufSize * 2;
      end;

      if (AInOff <= LInLimit1) then
      begin
        ProcessBlock(AInput, AInOff, AOutput, AOutOff + LResultLen);
        AInOff := AInOff + BufSize;
        LResultLen := LResultLen + BufSize;
      end;

      FPoly1305.BlockUpdate(AOutput, AOutOff, LResultLen);

      FBufPos := BufSize + LInLimit1 - AInOff;
      System.Move(AInput[AInOff], FBuf[0], FBufPos);
    end;
  else
    raise EInvalidOperationCryptoLibException.Create('');
  end;

  Result := LResultLen;
end;

function TChaCha20Poly1305.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LResultLen: Int32;
begin
  if (AOutput = nil) then
    raise EArgumentNilCryptoLibException.Create('outBytes');
  if (AOutOff < 0) then
    raise EArgumentCryptoLibException.CreateRes(@SCannotBeNegative);

  CheckData();

  TArrayUtilities.Fill<Byte>(FMac, 0, MacSize, Byte(0));

  LResultLen := 0;

  case FState of
    TState.DecData:
    begin
      if (FBufPos < MacSize) then
        raise EInvalidCipherTextCryptoLibException.CreateRes(@SDataTooShort);

      LResultLen := FBufPos - MacSize;

      TCheck.OutputLength(AOutput, AOutOff, LResultLen, SOutputBufferTooShort);

      if (LResultLen > 0) then
      begin
        FPoly1305.BlockUpdate(FBuf, 0, LResultLen);
        ProcessData(FBuf, 0, LResultLen, AOutput, AOutOff);
      end;

      FinishData(TState.DecFinal);

      if (not TArrayUtilities.FixedTimeEquals(MacSize, FMac, 0, FBuf, LResultLen)) then
        raise EInvalidCipherTextCryptoLibException.CreateRes(@SMacCheckFailed);
    end;
    TState.EncData:
    begin
      LResultLen := FBufPos + MacSize;

      TCheck.OutputLength(AOutput, AOutOff, LResultLen, SOutputBufferTooShort);

      if (FBufPos > 0) then
      begin
        ProcessData(FBuf, 0, FBufPos, AOutput, AOutOff);
        FPoly1305.BlockUpdate(AOutput, AOutOff, FBufPos);
      end;

      FinishData(TState.EncFinal);

      System.Move(FMac[0], AOutput[AOutOff + FBufPos], MacSize);
    end;
  else
    raise EInvalidOperationCryptoLibException.Create('');
  end;

  Reset(False, True);

  Result := LResultLen;
end;

function TChaCha20Poly1305.GetMac: TCryptoLibByteArray;
begin
  Result := System.Copy(FMac);
end;

procedure TChaCha20Poly1305.Reset;
begin
  Reset(True, True);
end;

procedure TChaCha20Poly1305.CheckAad;
begin
  case FState of
    TState.DecInit:
      FState := TState.DecAad;
    TState.EncInit:
      FState := TState.EncAad;
    TState.DecAad, TState.EncAad:
      ;
    TState.EncFinal:
      raise EInvalidOperationCryptoLibException.Create(AlgorithmName + SCannotReuseEncryption);
  else
    raise EInvalidOperationCryptoLibException.Create(AlgorithmName + SNeedsInit);
  end;
end;

procedure TChaCha20Poly1305.CheckData;
begin
  case FState of
    TState.DecInit, TState.DecAad:
      FinishAad(TState.DecData);
    TState.EncInit, TState.EncAad:
      FinishAad(TState.EncData);
    TState.DecData, TState.EncData:
      ;
    TState.EncFinal:
      raise EInvalidOperationCryptoLibException.Create(AlgorithmName + SCannotReuseEncryption);
  else
    raise EInvalidOperationCryptoLibException.Create(AlgorithmName + SNeedsInit);
  end;
end;

procedure TChaCha20Poly1305.FinishAad(ANextState: TState);
begin
  PadMac(FAadCount);
  FState := ANextState;
end;

procedure TChaCha20Poly1305.FinishData(ANextState: TState);
var
  LLengths: TCryptoLibByteArray;
begin
  PadMac(FDataCount);

  System.SetLength(LLengths, 16);
  TPack.UInt64_To_LE(FAadCount, LLengths, 0);
  TPack.UInt64_To_LE(FDataCount, LLengths, 8);
  FPoly1305.BlockUpdate(LLengths, 0, 16);

  FPoly1305.DoFinal(FMac, 0);

  FState := ANextState;
end;

function TChaCha20Poly1305.IncrementCount(ACount: UInt64;
  AIncrement: UInt32; ALimit: UInt64): UInt64;
begin
  if (ACount > (ALimit - AIncrement)) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SLimitExceeded);

  Result := ACount + AIncrement;
end;

procedure TChaCha20Poly1305.InitMac;
var
  LFirstBlock: TCryptoLibByteArray;
begin
  System.SetLength(LFirstBlock, 64);
  try
    FChaCha20.ProcessBytes(LFirstBlock, 0, 64, LFirstBlock, 0);
    FPoly1305.Init(TKeyParameter.Create(LFirstBlock, 0, 32) as IKeyParameter);
  finally
    TArrayUtilities.Fill<Byte>(LFirstBlock, 0, 64, Byte(0));
  end;
end;

procedure TChaCha20Poly1305.PadMac(ACount: UInt64);
var
  LPartial: Int32;
begin
  LPartial := Int32(ACount) and (MacSize - 1);
  if (0 <> LPartial) then
  begin
    FPoly1305.BlockUpdate(FZeroes, 0, MacSize - LPartial);
  end;
end;

procedure TChaCha20Poly1305.ProcessBlock(const AInBytes: TCryptoLibByteArray;
  AInOff: Int32; const AOutBytes: TCryptoLibByteArray; AOutOff: Int32);
begin
  TCheck.OutputLength(AOutBytes, AOutOff, 64, SOutputBufferTooShort);

  FChaCha20.ProcessBlock(AInBytes, AInOff, AOutBytes, AOutOff);

  FDataCount := IncrementCount(FDataCount, 64, DataLimit);
end;

procedure TChaCha20Poly1305.ProcessBlocks2(const AInBytes: TCryptoLibByteArray;
  AInOff: Int32; const AOutBytes: TCryptoLibByteArray; AOutOff: Int32);
begin
  TCheck.OutputLength(AOutBytes, AOutOff, 128, SOutputBufferTooShort);

  FChaCha20.ProcessBlocks2(AInBytes, AInOff, AOutBytes, AOutOff);

  FDataCount := IncrementCount(FDataCount, 128, DataLimit);
end;

procedure TChaCha20Poly1305.ProcessData(const AInBytes: TCryptoLibByteArray;
  AInOff, AInLen: Int32; const AOutBytes: TCryptoLibByteArray; AOutOff: Int32);
begin
  TCheck.OutputLength(AOutBytes, AOutOff, AInLen, SOutputBufferTooShort);

  FChaCha20.ProcessBytes(AInBytes, AInOff, AInLen, AOutBytes, AOutOff);

  FDataCount := IncrementCount(FDataCount, UInt32(AInLen), DataLimit);
end;

procedure TChaCha20Poly1305.Reset(AClearMac, AResetCipher: Boolean);
begin
  TArrayUtilities.Fill<Byte>(FBuf, 0, System.Length(FBuf), Byte(0));

  if AClearMac then
  begin
    TArrayUtilities.Fill<Byte>(FMac, 0, System.Length(FMac), Byte(0));
  end;

  FAadCount := UInt64(0);
  FDataCount := UInt64(0);
  FBufPos := 0;

  case FState of
    TState.DecInit, TState.EncInit:
      ;
    TState.DecAad, TState.DecData, TState.DecFinal:
      FState := TState.DecInit;
    TState.EncAad, TState.EncData, TState.EncFinal:
    begin
      FState := TState.EncFinal;
      Exit;
    end;
  else
    raise EInvalidOperationCryptoLibException.Create(AlgorithmName + SNeedsInit);
  end;

  if AResetCipher then
  begin
    FChaCha20.Reset();
  end;

  InitMac();

  if (FInitialAad <> nil) then
  begin
    ProcessAadBytes(FInitialAad, 0, System.Length(FInitialAad));
  end;
end;

end.
