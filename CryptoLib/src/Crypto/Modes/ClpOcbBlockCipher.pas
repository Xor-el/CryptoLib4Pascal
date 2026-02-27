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

unit ClpOcbBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpIBlockCipher,
  ClpIOcbBlockCipher,
  ClpIAeadBlockCipher,
  ClpIAeadCipher,
  ClpICipherParameters,
  ClpIAeadParameters,
  ClpIParametersWithIV,
  ClpIKeyParameter,
  ClpCheck,
  ClpBitOperations,
  ClpByteUtilities,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SHashCipherNil = 'hashCipher';
  SMainCipherNil = 'mainCipher';
  SBlockSizeRequired = 'must have a block size of %d';
  SCiphersMustMatch = '''hashCipher'' and ''mainCipher'' must be the same algorithm';
  SInvalidParametersOCB = 'invalid parameters passed to OCB';
  SIVTooLong = 'IV must be no more than 15 bytes';
  SCannotChangeEncState = 'cannot change encrypting state without providing key.';
  SInvalidMacSize = 'Invalid value for MAC size: %d';
  SDataTooShort = 'data too short';
  SMacCheckFailed = 'mac check in OCB failed';
  SOutputBufferTooShort = 'output buffer too short';

type
  TOcbBlockCipher = class(TInterfacedObject, IOcbBlockCipher,
    IAeadBlockCipher, IAeadCipher)

  strict private
  const
    BLOCK_SIZE: Int32 = 16;

  var
    FHashCipher: IBlockCipher;
    FMainCipher: IBlockCipher;

    FForEncryption: Boolean;
    FMacSize: Int32;
    FInitialAssociatedText: TCryptoLibByteArray;

    FL: TList<TCryptoLibByteArray>;
    FL_Asterisk, FL_Dollar: TCryptoLibByteArray;

    FKTopInput: TCryptoLibByteArray;
    FStretch: TCryptoLibByteArray;
    FOffsetMAIN_0: TCryptoLibByteArray;

    FHashBlock, FMainBlock: TCryptoLibByteArray;
    FHashBlockPos, FMainBlockPos: Int32;
    FHashBlockCount, FMainBlockCount: Int64;
    FOffsetHASH: TCryptoLibByteArray;
    FSum: TCryptoLibByteArray;
    FOffsetMAIN: TCryptoLibByteArray;
    FChecksum: TCryptoLibByteArray;

    FMacBlock: TCryptoLibByteArray;

    class function OCB_double(const ABlock: TCryptoLibByteArray): TCryptoLibByteArray; static;
    class procedure OCB_extend(const ABlock: TCryptoLibByteArray; APos: Int32); static;
    class function OCB_ntz(AX: Int64): Int32; static;
    class function ShiftLeft(const ABlock, AOutput: TCryptoLibByteArray): Int32; static;
    class procedure &Xor(const ABlock, AVal: TCryptoLibByteArray); static;

  strict protected
    function ProcessNonce(const AN: TCryptoLibByteArray): Int32; virtual;
    procedure Clear(const ABs: TCryptoLibByteArray); virtual;
    function GetLSub(AN: Int32): TCryptoLibByteArray; virtual;
    procedure ProcessHashBlock(); virtual;
    procedure ProcessMainBlock(const AOutput: TCryptoLibByteArray; AOutOff: Int32); virtual;
    procedure Reset(AClearMac: Boolean); overload; virtual;
    procedure UpdateHASH(const ALSub: TCryptoLibByteArray); virtual;

    function GetAlgorithmName: String; virtual;
    function GetUnderlyingCipher(): IBlockCipher; virtual;

  public
    constructor Create(const AHashCipher, AMainCipher: IBlockCipher);
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
    function GetUpdateOutputSize(ALen: Int32): Int32; virtual;
    function GetOutputSize(ALen: Int32): Int32; virtual;
    procedure Reset(); overload; virtual;

    property UnderlyingCipher: IBlockCipher read GetUnderlyingCipher;
    property AlgorithmName: String read GetAlgorithmName;
  end;

implementation

{ TOcbBlockCipher }

constructor TOcbBlockCipher.Create(const AHashCipher, AMainCipher: IBlockCipher);
begin
  inherited Create();

  if (AHashCipher = nil) then
    raise EArgumentNilCryptoLibException.CreateRes(@SHashCipherNil);
  if (AHashCipher.GetBlockSize() <> BLOCK_SIZE) then
    raise EArgumentCryptoLibException.CreateResFmt(@SBlockSizeRequired, [BLOCK_SIZE]);
  if (AMainCipher = nil) then
    raise EArgumentNilCryptoLibException.CreateRes(@SMainCipherNil);
  if (AMainCipher.GetBlockSize() <> BLOCK_SIZE) then
    raise EArgumentCryptoLibException.CreateResFmt(@SBlockSizeRequired, [BLOCK_SIZE]);

  if (AHashCipher.AlgorithmName <> AMainCipher.AlgorithmName) then
    raise EArgumentCryptoLibException.CreateRes(@SCiphersMustMatch);

  FHashCipher := AHashCipher;
  FMainCipher := AMainCipher;

  System.SetLength(FStretch, 24);
  System.SetLength(FOffsetMAIN_0, 16);
  System.SetLength(FOffsetMAIN, 16);
  FL := TList<TCryptoLibByteArray>.Create;
end;

destructor TOcbBlockCipher.Destroy;
begin
  FL.Free;
  inherited Destroy;
end;

function TOcbBlockCipher.GetAlgorithmName: String;
begin
  Result := FMainCipher.AlgorithmName + '/OCB';
end;

function TOcbBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  Result := FMainCipher;
end;

procedure TOcbBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LOldForEncryption: Boolean;
  LKeyParameter: IKeyParameter;
  LAeadParameters: IAeadParameters;
  LParametersWithIV: IParametersWithIV;
  LN: TCryptoLibByteArray;
  LMacSizeBits, LBottom, LBits, LBytes, LI: Int32;
  LB1, LB2: UInt32;
begin
  LOldForEncryption := FForEncryption;
  FForEncryption := AForEncryption;
  FMacBlock := nil;
  FL.Clear;

  if Supports(AParameters, IAeadParameters, LAeadParameters) then
  begin
    LN := LAeadParameters.GetNonce();
    FInitialAssociatedText := LAeadParameters.GetAssociatedText();

    LMacSizeBits := LAeadParameters.MacSize;
    if (LMacSizeBits < 64) or (LMacSizeBits > 128) or (LMacSizeBits mod 8 <> 0) then
      raise EArgumentCryptoLibException.CreateResFmt(@SInvalidMacSize, [LMacSizeBits]);

    FMacSize := LMacSizeBits div 8;
    LKeyParameter := LAeadParameters.Key;
  end
  else if Supports(AParameters, IParametersWithIV, LParametersWithIV) then
  begin
    LN := LParametersWithIV.GetIV();
    FInitialAssociatedText := nil;
    FMacSize := 16;
    LKeyParameter := LParametersWithIV.Parameters as IKeyParameter;
  end
  else
    raise EArgumentCryptoLibException.CreateRes(@SInvalidParametersOCB);

  System.SetLength(FHashBlock, 16);
  TArrayUtilities.Fill<Byte>(FHashBlock, 0, 16, Byte(0));
  if FForEncryption then
  begin
    System.SetLength(FMainBlock, BLOCK_SIZE);
    TArrayUtilities.Fill<Byte>(FMainBlock, 0, BLOCK_SIZE, Byte(0));
  end
  else
  begin
    System.SetLength(FMainBlock, BLOCK_SIZE + FMacSize);
    TArrayUtilities.Fill<Byte>(FMainBlock, 0, BLOCK_SIZE + FMacSize, Byte(0));
  end;

  if (System.Length(LN) > 15) then
    raise EArgumentCryptoLibException.CreateRes(@SIVTooLong);

  if (LKeyParameter <> nil) then
  begin
    FHashCipher.Init(True, LKeyParameter);
    FMainCipher.Init(AForEncryption, LKeyParameter);
    FKTopInput := nil;
  end
  else if (LOldForEncryption <> AForEncryption) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SCannotChangeEncState);
  end;

  System.SetLength(FL_Asterisk, 16);
  TArrayUtilities.Fill<Byte>(FL_Asterisk, 0, 16, Byte(0));
  FHashCipher.ProcessBlock(FL_Asterisk, 0, FL_Asterisk, 0);

  FL_Dollar := OCB_double(FL_Asterisk);

  FL.Add(OCB_double(FL_Dollar));

  LBottom := ProcessNonce(LN);

  LBits := LBottom mod 8;
  LBytes := LBottom div 8;
  if (LBits = 0) then
  begin
    System.Move(FStretch[LBytes], FOffsetMAIN_0[0], 16);
  end
  else
  begin
    for LI := 0 to 15 do
    begin
      LB1 := UInt32(FStretch[LBytes]);
      System.Inc(LBytes);
      LB2 := UInt32(FStretch[LBytes]);
      FOffsetMAIN_0[LI] := Byte((LB1 shl LBits) or (LB2 shr (8 - LBits)));
    end;
  end;

  FHashBlockPos := 0;
  FMainBlockPos := 0;

  FHashBlockCount := 0;
  FMainBlockCount := 0;

  System.SetLength(FOffsetHASH, 16);
  TArrayUtilities.Fill<Byte>(FOffsetHASH, 0, 16, Byte(0));
  System.SetLength(FSum, 16);
  TArrayUtilities.Fill<Byte>(FSum, 0, 16, Byte(0));
  System.Move(FOffsetMAIN_0[0], FOffsetMAIN[0], 16);
  System.SetLength(FChecksum, 16);
  TArrayUtilities.Fill<Byte>(FChecksum, 0, 16, Byte(0));

  if (FInitialAssociatedText <> nil) then
  begin
    ProcessAadBytes(FInitialAssociatedText, 0, System.Length(FInitialAssociatedText));
  end;
end;

function TOcbBlockCipher.ProcessNonce(const AN: TCryptoLibByteArray): Int32;
var
  LNonce, LKTop: TCryptoLibByteArray;
  LBottom, LI: Int32;
begin
  System.SetLength(LNonce, 16);
  System.Move(AN[0], LNonce[System.Length(LNonce) - System.Length(AN)], System.Length(AN));
  LNonce[0] := Byte(FMacSize shl 4);
  LNonce[15 - System.Length(AN)] := LNonce[15 - System.Length(AN)] or 1;

  LBottom := LNonce[15] and $3F;
  LNonce[15] := LNonce[15] and Byte($C0);

  if (FKTopInput = nil) or (not TArrayUtilities.AreEqual(LNonce, FKTopInput)) then
  begin
    System.SetLength(LKTop, 16);
    FKTopInput := LNonce;
    FHashCipher.ProcessBlock(FKTopInput, 0, LKTop, 0);
    System.Move(LKTop[0], FStretch[0], 16);
    for LI := 0 to 7 do
    begin
      FStretch[16 + LI] := Byte(LKTop[LI] xor LKTop[LI + 1]);
    end;
  end;

  Result := LBottom;
end;

function TOcbBlockCipher.GetBlockSize: Int32;
begin
  Result := BLOCK_SIZE;
end;

function TOcbBlockCipher.GetMac: TCryptoLibByteArray;
begin
  if FMacBlock = nil then
    System.SetLength(Result, FMacSize)
  else
    Result := System.Copy(FMacBlock);
end;

function TOcbBlockCipher.GetOutputSize(ALen: Int32): Int32;
var
  LTotalData: Int32;
begin
  LTotalData := ALen + FMainBlockPos;
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

function TOcbBlockCipher.GetUpdateOutputSize(ALen: Int32): Int32;
var
  LTotalData: Int32;
begin
  LTotalData := ALen + FMainBlockPos;
  if (not FForEncryption) then
  begin
    if (LTotalData < FMacSize) then
    begin
      Result := 0;
      Exit;
    end;
    LTotalData := LTotalData - FMacSize;
  end;
  Result := LTotalData - LTotalData mod BLOCK_SIZE;
end;

procedure TOcbBlockCipher.ProcessAadByte(AInput: Byte);
begin
  FHashBlock[FHashBlockPos] := AInput;
  System.Inc(FHashBlockPos);
  if (FHashBlockPos = System.Length(FHashBlock)) then
  begin
    ProcessHashBlock();
  end;
end;

procedure TOcbBlockCipher.ProcessAadBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32);
var
  LI: Int32;
begin
  for LI := 0 to System.Pred(ALen) do
  begin
    FHashBlock[FHashBlockPos] := AInput[AInOff + LI];
    System.Inc(FHashBlockPos);
    if (FHashBlockPos = System.Length(FHashBlock)) then
    begin
      ProcessHashBlock();
    end;
  end;
end;

function TOcbBlockCipher.ProcessByte(AInput: Byte;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  FMainBlock[FMainBlockPos] := AInput;
  System.Inc(FMainBlockPos);
  if (FMainBlockPos = System.Length(FMainBlock)) then
  begin
    ProcessMainBlock(AOutput, AOutOff);
    Result := BLOCK_SIZE;
    Exit;
  end;
  Result := 0;
end;

function TOcbBlockCipher.ProcessBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LI, LResultLen: Int32;
begin
  LResultLen := 0;

  for LI := 0 to System.Pred(ALen) do
  begin
    FMainBlock[FMainBlockPos] := AInput[AInOff + LI];
    System.Inc(FMainBlockPos);
    if (FMainBlockPos = System.Length(FMainBlock)) then
    begin
      ProcessMainBlock(AOutput, AOutOff + LResultLen);
      LResultLen := LResultLen + BLOCK_SIZE;
    end;
  end;

  Result := LResultLen;
end;

function TOcbBlockCipher.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LTag, LPad: TCryptoLibByteArray;
  LResultLen: Int32;
begin
  LTag := nil;
  if (not FForEncryption) then
  begin
    if (FMainBlockPos < FMacSize) then
      raise EInvalidCipherTextCryptoLibException.CreateRes(@SDataTooShort);

    FMainBlockPos := FMainBlockPos - FMacSize;
    System.SetLength(LTag, FMacSize);
    System.Move(FMainBlock[FMainBlockPos], LTag[0], FMacSize);
  end;

  if (FHashBlockPos > 0) then
  begin
    OCB_extend(FHashBlock, FHashBlockPos);
    UpdateHASH(FL_Asterisk);
  end;

  if (FMainBlockPos > 0) then
  begin
    if FForEncryption then
    begin
      OCB_extend(FMainBlock, FMainBlockPos);
      &Xor(FChecksum, FMainBlock);
    end;

    &Xor(FOffsetMAIN, FL_Asterisk);

    System.SetLength(LPad, 16);
    FHashCipher.ProcessBlock(FOffsetMAIN, 0, LPad, 0);

    &Xor(FMainBlock, LPad);

    TCheck.OutputLength(AOutput, AOutOff, FMainBlockPos, SOutputBufferTooShort);
    System.Move(FMainBlock[0], AOutput[AOutOff], FMainBlockPos);

    if (not FForEncryption) then
    begin
      OCB_extend(FMainBlock, FMainBlockPos);
      &Xor(FChecksum, FMainBlock);
    end;
  end;

  &Xor(FChecksum, FOffsetMAIN);
  &Xor(FChecksum, FL_Dollar);
  FHashCipher.ProcessBlock(FChecksum, 0, FChecksum, 0);
  &Xor(FChecksum, FSum);

  System.SetLength(FMacBlock, FMacSize);
  System.Move(FChecksum[0], FMacBlock[0], FMacSize);

  LResultLen := FMainBlockPos;

  if FForEncryption then
  begin
    TCheck.OutputLength(AOutput, AOutOff, LResultLen + FMacSize, SOutputBufferTooShort);

    System.Move(FMacBlock[0], AOutput[AOutOff + LResultLen], FMacSize);
    LResultLen := LResultLen + FMacSize;
  end
  else
  begin
    if (not TArrayUtilities.FixedTimeEquals(FMacBlock, LTag)) then
      raise EInvalidCipherTextCryptoLibException.CreateRes(@SMacCheckFailed);
  end;

  Reset(False);

  Result := LResultLen;
end;

procedure TOcbBlockCipher.Reset;
begin
  Reset(True);
end;

procedure TOcbBlockCipher.Clear(const ABs: TCryptoLibByteArray);
begin
  if (ABs <> nil) then
  begin
    TArrayUtilities.Fill<Byte>(ABs, 0, System.Length(ABs), Byte(0));
  end;
end;

function TOcbBlockCipher.GetLSub(AN: Int32): TCryptoLibByteArray;
begin
  while (AN >= FL.Count) do
  begin
    FL.Add(OCB_double(FL[FL.Count - 1]));
  end;
  Result := FL[AN];
end;

procedure TOcbBlockCipher.ProcessHashBlock;
begin
  System.Inc(FHashBlockCount);
  UpdateHASH(GetLSub(OCB_ntz(FHashBlockCount)));
  FHashBlockPos := 0;
end;

procedure TOcbBlockCipher.ProcessMainBlock(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32);
begin
  TCheck.OutputLength(AOutput, AOutOff, BLOCK_SIZE, SOutputBufferTooShort);

  if FForEncryption then
  begin
    &Xor(FChecksum, FMainBlock);
    FMainBlockPos := 0;
  end;

  System.Inc(FMainBlockCount);
  &Xor(FOffsetMAIN, GetLSub(OCB_ntz(FMainBlockCount)));

  &Xor(FMainBlock, FOffsetMAIN);
  FMainCipher.ProcessBlock(FMainBlock, 0, FMainBlock, 0);
  &Xor(FMainBlock, FOffsetMAIN);

  System.Move(FMainBlock[0], AOutput[AOutOff], 16);

  if (not FForEncryption) then
  begin
    &Xor(FChecksum, FMainBlock);
    System.Move(FMainBlock[BLOCK_SIZE], FMainBlock[0], FMacSize);
    FMainBlockPos := FMacSize;
  end;
end;

procedure TOcbBlockCipher.Reset(AClearMac: Boolean);
begin
  Clear(FHashBlock);
  Clear(FMainBlock);

  FHashBlockPos := 0;
  FMainBlockPos := 0;

  FHashBlockCount := 0;
  FMainBlockCount := 0;

  Clear(FOffsetHASH);
  Clear(FSum);
  System.Move(FOffsetMAIN_0[0], FOffsetMAIN[0], 16);
  Clear(FChecksum);

  if AClearMac then
  begin
    FMacBlock := nil;
    FL.Clear;
  end;

  if (FInitialAssociatedText <> nil) then
  begin
    ProcessAadBytes(FInitialAssociatedText, 0, System.Length(FInitialAssociatedText));
  end;
end;

procedure TOcbBlockCipher.UpdateHASH(const ALSub: TCryptoLibByteArray);
begin
  &Xor(FOffsetHASH, ALSub);
  &Xor(FHashBlock, FOffsetHASH);
  FHashCipher.ProcessBlock(FHashBlock, 0, FHashBlock, 0);
  &Xor(FSum, FHashBlock);
end;

class function TOcbBlockCipher.OCB_double(
  const ABlock: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LCarry: Int32;
begin
  System.SetLength(Result, 16);
  LCarry := ShiftLeft(ABlock, Result);
  Result[15] := Result[15] xor Byte($87 shr ((1 - LCarry) shl 3));
end;

class procedure TOcbBlockCipher.OCB_extend(const ABlock: TCryptoLibByteArray;
  APos: Int32);
begin
  ABlock[APos] := Byte($80);
  System.Inc(APos);
  while (APos < 16) do
  begin
    ABlock[APos] := 0;
    System.Inc(APos);
  end;
end;

class function TOcbBlockCipher.OCB_ntz(AX: Int64): Int32;
begin
  Result := TBitOperations.NumberOfTrailingZeros64(UInt64(AX));
end;

class function TOcbBlockCipher.ShiftLeft(const ABlock,
  AOutput: TCryptoLibByteArray): Int32;
var
  LI: Int32;
  LBit, LB: UInt32;
begin
  LI := 16;
  LBit := 0;
  while (LI > 0) do
  begin
    System.Dec(LI);
    LB := UInt32(ABlock[LI]);
    AOutput[LI] := Byte((LB shl 1) or LBit);
    LBit := (LB shr 7) and 1;
  end;
  Result := Int32(LBit);
end;

class procedure TOcbBlockCipher.&Xor(const ABlock,
  AVal: TCryptoLibByteArray);
begin
  TByteUtilities.XorTo(16, AVal, ABlock);
end;

end.
