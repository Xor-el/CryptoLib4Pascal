{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpEaxBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIEaxBlockCipher,
  ClpIAeadBlockCipher,
  ClpIAeadCipher,
  ClpICipherParameters,
  ClpIAeadParameters,
  ClpIParametersWithIV,
  ClpSicBlockCipher,
  ClpISicBlockCipher,
  ClpCMac,
  ClpIMac,
  ClpParametersWithIV,
  ClpCheck,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SInvalidParametersEAX = 'invalid parameters passed to EAX';
  SOutputBufferTooShort = 'output buffer too short';
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
end;

function TEaxBlockCipher.GetAlgorithmName: String;
begin
  Result := FCipher.GetUnderlyingCipher().AlgorithmName + '/EAX';
end;

function TEaxBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  Result := FCipher as IBlockCipher;
end;

function TEaxBlockCipher.GetBlockSize: Int32;
begin
  Result := (FCipher as IBlockCipher).GetBlockSize();
end;

procedure TEaxBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LAeadParameters: IAeadParameters;
  LParametersWithIV: IParametersWithIV;
  LNonce: TCryptoLibByteArray;
  LKeyParam: ICipherParameters;
  LTag: TCryptoLibByteArray;
begin
  FForEncryption := AForEncryption;

  if Supports(AParameters, IAeadParameters, LAeadParameters) then
  begin
    LNonce := LAeadParameters.GetNonce();
    FInitialAssociatedText := LAeadParameters.GetAssociatedText();
    FMacSize := LAeadParameters.MacSize div 8;
    LKeyParam := LAeadParameters.Key;
  end
  else if Supports(AParameters, IParametersWithIV, LParametersWithIV) then
  begin
    LNonce := LParametersWithIV.GetIV();
    FInitialAssociatedText := nil;
    FMacSize := FMac.GetMacSize() div 2;
    LKeyParam := LParametersWithIV.Parameters;
  end
  else
    raise EArgumentCryptoLibException.CreateRes(@SInvalidParametersEAX);

  if FForEncryption then
    System.SetLength(FBufBlock, FBlockSize)
  else
    System.SetLength(FBufBlock, FBlockSize + FMacSize);

  System.SetLength(LTag, FBlockSize);

  FMac.Init(LKeyParam);

  LTag[FBlockSize - 1] := Byte(Ord(TTag.TagN));
  FMac.BlockUpdate(LTag, 0, FBlockSize);
  FMac.BlockUpdate(LNonce, 0, System.Length(LNonce));
  FMac.DoFinal(FNonceMac, 0);

  (FCipher as IBlockCipher).Init(True, TParametersWithIV.Create(nil, FNonceMac) as IParametersWithIV);

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
  LI, LResultLen: Int32;
begin
  InitCipher();

  LResultLen := 0;

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

    (FCipher as IBlockCipher).ProcessBlock(FBufBlock, 0, LTmp, 0);

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

      (FCipher as IBlockCipher).ProcessBlock(FBufBlock, 0, LTmp, 0);

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
      LSize := (FCipher as IBlockCipher).ProcessBlock(FBufBlock, 0, AOutBytes, AOutOff);
      FMac.BlockUpdate(AOutBytes, AOutOff, FBlockSize);
    end
    else
    begin
      FMac.BlockUpdate(FBufBlock, 0, FBlockSize);
      LSize := (FCipher as IBlockCipher).ProcessBlock(FBufBlock, 0, AOutBytes, AOutOff);
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
