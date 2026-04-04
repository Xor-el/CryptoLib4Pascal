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

unit ClpPkcs1Encoding;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Math,
  ClpArrayUtilities,
  ClpBitOperations,
  ClpICipherParameters,
  ClpIAsymmetricKeyParameter,
  ClpIAsymmetricBlockCipher,
  ClpIPkcs1Encoding,
  ClpISecureRandom,
  ClpCryptoServicesRegistrar,
  ClpParameterUtilities,
  ClpCryptoLibTypes;

resourcestring
  SInputDataTooLarge = 'Input data too large';
  SBlockIncorrect = 'Block incorrect';
  SBlockIncorrectSize = 'Block incorrect size';
  SDecryptionOnly = 'This method is only for decryption, not for signing';

type
  /// <summary>
  /// PKCS#1 v1.5 padding.
  /// Type 1 (0x01) for private key operations (signing).
  /// Type 2 (0x02) for public key operations (encryption).
  /// </summary>
  TPkcs1Encoding = class(TInterfacedObject, IAsymmetricBlockCipher, IPkcs1Encoding)

  strict private
  const
    HeaderLength = 10;

  class var
    FStrictLengthEnabled: Boolean;

  var
    FEngine: IAsymmetricBlockCipher;
    FRandom: ISecureRandom;
    FForEncryption: Boolean;
    FForPrivateKey: Boolean;
    FUseStrictLength: Boolean;
    FPLen: Int32;
    FFallback: TCryptoLibByteArray;
    FBlockBuffer: TCryptoLibByteArray;

    function EncodeBlock(const AInput: TCryptoLibByteArray;
      AInOff, AInLen: Int32): TCryptoLibByteArray;
    function DecodeBlock(const AInput: TCryptoLibByteArray;
      AInOff, AInLen: Int32): TCryptoLibByteArray;
    function DecodeBlockOrRandom(const AInput: TCryptoLibByteArray;
      AInOff, AInLen: Int32): TCryptoLibByteArray;

    class function CheckPkcs1Encoding1(const ABuf: TCryptoLibByteArray): Int32; static;
    class function CheckPkcs1Encoding2(const ABuf: TCryptoLibByteArray): Int32; overload; static;
    class function CheckPkcs1Encoding2(const ABuf: TCryptoLibByteArray;
      APlaintextLength: Int32): Int32; overload; static;

  strict protected
    function GetAlgorithmName: String;
    function GetInputBlockSize: Int32;
    function GetOutputBlockSize: Int32;
    function GetUnderlyingCipher: IAsymmetricBlockCipher;

  public
    class constructor CreatePkcs1Encoding;

    constructor Create(const ACipher: IAsymmetricBlockCipher); overload;
    constructor Create(const ACipher: IAsymmetricBlockCipher; APLen: Int32); overload;
    constructor Create(const ACipher: IAsymmetricBlockCipher;
      const AFallback: TCryptoLibByteArray); overload;

    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters);
    function ProcessBlock(const AInBuf: TCryptoLibByteArray;
      AInOff, AInLen: Int32): TCryptoLibByteArray;

    class property StrictLengthEnabled: Boolean read FStrictLengthEnabled
      write FStrictLengthEnabled;

    property AlgorithmName: String read GetAlgorithmName;
    property InputBlockSize: Int32 read GetInputBlockSize;
    property OutputBlockSize: Int32 read GetOutputBlockSize;
    property UnderlyingCipher: IAsymmetricBlockCipher read GetUnderlyingCipher;

  end;

implementation

{ TPkcs1Encoding }

class constructor TPkcs1Encoding.CreatePkcs1Encoding;
begin
  FStrictLengthEnabled := True;
end;

constructor TPkcs1Encoding.Create(const ACipher: IAsymmetricBlockCipher);
begin
  inherited Create();
  FEngine := ACipher;
  FUseStrictLength := FStrictLengthEnabled;
  FPLen := -1;
  FFallback := nil;
end;

constructor TPkcs1Encoding.Create(const ACipher: IAsymmetricBlockCipher; APLen: Int32);
begin
  inherited Create();
  FEngine := ACipher;
  FUseStrictLength := FStrictLengthEnabled;
  FPLen := APLen;
  FFallback := nil;
end;

constructor TPkcs1Encoding.Create(const ACipher: IAsymmetricBlockCipher;
  const AFallback: TCryptoLibByteArray);
begin
  inherited Create();
  FEngine := ACipher;
  FUseStrictLength := FStrictLengthEnabled;
  FFallback := AFallback;
  FPLen := System.Length(AFallback);
end;

function TPkcs1Encoding.GetAlgorithmName: String;
begin
  Result := FEngine.AlgorithmName + '/PKCS1Padding';
end;

function TPkcs1Encoding.GetUnderlyingCipher: IAsymmetricBlockCipher;
begin
  Result := FEngine;
end;

procedure TPkcs1Encoding.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LKeyParam: IAsymmetricKeyParameter;
  LParameters: ICipherParameters;
  LProvidedRandom: ISecureRandom;
  LNeedsRandom: Boolean;
begin
  FEngine.Init(AForEncryption, AParameters);

  LParameters := TParameterUtilities.GetRandom(AParameters, LProvidedRandom);

  if not Supports(LParameters, IAsymmetricKeyParameter, LKeyParam) then
    raise EInvalidKeyCryptoLibException.Create('Expected asymmetric key parameter');
  FForPrivateKey := LKeyParam.IsPrivate;
  FForEncryption := AForEncryption;
  SetLength(FBlockBuffer, FEngine.OutputBlockSize);

  if FForPrivateKey then
    LNeedsRandom := (FPLen <> -1) and (FFallback = nil)
  else
    LNeedsRandom := FForEncryption;

  if LNeedsRandom then
    FRandom := TCryptoServicesRegistrar.GetSecureRandom(LProvidedRandom)
  else
    FRandom := nil;
end;

function TPkcs1Encoding.GetInputBlockSize: Int32;
begin
  if FForEncryption then
    Result := FEngine.InputBlockSize - HeaderLength
  else
    Result := FEngine.InputBlockSize;
end;

function TPkcs1Encoding.GetOutputBlockSize: Int32;
begin
  if FForEncryption then
    Result := FEngine.OutputBlockSize
  else
    Result := FEngine.OutputBlockSize - HeaderLength;
end;

function TPkcs1Encoding.ProcessBlock(const AInBuf: TCryptoLibByteArray;
  AInOff, AInLen: Int32): TCryptoLibByteArray;
begin
  if FForEncryption then
    Result := EncodeBlock(AInBuf, AInOff, AInLen)
  else
    Result := DecodeBlock(AInBuf, AInOff, AInLen);
end;

function TPkcs1Encoding.EncodeBlock(const AInput: TCryptoLibByteArray;
  AInOff, AInLen: Int32): TCryptoLibByteArray;
var
  LBlockSize, LLastPadPos, LI: Int32;
  LBlock: TCryptoLibByteArray;
begin
  LBlockSize := FEngine.InputBlockSize;

  if AInLen > (LBlockSize - HeaderLength) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInputDataTooLarge);
  end;

  SetLength(LBlock, LBlockSize);
  LLastPadPos := LBlockSize - 1 - AInLen;

  if FForPrivateKey then
  begin
    // Type 1
    LBlock[0] := $01;
    for LI := 1 to LLastPadPos - 1 do
    begin
      LBlock[LI] := $FF;
    end;
  end
  else
  begin
    // Type 2 - random fill
    FRandom.NextBytes(LBlock, 0, LBlockSize);
    LBlock[0] := $02;

    // A zero byte marks the end of the padding, so all pad bytes must be non-zero
    for LI := 1 to LLastPadPos - 1 do
    begin
      while LBlock[LI] = 0 do
      begin
        LBlock[LI] := Byte(FRandom.NextInt32);
      end;
    end;
  end;

  // Mark the end of the padding
  LBlock[LLastPadPos] := $00;

  // Copy the data
  System.Move(AInput[AInOff], LBlock[LBlockSize - AInLen], AInLen);

  Result := FEngine.ProcessBlock(LBlock, 0, LBlockSize);
end;

class function TPkcs1Encoding.CheckPkcs1Encoding1(
  const ABuf: TCryptoLibByteArray): Int32;
var
  LI, LFoundZeroMask, LLastPadPos, LBadPadSign: Int32;
  LPadByte, LIs0x00Mask, LIs0xFFMask: Int32;
  LPlaintextLength: Int32;
begin
  LFoundZeroMask := 0;
  LLastPadPos := 0;

  // The first byte should be 0x01
  LBadPadSign := -(ABuf[0] xor $01);

  // There must be a zero terminator for the padding somewhere
  for LI := 1 to System.Length(ABuf) - 1 do
  begin
    LPadByte := ABuf[LI];
    LIs0x00Mask := TBitOperations.Asr32((LPadByte xor $00) - 1, 31);
    LIs0xFFMask := TBitOperations.Asr32((LPadByte xor $FF) - 1, 31);
    LLastPadPos := LLastPadPos xor (LI and (not LFoundZeroMask) and LIs0x00Mask);
    LFoundZeroMask := LFoundZeroMask or LIs0x00Mask;
    LBadPadSign := LBadPadSign or (not (LFoundZeroMask or LIs0xFFMask));
  end;

  // The header should be at least 10 bytes
  LBadPadSign := LBadPadSign or (LLastPadPos - 9);

  LPlaintextLength := System.Length(ABuf) - 1 - LLastPadPos;
  Result := LPlaintextLength or TBitOperations.Asr32(LBadPadSign, 31);
end;

class function TPkcs1Encoding.CheckPkcs1Encoding2(
  const ABuf: TCryptoLibByteArray): Int32;
var
  LI, LFoundZeroMask, LLastPadPos, LBadPadSign: Int32;
  LPadByte, LIs0x00Mask: Int32;
  LPlaintextLength: Int32;
begin
  LFoundZeroMask := 0;
  LLastPadPos := 0;

  // The first byte should be 0x02
  LBadPadSign := -(ABuf[0] xor $02);

  // There must be a zero terminator for the padding somewhere
  for LI := 1 to System.Length(ABuf) - 1 do
  begin
    LPadByte := ABuf[LI];
    LIs0x00Mask := TBitOperations.Asr32((LPadByte xor $00) - 1, 31);
    LLastPadPos := LLastPadPos xor (LI and (not LFoundZeroMask) and LIs0x00Mask);
    LFoundZeroMask := LFoundZeroMask or LIs0x00Mask;
  end;

  // The header should be at least 10 bytes
  LBadPadSign := LBadPadSign or (LLastPadPos - 9);

  LPlaintextLength := System.Length(ABuf) - 1 - LLastPadPos;
  Result := LPlaintextLength or TBitOperations.Asr32(LBadPadSign, 31);
end;

class function TPkcs1Encoding.CheckPkcs1Encoding2(
  const ABuf: TCryptoLibByteArray; APlaintextLength: Int32): Int32;
var
  LI, LBadPadSign, LLastPadPos: Int32;
begin
  // The first byte should be 0x02
  LBadPadSign := -(ABuf[0] xor $02);
  LLastPadPos := System.Length(ABuf) - 1 - APlaintextLength;

  // The header should be at least 10 bytes
  LBadPadSign := LBadPadSign or (LLastPadPos - 9);

  // All pad bytes before the last one should be non-zero
  for LI := 1 to LLastPadPos - 1 do
  begin
    LBadPadSign := LBadPadSign or (ABuf[LI] - 1);
  end;

  // Last pad byte should be zero
  LBadPadSign := LBadPadSign or (-ABuf[LLastPadPos]);

  Result := TBitOperations.Asr32(LBadPadSign, 31);
end;

function TPkcs1Encoding.DecodeBlockOrRandom(const AInput: TCryptoLibByteArray;
  AInOff, AInLen: Int32): TCryptoLibByteArray;
var
  LPlaintextLength, LStrictBlockSize, LBadPadMask, LDataOff, LI: Int32;
  LRandomBytes, LBlock, LData: TCryptoLibByteArray;
begin
  if not FForPrivateKey then
  begin
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SDecryptionOnly);
  end;

  LPlaintextLength := FPLen;

  if FFallback <> nil then
    LRandomBytes := FFallback
  else
  begin
    SetLength(LRandomBytes, LPlaintextLength);
    FRandom.NextBytes(LRandomBytes);
  end;

  LBadPadMask := 0;
  LStrictBlockSize := FEngine.OutputBlockSize;
  LBlock := FEngine.ProcessBlock(AInput, AInOff, AInLen);

  LData := LBlock;
  if System.Length(LBlock) <> LStrictBlockSize then
  begin
    if FUseStrictLength or (System.Length(LBlock) < LStrictBlockSize) then
    begin
      LData := FBlockBuffer;
    end;
  end;

  LBadPadMask := LBadPadMask or CheckPkcs1Encoding2(LData, LPlaintextLength);

  // Constant time copy
  LDataOff := System.Length(LData) - LPlaintextLength;
  SetLength(Result, LPlaintextLength);
  for LI := 0 to LPlaintextLength - 1 do
  begin
    Result[LI] := Byte((LData[LDataOff + LI] and (not LBadPadMask)) or
      (LRandomBytes[LI] and LBadPadMask));
  end;

  // Clear sensitive data
  TArrayUtilities.Fill<Byte>(LBlock, 0, System.Length(LBlock), Byte(0));
end;

function TPkcs1Encoding.DecodeBlock(const AInput: TCryptoLibByteArray;
  AInOff, AInLen: Int32): TCryptoLibByteArray;
var
  LStrictBlockSize, LPlaintextLength: Int32;
  LIncorrectLength: Boolean;
  LBlock, LData: TCryptoLibByteArray;
begin
  // If expected plaintext length is known, use constant-time decryption
  if FForPrivateKey and (FPLen <> -1) then
  begin
    Result := DecodeBlockOrRandom(AInput, AInOff, AInLen);
    Exit;
  end;

  LStrictBlockSize := FEngine.OutputBlockSize;
  LBlock := FEngine.ProcessBlock(AInput, AInOff, AInLen);

  LIncorrectLength := FUseStrictLength and (System.Length(LBlock) <> LStrictBlockSize);

  LData := LBlock;
  if System.Length(LBlock) < LStrictBlockSize then
  begin
    LData := FBlockBuffer;
  end;

  if FForPrivateKey then
    LPlaintextLength := CheckPkcs1Encoding2(LData)
  else
    LPlaintextLength := CheckPkcs1Encoding1(LData);

  try
    if LPlaintextLength < 0 then
    begin
      raise EInvalidCipherTextCryptoLibException.CreateRes(@SBlockIncorrect);
    end;

    if LIncorrectLength then
    begin
      raise EInvalidCipherTextCryptoLibException.CreateRes(@SBlockIncorrectSize);
    end;

    SetLength(Result, LPlaintextLength);
    System.Move(LData[System.Length(LData) - LPlaintextLength], Result[0], LPlaintextLength);
  finally
    // Clear sensitive data
    TArrayUtilities.Fill<Byte>(LBlock, 0, System.Length(LBlock), Byte(0));
    TArrayUtilities.Fill<Byte>(FBlockBuffer, 0, Math.Max(0, System.Length(FBlockBuffer) - System.Length(LBlock)), Byte(0));
  end;
end;

end.
