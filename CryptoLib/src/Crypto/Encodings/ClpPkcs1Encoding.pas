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

unit ClpPkcs1Encoding;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Math,
  ClpBits,
  ClpICipherParameters,
  ClpIParametersWithRandom,
  ClpIAsymmetricKeyParameter,
  ClpIAsymmetricBlockCipher,
  ClpIPkcs1Encoding,
  ClpISecureRandom,
  ClpSecureRandom,
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

    function EncodeBlock(const input: TCryptoLibByteArray;
      inOff, inLen: Int32): TCryptoLibByteArray;
    function DecodeBlock(const input: TCryptoLibByteArray;
      inOff, inLen: Int32): TCryptoLibByteArray;
    function DecodeBlockOrRandom(const input: TCryptoLibByteArray;
      inOff, inLen: Int32): TCryptoLibByteArray;

    class function CheckPkcs1Encoding1(const buf: TCryptoLibByteArray): Int32; static;
    class function CheckPkcs1Encoding2(const buf: TCryptoLibByteArray): Int32; overload; static;
    class function CheckPkcs1Encoding2(const buf: TCryptoLibByteArray;
      plaintextLength: Int32): Int32; overload; static;

  strict protected
    function GetAlgorithmName: String;
    function GetInputBlockSize: Int32;
    function GetOutputBlockSize: Int32;
    function GetUnderlyingCipher: IAsymmetricBlockCipher;

  public
    class constructor CreatePkcs1Encoding;

    constructor Create(const cipher: IAsymmetricBlockCipher); overload;
    constructor Create(const cipher: IAsymmetricBlockCipher; pLen: Int32); overload;
    constructor Create(const cipher: IAsymmetricBlockCipher;
      const fallback: TCryptoLibByteArray); overload;

    procedure Init(forEncryption: Boolean; const parameters: ICipherParameters);
    function ProcessBlock(const inBuf: TCryptoLibByteArray;
      inOff, inLen: Int32): TCryptoLibByteArray;

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

constructor TPkcs1Encoding.Create(const cipher: IAsymmetricBlockCipher);
begin
  inherited Create();
  FEngine := cipher;
  FUseStrictLength := FStrictLengthEnabled;
  FPLen := -1;
  FFallback := nil;
end;

constructor TPkcs1Encoding.Create(const cipher: IAsymmetricBlockCipher; pLen: Int32);
begin
  inherited Create();
  FEngine := cipher;
  FUseStrictLength := FStrictLengthEnabled;
  FPLen := pLen;
  FFallback := nil;
end;

constructor TPkcs1Encoding.Create(const cipher: IAsymmetricBlockCipher;
  const fallback: TCryptoLibByteArray);
begin
  inherited Create();
  FEngine := cipher;
  FUseStrictLength := FStrictLengthEnabled;
  FFallback := fallback;
  FPLen := System.Length(fallback);
end;

function TPkcs1Encoding.GetAlgorithmName: String;
begin
  Result := FEngine.AlgorithmName + '/PKCS1Padding';
end;

function TPkcs1Encoding.GetUnderlyingCipher: IAsymmetricBlockCipher;
begin
  Result := FEngine;
end;

procedure TPkcs1Encoding.Init(forEncryption: Boolean;
  const parameters: ICipherParameters);
var
  kParam: IAsymmetricKeyParameter;
  LParameters: ICipherParameters;
  providedRandom: ISecureRandom;
  NeedsRandom: Boolean;
begin
  FEngine.Init(forEncryption, parameters);

  LParameters := TParameterUtilities.GetRandom(parameters, providedRandom);

  kParam := LParameters as IAsymmetricKeyParameter;
  FForPrivateKey := kParam.IsPrivate;
  FForEncryption := forEncryption;
  SetLength(FBlockBuffer, FEngine.OutputBlockSize);

  if FForPrivateKey then
    NeedsRandom := (FPLen <> -1) and (FFallback = nil)
  else
    NeedsRandom := FForEncryption;

  if NeedsRandom then
  begin
    if providedRandom <> nil then
      FRandom := providedRandom
    else
      FRandom := TSecureRandom.Create();
  end
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

function TPkcs1Encoding.ProcessBlock(const inBuf: TCryptoLibByteArray;
  inOff, inLen: Int32): TCryptoLibByteArray;
begin
  if FForEncryption then
    Result := EncodeBlock(inBuf, inOff, inLen)
  else
    Result := DecodeBlock(inBuf, inOff, inLen);
end;

function TPkcs1Encoding.EncodeBlock(const input: TCryptoLibByteArray;
  inOff, inLen: Int32): TCryptoLibByteArray;
var
  blockSize, lastPadPos, i: Int32;
  block: TCryptoLibByteArray;
begin
  blockSize := FEngine.InputBlockSize;

  if inLen > (blockSize - HeaderLength) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInputDataTooLarge);
  end;

  SetLength(block, blockSize);
  lastPadPos := blockSize - 1 - inLen;

  if FForPrivateKey then
  begin
    // Type 1
    block[0] := $01;
    for i := 1 to lastPadPos - 1 do
    begin
      block[i] := $FF;
    end;
  end
  else
  begin
    // Type 2 - random fill
    FRandom.NextBytes(block, 0, blockSize);
    block[0] := $02;

    // A zero byte marks the end of the padding, so all pad bytes must be non-zero
    for i := 1 to lastPadPos - 1 do
    begin
      while block[i] = 0 do
      begin
        block[i] := Byte(FRandom.NextInt32);
      end;
    end;
  end;

  // Mark the end of the padding
  block[lastPadPos] := $00;

  // Copy the data
  System.Move(input[inOff], block[blockSize - inLen], inLen);

  Result := FEngine.ProcessBlock(block, 0, blockSize);
end;

class function TPkcs1Encoding.CheckPkcs1Encoding1(
  const buf: TCryptoLibByteArray): Int32;
var
  i, foundZeroMask, lastPadPos, badPadSign: Int32;
  padByte, is0x00Mask, is0xFFMask: Int32;
  plaintextLength: Int32;
begin
  foundZeroMask := 0;
  lastPadPos := 0;

  // The first byte should be 0x01
  badPadSign := -(buf[0] xor $01);

  // There must be a zero terminator for the padding somewhere
  for i := 1 to System.Length(buf) - 1 do
  begin
    padByte := buf[i];
    is0x00Mask := TBits.Asr32((padByte xor $00) - 1, 31);
    is0xFFMask := TBits.Asr32((padByte xor $FF) - 1, 31);
    lastPadPos := lastPadPos xor (i and (not foundZeroMask) and is0x00Mask);
    foundZeroMask := foundZeroMask or is0x00Mask;
    badPadSign := badPadSign or (not (foundZeroMask or is0xFFMask));
  end;

  // The header should be at least 10 bytes
  badPadSign := badPadSign or (lastPadPos - 9);

  plaintextLength := System.Length(buf) - 1 - lastPadPos;
  Result := plaintextLength or TBits.Asr32(badPadSign, 31);
end;

class function TPkcs1Encoding.CheckPkcs1Encoding2(
  const buf: TCryptoLibByteArray): Int32;
var
  i, foundZeroMask, lastPadPos, badPadSign: Int32;
  padByte, is0x00Mask: Int32;
  plaintextLength: Int32;
begin
  foundZeroMask := 0;
  lastPadPos := 0;

  // The first byte should be 0x02
  badPadSign := -(buf[0] xor $02);

  // There must be a zero terminator for the padding somewhere
  for i := 1 to System.Length(buf) - 1 do
  begin
    padByte := buf[i];
    is0x00Mask := TBits.Asr32((padByte xor $00) - 1, 31);
    lastPadPos := lastPadPos xor (i and (not foundZeroMask) and is0x00Mask);
    foundZeroMask := foundZeroMask or is0x00Mask;
  end;

  // The header should be at least 10 bytes
  badPadSign := badPadSign or (lastPadPos - 9);

  plaintextLength := System.Length(buf) - 1 - lastPadPos;
  Result := plaintextLength or TBits.Asr32(badPadSign, 31);
end;

class function TPkcs1Encoding.CheckPkcs1Encoding2(
  const buf: TCryptoLibByteArray; plaintextLength: Int32): Int32;
var
  i, badPadSign, lastPadPos: Int32;
begin
  // The first byte should be 0x02
  badPadSign := -(buf[0] xor $02);
  lastPadPos := System.Length(buf) - 1 - plaintextLength;

  // The header should be at least 10 bytes
  badPadSign := badPadSign or (lastPadPos - 9);

  // All pad bytes before the last one should be non-zero
  for i := 1 to lastPadPos - 1 do
  begin
    badPadSign := badPadSign or (buf[i] - 1);
  end;

  // Last pad byte should be zero
  badPadSign := badPadSign or (-buf[lastPadPos]);

  Result := TBits.Asr32(badPadSign, 31);
end;

function TPkcs1Encoding.DecodeBlockOrRandom(const input: TCryptoLibByteArray;
  inOff, inLen: Int32): TCryptoLibByteArray;
var
  plaintextLength, strictBlockSize, badPadMask, dataOff, i: Int32;
  randomBytes, block, data: TCryptoLibByteArray;
begin
  if not FForPrivateKey then
  begin
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SDecryptionOnly);
  end;

  plaintextLength := FPLen;

  if FFallback <> nil then
    randomBytes := FFallback
  else
  begin
    SetLength(randomBytes, plaintextLength);
    FRandom.NextBytes(randomBytes);
  end;

  badPadMask := 0;
  strictBlockSize := FEngine.OutputBlockSize;
  block := FEngine.ProcessBlock(input, inOff, inLen);

  data := block;
  if System.Length(block) <> strictBlockSize then
  begin
    if FUseStrictLength or (System.Length(block) < strictBlockSize) then
    begin
      data := FBlockBuffer;
    end;
  end;

  badPadMask := badPadMask or CheckPkcs1Encoding2(data, plaintextLength);

  // Constant time copy
  dataOff := System.Length(data) - plaintextLength;
  SetLength(Result, plaintextLength);
  for i := 0 to plaintextLength - 1 do
  begin
    Result[i] := Byte((data[dataOff + i] and (not badPadMask)) or
      (randomBytes[i] and badPadMask));
  end;

  // Clear sensitive data
  FillChar(block[0], System.Length(block), 0);
end;

function TPkcs1Encoding.DecodeBlock(const input: TCryptoLibByteArray;
  inOff, inLen: Int32): TCryptoLibByteArray;
var
  strictBlockSize, plaintextLength: Int32;
  incorrectLength: Boolean;
  block, data: TCryptoLibByteArray;
begin
  // If expected plaintext length is known, use constant-time decryption
  if FForPrivateKey and (FPLen <> -1) then
  begin
    Result := DecodeBlockOrRandom(input, inOff, inLen);
    Exit;
  end;

  strictBlockSize := FEngine.OutputBlockSize;
  block := FEngine.ProcessBlock(input, inOff, inLen);

  incorrectLength := FUseStrictLength and (System.Length(block) <> strictBlockSize);

  data := block;
  if System.Length(block) < strictBlockSize then
  begin
    data := FBlockBuffer;
  end;

  if FForPrivateKey then
    plaintextLength := CheckPkcs1Encoding2(data)
  else
    plaintextLength := CheckPkcs1Encoding1(data);

  try
    if plaintextLength < 0 then
    begin
      raise EInvalidCipherTextCryptoLibException.CreateRes(@SBlockIncorrect);
    end;

    if incorrectLength then
    begin
      raise EInvalidCipherTextCryptoLibException.CreateRes(@SBlockIncorrectSize);
    end;

    SetLength(Result, plaintextLength);
    System.Move(data[System.Length(data) - plaintextLength], Result[0], plaintextLength);
  finally
    // Clear sensitive data
    FillChar(block[0], System.Length(block), 0);
    FillChar(FBlockBuffer[0], Math.Max(0, System.Length(FBlockBuffer) - System.Length(block)), 0);
  end;
end;

end.
