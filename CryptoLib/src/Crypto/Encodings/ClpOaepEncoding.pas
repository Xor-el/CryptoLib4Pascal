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

unit ClpOaepEncoding;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBitUtilities,
  ClpICipherParameters,
  ClpIParametersWithRandom,
  ClpIDigest,
  ClpDigestUtilities,
  ClpIAsymmetricBlockCipher,
  ClpIOaepEncoding,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpCryptoLibTypes,
  ClpConverters;

resourcestring
  SInputDataTooLong = 'Input data too long';
  SDataWrong = 'Data wrong';

type
  /// <summary>
  /// Optimal Asymmetric Encryption Padding (OAEP) - see PKCS #1 V 2.
  /// </summary>
  TOaepEncoding = class(TInterfacedObject, IAsymmetricBlockCipher, IOaepEncoding)

  strict private
  var
    FEngine: IAsymmetricBlockCipher;
    FMgf1Hash: IDigest;
    FDefHash: TCryptoLibByteArray;
    FRandom: ISecureRandom;
    FForEncryption: Boolean;

    function EncodeBlock(const inBytes: TCryptoLibByteArray;
      inOff, inLen: Int32): TCryptoLibByteArray;
    function DecodeBlock(const inBytes: TCryptoLibByteArray;
      inOff, inLen: Int32): TCryptoLibByteArray;

    procedure MaskGeneratorFunction(
      const z: TCryptoLibByteArray; zOff, zLen: Int32;
      const mask: TCryptoLibByteArray; maskOff, maskLen: Int32);

    function GetReducedBlockSize(blockSize: Int32): Int32; inline;

  strict protected
    function GetAlgorithmName: String;
    function GetInputBlockSize: Int32;
    function GetOutputBlockSize: Int32;
    function GetUnderlyingCipher: IAsymmetricBlockCipher;

  public
    constructor Create(const cipher: IAsymmetricBlockCipher); overload;
    constructor Create(const cipher: IAsymmetricBlockCipher;
      const hash: IDigest); overload;
    constructor Create(const cipher: IAsymmetricBlockCipher;
      const hash: IDigest;
      const encodingParams: TCryptoLibByteArray); overload;
    constructor Create(const cipher: IAsymmetricBlockCipher;
      const hash, mgf1Hash: IDigest;
      const encodingParams: TCryptoLibByteArray); overload;

    procedure Init(forEncryption: Boolean; const parameters: ICipherParameters);
    function ProcessBlock(const inBuf: TCryptoLibByteArray;
      inOff, inLen: Int32): TCryptoLibByteArray;

    property AlgorithmName: String read GetAlgorithmName;
    property InputBlockSize: Int32 read GetInputBlockSize;
    property OutputBlockSize: Int32 read GetOutputBlockSize;
    property UnderlyingCipher: IAsymmetricBlockCipher read GetUnderlyingCipher;

  end;

implementation

{ TOaepEncoding }

constructor TOaepEncoding.Create(const cipher: IAsymmetricBlockCipher);
begin
  Create(cipher, TDigestUtilities.GetDigest('SHA-1'), nil);
end;

constructor TOaepEncoding.Create(const cipher: IAsymmetricBlockCipher;
  const hash: IDigest);
begin
  Create(cipher, hash, nil);
end;

constructor TOaepEncoding.Create(const cipher: IAsymmetricBlockCipher;
  const hash: IDigest; const encodingParams: TCryptoLibByteArray);
begin
  Create(cipher, hash, hash, encodingParams);
end;

constructor TOaepEncoding.Create(const cipher: IAsymmetricBlockCipher;
  const hash, mgf1Hash: IDigest; const encodingParams: TCryptoLibByteArray);
begin
  inherited Create();
  FEngine := cipher;
  FMgf1Hash := mgf1Hash;
  SetLength(FDefHash, hash.GetDigestSize);

  hash.Reset();
  if encodingParams <> nil then
  begin
    hash.BlockUpdate(encodingParams, 0, System.Length(encodingParams));
  end;
  hash.DoFinal(FDefHash, 0);
end;

function TOaepEncoding.GetAlgorithmName: String;
begin
  Result := FEngine.AlgorithmName + '/OAEPPadding';
end;

function TOaepEncoding.GetUnderlyingCipher: IAsymmetricBlockCipher;
begin
  Result := FEngine;
end;

procedure TOaepEncoding.Init(forEncryption: Boolean;
  const parameters: ICipherParameters);
var
  rndParam: IParametersWithRandom;
begin
  if Supports(parameters, IParametersWithRandom, rndParam) then
    FRandom := rndParam.Random
  else
    FRandom := TSecureRandom.Create();

  FForEncryption := forEncryption;
  FEngine.Init(forEncryption, parameters);
end;

function TOaepEncoding.GetReducedBlockSize(blockSize: Int32): Int32;
begin
  Result := blockSize - 1 - 2 * System.Length(FDefHash);
end;

function TOaepEncoding.GetInputBlockSize: Int32;
begin
  if FForEncryption then
    Result := GetReducedBlockSize(FEngine.InputBlockSize)
  else
    Result := FEngine.InputBlockSize;
end;

function TOaepEncoding.GetOutputBlockSize: Int32;
begin
  if FForEncryption then
    Result := FEngine.OutputBlockSize
  else
    Result := GetReducedBlockSize(FEngine.OutputBlockSize);
end;

function TOaepEncoding.ProcessBlock(const inBuf: TCryptoLibByteArray;
  inOff, inLen: Int32): TCryptoLibByteArray;
begin
  if FForEncryption then
    Result := EncodeBlock(inBuf, inOff, inLen)
  else
    Result := DecodeBlock(inBuf, inOff, inLen);
end;

function TOaepEncoding.EncodeBlock(const inBytes: TCryptoLibByteArray;
  inOff, inLen: Int32): TCryptoLibByteArray;
var
  inBlockSize, defHashLen: Int32;
  block: TCryptoLibByteArray;
begin
  inBlockSize := FEngine.InputBlockSize;
  defHashLen := System.Length(FDefHash);

  if inLen > GetReducedBlockSize(inBlockSize) then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SInputDataTooLong);
  end;

  SetLength(block, inBlockSize);

  // Copy in the message
  System.Move(inBytes[inOff], block[System.Length(block) - inLen], inLen);

  // Add sentinel
  block[System.Length(block) - inLen - 1] := $01;

  // Add the hash of the encoding params
  System.Move(FDefHash[0], block[defHashLen], defHashLen);

  // Generate the seed (random bytes in first defHashLen bytes)
  FRandom.NextBytes(block, 0, defHashLen);

  FMgf1Hash.Reset();

  // Mask the message block (DB)
  MaskGeneratorFunction(block, 0, defHashLen,
    block, defHashLen, System.Length(block) - defHashLen);

  // Mask the seed
  MaskGeneratorFunction(block, defHashLen, System.Length(block) - defHashLen,
    block, 0, defHashLen);

  Result := FEngine.ProcessBlock(block, 0, System.Length(block));
end;

function TOaepEncoding.DecodeBlock(const inBytes: TCryptoLibByteArray;
  inOff, inLen: Int32): TCryptoLibByteArray;
var
  outBlockSize, defHashLen, wrongMask, copyLen: Int32;
  block, data: TCryptoLibByteArray;
  start, index, octet, shouldSetMask: Int32;
  i: Int32;
begin
  outBlockSize := FEngine.OutputBlockSize;
  defHashLen := System.Length(FDefHash);

  // Check reduced block size is valid
  wrongMask := TBitUtilities.Asr32(GetReducedBlockSize(outBlockSize), 31);

  SetLength(block, outBlockSize);
  data := FEngine.ProcessBlock(inBytes, inOff, inLen);

  wrongMask := wrongMask or TBitUtilities.Asr32((System.Length(block) - System.Length(data)), 31);

  copyLen := System.Length(data);
  if copyLen > System.Length(block) then
    copyLen := System.Length(block);

  System.Move(data[0], block[System.Length(block) - copyLen], copyLen);
  FillChar(data[0], System.Length(data), 0);

  FMgf1Hash.Reset();

  // Unmask the seed
  MaskGeneratorFunction(block, defHashLen, System.Length(block) - defHashLen,
    block, 0, defHashLen);

  // Unmask the message block
  MaskGeneratorFunction(block, 0, defHashLen,
    block, defHashLen, System.Length(block) - defHashLen);

  // Check the hash of the encoding params (constant time)
  for i := 0 to defHashLen - 1 do
  begin
    wrongMask := wrongMask or (FDefHash[i] xor block[defHashLen + i]);
  end;

  // Find the data block
  start := -1;
  for index := 2 * defHashLen to System.Length(block) - 1 do
  begin
    octet := block[index];
    // Mask will be 0xFFFFFFFF if octet is non-zero and start is (still) negative
    shouldSetMask := TBitUtilities.Asr32((-octet) and start, 31);
    start := start + (index and shouldSetMask);
  end;

  wrongMask := wrongMask or TBitUtilities.Asr32(start, 31);
  Inc(start);
  wrongMask := wrongMask or (block[start] xor 1);

  if wrongMask <> 0 then
  begin
    FillChar(block[0], System.Length(block), 0);
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SDataWrong);
  end;

  Inc(start);

  // Extract the data block
  SetLength(Result, System.Length(block) - start);
  System.Move(block[start], Result[0], System.Length(Result));
  FillChar(block[0], System.Length(block), 0);
end;

procedure TOaepEncoding.MaskGeneratorFunction(
  const z: TCryptoLibByteArray; zOff, zLen: Int32;
  const mask: TCryptoLibByteArray; maskOff, maskLen: Int32);
var
  digestSize, counter, maskPos, maskEnd, maskLimit, xorLen: Int32;
  hash, C: TCryptoLibByteArray;
  i: Int32;
begin
  digestSize := FMgf1Hash.GetDigestSize;
  SetLength(hash, digestSize);
  SetLength(C, 4);
  counter := 0;

  maskEnd := maskOff + maskLen;
  maskLimit := maskEnd - digestSize;
  maskPos := maskOff;

  // Note: we are re-hashing z on each iteration. Our approach recomputes Hash(z || counter) each time.

  while maskPos < maskLimit do
  begin
    // C = I2OSP(counter, 4)
    C[0] := Byte(counter shr 24);
    C[1] := Byte(counter shr 16);
    C[2] := Byte(counter shr 8);
    C[3] := Byte(counter);

    FMgf1Hash.Reset();
    FMgf1Hash.BlockUpdate(z, zOff, zLen);
    FMgf1Hash.BlockUpdate(C, 0, 4);
    FMgf1Hash.DoFinal(hash, 0);

    // XOR hash with mask
    for i := 0 to digestSize - 1 do
    begin
      mask[maskPos + i] := mask[maskPos + i] xor hash[i];
    end;

    Inc(maskPos, digestSize);
    Inc(counter);
  end;

  // Handle remaining bytes
  if maskPos < maskEnd then
  begin
    C[0] := Byte(counter shr 24);
    C[1] := Byte(counter shr 16);
    C[2] := Byte(counter shr 8);
    C[3] := Byte(counter);

    FMgf1Hash.Reset();
    FMgf1Hash.BlockUpdate(z, zOff, zLen);
    FMgf1Hash.BlockUpdate(C, 0, 4);
    FMgf1Hash.DoFinal(hash, 0);

    xorLen := maskEnd - maskPos;
    for i := 0 to xorLen - 1 do
    begin
      mask[maskPos + i] := mask[maskPos + i] xor hash[i];
    end;
  end;
end;

end.
