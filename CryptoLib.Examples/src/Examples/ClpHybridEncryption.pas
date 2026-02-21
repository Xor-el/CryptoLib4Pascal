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

unit ClpHybridEncryption;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
  ClpBigInteger,
  ClpBigIntegerUtilities,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpICipherParameters,
  ClpIBufferedCipher,
  ClpIBasicAgreement,
  ClpIECParameters,
  ClpIKeyParameter,
  ClpIAeadParameters,
  ClpIHkdfParameters,
  ClpIHkdfBytesGenerator,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIECGenerators,
  ClpISecureRandom,
  ClpIEphemeralKeyPair,
  ClpIEphemeralKeyPairGenerator,
  ClpIKeyEncoder,
  ClpKeyParameter,
  ClpIECCommon,
  ClpAeadParameters,
  ClpHkdfParameters,
  ClpHkdfBytesGenerator,
  ClpAgreementUtilities,
  ClpECParameters,
  ClpECGenerators,
  ClpEphemeralKeyPairGenerator,
  ClpKeyEncoder,
  ClpGeneratorUtilities,
  ClpCipherUtilities,
  ClpDigestUtilities,
  ClpSecureRandom,
  ClpConverters,
  ClpArrayUtilities,
  ClpPack,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Base class providing shared utilities for hybrid encryption envelopes.
  /// Handles AES-256-GCM cipher creation, stream-based chunked processing,
  /// big-endian envelope field I/O via TPack, and sensitive buffer zeroization.
  /// </summary>
  THybridEncryptionBase = class
  strict protected
    const
      AES_KEY_SIZE = 32;
      GCM_NONCE_SIZE = 12;
      GCM_TAG_BITS = 128;
      HKDF_SALT_SIZE = 32;
      STREAM_BUFFER_SIZE = 8192;
      AES_GCM_CIPHER = 'AES/GCM/NOPADDING';

    /// <summary>
    /// Creates and initialises an AES-256-GCM cipher via
    /// <c>TCipherUtilities.GetCipher('AES/GCM/NOPADDING')</c>.
    /// The returned <c>IBufferedCipher</c> wraps a <c>TBufferedAeadBlockCipher</c>
    /// over <c>TGcmBlockCipher</c> and supports chunked ProcessBytes/DoFinal.
    /// </summary>
    /// <param name="AForEncryption">True for encryption, False for decryption.</param>
    /// <param name="AKey">256-bit (32-byte) AES key.</param>
    /// <param name="ANonce">12-byte GCM nonce (must be unique per key).</param>
    /// <param name="AAad">Associated Authenticated Data (integrity-protected, not encrypted).
    /// May be empty/nil.</param>
    class function CreateAesGcmCipher(AForEncryption: Boolean;
      const AKey, ANonce, AAad: TBytes): IBufferedCipher; static;

    /// <summary>
    /// Reads all remaining bytes from <c>AInputStream</c> in 8 KB chunks,
    /// feeds them through <c>ACipher.ProcessBytes</c>, writes output to
    /// <c>AOutputStream</c>, then calls <c>ACipher.DoFinal</c> for the
    /// final block and GCM authentication tag.
    /// Used during encryption where input is consumed until EOF.
    /// </summary>
    class procedure StreamCipherProcess(const ACipher: IBufferedCipher;
      const AInputStream, AOutputStream: TStream); static;

    /// <summary>
    /// Reads exactly <c>AByteCount</c> bytes from <c>AInputStream</c> in chunks,
    /// feeds them through <c>ACipher.ProcessBytes</c>, writes output to
    /// <c>AOutputStream</c>, then calls <c>ACipher.DoFinal</c>.
    /// Used during decryption where the envelope specifies the exact ciphertext
    /// length (including the 16-byte GCM tag).
    /// </summary>
    class procedure StreamCipherProcessCount(const ACipher: IBufferedCipher;
      const AInputStream, AOutputStream: TStream;
      AByteCount: Int64); static;

    /// <summary>
    /// Overwrites all bytes in <c>ABuffer</c> with zero using
    /// <c>TArrayUtilities.Fill</c>, then releases the buffer.
    /// </summary>
    class procedure ZeroBuffer(var ABuffer: TBytes); static;

    class procedure WriteRawBytes(const AStream: TStream;
      const AData: TBytes); static;

    class function ReadRawBytes(const AStream: TStream;
      ACount: Int32): TBytes; static;

    /// <summary>
    /// Writes a 16-bit unsigned integer to the stream in big-endian byte order
    /// using <c>TPack.UInt16_To_BE</c>.
    /// </summary>
    class procedure WriteU16BE(const AStream: TStream;
      AValue: UInt16); static;

    /// <summary>
    /// Reads a 16-bit unsigned integer from the stream in big-endian byte order
    /// using <c>TPack.BE_To_UInt16</c>.
    /// </summary>
    class function ReadU16BE(const AStream: TStream): UInt16; static;

    /// <summary>
    /// Writes a 32-bit unsigned integer to the stream in big-endian byte order
    /// using <c>TPack.UInt32_To_BE</c>.
    /// </summary>
    class procedure WriteU32BE(const AStream: TStream;
      AValue: UInt32); static;

    /// <summary>
    /// Reads a 32-bit unsigned integer from the stream in big-endian byte order
    /// using <c>TPack.BE_To_UInt32</c>.
    /// </summary>
    class function ReadU32BE(const AStream: TStream): UInt32; static;

    /// <summary>
    /// Reads <c>Length(AExpected)</c> bytes from the stream and raises
    /// <c>EArgumentCryptoLibException</c> if they do not match.
    /// </summary>
    class procedure ValidateMagic(const AStream: TStream;
      const AExpected: TBytes); static;
  end;

  /// <summary>
  /// <para>RSA Hybrid Encryption — envelope version <b>RH01</b>.</para>
  /// <para>
  /// Combines RSA-OAEP (SHA-256, MGF1-SHA-256) for key wrapping with
  /// AES-256-GCM for authenticated bulk data encryption.
  /// </para>
  /// <para><b>Encryption flow:</b></para>
  /// <list type="number">
  ///   <item>Generate a random 256-bit AES key and a 12-byte GCM nonce.</item>
  ///   <item>Encrypt (wrap) the AES key with the recipient's RSA public key
  ///         using RSA-OAEP (SHA-256/MGF1-SHA-256).</item>
  ///   <item>Encrypt the plaintext with AES-256-GCM using the random key and nonce,
  ///         producing ciphertext and a 128-bit authentication tag.</item>
  ///   <item>Serialise the versioned binary envelope:
  ///         <c>"RH01" || u16BE(encKeyLen) || encKey || u8(12) || nonce ||
  ///         u32BE(ctLen) || ciphertext||tag</c>.</item>
  ///   <item>Zeroize the AES key from memory.</item>
  /// </list>
  /// <para><b>Decryption flow:</b></para>
  /// <list type="number">
  ///   <item>Parse and validate the "RH01" envelope header.</item>
  ///   <item>Unwrap the AES key with the recipient's RSA private key.</item>
  ///   <item>Decrypt and verify the payload with AES-256-GCM.</item>
  /// </list>
  /// <para>
  /// Both <c>TBytes</c> and <c>TStream</c> overloads are provided.
  /// The <c>TBytes</c> overloads delegate to the <c>TStream</c> overloads
  /// via <c>TBytesStream</c>, so large payloads can be processed in chunks
  /// without loading everything into memory.
  /// </para>
  /// </summary>
  TRsaHybridEncryption = class(THybridEncryptionBase)
  strict private
    const
      RSA_MAGIC = 'RH01';
      RSA_OAEP_CIPHER = 'RSA/NONE/OAEPWITHSHA-256ANDMGF1PADDING';
  public
    class function Encrypt(const ARsaPublicKey: IAsymmetricKeyParameter;
      const APlaintext, AAad: TBytes): TBytes; overload; static;

    class function Decrypt(const ARsaPrivateKey: IAsymmetricKeyParameter;
      const AEnvelope, AAad: TBytes): TBytes; overload; static;

    class procedure Encrypt(const ARsaPublicKey: IAsymmetricKeyParameter;
      const AInputStream, AOutputStream: TStream;
      const AAad: TBytes); overload; static;

    class procedure Decrypt(const ARsaPrivateKey: IAsymmetricKeyParameter;
      const AInputStream, AOutputStream: TStream;
      const AAad: TBytes); overload; static;
  end;

  /// <summary>
  /// <para>ECC Hybrid Encryption — envelope version <b>EH01</b>.</para>
  /// <para>
  /// Combines ECDH key agreement (on the receiver's curve, e.g. secp256r1/P-256)
  /// with HKDF-SHA-256 key derivation and AES-256-GCM authenticated encryption.
  /// A fresh ephemeral EC key pair is generated per message (ECIES-KEM style),
  /// so each encryption produces a unique shared secret.
  /// </para>
  /// <para><b>Encryption flow:</b></para>
  /// <list type="number">
  ///   <item>Generate a fresh ephemeral EC key pair on the receiver's curve.</item>
  ///   <item>Perform ECDH key agreement between the ephemeral private key and
  ///         the receiver's public key to produce a shared secret.</item>
  ///   <item>Generate a random 32-byte HKDF salt and 12-byte GCM nonce.</item>
  ///   <item>Derive a 256-bit AES key via HKDF-SHA-256 with
  ///         <c>ikm=sharedSecret</c>, the random salt, and
  ///         <c>info="EH01-AES256GCM"</c> for domain separation.</item>
  ///   <item>Encrypt the plaintext with AES-256-GCM, producing ciphertext
  ///         and a 128-bit authentication tag.</item>
  ///   <item>Serialise the versioned binary envelope:
  ///         <c>"EH01" || u16BE(ephPubLen) || ephPub(uncompressed) ||
  ///         u8(12) || nonce || u16BE(saltLen) || salt ||
  ///         u32BE(ctLen) || ciphertext||tag</c>.</item>
  ///   <item>Zeroize the shared secret and AES key from memory.</item>
  /// </list>
  /// <para><b>Decryption flow:</b></para>
  /// <list type="number">
  ///   <item>Parse and validate the "EH01" envelope header.</item>
  ///   <item>Reconstruct the ephemeral public key from the encoded point.</item>
  ///   <item>Perform ECDH between the receiver's private key and the ephemeral
  ///         public key to recover the shared secret.</item>
  ///   <item>Derive the AES key via HKDF-SHA-256 with the same salt and info.</item>
  ///   <item>Decrypt and verify the payload with AES-256-GCM.</item>
  /// </list>
  /// <para>
  /// Both <c>TBytes</c> and <c>TStream</c> overloads are provided.
  /// The <c>TBytes</c> overloads delegate to the <c>TStream</c> overloads
  /// via <c>TBytesStream</c>, so large payloads can be processed in chunks
  /// without loading everything into memory.
  /// </para>
  /// </summary>
  TEcHybridEncryption = class(THybridEncryptionBase)
  strict private
    const
      EC_MAGIC = 'EH01';
      EC_HKDF_INFO = 'EH01-AES256GCM';
  public
    class function Encrypt(const AReceiverPublicKey: IAsymmetricKeyParameter;
      const AReceiverDomain: IECDomainParameters;
      const APlaintext, AAad: TBytes): TBytes; overload; static;

    class function Decrypt(const AReceiverPrivateKey: IAsymmetricKeyParameter;
      const AReceiverDomain: IECDomainParameters;
      const AEnvelope, AAad: TBytes): TBytes; overload; static;

    class procedure Encrypt(const AReceiverPublicKey: IAsymmetricKeyParameter;
      const AReceiverDomain: IECDomainParameters;
      const AInputStream, AOutputStream: TStream;
      const AAad: TBytes); overload; static;

    class procedure Decrypt(const AReceiverPrivateKey: IAsymmetricKeyParameter;
      const AReceiverDomain: IECDomainParameters;
      const AInputStream, AOutputStream: TStream;
      const AAad: TBytes); overload; static;
  end;

implementation

{ THybridEncryptionBase }

class function THybridEncryptionBase.CreateAesGcmCipher(
  AForEncryption: Boolean;
  const AKey, ANonce, AAad: TBytes): IBufferedCipher;
var
  LParams: IAeadParameters;
begin
  Result := TCipherUtilities.GetCipher(AES_GCM_CIPHER);
  LParams := TAeadParameters.Create(
    TKeyParameter.Create(AKey) as IKeyParameter,
    GCM_TAG_BITS, ANonce, AAad);
  Result.Init(AForEncryption, LParams as ICipherParameters);
end;

class procedure THybridEncryptionBase.StreamCipherProcess(
  const ACipher: IBufferedCipher;
  const AInputStream, AOutputStream: TStream);
var
  LInBuf, LOutBuf: TBytes;
  LBytesRead, LOutLen: Int32;
begin
  System.SetLength(LInBuf, STREAM_BUFFER_SIZE);
  System.SetLength(LOutBuf, STREAM_BUFFER_SIZE + 256);
  LBytesRead := AInputStream.Read(LInBuf[0], STREAM_BUFFER_SIZE);
  while LBytesRead > 0 do
  begin
    LOutLen := ACipher.ProcessBytes(LInBuf, 0, LBytesRead,
      LOutBuf, 0);
    if LOutLen > 0 then
      AOutputStream.WriteBuffer(LOutBuf[0], LOutLen);
    LBytesRead := AInputStream.Read(LInBuf[0], STREAM_BUFFER_SIZE);
  end;
  LOutBuf := ACipher.DoFinal();
  if System.Length(LOutBuf) > 0 then
    AOutputStream.WriteBuffer(LOutBuf[0], System.Length(LOutBuf));
end;

class procedure THybridEncryptionBase.StreamCipherProcessCount(
  const ACipher: IBufferedCipher;
  const AInputStream, AOutputStream: TStream;
  AByteCount: Int64);
var
  LInBuf, LOutBuf: TBytes;
  LChunk, LBytesRead, LOutLen: Int32;
  LRemaining: Int64;
begin
  System.SetLength(LInBuf, STREAM_BUFFER_SIZE);
  System.SetLength(LOutBuf, STREAM_BUFFER_SIZE + 256);
  LRemaining := AByteCount;
  while LRemaining > 0 do
  begin
    if LRemaining > STREAM_BUFFER_SIZE then
      LChunk := STREAM_BUFFER_SIZE
    else
      LChunk := Int32(LRemaining);
    LBytesRead := AInputStream.Read(LInBuf[0], LChunk);
    if LBytesRead <= 0 then
      raise EArgumentCryptoLibException.Create(
        'Unexpected end of stream during decryption');
    LOutLen := ACipher.ProcessBytes(LInBuf, 0, LBytesRead,
      LOutBuf, 0);
    if LOutLen > 0 then
      AOutputStream.WriteBuffer(LOutBuf[0], LOutLen);
    System.Dec(LRemaining, LBytesRead);
  end;
  LOutBuf := ACipher.DoFinal();
  if System.Length(LOutBuf) > 0 then
    AOutputStream.WriteBuffer(LOutBuf[0], System.Length(LOutBuf));
end;

class procedure THybridEncryptionBase.ZeroBuffer(var ABuffer: TBytes);
begin
  if System.Length(ABuffer) > 0 then
    TArrayUtilities.Fill<Byte>(ABuffer, 0, System.Length(ABuffer), Byte(0));
  ABuffer := nil;
end;

class procedure THybridEncryptionBase.WriteRawBytes(const AStream: TStream;
  const AData: TBytes);
begin
  if System.Length(AData) > 0 then
    AStream.WriteBuffer(AData[0], System.Length(AData));
end;

class function THybridEncryptionBase.ReadRawBytes(const AStream: TStream;
  ACount: Int32): TBytes;
begin
  System.SetLength(Result, ACount);
  if ACount > 0 then
    AStream.ReadBuffer(Result[0], ACount);
end;

class procedure THybridEncryptionBase.WriteU16BE(const AStream: TStream;
  AValue: UInt16);
var
  LBuf: TBytes;
begin
  LBuf := TPack.UInt16_To_BE(AValue);
  AStream.WriteBuffer(LBuf[0], 2);
end;

class function THybridEncryptionBase.ReadU16BE(
  const AStream: TStream): UInt16;
var
  LBuf: TBytes;
begin
  LBuf := ReadRawBytes(AStream, 2);
  Result := TPack.BE_To_UInt16(LBuf);
end;

class procedure THybridEncryptionBase.WriteU32BE(const AStream: TStream;
  AValue: UInt32);
var
  LBuf: TBytes;
begin
  LBuf := TPack.UInt32_To_BE(AValue);
  AStream.WriteBuffer(LBuf[0], 4);
end;

class function THybridEncryptionBase.ReadU32BE(
  const AStream: TStream): UInt32;
var
  LBuf: TBytes;
begin
  LBuf := ReadRawBytes(AStream, 4);
  Result := TPack.BE_To_UInt32(LBuf);
end;

class procedure THybridEncryptionBase.ValidateMagic(const AStream: TStream;
  const AExpected: TBytes);
var
  LActual: TBytes;
begin
  LActual := ReadRawBytes(AStream, System.Length(AExpected));
  if not TArrayUtilities.AreEqual(LActual, AExpected) then
    raise EArgumentCryptoLibException.Create(
      'Invalid envelope magic/version');
end;

{ TRsaHybridEncryption }

class function TRsaHybridEncryption.Encrypt(
  const ARsaPublicKey: IAsymmetricKeyParameter;
  const APlaintext, AAad: TBytes): TBytes;
var
  LInput, LOutput: TBytesStream;
begin
  LInput := TBytesStream.Create(APlaintext);
  try
    LOutput := TBytesStream.Create(nil);
    try
      Encrypt(ARsaPublicKey, LInput, LOutput, AAad);
      Result := Copy(LOutput.Bytes, 0, LOutput.Size);
    finally
      LOutput.Free;
    end;
  finally
    LInput.Free;
  end;
end;

class function TRsaHybridEncryption.Decrypt(
  const ARsaPrivateKey: IAsymmetricKeyParameter;
  const AEnvelope, AAad: TBytes): TBytes;
var
  LInput, LOutput: TBytesStream;
begin
  LInput := TBytesStream.Create(AEnvelope);
  try
    LOutput := TBytesStream.Create(nil);
    try
      Decrypt(ARsaPrivateKey, LInput, LOutput, AAad);
      Result := Copy(LOutput.Bytes, 0, LOutput.Size);
    finally
      LOutput.Free;
    end;
  finally
    LInput.Free;
  end;
end;

class procedure TRsaHybridEncryption.Encrypt(
  const ARsaPublicKey: IAsymmetricKeyParameter;
  const AInputStream, AOutputStream: TStream;
  const AAad: TBytes);
var
  LAesKey, LNonce, LEncKey: TBytes;
  LSecureRandom: ISecureRandom;
  LRsaCipher, LGcmCipher: IBufferedCipher;
  LNonceLen: Byte;
  LCtLen: UInt32;
  LMagic: TBytes;
begin
  LSecureRandom := TSecureRandom.Create() as ISecureRandom;
  System.SetLength(LAesKey, AES_KEY_SIZE);
  System.SetLength(LNonce, GCM_NONCE_SIZE);
  LSecureRandom.NextBytes(LAesKey);
  LSecureRandom.NextBytes(LNonce);
  try
    LRsaCipher := TCipherUtilities.GetCipher(RSA_OAEP_CIPHER);
    LRsaCipher.Init(True, ARsaPublicKey as ICipherParameters);
    LEncKey := LRsaCipher.DoFinal(LAesKey);

    LMagic := TConverters.ConvertStringToBytes(RSA_MAGIC, TEncoding.ASCII);
    WriteRawBytes(AOutputStream, LMagic);
    WriteU16BE(AOutputStream, UInt16(System.Length(LEncKey)));
    WriteRawBytes(AOutputStream, LEncKey);
    LNonceLen := GCM_NONCE_SIZE;
    AOutputStream.WriteBuffer(LNonceLen, 1);
    WriteRawBytes(AOutputStream, LNonce);
    LCtLen := UInt32(AInputStream.Size - AInputStream.Position) + (GCM_TAG_BITS div 8);
    WriteU32BE(AOutputStream, LCtLen);

    LGcmCipher := CreateAesGcmCipher(True, LAesKey, LNonce, AAad);
    StreamCipherProcess(LGcmCipher, AInputStream, AOutputStream);
  finally
    ZeroBuffer(LAesKey);
  end;
end;

class procedure TRsaHybridEncryption.Decrypt(
  const ARsaPrivateKey: IAsymmetricKeyParameter;
  const AInputStream, AOutputStream: TStream;
  const AAad: TBytes);
var
  LAesKey, LEncKey, LNonce: TBytes;
  LRsaCipher, LGcmCipher: IBufferedCipher;
  LEncKeyLen: UInt16;
  LNonceLen: Byte;
  LCtLen: UInt32;
  LMagic: TBytes;
begin
  LMagic := TConverters.ConvertStringToBytes(RSA_MAGIC, TEncoding.ASCII);
  ValidateMagic(AInputStream, LMagic);

  LEncKeyLen := ReadU16BE(AInputStream);
  LEncKey := ReadRawBytes(AInputStream, LEncKeyLen);

  AInputStream.ReadBuffer(LNonceLen, 1);
  if LNonceLen <> GCM_NONCE_SIZE then
    raise EArgumentCryptoLibException.Create(
      'Invalid nonce length in RSA hybrid envelope');
  LNonce := ReadRawBytes(AInputStream, GCM_NONCE_SIZE);

  LCtLen := ReadU32BE(AInputStream);

  LRsaCipher := TCipherUtilities.GetCipher(RSA_OAEP_CIPHER);
  LRsaCipher.Init(False, ARsaPrivateKey as ICipherParameters);
  LAesKey := LRsaCipher.DoFinal(LEncKey);
  try
    if System.Length(LAesKey) <> AES_KEY_SIZE then
      raise EArgumentCryptoLibException.Create(
        'Unwrapped AES key has invalid length');

    LGcmCipher := CreateAesGcmCipher(False, LAesKey, LNonce, AAad);
    StreamCipherProcessCount(LGcmCipher, AInputStream, AOutputStream, LCtLen);
  finally
    ZeroBuffer(LAesKey);
  end;
end;

{ TEcHybridEncryption }

class function TEcHybridEncryption.Encrypt(
  const AReceiverPublicKey: IAsymmetricKeyParameter;
  const AReceiverDomain: IECDomainParameters;
  const APlaintext, AAad: TBytes): TBytes;
var
  LInput, LOutput: TBytesStream;
begin
  LInput := TBytesStream.Create(APlaintext);
  try
    LOutput := TBytesStream.Create(nil);
    try
      Encrypt(AReceiverPublicKey, AReceiverDomain, LInput, LOutput, AAad);
      Result := Copy(LOutput.Bytes, 0, LOutput.Size);
    finally
      LOutput.Free;
    end;
  finally
    LInput.Free;
  end;
end;

class function TEcHybridEncryption.Decrypt(
  const AReceiverPrivateKey: IAsymmetricKeyParameter;
  const AReceiverDomain: IECDomainParameters;
  const AEnvelope, AAad: TBytes): TBytes;
var
  LInput, LOutput: TBytesStream;
begin
  LInput := TBytesStream.Create(AEnvelope);
  try
    LOutput := TBytesStream.Create(nil);
    try
      Decrypt(AReceiverPrivateKey, AReceiverDomain, LInput, LOutput, AAad);
      Result := Copy(LOutput.Bytes, 0, LOutput.Size);
    finally
      LOutput.Free;
    end;
  finally
    LInput.Free;
  end;
end;

class procedure TEcHybridEncryption.Encrypt(
  const AReceiverPublicKey: IAsymmetricKeyParameter;
  const AReceiverDomain: IECDomainParameters;
  const AInputStream, AOutputStream: TStream;
  const AAad: TBytes);
var
  LAesKey, LNonce, LSalt, LSharedSecret, LEphPubBytes, LInfo: TBytes;
  LSecureRandom: ISecureRandom;
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LEphGen: IEphemeralKeyPairGenerator;
  LEphPair: IEphemeralKeyPair;
  LAgree: IBasicAgreement;
  LZ: TBigInteger;
  LHkdf: IHkdfBytesGenerator;
  LHkdfParams: IHkdfParameters;
  LGcmCipher: IBufferedCipher;
  LNonceLen: Byte;
  LCtLen: UInt32;
  LMagic: TBytes;
begin
  LSecureRandom := TSecureRandom.Create() as ISecureRandom;

  LKpg := TGeneratorUtilities.GetKeyPairGenerator('ECDSA');
  LKpg.Init(TECKeyGenerationParameters.Create(AReceiverDomain,
    LSecureRandom) as IECKeyGenerationParameters);
  LEphGen := TEphemeralKeyPairGenerator.Create(LKpg,
    TKeyEncoder.Create(False) as IKeyEncoder);
  LEphPair := LEphGen.Generate();
  LEphPubBytes := LEphPair.GetEncodedPublicKey();

  LAgree := TAgreementUtilities.GetBasicAgreement('ECDH');
  LAgree.Init(LEphPair.GetKeyPair.Private as ICipherParameters);
  LZ := LAgree.CalculateAgreement(AReceiverPublicKey as ICipherParameters);
  LSharedSecret := TBigIntegerUtilities.AsUnsignedByteArray(
    LAgree.GetFieldSize(), LZ);

  System.SetLength(LSalt, HKDF_SALT_SIZE);
  System.SetLength(LNonce, GCM_NONCE_SIZE);
  LSecureRandom.NextBytes(LSalt);
  LSecureRandom.NextBytes(LNonce);

  LInfo := TConverters.ConvertStringToBytes(EC_HKDF_INFO, TEncoding.UTF8);
  System.SetLength(LAesKey, AES_KEY_SIZE);
  try
    LHkdf := THkdfBytesGenerator.Create(
      TDigestUtilities.GetDigest('SHA-256'));
    LHkdfParams := THkdfParameters.Create(LSharedSecret, LSalt, LInfo);
    LHkdf.Init(LHkdfParams);
    LHkdf.GenerateBytes(LAesKey, 0, AES_KEY_SIZE);

    LMagic := TConverters.ConvertStringToBytes(EC_MAGIC, TEncoding.ASCII);
    WriteRawBytes(AOutputStream, LMagic);
    WriteU16BE(AOutputStream, UInt16(System.Length(LEphPubBytes)));
    WriteRawBytes(AOutputStream, LEphPubBytes);
    LNonceLen := GCM_NONCE_SIZE;
    AOutputStream.WriteBuffer(LNonceLen, 1);
    WriteRawBytes(AOutputStream, LNonce);
    WriteU16BE(AOutputStream, UInt16(System.Length(LSalt)));
    WriteRawBytes(AOutputStream, LSalt);
    LCtLen := UInt32(AInputStream.Size - AInputStream.Position) + (GCM_TAG_BITS div 8);
    WriteU32BE(AOutputStream, LCtLen);

    LGcmCipher := CreateAesGcmCipher(True, LAesKey, LNonce, AAad);
    StreamCipherProcess(LGcmCipher, AInputStream, AOutputStream);
  finally
    ZeroBuffer(LSharedSecret);
    ZeroBuffer(LAesKey);
  end;
end;

class procedure TEcHybridEncryption.Decrypt(
  const AReceiverPrivateKey: IAsymmetricKeyParameter;
  const AReceiverDomain: IECDomainParameters;
  const AInputStream, AOutputStream: TStream;
  const AAad: TBytes);
var
  LAesKey, LNonce, LSalt, LSharedSecret, LEphPubBytes, LInfo: TBytes;
  LEphPub: IECPublicKeyParameters;
  LPoint: IECPoint;
  LAgree: IBasicAgreement;
  LZ: TBigInteger;
  LHkdf: IHkdfBytesGenerator;
  LHkdfParams: IHkdfParameters;
  LGcmCipher: IBufferedCipher;
  LEphPubLen, LSaltLen: UInt16;
  LNonceLen: Byte;
  LCtLen: UInt32;
  LMagic: TBytes;
begin
  LMagic := TConverters.ConvertStringToBytes(EC_MAGIC, TEncoding.ASCII);
  ValidateMagic(AInputStream, LMagic);

  LEphPubLen := ReadU16BE(AInputStream);
  LEphPubBytes := ReadRawBytes(AInputStream, LEphPubLen);

  AInputStream.ReadBuffer(LNonceLen, 1);
  if LNonceLen <> GCM_NONCE_SIZE then
    raise EArgumentCryptoLibException.Create(
      'Invalid nonce length in EC hybrid envelope');
  LNonce := ReadRawBytes(AInputStream, GCM_NONCE_SIZE);

  LSaltLen := ReadU16BE(AInputStream);
  LSalt := ReadRawBytes(AInputStream, LSaltLen);

  LCtLen := ReadU32BE(AInputStream);

  LPoint := AReceiverDomain.Curve.DecodePoint(LEphPubBytes);
  LEphPub := TECPublicKeyParameters.Create(LPoint,
    AReceiverDomain) as IECPublicKeyParameters;

  LAgree := TAgreementUtilities.GetBasicAgreement('ECDH');
  LAgree.Init(AReceiverPrivateKey as ICipherParameters);
  LZ := LAgree.CalculateAgreement(LEphPub as ICipherParameters);
  LSharedSecret := TBigIntegerUtilities.AsUnsignedByteArray(
    LAgree.GetFieldSize(), LZ);

  LInfo := TConverters.ConvertStringToBytes(EC_HKDF_INFO, TEncoding.UTF8);
  System.SetLength(LAesKey, AES_KEY_SIZE);
  try
    LHkdf := THkdfBytesGenerator.Create(
      TDigestUtilities.GetDigest('SHA-256'));
    LHkdfParams := THkdfParameters.Create(LSharedSecret, LSalt, LInfo);
    LHkdf.Init(LHkdfParams);
    LHkdf.GenerateBytes(LAesKey, 0, AES_KEY_SIZE);

    LGcmCipher := CreateAesGcmCipher(False, LAesKey, LNonce, AAad);
    StreamCipherProcessCount(LGcmCipher, AInputStream, AOutputStream, LCtLen);
  finally
    ZeroBuffer(LSharedSecret);
    ZeroBuffer(LAesKey);
  end;
end;

end.
