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
  ClpIRawAgreement,
  ClpIX25519Parameters,
  ClpIX25519Generators,
  ClpKeyParameter,
  ClpX25519Parameters,
  ClpX25519Generators,
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
    /// Intermediate buffers are zeroized before release.
    /// </summary>
    class procedure StreamCipherProcess(const ACipher: IBufferedCipher;
      const AInputStream, AOutputStream: TStream); static;

    /// <summary>
    /// Reads exactly <c>AByteCount</c> bytes from <c>AInputStream</c> in chunks,
    /// feeds them through <c>ACipher.ProcessBytes</c>, writes output to
    /// <c>AOutputStream</c>, then calls <c>ACipher.DoFinal</c>.
    /// Used during decryption where the envelope specifies the exact ciphertext
    /// length (including the 16-byte GCM tag).
    /// Intermediate buffers are zeroized before release.
    /// </summary>
    class procedure StreamCipherProcessCount(const ACipher: IBufferedCipher;
      const AInputStream, AOutputStream: TStream;
      AByteCount: UInt64); static;

    /// <summary>
    /// Overwrites all bytes in <c>ABuffer</c> with zero using
    /// <c>TArrayUtilities.Fill</c>, then releases the buffer.
    /// </summary>
    class procedure ZeroBuffer(var ABuffer: TBytes); static;

    /// <summary>
    /// Builds combined AAD by concatenating the envelope header bytes
    /// (written before the ciphertext) with any user-supplied AAD.
    /// This binds the envelope metadata (magic, ephemeral key, salt, nonce, etc.)
    /// into the GCM authentication, preventing header-swapping attacks.
    /// </summary>
    class function BuildCombinedAad(const AEnvelopeHeader,
      AUserAad: TBytes): TBytes; static;

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
    /// Writes a 64-bit unsigned integer to the stream in big-endian byte order
    /// using <c>TPack.UInt64_To_BE</c>.
    /// </summary>
    class procedure WriteU64BE(const AStream: TStream;
      AValue: UInt64); static;

    /// <summary>
    /// Reads a 64-bit unsigned integer from the stream in big-endian byte order
    /// using <c>TPack.BE_To_UInt64</c>.
    /// </summary>
    class function ReadU64BE(const AStream: TStream): UInt64; static;

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
  /// The full envelope header (magic, wrapped key, nonce, ctLen) is bound
  /// into the GCM AAD to prevent header-swapping attacks.
  /// The ciphertext length field is 64-bit, supporting payloads beyond 4 GB.
  /// </para>
  /// <para><b>Encryption flow:</b></para>
  /// <list type="number">
  ///   <item>Generate a random 256-bit AES key and a 12-byte GCM nonce.</item>
  ///   <item>Encrypt (wrap) the AES key with the recipient's RSA public key
  ///         using RSA-OAEP (SHA-256/MGF1-SHA-256).</item>
  ///   <item>Serialise the envelope header:
  ///         <c>"RH01" || u16BE(encKeyLen) || encKey || u8(12) || nonce ||
  ///         u64BE(ctLen)</c>.</item>
  ///   <item>Encrypt the plaintext with AES-256-GCM using the random key, nonce,
  ///         and combined AAD (envelope header + user AAD), producing ciphertext
  ///         and a 128-bit authentication tag.</item>
  ///   <item>Zeroize the AES key from memory.</item>
  /// </list>
  /// <para><b>Decryption flow:</b></para>
  /// <list type="number">
  ///   <item>Parse and validate the "RH01" envelope header.</item>
  ///   <item>Unwrap the AES key with the recipient's RSA private key.</item>
  ///   <item>Reconstruct the combined AAD from the header bytes.</item>
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
  /// The full envelope header is bound into the GCM AAD to prevent
  /// header-swapping attacks. The ephemeral private key is explicitly zeroized
  /// after use. The ciphertext length field is 64-bit, supporting payloads
  /// beyond 4 GB.
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
  ///   <item>Serialise the envelope header:
  ///         <c>"EH01" || u16BE(ephPubLen) || ephPub(uncompressed) ||
  ///         u8(12) || nonce || u16BE(saltLen) || salt ||
  ///         u64BE(ctLen)</c>.</item>
  ///   <item>Encrypt the plaintext with AES-256-GCM using the derived key, nonce,
  ///         and combined AAD (envelope header + user AAD), producing ciphertext
  ///         and a 128-bit authentication tag.</item>
  ///   <item>Zeroize the ephemeral private key, shared secret and AES key
  ///         from memory.</item>
  /// </list>
  /// <para><b>Decryption flow:</b></para>
  /// <list type="number">
  ///   <item>Parse and validate the "EH01" envelope header.</item>
  ///   <item>Reconstruct the ephemeral public key from the encoded point.</item>
  ///   <item>Perform ECDH between the receiver's private key and the ephemeral
  ///         public key to recover the shared secret.</item>
  ///   <item>Derive the AES key via HKDF-SHA-256 with the same salt and info.</item>
  ///   <item>Reconstruct the combined AAD from the header bytes.</item>
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

  /// <summary>
  /// <para>X25519 Hybrid Encryption — envelope version <b>EX01</b>.</para>
  /// <para>
  /// Combines X25519 key agreement with HKDF-SHA-256 key derivation and
  /// AES-256-GCM authenticated encryption. A fresh ephemeral X25519 key pair
  /// is generated per message, providing forward secrecy.
  /// The full envelope header is bound into the GCM AAD to prevent
  /// header-swapping attacks. The ephemeral private key is explicitly zeroized
  /// after use. The ciphertext length field is 64-bit, supporting payloads
  /// beyond 4 GB.
  /// </para>
  /// <para><b>Encryption flow:</b></para>
  /// <list type="number">
  ///   <item>Generate a fresh ephemeral X25519 key pair.</item>
  ///   <item>Perform X25519 key agreement between the ephemeral private key and
  ///         the receiver's X25519 public key to produce a 32-byte shared secret.</item>
  ///   <item>Generate a random 32-byte HKDF salt and 12-byte GCM nonce.</item>
  ///   <item>Derive a 256-bit AES key via HKDF-SHA-256 with
  ///         <c>ikm=sharedSecret</c>, the random salt, and
  ///         <c>info="EX01-X25519-AESGCM"</c> for domain separation.</item>
  ///   <item>Serialise the envelope header:
  ///         <c>"EX01" || ephPub(32) || nonce(12) || salt(32) ||
  ///         u64BE(ctLen)</c>.</item>
  ///   <item>Encrypt the plaintext with AES-256-GCM using the derived key, nonce,
  ///         and combined AAD (envelope header + user AAD), producing ciphertext
  ///         and a 128-bit authentication tag.</item>
  ///   <item>Zeroize the ephemeral private key, shared secret and AES key
  ///         from memory.</item>
  /// </list>
  /// <para><b>Decryption flow:</b></para>
  /// <list type="number">
  ///   <item>Parse and validate the "EX01" envelope header.</item>
  ///   <item>Read the fixed-size fields: ephPub(32), nonce(12), salt(32).</item>
  ///   <item>Perform X25519 between the receiver's private key and the ephemeral
  ///         public key to recover the shared secret.</item>
  ///   <item>Derive the AES key via HKDF-SHA-256 with the same salt and info.</item>
  ///   <item>Reconstruct the combined AAD from the header bytes.</item>
  ///   <item>Decrypt and verify the payload with AES-256-GCM.</item>
  /// </list>
  /// <para>
  /// Both <c>TBytes</c> and <c>TStream</c> overloads are provided.
  /// The <c>TBytes</c> overloads delegate to the <c>TStream</c> overloads
  /// via <c>TBytesStream</c>.
  /// </para>
  /// </summary>
  TX25519HybridEncryption = class(THybridEncryptionBase)
  strict private
    const
      X25519_MAGIC = 'EX01';
      X25519_HKDF_INFO = 'EX01-X25519-AESGCM';
      X25519_PUBLIC_KEY_SIZE = 32;
  public
    class function Encrypt(const AReceiverPublicKey: IAsymmetricKeyParameter;
      const APlaintext, AAad: TBytes): TBytes; overload; static;

    class function Decrypt(const AReceiverPrivateKey: IAsymmetricKeyParameter;
      const AEnvelope, AAad: TBytes): TBytes; overload; static;

    class procedure Encrypt(const AReceiverPublicKey: IAsymmetricKeyParameter;
      const AInputStream, AOutputStream: TStream;
      const AAad: TBytes); overload; static;

    class procedure Decrypt(const AReceiverPrivateKey: IAsymmetricKeyParameter;
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
  LInBuf, LOutBuf, LFinalBuf: TBytes;
  LBytesRead, LOutLen: Int32;
begin
  System.SetLength(LInBuf, STREAM_BUFFER_SIZE);
  System.SetLength(LOutBuf, STREAM_BUFFER_SIZE + 256);
  try
    LBytesRead := AInputStream.Read(LInBuf[0], STREAM_BUFFER_SIZE);
    while LBytesRead > 0 do
    begin
      LOutLen := ACipher.ProcessBytes(LInBuf, 0, LBytesRead,
        LOutBuf, 0);
      if LOutLen > 0 then
        AOutputStream.WriteBuffer(LOutBuf[0], LOutLen);
      LBytesRead := AInputStream.Read(LInBuf[0], STREAM_BUFFER_SIZE);
    end;
    LFinalBuf := ACipher.DoFinal();
    if System.Length(LFinalBuf) > 0 then
      AOutputStream.WriteBuffer(LFinalBuf[0], System.Length(LFinalBuf));
  finally
    ZeroBuffer(LInBuf);
    ZeroBuffer(LOutBuf);
  end;
end;

class procedure THybridEncryptionBase.StreamCipherProcessCount(
  const ACipher: IBufferedCipher;
  const AInputStream, AOutputStream: TStream;
  AByteCount: UInt64);
var
  LInBuf, LOutBuf, LFinalBuf: TBytes;
  LChunk, LBytesRead, LOutLen: Int32;
  LRemaining: UInt64;
begin
  System.SetLength(LInBuf, STREAM_BUFFER_SIZE);
  System.SetLength(LOutBuf, STREAM_BUFFER_SIZE + 256);
  try
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
    LFinalBuf := ACipher.DoFinal();
    if System.Length(LFinalBuf) > 0 then
      AOutputStream.WriteBuffer(LFinalBuf[0], System.Length(LFinalBuf));
  finally
    ZeroBuffer(LInBuf);
    ZeroBuffer(LOutBuf);
  end;
end;

class procedure THybridEncryptionBase.ZeroBuffer(var ABuffer: TBytes);
begin
  if System.Length(ABuffer) > 0 then
    TArrayUtilities.Fill<Byte>(ABuffer, 0, System.Length(ABuffer), Byte(0));
  ABuffer := nil;
end;

class function THybridEncryptionBase.BuildCombinedAad(
  const AEnvelopeHeader, AUserAad: TBytes): TBytes;
var
  LHeaderLen, LUserLen: Int32;
begin
  LHeaderLen := System.Length(AEnvelopeHeader);
  LUserLen := System.Length(AUserAad);
  System.SetLength(Result, LHeaderLen + LUserLen);
  if LHeaderLen > 0 then
    System.Move(AEnvelopeHeader[0], Result[0], LHeaderLen);
  if LUserLen > 0 then
    System.Move(AUserAad[0], Result[LHeaderLen], LUserLen);
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

class procedure THybridEncryptionBase.WriteU64BE(const AStream: TStream;
  AValue: UInt64);
var
  LBuf: TBytes;
begin
  LBuf := TPack.UInt64_To_BE(AValue);
  AStream.WriteBuffer(LBuf[0], 8);
end;

class function THybridEncryptionBase.ReadU64BE(
  const AStream: TStream): UInt64;
var
  LBuf: TBytes;
begin
  LBuf := ReadRawBytes(AStream, 8);
  Result := TPack.BE_To_UInt64(LBuf);
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
  LAesKey, LNonce, LEncKey, LCombinedAad: TBytes;
  LSecureRandom: ISecureRandom;
  LRsaCipher, LGcmCipher: IBufferedCipher;
  LNonceLen: Byte;
  LCtLen: UInt64;
  LMagic: TBytes;
  LHeaderStream: TBytesStream;
  LHeaderBytes: TBytes;
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

    LCtLen := UInt64(AInputStream.Size - AInputStream.Position) + (GCM_TAG_BITS div 8);

    // Build envelope header into a temporary stream to capture the bytes
    // for AAD binding, then write them to the real output.
    LHeaderStream := TBytesStream.Create(nil);
    try
      LMagic := TConverters.ConvertStringToBytes(RSA_MAGIC, TEncoding.ASCII);
      WriteRawBytes(LHeaderStream, LMagic);
      WriteU16BE(LHeaderStream, UInt16(System.Length(LEncKey)));
      WriteRawBytes(LHeaderStream, LEncKey);
      LNonceLen := GCM_NONCE_SIZE;
      LHeaderStream.WriteBuffer(LNonceLen, 1);
      WriteRawBytes(LHeaderStream, LNonce);
      WriteU64BE(LHeaderStream, LCtLen);

      LHeaderBytes := Copy(LHeaderStream.Bytes, 0, LHeaderStream.Size);
    finally
      LHeaderStream.Free;
    end;

    // Write the header to the actual output stream
    WriteRawBytes(AOutputStream, LHeaderBytes);

    // Combine envelope header + user AAD for GCM authentication
    LCombinedAad := BuildCombinedAad(LHeaderBytes, AAad);

    LGcmCipher := CreateAesGcmCipher(True, LAesKey, LNonce, LCombinedAad);
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
  LAesKey, LEncKey, LNonce, LCombinedAad: TBytes;
  LRsaCipher, LGcmCipher: IBufferedCipher;
  LEncKeyLen: UInt16;
  LNonceLen: Byte;
  LCtLen: UInt64;
  LMagic: TBytes;
  LHeaderStart: Int64;
  LHeaderEnd: Int64;
  LHeaderBytes: TBytes;
begin
  // Record start position to capture header bytes for AAD binding
  LHeaderStart := AInputStream.Position;

  LMagic := TConverters.ConvertStringToBytes(RSA_MAGIC, TEncoding.ASCII);
  ValidateMagic(AInputStream, LMagic);

  LEncKeyLen := ReadU16BE(AInputStream);
  LEncKey := ReadRawBytes(AInputStream, LEncKeyLen);

  AInputStream.ReadBuffer(LNonceLen, 1);
  if LNonceLen <> GCM_NONCE_SIZE then
    raise EArgumentCryptoLibException.Create(
      'Invalid nonce length in RSA hybrid envelope');
  LNonce := ReadRawBytes(AInputStream, GCM_NONCE_SIZE);

  LCtLen := ReadU64BE(AInputStream);

  // Capture the full header bytes for AAD reconstruction
  LHeaderEnd := AInputStream.Position;
  AInputStream.Position := LHeaderStart;
  LHeaderBytes := ReadRawBytes(AInputStream, Int32(LHeaderEnd - LHeaderStart));
  // Stream is now back at the ciphertext position

  LRsaCipher := TCipherUtilities.GetCipher(RSA_OAEP_CIPHER);
  LRsaCipher.Init(False, ARsaPrivateKey as ICipherParameters);
  LAesKey := LRsaCipher.DoFinal(LEncKey);
  try
    if System.Length(LAesKey) <> AES_KEY_SIZE then
      raise EArgumentCryptoLibException.Create(
        'Unwrapped AES key has invalid length');

    // Reconstruct combined AAD: envelope header + user AAD
    LCombinedAad := BuildCombinedAad(LHeaderBytes, AAad);

    LGcmCipher := CreateAesGcmCipher(False, LAesKey, LNonce, LCombinedAad);
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
  LAesKey, LNonce, LSalt, LSharedSecret, LEphPubBytes, LInfo,
    LEphPrivBytes, LCombinedAad: TBytes;
  LSecureRandom: ISecureRandom;
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LEphGen: IEphemeralKeyPairGenerator;
  LEphPair: IEphemeralKeyPair;
  LEphPriv: IECPrivateKeyParameters;
  LAgree: IBasicAgreement;
  LZ: TBigInteger;
  LHkdf: IHkdfBytesGenerator;
  LHkdfParams: IHkdfParameters;
  LGcmCipher: IBufferedCipher;
  LNonceLen: Byte;
  LCtLen: UInt64;
  LMagic: TBytes;
  LHeaderStream: TBytesStream;
  LHeaderBytes: TBytes;
begin
  LSecureRandom := TSecureRandom.Create() as ISecureRandom;

  LKpg := TGeneratorUtilities.GetKeyPairGenerator('ECDH');
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

  // Zeroize ephemeral private key material
  if Supports(LEphPair.GetKeyPair.Private, IECPrivateKeyParameters, LEphPriv) then
  begin
    LEphPrivBytes := LEphPriv.GetD().ToByteArray();
    ZeroBuffer(LEphPrivBytes);
  end;

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

    LCtLen := UInt64(AInputStream.Size - AInputStream.Position) + (GCM_TAG_BITS div 8);

    // Build envelope header into a temporary stream to capture the bytes
    // for AAD binding, then write them to the real output.
    LHeaderStream := TBytesStream.Create(nil);
    try
      LMagic := TConverters.ConvertStringToBytes(EC_MAGIC, TEncoding.ASCII);
      WriteRawBytes(LHeaderStream, LMagic);
      WriteU16BE(LHeaderStream, UInt16(System.Length(LEphPubBytes)));
      WriteRawBytes(LHeaderStream, LEphPubBytes);
      LNonceLen := GCM_NONCE_SIZE;
      LHeaderStream.WriteBuffer(LNonceLen, 1);
      WriteRawBytes(LHeaderStream, LNonce);
      WriteU16BE(LHeaderStream, UInt16(System.Length(LSalt)));
      WriteRawBytes(LHeaderStream, LSalt);
      WriteU64BE(LHeaderStream, LCtLen);

      LHeaderBytes := Copy(LHeaderStream.Bytes, 0, LHeaderStream.Size);
    finally
      LHeaderStream.Free;
    end;

    // Write the header to the actual output stream
    WriteRawBytes(AOutputStream, LHeaderBytes);

    // Combine envelope header + user AAD for GCM authentication
    LCombinedAad := BuildCombinedAad(LHeaderBytes, AAad);

    LGcmCipher := CreateAesGcmCipher(True, LAesKey, LNonce, LCombinedAad);
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
  LAesKey, LNonce, LSalt, LSharedSecret, LEphPubBytes, LInfo,
    LCombinedAad: TBytes;
  LEphPub: IECPublicKeyParameters;
  LPoint: IECPoint;
  LAgree: IBasicAgreement;
  LZ: TBigInteger;
  LHkdf: IHkdfBytesGenerator;
  LHkdfParams: IHkdfParameters;
  LGcmCipher: IBufferedCipher;
  LEphPubLen, LSaltLen: UInt16;
  LNonceLen: Byte;
  LCtLen: UInt64;
  LMagic: TBytes;
  LHeaderStart: Int64;
  LHeaderEnd: Int64;
  LHeaderBytes: TBytes;
begin
  // Record start position to capture header bytes for AAD binding
  LHeaderStart := AInputStream.Position;

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

  LCtLen := ReadU64BE(AInputStream);

  // Capture the full header bytes for AAD reconstruction
  LHeaderEnd := AInputStream.Position;
  AInputStream.Position := LHeaderStart;
  LHeaderBytes := ReadRawBytes(AInputStream, Int32(LHeaderEnd - LHeaderStart));
  // Stream is now back at the ciphertext position

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

    // Reconstruct combined AAD: envelope header + user AAD
    LCombinedAad := BuildCombinedAad(LHeaderBytes, AAad);

    LGcmCipher := CreateAesGcmCipher(False, LAesKey, LNonce, LCombinedAad);
    StreamCipherProcessCount(LGcmCipher, AInputStream, AOutputStream, LCtLen);
  finally
    ZeroBuffer(LSharedSecret);
    ZeroBuffer(LAesKey);
  end;
end;

{ TX25519HybridEncryption }

class function TX25519HybridEncryption.Encrypt(
  const AReceiverPublicKey: IAsymmetricKeyParameter;
  const APlaintext, AAad: TBytes): TBytes;
var
  LInput, LOutput: TBytesStream;
begin
  LInput := TBytesStream.Create(APlaintext);
  try
    LOutput := TBytesStream.Create(nil);
    try
      Encrypt(AReceiverPublicKey, LInput, LOutput, AAad);
      Result := Copy(LOutput.Bytes, 0, LOutput.Size);
    finally
      LOutput.Free;
    end;
  finally
    LInput.Free;
  end;
end;

class function TX25519HybridEncryption.Decrypt(
  const AReceiverPrivateKey: IAsymmetricKeyParameter;
  const AEnvelope, AAad: TBytes): TBytes;
var
  LInput, LOutput: TBytesStream;
begin
  LInput := TBytesStream.Create(AEnvelope);
  try
    LOutput := TBytesStream.Create(nil);
    try
      Decrypt(AReceiverPrivateKey, LInput, LOutput, AAad);
      Result := Copy(LOutput.Bytes, 0, LOutput.Size);
    finally
      LOutput.Free;
    end;
  finally
    LInput.Free;
  end;
end;

class procedure TX25519HybridEncryption.Encrypt(
  const AReceiverPublicKey: IAsymmetricKeyParameter;
  const AInputStream, AOutputStream: TStream;
  const AAad: TBytes);
var
  LAesKey, LNonce, LSalt, LSharedSecret, LEphPubBytes, LInfo,
    LEphPrivBytes, LCombinedAad: TBytes;
  LSecureRandom: ISecureRandom;
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LEphKp: IAsymmetricCipherKeyPair;
  LEphPub: IX25519PublicKeyParameters;
  LEphPriv: IX25519PrivateKeyParameters;
  LAgree: IRawAgreement;
  LHkdf: IHkdfBytesGenerator;
  LHkdfParams: IHkdfParameters;
  LGcmCipher: IBufferedCipher;
  LCtLen: UInt64;
  LMagic: TBytes;
  LHeaderStream: TBytesStream;
  LHeaderBytes: TBytes;
begin
  LSecureRandom := TSecureRandom.Create() as ISecureRandom;

  LKpg := TGeneratorUtilities.GetKeyPairGenerator('X25519');
  LKpg.Init(TX25519KeyGenerationParameters.Create(LSecureRandom)
    as IX25519KeyGenerationParameters);
  LEphKp := LKpg.GenerateKeyPair();

  if not Supports(LEphKp.Public, IX25519PublicKeyParameters, LEphPub) then
    raise EArgumentCryptoLibException.Create(
      'Ephemeral key is not IX25519PublicKeyParameters');
  LEphPubBytes := LEphPub.GetEncoded();

  LAgree := TAgreementUtilities.GetRawAgreement('X25519');
  LAgree.Init(LEphKp.Private as ICipherParameters);
  System.SetLength(LSharedSecret, LAgree.AgreementSize);
  LAgree.CalculateAgreement(AReceiverPublicKey as ICipherParameters,
    LSharedSecret, 0);

  // Zeroize ephemeral private key material
  if Supports(LEphKp.Private, IX25519PrivateKeyParameters, LEphPriv) then
  begin
    LEphPrivBytes := LEphPriv.GetEncoded();
    ZeroBuffer(LEphPrivBytes);
  end;

  System.SetLength(LSalt, HKDF_SALT_SIZE);
  System.SetLength(LNonce, GCM_NONCE_SIZE);
  LSecureRandom.NextBytes(LSalt);
  LSecureRandom.NextBytes(LNonce);

  LInfo := TConverters.ConvertStringToBytes(X25519_HKDF_INFO, TEncoding.UTF8);
  System.SetLength(LAesKey, AES_KEY_SIZE);
  try
    LHkdf := THkdfBytesGenerator.Create(
      TDigestUtilities.GetDigest('SHA-256'));
    LHkdfParams := THkdfParameters.Create(LSharedSecret, LSalt, LInfo);
    LHkdf.Init(LHkdfParams);
    LHkdf.GenerateBytes(LAesKey, 0, AES_KEY_SIZE);

    LCtLen := UInt64(AInputStream.Size - AInputStream.Position) + (GCM_TAG_BITS div 8);

    // Build envelope header into a temporary stream to capture the bytes
    // for AAD binding, then write them to the real output.
    LHeaderStream := TBytesStream.Create(nil);
    try
      LMagic := TConverters.ConvertStringToBytes(X25519_MAGIC, TEncoding.ASCII);
      WriteRawBytes(LHeaderStream, LMagic);
      WriteRawBytes(LHeaderStream, LEphPubBytes);
      WriteRawBytes(LHeaderStream, LNonce);
      WriteRawBytes(LHeaderStream, LSalt);
      WriteU64BE(LHeaderStream, LCtLen);

      LHeaderBytes := Copy(LHeaderStream.Bytes, 0, LHeaderStream.Size);
    finally
      LHeaderStream.Free;
    end;

    // Write the header to the actual output stream
    WriteRawBytes(AOutputStream, LHeaderBytes);

    // Combine envelope header + user AAD for GCM authentication
    LCombinedAad := BuildCombinedAad(LHeaderBytes, AAad);

    LGcmCipher := CreateAesGcmCipher(True, LAesKey, LNonce, LCombinedAad);
    StreamCipherProcess(LGcmCipher, AInputStream, AOutputStream);
  finally
    ZeroBuffer(LSharedSecret);
    ZeroBuffer(LAesKey);
  end;
end;

class procedure TX25519HybridEncryption.Decrypt(
  const AReceiverPrivateKey: IAsymmetricKeyParameter;
  const AInputStream, AOutputStream: TStream;
  const AAad: TBytes);
var
  LAesKey, LNonce, LSalt, LSharedSecret, LEphPubBytes, LInfo,
    LCombinedAad: TBytes;
  LEphPub: IX25519PublicKeyParameters;
  LAgree: IRawAgreement;
  LHkdf: IHkdfBytesGenerator;
  LHkdfParams: IHkdfParameters;
  LGcmCipher: IBufferedCipher;
  LCtLen: UInt64;
  LMagic: TBytes;
  LHeaderStart: Int64;
  LHeaderEnd: Int64;
  LHeaderBytes: TBytes;
begin
  // Record start position to capture header bytes for AAD binding
  LHeaderStart := AInputStream.Position;

  LMagic := TConverters.ConvertStringToBytes(X25519_MAGIC, TEncoding.ASCII);
  ValidateMagic(AInputStream, LMagic);

  LEphPubBytes := ReadRawBytes(AInputStream, X25519_PUBLIC_KEY_SIZE);
  LNonce := ReadRawBytes(AInputStream, GCM_NONCE_SIZE);
  LSalt := ReadRawBytes(AInputStream, HKDF_SALT_SIZE);
  LCtLen := ReadU64BE(AInputStream);

  // Capture the full header bytes for AAD reconstruction
  LHeaderEnd := AInputStream.Position;
  AInputStream.Position := LHeaderStart;
  LHeaderBytes := ReadRawBytes(AInputStream, Int32(LHeaderEnd - LHeaderStart));
  // Stream is now back at the ciphertext position

  LEphPub := TX25519PublicKeyParameters.Create(LEphPubBytes);

  LAgree := TAgreementUtilities.GetRawAgreement('X25519');
  LAgree.Init(AReceiverPrivateKey as ICipherParameters);
  System.SetLength(LSharedSecret, LAgree.AgreementSize);
  LAgree.CalculateAgreement(LEphPub as ICipherParameters,
    LSharedSecret, 0);

  LInfo := TConverters.ConvertStringToBytes(X25519_HKDF_INFO, TEncoding.UTF8);
  System.SetLength(LAesKey, AES_KEY_SIZE);
  try
    LHkdf := THkdfBytesGenerator.Create(
      TDigestUtilities.GetDigest('SHA-256'));
    LHkdfParams := THkdfParameters.Create(LSharedSecret, LSalt, LInfo);
    LHkdf.Init(LHkdfParams);
    LHkdf.GenerateBytes(LAesKey, 0, AES_KEY_SIZE);

    // Reconstruct combined AAD: envelope header + user AAD
    LCombinedAad := BuildCombinedAad(LHeaderBytes, AAad);

    LGcmCipher := CreateAesGcmCipher(False, LAesKey, LNonce, LCombinedAad);
    StreamCipherProcessCount(LGcmCipher, AInputStream, AOutputStream, LCtLen);
  finally
    ZeroBuffer(LSharedSecret);
    ZeroBuffer(LAesKey);
  end;
end;

end.
