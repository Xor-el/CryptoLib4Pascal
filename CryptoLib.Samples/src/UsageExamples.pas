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

unit UsageExamples;

{$IFDEF FPC}
{$MODE DELPHI}
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

interface

uses
  SysUtils,
  ClpIDigest,
  ClpIMac,
  ClpDigestUtilities,
  ClpMacUtilities,
  ClpBigInteger,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpIX9ECParameters,
  ClpIECDomainParameters,
  ClpECDomainParameters,
  ClpIECKeyPairGenerator,
  ClpECKeyPairGenerator,
  ClpIECKeyGenerationParameters,
  ClpECKeyGenerationParameters,
  ClpIAsymmetricCipherKeyPair,
  ClpAsymmetricCipherKeyPair,
  ClpIECPrivateKeyParameters,
  ClpIECPublicKeyParameters,
  ClpECPublicKeyParameters,
  ClpECPrivateKeyParameters,
  ClpIAsymmetricKeyParameter,
  ClpIECC,
  ClpECC,
  ClpISigner,
  ClpSignerUtilities,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpIBufferedCipher,
  ClpIBufferedBlockCipher,
  // ClpIIESEngine,
  // ClpIESEngine,
  ClpPascalCoinIESEngine,
  ClpIPascalCoinIESEngine,
  ClpIIESParameterSpec,
  ClpIESParameterSpec,
  ClpIAesEngine,
  ClpAesEngine,
  ClpIBlockCipherModes,
  ClpBlockCipherModes,
  ClpIPaddingModes,
  ClpPaddingModes,
  ClpIIESCipher,
  ClpIESCipher,
  ClpIECDHBasicAgreement,
  ClpECDHBasicAgreement,
  ClpIPascalCoinECIESKdfBytesGenerator,
  ClpPascalCoinECIESKdfBytesGenerator,
  ClpPaddedBufferedBlockCipher,
  ClpParameterUtilities,
  ClpCipherUtilities,
  ClpGeneratorUtilities,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpArrayUtils,
  ClpEncoders,
  // ClpSecNamedCurves,
  ClpCustomNamedCurves,
  ClpConverters;

type

  { TUsageExamples }

  TUsageExamples = class sealed(TObject)

  strict private

  const

    /// <summary>
    /// supported curves are secp256k1, sect283k1, secp384r1 and secp521r1
    /// </summary>
    CurveName = 'secp256k1';

    /// <summary>
    /// supported signing algorithms are NONEwithECDSA, SHA-1withECDSA, <br />
    /// SHA-224withECDSA, SHA-256withECDSA, SHA-384withECDSA,
    /// SHA-512withECDSA and RIPEMD160withECDSA
    /// </summary>
    SigningAlgorithmECDSA = 'SHA-1withECDSA';
    SigningAlgorithmECSCHNORR = 'SHA-256withECSCHNORRSIPA';

    PKCS5_SALT_LEN = Int32(8);
    SALT_MAGIC_LEN = Int32(8);
    SALT_SIZE = Int32(8);
    SALT_MAGIC: String = 'Salted__';

  class var
    FRandom: ISecureRandom;
    FCurve: IX9ECParameters;
    class function BytesToHexString(input: TBytes): String; static;
    class function GetCurveByName(const AName: String): IX9ECParameters;
      static; inline;
    class constructor UsageExamples();

    class procedure DoSigningAndVerifying(const PublicKey
      : IECPublicKeyParameters; const PrivateKey: IECPrivateKeyParameters;
      const CallerMethod, TextToSign: String;
      const SigningAlgo: String = SigningAlgorithmECDSA); static;

    class function EVP_GetSalt(): TBytes; static; inline;
    class function EVP_GetKeyIV(PasswordBytes, SaltBytes: TBytes;
      out KeyBytes, IVBytes: TBytes): Boolean; static;
    class function AES256CBCPascalCoinEncrypt(PlainText, PasswordBytes: TBytes)
      : TBytes; static;

    class function AES256CBCPascalCoinDecrypt(CipherText, PasswordBytes: TBytes;
      out PlainText: TBytes): Boolean; static;

    class function GetECIESPascalCoinCompatibilityEngine
      : IPascalCoinIESEngine; static;
    class function GetECKeyPair: IAsymmetricCipherKeyPair; static;
    class function GetIESParameterSpec: IIESParameterSpec; static;

    class function ECIESPascalCoinEncrypt(const PublicKey
      : IAsymmetricKeyParameter; PlainText: TBytes): TBytes; static;
    class function ECIESPascalCoinDecrypt(const PrivateKey
      : IAsymmetricKeyParameter; CipherText: TBytes; out PlainText: TBytes)
      : Boolean; static;

  public
    class procedure GenerateKeyPairAndSignECDSA(); static;
    class procedure GenerateKeyPairAndSignECSchnorr(); static;
    class procedure GetPublicKeyFromPrivateKey(); static;
    class procedure RecreatePublicAndPrivateKeyPairsFromByteArray(); static;
    class procedure RecreatePublicKeyFromXAndYCoordByteArray; static;
    class procedure BinaryCompatiblePascalCoinAES256EncryptDecryptDemo
      (const inputmessage, password: string); static;
    class procedure BinaryCompatiblePascalCoinECIESEncryptDecryptDemo
      (const input: string); static;

    class procedure BinaryCompatiblePascalCoinECIESEncryptExistingPayloadDemo
      (const PublicKeyInHex, PureMessageInHex, ACurveName: string); static;

    class procedure BinaryCompatiblePascalCoinECIESDecryptExistingPayloadDemo
      (const PrivateKeyInHex, EncryptedMessageInHex,
      ACurveName: string); static;
  end;

implementation

{ TUsageExamples }

class function TUsageExamples.GetCurveByName(const AName: String)
  : IX9ECParameters;
begin
  // result := TSecNamedCurves.GetByName(AName);
  result := TCustomNamedCurves.GetByName(AName);
end;

class function TUsageExamples.ECIESPascalCoinDecrypt(const PrivateKey
  : IAsymmetricKeyParameter; CipherText: TBytes; out PlainText: TBytes)
  : Boolean;
var
  CipherDecrypt: IIESCipher;
begin
  // Decryption
  CipherDecrypt := TIESCipher.Create(GetECIESPascalCoinCompatibilityEngine);
  CipherDecrypt.Init(False, PrivateKey, GetIESParameterSpec, FRandom);
  PlainText := CipherDecrypt.DoFinal(CipherText);
  result := True;
end;

class function TUsageExamples.ECIESPascalCoinEncrypt(const PublicKey
  : IAsymmetricKeyParameter; PlainText: TBytes): TBytes;
var
  CipherEncrypt: IIESCipher;
begin
  // Encryption
  CipherEncrypt := TIESCipher.Create(GetECIESPascalCoinCompatibilityEngine);
  CipherEncrypt.Init(True, PublicKey, GetIESParameterSpec, FRandom);
  result := CipherEncrypt.DoFinal(PlainText);
end;

class function TUsageExamples.EVP_GetKeyIV(PasswordBytes, SaltBytes: TBytes;
  out KeyBytes, IVBytes: TBytes): Boolean;
var
  LKey, LIV: integer;
  LDigest: IDigest;
begin
  LKey := 32; // AES256 CBC Key Length
  LIV := 16; // AES256 CBC IV Length
  System.SetLength(KeyBytes, LKey);
  System.SetLength(IVBytes, LKey);
  // Max size to start then reduce it at the end
  LDigest := TDigestUtilities.GetDigest('SHA-256'); // SHA2_256
  System.Assert(LDigest.GetDigestSize >= LKey);
  System.Assert(LDigest.GetDigestSize >= LIV);
  // Derive Key First
  LDigest.BlockUpdate(PasswordBytes, 0, System.Length(PasswordBytes));
  if SaltBytes <> Nil then
  begin
    LDigest.BlockUpdate(SaltBytes, 0, System.Length(SaltBytes));
  end;
  LDigest.DoFinal(KeyBytes, 0);
  // Derive IV Next
  LDigest.Reset();
  LDigest.BlockUpdate(KeyBytes, 0, System.Length(KeyBytes));
  LDigest.BlockUpdate(PasswordBytes, 0, System.Length(PasswordBytes));
  if SaltBytes <> Nil then
  begin
    LDigest.BlockUpdate(SaltBytes, 0, System.Length(SaltBytes));
  end;
  LDigest.DoFinal(IVBytes, 0);

  System.SetLength(IVBytes, LIV);
  result := True;
end;

class function TUsageExamples.EVP_GetSalt(): TBytes;
begin
  System.SetLength(result, PKCS5_SALT_LEN);
  FRandom.NextBytes(result);
end;

class function TUsageExamples.AES256CBCPascalCoinDecrypt(CipherText,
  PasswordBytes: TBytes; out PlainText: TBytes): Boolean;
var
  SaltBytes, KeyBytes, IVBytes, Buf, Chopped: TBytes;
  KeyParametersWithIV: IParametersWithIV;
  cipher: IBufferedCipher;
  LBufStart, LSrcStart, Count: Int32;
begin
  result := False;

  System.SetLength(SaltBytes, SALT_SIZE);
  // First read the magic text and the salt - if any
  Chopped := System.Copy(CipherText, 0, SALT_MAGIC_LEN);
  if (System.Length(CipherText) >= SALT_MAGIC_LEN) and
    (TArrayUtils.AreEqual(Chopped, TConverters.ConvertStringToBytes(SALT_MAGIC,
    TEncoding.UTF8))) then
  begin
    System.Move(CipherText[SALT_MAGIC_LEN], SaltBytes[0], SALT_SIZE);
    If not EVP_GetKeyIV(PasswordBytes, SaltBytes, KeyBytes, IVBytes) then
    begin
      Exit;
    end;
    LSrcStart := SALT_MAGIC_LEN + SALT_SIZE;
  end
  else
  begin
    If Not EVP_GetKeyIV(PasswordBytes, Nil, KeyBytes, IVBytes) then
    begin
      Exit;
    end;
    LSrcStart := 0;
  end;

  cipher := TCipherUtilities.GetCipher('AES/CBC/PKCS7PADDING');
  KeyParametersWithIV := TParametersWithIV.Create
    (TParameterUtilities.CreateKeyParameter('AES', KeyBytes), IVBytes);

  cipher.Init(False, KeyParametersWithIV); // init decryption cipher

  System.SetLength(Buf, System.Length(CipherText));

  LBufStart := 0;

  Count := cipher.ProcessBytes(CipherText, LSrcStart, System.Length(CipherText)
    - LSrcStart, Buf, LBufStart);
  System.Inc(LBufStart, Count);
  Count := cipher.DoFinal(Buf, LBufStart);
  System.Inc(LBufStart, Count);

  System.SetLength(Buf, LBufStart);

  PlainText := System.Copy(Buf);
  result := True;

end;

class function TUsageExamples.AES256CBCPascalCoinEncrypt(PlainText,
  PasswordBytes: TBytes): TBytes;
var
  SaltBytes, KeyBytes, IVBytes, Buf: TBytes;
  KeyParametersWithIV: IParametersWithIV;
  cipher: IBufferedCipher;
  LBlockSize, LBufStart, Count: Int32;
begin
  SaltBytes := EVP_GetSalt;
  EVP_GetKeyIV(PasswordBytes, SaltBytes, KeyBytes, IVBytes);
  cipher := TCipherUtilities.GetCipher('AES/CBC/PKCS7PADDING');
  KeyParametersWithIV := TParametersWithIV.Create
    (TParameterUtilities.CreateKeyParameter('AES', KeyBytes), IVBytes);

  cipher.Init(True, KeyParametersWithIV); // init encryption cipher
  LBlockSize := cipher.GetBlockSize;

  System.SetLength(Buf, System.Length(PlainText) + LBlockSize + SALT_MAGIC_LEN +
    PKCS5_SALT_LEN);

  LBufStart := 0;

  System.Move(TConverters.ConvertStringToBytes(SALT_MAGIC, TEncoding.UTF8)[0],
    Buf[LBufStart], SALT_MAGIC_LEN * System.SizeOf(Byte));
  System.Inc(LBufStart, SALT_MAGIC_LEN);
  System.Move(SaltBytes[0], Buf[LBufStart],
    PKCS5_SALT_LEN * System.SizeOf(Byte));
  System.Inc(LBufStart, PKCS5_SALT_LEN);

  Count := cipher.ProcessBytes(PlainText, 0, System.Length(PlainText), Buf,
    LBufStart);
  System.Inc(LBufStart, Count);
  Count := cipher.DoFinal(Buf, LBufStart);
  System.Inc(LBufStart, Count);

  System.SetLength(Buf, LBufStart);
  result := Buf;
end;

class procedure TUsageExamples.
  BinaryCompatiblePascalCoinAES256EncryptDecryptDemo(const inputmessage,
  password: string);
var
  PlainText, PasswordBytes, CipherText, DecryptedCipherText: TBytes;
begin

  PlainText := TConverters.ConvertStringToBytes(inputmessage, TEncoding.UTF8);
  PasswordBytes := TConverters.ConvertStringToBytes(password, TEncoding.UTF8);
  CipherText := TUsageExamples.AES256CBCPascalCoinEncrypt(PlainText,
    PasswordBytes);

  if TUsageExamples.AES256CBCPascalCoinDecrypt(CipherText, PasswordBytes,
    DecryptedCipherText) then
  begin
    if TArrayUtils.AreEqual(PlainText, DecryptedCipherText) then
    begin
      Writeln('AES_256_CBC PascalCoin Compatability Encrypt, Decrypt Was Successful '
        + sLineBreak);
      Exit;
    end;

  end;

  Writeln('AES_256_CBC PascalCoin Compatability Encrypt, Decrypt Failed ' +
    sLineBreak);

end;

class procedure TUsageExamples.
  BinaryCompatiblePascalCoinECIESEncryptExistingPayloadDemo
  (const PublicKeyInHex, PureMessageInHex, ACurveName: string);

const
  MethodName = 'BinaryCompatiblePascalCoinECIESEncryptExistingPayloadDemo';
var
  PublicKeyBytes, PayloadToEncodeBytes, EncryptedCipherText: TBytes;
  Lcurve: IX9ECParameters;
  domain: IECDomainParameters;
  RegeneratedPublicKey: IECPublicKeyParameters;
begin

  // Create From Existing Parameter Method
  System.Assert(PublicKeyInHex <> '', 'PublicKeyInHex Cannot be Empty');
  System.Assert(PureMessageInHex <> '', 'PureMessageInHex Cannot be Empty');
  System.Assert(ACurveName <> '', 'ACurveName Cannot be Empty');

  PublicKeyBytes := THex.Decode(PublicKeyInHex);
  System.Assert(PublicKeyBytes <> Nil, 'PublicKeyBytes Cannot be Nil');

  PayloadToEncodeBytes := THex.Decode(PureMessageInHex);
  System.Assert(PayloadToEncodeBytes <> Nil,
    'PayloadToDecodeBytes Cannot be Nil');

  Lcurve := GetCurveByName(ACurveName);
  System.Assert(Lcurve <> Nil, 'Lcurve Cannot be Nil');

  // Set Up Asymmetric Key Pair from known public key ByteArray

  domain := TECDomainParameters.Create(Lcurve.Curve, Lcurve.G, Lcurve.N,
    Lcurve.H, Lcurve.GetSeed);

  RegeneratedPublicKey := TECPublicKeyParameters.Create('ECDSA',
    Lcurve.Curve.DecodePoint(PublicKeyBytes), domain);

  // Do Encryption Of Payload

  EncryptedCipherText := TUsageExamples.ECIESPascalCoinEncrypt
    (RegeneratedPublicKey, PayloadToEncodeBytes);

  if EncryptedCipherText <> Nil then
  begin

    Writeln('ECIES PascalCoin Existing Payload Compatability Encrypt Was Successful '
      + sLineBreak);

    Writeln('Encrypted Payload Message Is "' +
      THex.Encode(EncryptedCipherText) + '"');
    Exit;

  end;

  Writeln('ECIES PascalCoin Existing Payload Compatability Encrypt Failed ' +
    sLineBreak);

end;

class procedure TUsageExamples.
  BinaryCompatiblePascalCoinECIESDecryptExistingPayloadDemo
  (const PrivateKeyInHex, EncryptedMessageInHex, ACurveName: string);

const
  MethodName = 'BinaryCompatiblePascalCoinECIESDecryptExistingPayloadDemo';
var
  PrivateKeyBytes, PayloadToDecodeBytes, DecryptedCipherText: TBytes;
  Lcurve: IX9ECParameters;
  domain: IECDomainParameters;
  RegeneratedPublicKey: IECPublicKeyParameters;
  RegeneratedPrivateKey: IECPrivateKeyParameters;
  KeyPair: IAsymmetricCipherKeyPair;
  PrivD: TBigInteger;
begin

  // Create From Existing Parameter Method
  System.Assert(PrivateKeyInHex <> '', 'PrivateKeyInHex Cannot be Empty');
  System.Assert(EncryptedMessageInHex <> '',
    'EncryptedMessageInHex Cannot be Empty');
  System.Assert(ACurveName <> '', 'ACurveName Cannot be Empty');

  PrivateKeyBytes := THex.Decode(PrivateKeyInHex);
  System.Assert(PrivateKeyBytes <> Nil, 'PrivateKeyBytes Cannot be Nil');

  PayloadToDecodeBytes := THex.Decode(EncryptedMessageInHex);
  System.Assert(PayloadToDecodeBytes <> Nil,
    'PayloadToDecodeBytes Cannot be Nil');

  Lcurve := GetCurveByName(ACurveName);
  System.Assert(Lcurve <> Nil, 'Lcurve Cannot be Nil');

  // Set Up Asymmetric Key Pair from known private key ByteArray

  domain := TECDomainParameters.Create(Lcurve.Curve, Lcurve.G, Lcurve.N,
    Lcurve.H, Lcurve.GetSeed);

  PrivD := TBigInteger.Create(1, PrivateKeyBytes);
  RegeneratedPrivateKey := TECPrivateKeyParameters.Create('ECDSA',
    PrivD, domain);

  RegeneratedPublicKey := TECKeyPairGenerator.GetCorrespondingPublicKey
    (RegeneratedPrivateKey);

  KeyPair := TAsymmetricCipherKeyPair.Create(RegeneratedPublicKey,
    RegeneratedPrivateKey);

  // Do Signing and Verifying to Assert Proper Recreation Of Public and Private Key
  DoSigningAndVerifying(KeyPair.Public as IECPublicKeyParameters,
    KeyPair.Private as IECPrivateKeyParameters, MethodName, 'PascalECDSA');

  // Do Decryption Of Payload

  if TUsageExamples.ECIESPascalCoinDecrypt(RegeneratedPrivateKey,
    PayloadToDecodeBytes, DecryptedCipherText) then
  begin

    Writeln('ECIES PascalCoin Existing Payload Compatability Decrypt Was Successful '
      + sLineBreak);

    Writeln('Decrypted Payload Message Is "' + TConverters.ConvertBytesToString
      (DecryptedCipherText, TEncoding.UTF8) + '"');
    Exit;

  end;

  Writeln('ECIES PascalCoin Existing Payload Compatability Decrypt Failed ' +
    sLineBreak);

end;

class procedure TUsageExamples.BinaryCompatiblePascalCoinECIESEncryptDecryptDemo
  (const input: string);
var
  PlainText, CipherText, DecryptedCipherText: TBytes;
  KeyPair: IAsymmetricCipherKeyPair;
begin
  KeyPair := GetECKeyPair;
  PlainText := TConverters.ConvertStringToBytes(input, TEncoding.UTF8);
  CipherText := TUsageExamples.ECIESPascalCoinEncrypt(KeyPair.Public,
    PlainText);

  if TUsageExamples.ECIESPascalCoinDecrypt(KeyPair.Private, CipherText,
    DecryptedCipherText) then
  begin
    if TArrayUtils.AreEqual(PlainText, DecryptedCipherText) then
    begin
      Writeln('ECIES PascalCoin Compatability Encrypt, Decrypt Was Successful '
        + sLineBreak);
      Exit;
    end;

  end;

  Writeln('ECIES PascalCoin Compatability Encrypt, Decrypt Failed ' +
    sLineBreak);
end;

class function TUsageExamples.BytesToHexString(input: TBytes): String;
var
  index: Int32;
begin
  result := '';
  for index := System.Low(input) to System.High(input) do
  begin
    if index = 0 then
    begin
      result := result + IntToHex(input[index], 2);
    end
    else
    begin
      result := result + ',' + IntToHex(input[index], 2);
    end;
  end;
  result := '[' + result + ']';
end;

class procedure TUsageExamples.DoSigningAndVerifying(const PublicKey
  : IECPublicKeyParameters; const PrivateKey: IECPrivateKeyParameters;
  const CallerMethod, TextToSign: String;
  const SigningAlgo: String = SigningAlgorithmECDSA);
var
  Signer: ISigner;
  &message, sigBytes: TBytes;
begin

  Writeln('Caller Method Is ' + CallerMethod + sLineBreak);

  Signer := TSignerUtilities.GetSigner(SigningAlgo);

  Writeln('Signer Name is: ' + Signer.AlgorithmName + sLineBreak);

  &message := TConverters.ConvertStringToBytes(TextToSign, TEncoding.UTF8);

  // Sign
  Signer.Init(True, PrivateKey);

  Signer.BlockUpdate(&message, 0, System.Length(&message));

  sigBytes := Signer.GenerateSignature();

  Writeln('Generated Signature is: ' + BytesToHexString(sigBytes) + sLineBreak);

  // Verify

  Signer.Init(False, PublicKey);

  Signer.BlockUpdate(&message, 0, System.Length(&message));

  if (not Signer.VerifySignature(sigBytes)) then
  begin
    Writeln(PublicKey.AlgorithmName + ' verification failed' + sLineBreak);
  end
  else
  begin
    Writeln(PublicKey.AlgorithmName + ' verification passed' + sLineBreak);
  end;
end;

class procedure TUsageExamples.GenerateKeyPairAndSignECDSA();
var
  domain: IECDomainParameters;
  generator: IECKeyPairGenerator;
  keygenParams: IECKeyGenerationParameters;
  KeyPair: IAsymmetricCipherKeyPair;
  privParams: IECPrivateKeyParameters;
  pubParams: IECPublicKeyParameters;
const
  MethodName = 'GenerateKeyPairAndSignECDSA';
begin

  Writeln('MethodName is: ' + MethodName + sLineBreak);

  domain := TECDomainParameters.Create(FCurve.Curve, FCurve.G, FCurve.N,
    FCurve.H, FCurve.GetSeed);
  generator := TECKeyPairGenerator.Create('ECDSA');
  keygenParams := TECKeyGenerationParameters.Create(domain, FRandom);
  generator.Init(keygenParams);

  KeyPair := generator.GenerateKeyPair();
  privParams := KeyPair.Private as IECPrivateKeyParameters; // for signing
  pubParams := KeyPair.Public as IECPublicKeyParameters; // for verifying

  Writeln('Algorithm Name is: ' + pubParams.AlgorithmName + sLineBreak);

  Writeln('Public Key Normalized XCoord is: ' +
    pubParams.Q.Normalize.AffineXCoord.ToBigInteger.ToString(16) + sLineBreak);
  Writeln('Public Key Normalized YCoord is: ' +
    pubParams.Q.Normalize.AffineYCoord.ToBigInteger.ToString(16) + sLineBreak);

  Writeln('Private Key D Parameter is: ' + privParams.D.ToString(16) +
    sLineBreak);

  DoSigningAndVerifying(pubParams, privParams, MethodName, 'PascalECDSA');

end;

class procedure TUsageExamples.GenerateKeyPairAndSignECSchnorr();
var
  domain: IECDomainParameters;
  generator: IECKeyPairGenerator;
  keygenParams: IECKeyGenerationParameters;
  KeyPair: IAsymmetricCipherKeyPair;
  privParams: IECPrivateKeyParameters;
  pubParams: IECPublicKeyParameters;
const
  MethodName = 'GenerateKeyPairAndSignECSchnorr';
begin

  Writeln('MethodName is: ' + MethodName + sLineBreak);

  domain := TECDomainParameters.Create(FCurve.Curve, FCurve.G, FCurve.N,
    FCurve.H, FCurve.GetSeed);
  generator := TECKeyPairGenerator.Create('ECSCHNORR');
  keygenParams := TECKeyGenerationParameters.Create(domain, FRandom);
  generator.Init(keygenParams);

  KeyPair := generator.GenerateKeyPair();
  privParams := KeyPair.Private as IECPrivateKeyParameters; // for signing
  pubParams := KeyPair.Public as IECPublicKeyParameters; // for verifying

  Writeln('Algorithm Name is: ' + pubParams.AlgorithmName + sLineBreak);

  Writeln('Public Key Normalized XCoord is: ' +
    pubParams.Q.Normalize.AffineXCoord.ToBigInteger.ToString(16) + sLineBreak);
  Writeln('Public Key Normalized YCoord is: ' +
    pubParams.Q.Normalize.AffineYCoord.ToBigInteger.ToString(16) + sLineBreak);

  Writeln('Private Key D Parameter is: ' + privParams.D.ToString(16) +
    sLineBreak);

  DoSigningAndVerifying(pubParams, privParams, MethodName, 'PascalECSCHNORR',
    SigningAlgorithmECSCHNORR);

end;

class function TUsageExamples.GetECIESPascalCoinCompatibilityEngine
  : IPascalCoinIESEngine;
var
  cipher: IBufferedBlockCipher;
  AesEngine: IAesEngine;
  blockCipher: ICbcBlockCipher;
  ECDHBasicAgreementInstance: IECDHBasicAgreement;
  KDFInstance: IPascalCoinECIESKdfBytesGenerator;
  DigestMACInstance: IMac;

begin
  // Set up IES Cipher Engine For Compatibility With PascalCoin

  ECDHBasicAgreementInstance := TECDHBasicAgreement.Create();

  KDFInstance := TPascalCoinECIESKdfBytesGenerator.Create
    (TDigestUtilities.GetDigest('SHA-512'));

  DigestMACInstance := TMacUtilities.GetMac('HMAC-MD5');

  // Set Up Block Cipher
  AesEngine := TAesEngine.Create(); // AES Engine

  blockCipher := TCbcBlockCipher.Create(AesEngine); // CBC

  cipher := TPaddedBufferedBlockCipher.Create(blockCipher,
    TZeroBytePadding.Create() as IZeroBytePadding); // ZeroBytePadding

  result := TPascalCoinIESEngine.Create(ECDHBasicAgreementInstance, KDFInstance,
    DigestMACInstance, cipher);
end;

class function TUsageExamples.GetECKeyPair: IAsymmetricCipherKeyPair;
var
  Lcurve: IX9ECParameters;
  domain: IECDomainParameters;
  KeyPairGeneratorInstance: IAsymmetricCipherKeyPairGenerator;
const
  MethodName = 'GetECKeyPair';
begin
  // Full Generation Method

  Lcurve := GetCurveByName(CurveName);
  KeyPairGeneratorInstance := TGeneratorUtilities.GetKeyPairGenerator('ECDSA');
  domain := TECDomainParameters.Create(Lcurve.Curve, Lcurve.G, Lcurve.N,
    Lcurve.H, Lcurve.GetSeed);
  KeyPairGeneratorInstance.Init(TECKeyGenerationParameters.Create(domain,
    FRandom));
  result := KeyPairGeneratorInstance.GenerateKeyPair();

  DoSigningAndVerifying(result.Public as IECPublicKeyParameters,
    result.Private as IECPrivateKeyParameters, MethodName, 'PascalECDSA');

end;

class function TUsageExamples.GetIESParameterSpec: IIESParameterSpec;
var
  Derivation, Encoding, IVBytes: TBytes;
  MacKeySizeInBits, CipherKeySizeInBits: Int32;
  UsePointCompression: Boolean;
begin
  // Set up  IES Parameter Spec For Compatibility With PascalCoin Current Implementation

  // The derivation and encoding vectors are used when initialising the KDF and MAC.
  // They're optional but if used then they need to be known by the other user so that
  // they can decrypt the ciphertext and verify the MAC correctly. The security is based
  // on the shared secret coming from the (static-ephemeral) ECDH key agreement.
  Derivation := Nil;

  Encoding := Nil;

  System.SetLength(IVBytes, 16); // using Zero Initialized IV for compatibility

  MacKeySizeInBits := 32 * 8;

  // Since we are using AES256_CBC for compatibility
  CipherKeySizeInBits := 32 * 8;

  // whether to use point compression when deriving the octets string
  // from a point or not in the EphemeralKeyPairGenerator
  UsePointCompression := True; // for compatibility

  result := TIESParameterSpec.Create(Derivation, Encoding, MacKeySizeInBits,
    CipherKeySizeInBits, IVBytes, UsePointCompression);
end;

class procedure TUsageExamples.GetPublicKeyFromPrivateKey();
var
  domain: IECDomainParameters;
  generator: IECKeyPairGenerator;
  keygenParams: IECKeyGenerationParameters;
  KeyPair: IAsymmetricCipherKeyPair;
  privParams: IECPrivateKeyParameters;
  pubParams, recreatedPubKeyParameters: IECPublicKeyParameters;
  EncodedPublicKey, RecreatedEncodedPublicKey: TBytes;
  qPoint: IECPoint;
const
  MethodName = 'GetPublicKeyFromPrivateKey';
begin

  Writeln('MethodName is: ' + MethodName + sLineBreak);

  domain := TECDomainParameters.Create(FCurve.Curve, FCurve.G, FCurve.N,
    FCurve.H, FCurve.GetSeed);
  generator := TECKeyPairGenerator.Create('ECDSA');
  keygenParams := TECKeyGenerationParameters.Create(domain, FRandom);
  generator.Init(keygenParams);

  KeyPair := generator.GenerateKeyPair();
  privParams := KeyPair.Private as IECPrivateKeyParameters; // for signing
  pubParams := KeyPair.Public as IECPublicKeyParameters; // for verifying

  Writeln('Algorithm Name is: ' + pubParams.AlgorithmName + sLineBreak);

  Writeln('Public Key Normalized XCoord is: ' +
    pubParams.Q.Normalize.AffineXCoord.ToBigInteger.ToString(16) + sLineBreak);
  Writeln('Public Key Normalized YCoord is: ' +
    pubParams.Q.Normalize.AffineYCoord.ToBigInteger.ToString(16) + sLineBreak);

  EncodedPublicKey := pubParams.Q.Normalize.GetEncoded;

  Writeln('Encoded Public Key is: ' + BytesToHexString(EncodedPublicKey) +
    sLineBreak);

  Writeln('Private Key D Parameter is: ' + privParams.D.ToString(16) +
    sLineBreak);

  // get public key from private key

  // Method One

  qPoint := domain.G.Multiply(privParams.D);

  RecreatedEncodedPublicKey := qPoint.GetEncoded();

  if CompareMem(PByte(EncodedPublicKey), PByte(RecreatedEncodedPublicKey),
    System.Length(EncodedPublicKey) * System.SizeOf(Byte)) then
  begin
    Writeln('Public Key Recreation From Private Key Was Successful' +
      sLineBreak);
  end
  else
  begin
    Writeln('Public Key Recreation From Private Key Failed' + sLineBreak);
  end;

  recreatedPubKeyParameters := TECPublicKeyParameters.Create(qPoint, domain);

  if pubParams.Equals(recreatedPubKeyParameters) then
  begin
    Writeln('Public Key Recreation Match With Original Public Key' +
      sLineBreak);
  end
  else
  begin
    Writeln('Public Key Recreation DOES NOT Match With Original Public Key' +
      sLineBreak);
  end;

  // Do Signing and Verifying to Assert Proper Recreation Of Public Key
  DoSigningAndVerifying(recreatedPubKeyParameters, privParams, MethodName,
    'PascalECDSA');

  // or the easier method
  // Method Two (** Preferred **)

  recreatedPubKeyParameters := TECKeyPairGenerator.GetCorrespondingPublicKey
    (privParams);
  if pubParams.Equals(recreatedPubKeyParameters) then
  begin
    Writeln('Public Key Recreation Match With Original Public Key' +
      sLineBreak);
  end
  else
  begin
    Writeln('Public Key Recreation DOES NOT Match With Original Public Key' +
      sLineBreak);
  end;

  // Do Signing and Verifying to Assert Proper Recreation Of Public Key

  DoSigningAndVerifying(recreatedPubKeyParameters, privParams, MethodName,
    'PascalECDSA');

end;

class procedure TUsageExamples.RecreatePublicAndPrivateKeyPairsFromByteArray();
var
  domain: IECDomainParameters;
  generator: IECKeyPairGenerator;
  keygenParams: IECKeyGenerationParameters;
  KeyPair: IAsymmetricCipherKeyPair;
  privParams, RegeneratedPrivateKey: IECPrivateKeyParameters;
  pubParams, RegeneratedPublicKey: IECPublicKeyParameters;
  PublicKeyByteArray, PrivateKeyByteArray: TBytes;
  PrivD: TBigInteger;
const
  MethodName = 'RecreatePublicAndPrivateKeyPairsFromByteArray';
begin
  Writeln('MethodName is: ' + MethodName + sLineBreak);

  domain := TECDomainParameters.Create(FCurve.Curve, FCurve.G, FCurve.N,
    FCurve.H, FCurve.GetSeed);
  generator := TECKeyPairGenerator.Create('ECDSA');
  keygenParams := TECKeyGenerationParameters.Create(domain, FRandom);
  generator.Init(keygenParams);

  KeyPair := generator.GenerateKeyPair();
  privParams := KeyPair.Private as IECPrivateKeyParameters; // for signing
  pubParams := KeyPair.Public as IECPublicKeyParameters; // for verifying

  Writeln('Algorithm Name is: ' + pubParams.AlgorithmName + sLineBreak);

  Writeln('Public Key Normalized XCoord is: ' +
    pubParams.Q.Normalize.AffineXCoord.ToBigInteger.ToString(16) + sLineBreak);
  Writeln('Public Key Normalized YCoord is: ' +
    pubParams.Q.Normalize.AffineYCoord.ToBigInteger.ToString(16) + sLineBreak);

  Writeln('Private Key D Parameter is: ' + privParams.D.ToString(16) +
    sLineBreak);

  PublicKeyByteArray := pubParams.Q.GetEncoded;
  // using ToByteArray here because bytes are unsigned in Pascal
  PrivateKeyByteArray := privParams.D.ToByteArray;

  RegeneratedPublicKey := TECPublicKeyParameters.Create('ECDSA',
    FCurve.Curve.DecodePoint(PublicKeyByteArray), domain);

  if pubParams.Equals(RegeneratedPublicKey) then
  begin
    Writeln('Public Key Recreation Match With Original Public Key' +
      sLineBreak);
  end
  else
  begin
    Writeln('Public Key Recreation DOES NOT Match With Original Public Key' +
      sLineBreak);
  end;

  PrivD := TBigInteger.Create(1, PrivateKeyByteArray);
  RegeneratedPrivateKey := TECPrivateKeyParameters.Create('ECDSA',
    PrivD, domain);

  if privParams.Equals(RegeneratedPrivateKey) then
  begin
    Writeln('Private Key Recreation Match With Original Private Key' +
      sLineBreak);
  end
  else
  begin
    Writeln('Private Key Recreation DOES NOT Match With Original Private Key' +
      sLineBreak);
  end;

  // Do Signing and Verifying to Assert Proper Recreation Of Public Key

  DoSigningAndVerifying(RegeneratedPublicKey, privParams, MethodName,
    'PascalECDSA');

  // Do Signing and Verifying to Assert Proper Recreation Of Private Key

  DoSigningAndVerifying(pubParams, RegeneratedPrivateKey, MethodName,
    'PascalECDSA');

end;

class procedure TUsageExamples.RecreatePublicKeyFromXAndYCoordByteArray;
var
  domain: IECDomainParameters;
  generator: IECKeyPairGenerator;
  keygenParams: IECKeyGenerationParameters;
  KeyPair: IAsymmetricCipherKeyPair;
  pubParams, RegeneratedPublicKey: IECPublicKeyParameters;
  privParams: IECPrivateKeyParameters;
  XCoordByteArray, YCoordByteArray: TBytes;
  BigXCoord, BigYCoord, BigXCoordRecreated, BigYCoordRecreated: TBigInteger;
  point: IECPoint;
const
  MethodName = 'RecreatePublicKeyFromXAndYCoordByteArray';
begin

  Writeln('MethodName is: ' + MethodName + sLineBreak);

  domain := TECDomainParameters.Create(FCurve.Curve, FCurve.G, FCurve.N,
    FCurve.H, FCurve.GetSeed);
  generator := TECKeyPairGenerator.Create('ECDSA');
  keygenParams := TECKeyGenerationParameters.Create(domain, FRandom);
  generator.Init(keygenParams);

  KeyPair := generator.GenerateKeyPair();
  privParams := KeyPair.Private as IECPrivateKeyParameters; // for signing
  pubParams := KeyPair.Public as IECPublicKeyParameters; // for verifying

  Writeln('Algorithm Name is: ' + pubParams.AlgorithmName + sLineBreak);

  BigXCoord := pubParams.Q.Normalize.AffineXCoord.ToBigInteger;
  BigYCoord := pubParams.Q.Normalize.AffineYCoord.ToBigInteger;

  Writeln('Public Key Normalized XCoord is: ' + BigXCoord.ToString(16) +
    sLineBreak);
  Writeln('Public Key Normalized YCoord is: ' + BigYCoord.ToString(16) +
    sLineBreak);

  XCoordByteArray := BigXCoord.ToByteArray;
  YCoordByteArray := BigYCoord.ToByteArray;

  BigXCoordRecreated := TBigInteger.Create(1, XCoordByteArray);
  BigYCoordRecreated := TBigInteger.Create(1, YCoordByteArray);

  point := FCurve.Curve.CreatePoint(BigXCoordRecreated, BigYCoordRecreated);

  RegeneratedPublicKey := TECPublicKeyParameters.Create(point, domain);

  if pubParams.Equals(RegeneratedPublicKey) then
  begin
    Writeln('Public Key Recreation Match With Original Public Key' +
      sLineBreak);
  end
  else
  begin
    Writeln('Public Key Recreation DOES NOT Match With Original Public Key' +
      sLineBreak);
  end;


  // Do Signing and Verifying to Assert Proper Recreation Of Public Key

  DoSigningAndVerifying(RegeneratedPublicKey, privParams, MethodName,
    'PascalECDSA');

end;

class constructor TUsageExamples.UsageExamples();
begin
  FRandom := TSecureRandom.Create();
  FCurve := GetCurveByName(CurveName);
end;

end.
