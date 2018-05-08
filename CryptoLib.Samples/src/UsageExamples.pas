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
{$ENDIF FPC}

interface

uses
  SysUtils,
  HlpIHash,
  HlpHashFactory,
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
  ClpIECPrivateKeyParameters,
  ClpIECPublicKeyParameters,
  ClpECPublicKeyParameters,
  ClpECPrivateKeyParameters,
  ClpECSchnorrSigner,
  ClpIECInterface,
  ClpECPoint,
  ClpISigner,
  ClpSignerUtilities,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpIBufferedCipher,
  ClpParameterUtilities,
  ClpCipherUtilities,
  ClpHex,
  ClpArrayUtils,
  ClpSecNamedCurves;

type
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
    SigningAlgorithmECSCHNORR = 'SHA-256withECSCHNORRLIBSECP';

    PKCS5_SALT_LEN = Int32(8);
    SALT_MAGIC_LEN = Int32(8);
    SALT_SIZE = Int32(8);
    SALT_MAGIC: String = 'Salted__';

  class var
    FRandom: ISecureRandom;
    FCurve: IX9ECParameters;
    class function BytesToHexString(input: TBytes): String; static;
    class constructor UsageExamples();
  private
    class function EVP_GetSalt(): TBytes; static; inline;
    class function EVP_GetKeyIV(PasswordBytes, SaltBytes: TBytes;
      out KeyBytes, IVBytes: TBytes): Boolean; static;
    class function AES256CBCPascalCoinEncrypt(PlainText, PasswordBytes: TBytes)
      : TBytes; static;

    class function AES256CBCPascalCoinDecrypt(CipherText, PasswordBytes: TBytes;
      out PlainText: TBytes): Boolean; static;

  public
    class procedure GenerateKeyPairAndSignECDSA(); static;
    class procedure GenerateKeyPairAndSignECSchnorr(); static;
    class procedure GetPublicKeyFromPrivateKey(); static;
    class procedure RecreatePublicAndPrivateKeyPairsFromByteArray(); static;
    class procedure RecreatePublicKeyFromXAndYCoordByteArray; static;
    class procedure BinaryCompatiblePascalCoinAES256EncryptDecryptDemo
      (const inputmessage, password: string); static;
  end;

implementation

{ TUsageExamples }

class function TUsageExamples.EVP_GetKeyIV(PasswordBytes, SaltBytes: TBytes;
  out KeyBytes, IVBytes: TBytes): Boolean;
var
  LKey, LIV: integer;
  LHash: IHash;
begin
  LKey := 32; // AES256 CBC Key Length
  LIV := 16; // AES256 CBC IV Length
  System.SetLength(KeyBytes, LKey);
  System.SetLength(IVBytes, LKey);
  // Max size to start then reduce it at the end
  LHash := THashFactory.TCrypto.CreateSHA2_256; // SHA2_256
  LHash.Initialize();
  System.Assert(LHash.HashSize >= LKey);
  System.Assert(LHash.HashSize >= LIV);
  // Derive Key First
  LHash.TransformBytes(PasswordBytes);
  if SaltBytes <> Nil then
  begin
    LHash.TransformBytes(SaltBytes);
  end;
  KeyBytes := System.Copy(LHash.TransformFinal.GetBytes);
  // Derive IV Next
  LHash.Initialize();
  LHash.TransformBytes(KeyBytes);
  LHash.TransformBytes(PasswordBytes);
  if SaltBytes <> Nil then
  begin
    LHash.TransformBytes(SaltBytes);
  end;
  IVBytes := System.Copy(LHash.TransformFinal.GetBytes);

  System.SetLength(IVBytes, LIV);
  Result := True;
end;

class function TUsageExamples.EVP_GetSalt: TBytes;
begin
  System.SetLength(Result, PKCS5_SALT_LEN);
  FRandom.NextBytes(Result);
end;

class function TUsageExamples.AES256CBCPascalCoinDecrypt(CipherText,
  PasswordBytes: TBytes; out PlainText: TBytes): Boolean;
var
  SaltBytes, KeyBytes, IVBytes, Buf, Chopped: TBytes;
  KeyParametersWithIV: IParametersWithIV;
  cipher: IBufferedCipher;
  LBufStart, LSrcStart, Count: Int32;
begin
  Result := false;

  System.SetLength(SaltBytes, SALT_SIZE);
  // First read the magic text and the salt - if any
  Chopped := System.Copy(CipherText, 0, SALT_MAGIC_LEN);
  if (System.Length(CipherText) >= SALT_MAGIC_LEN) and
    (TArrayUtils.AreEqual(Chopped, TEncoding.UTF8.GetBytes(SALT_MAGIC))) then
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

  cipher.Init(false, KeyParametersWithIV); // init decryption cipher

  System.SetLength(Buf, System.Length(CipherText));

  LBufStart := 0;

  Count := cipher.ProcessBytes(CipherText, LSrcStart, System.Length(CipherText)
    - LSrcStart, Buf, LBufStart);
  System.Inc(LBufStart, Count);
  Count := cipher.DoFinal(Buf, LBufStart);
  System.Inc(LBufStart, Count);

  System.SetLength(Buf, LBufStart);

  PlainText := System.Copy(Buf);
  Result := True;

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

  System.Move(TEncoding.UTF8.GetBytes(SALT_MAGIC)[0], Buf[LBufStart],
    SALT_MAGIC_LEN * System.SizeOf(Byte));
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
  Result := Buf;
end;

class procedure TUsageExamples.
  BinaryCompatiblePascalCoinAES256EncryptDecryptDemo(const inputmessage,
  password: string);
var
  PlainText, PasswordBytes, CipherText, DecryptedCipherText: TBytes;
begin

  PlainText := TEncoding.UTF8.GetBytes(inputmessage);
  PasswordBytes := TEncoding.UTF8.GetBytes(password);
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

class function TUsageExamples.BytesToHexString(input: TBytes): String;
var
  index: Int32;
begin
  Result := '';
  for index := System.Low(input) to System.High(input) do
  begin
    if index = 0 then
    begin
      Result := Result + IntToHex(input[index], 2);
    end
    else
    begin
      Result := Result + ',' + IntToHex(input[index], 2);
    end;
  end;
  Result := '[' + Result + ']';
end;

class procedure TUsageExamples.GenerateKeyPairAndSignECDSA;
var
  domain: IECDomainParameters;
  generator: IECKeyPairGenerator;
  keygenParams: IECKeyGenerationParameters;
  keypair: IAsymmetricCipherKeyPair;
  privParams: IECPrivateKeyParameters;
  pubParams: IECPublicKeyParameters;
  signer: ISigner;
  &message, sigBytes: TBytes;
const
  MethodName = 'GenerateKeyPairAndSignECDSA';
begin

  Writeln('MethodName is: ' + MethodName + sLineBreak);

  domain := TECDomainParameters.Create(FCurve.Curve, FCurve.G, FCurve.N,
    FCurve.H, FCurve.GetSeed);
  generator := TECKeyPairGenerator.Create('ECDSA');
  keygenParams := TECKeyGenerationParameters.Create(domain, FRandom);
  generator.Init(keygenParams);

  keypair := generator.GenerateKeyPair();
  privParams := keypair.Private as IECPrivateKeyParameters; // for signing
  pubParams := keypair.Public as IECPublicKeyParameters; // for verifying

  Writeln('Algorithm Name is: ' + pubParams.AlgorithmName + sLineBreak);

  Writeln('Public Key Normalized XCoord is: ' +
    pubParams.Q.Normalize.AffineXCoord.ToBigInteger.ToString(16) + sLineBreak);
  Writeln('Public Key Normalized YCoord is: ' +
    pubParams.Q.Normalize.AffineYCoord.ToBigInteger.ToString(16) + sLineBreak);

  Writeln('Private Key D Parameter is: ' + privParams.D.ToString(16) +
    sLineBreak);

  signer := TSignerUtilities.GetSigner(SigningAlgorithmECDSA);

  Writeln('Signer Name is: ' + signer.AlgorithmName + sLineBreak);

  // sign

  signer.Init(True, privParams);

  &message := TEncoding.UTF8.GetBytes('PascalECDSA');

  signer.BlockUpdate(&message, 0, System.Length(&message));

  sigBytes := signer.GenerateSignature();

  Writeln('Generated Signature is: ' + BytesToHexString(sigBytes) + sLineBreak);

  // verify

  signer.Init(false, pubParams);

  signer.BlockUpdate(&message, 0, System.Length(&message));

  if (not signer.VerifySignature(sigBytes)) then
  begin
    Writeln(pubParams.AlgorithmName + ' verification failed' + sLineBreak);
  end
  else
  begin
    Writeln(pubParams.AlgorithmName + ' verification passed' + sLineBreak);
  end;

end;

class procedure TUsageExamples.GenerateKeyPairAndSignECSchnorr;
var
  domain: IECDomainParameters;
  generator: IECKeyPairGenerator;
  keygenParams: IECKeyGenerationParameters;
  keypair: IAsymmetricCipherKeyPair;
  privParams: IECPrivateKeyParameters;
  pubParams: IECPublicKeyParameters;
  signer: ISigner;
  &message, sigBytes: TBytes;
const
  MethodName = 'GenerateKeyPairAndSignECSchnorr';
begin

  Writeln('MethodName is: ' + MethodName + sLineBreak);

  domain := TECDomainParameters.Create(FCurve.Curve, FCurve.G, FCurve.N,
    FCurve.H, FCurve.GetSeed);
  generator := TECKeyPairGenerator.Create('ECSCHNORR');
  keygenParams := TECKeyGenerationParameters.Create(domain, FRandom);
  generator.Init(keygenParams);

  keypair := generator.GenerateKeyPair();
  privParams := keypair.Private as IECPrivateKeyParameters; // for signing
  pubParams := keypair.Public as IECPublicKeyParameters; // for verifying

  Writeln('Algorithm Name is: ' + pubParams.AlgorithmName + sLineBreak);

  Writeln('Public Key Normalized XCoord is: ' +
    pubParams.Q.Normalize.AffineXCoord.ToBigInteger.ToString(16) + sLineBreak);
  Writeln('Public Key Normalized YCoord is: ' +
    pubParams.Q.Normalize.AffineYCoord.ToBigInteger.ToString(16) + sLineBreak);

  Writeln('Private Key D Parameter is: ' + privParams.D.ToString(16) +
    sLineBreak);

  signer := TSignerUtilities.GetSigner(SigningAlgorithmECSCHNORR);

  Writeln('Signer Name is: ' + signer.AlgorithmName + sLineBreak);

  // sign

  signer.Init(True, privParams);

  &message := TEncoding.UTF8.GetBytes('PascalECSCHNORR');

  signer.BlockUpdate(&message, 0, System.Length(&message));

  sigBytes := signer.GenerateSignature();

  Writeln('Generated Signature is: ' + BytesToHexString(sigBytes) + sLineBreak);

  // verify

  signer.Init(false, pubParams);

  signer.BlockUpdate(&message, 0, System.Length(&message));

  if (not signer.VerifySignature(sigBytes)) then
  begin
    Writeln(pubParams.AlgorithmName + ' verification failed' + sLineBreak);
  end
  else
  begin
    Writeln(pubParams.AlgorithmName + ' verification passed' + sLineBreak);
  end;

end;

class procedure TUsageExamples.GetPublicKeyFromPrivateKey;
var
  domain: IECDomainParameters;
  generator: IECKeyPairGenerator;
  keygenParams: IECKeyGenerationParameters;
  keypair: IAsymmetricCipherKeyPair;
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

  keypair := generator.GenerateKeyPair();
  privParams := keypair.Private as IECPrivateKeyParameters; // for signing
  pubParams := keypair.Public as IECPublicKeyParameters; // for verifying

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

  // or the easier method
  // Method Two (** Preferred **)

  if pubParams.Equals(TECKeyPairGenerator.GetCorrespondingPublicKey(privParams))
  then
  begin
    Writeln('Public Key Recreation Match With Original Public Key' +
      sLineBreak);
  end
  else
  begin
    Writeln('Public Key Recreation DOES NOT Match With Original Public Key' +
      sLineBreak);
  end;

end;

class procedure TUsageExamples.RecreatePublicAndPrivateKeyPairsFromByteArray;
var
  domain: IECDomainParameters;
  generator: IECKeyPairGenerator;
  keygenParams: IECKeyGenerationParameters;
  keypair: IAsymmetricCipherKeyPair;
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

  keypair := generator.GenerateKeyPair();
  privParams := keypair.Private as IECPrivateKeyParameters; // for signing
  pubParams := keypair.Public as IECPublicKeyParameters; // for verifying

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

  PrivD := TBigInteger.Create(PrivateKeyByteArray);
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

end;

class procedure TUsageExamples.RecreatePublicKeyFromXAndYCoordByteArray;
var
  domain: IECDomainParameters;
  generator: IECKeyPairGenerator;
  keygenParams: IECKeyGenerationParameters;
  keypair: IAsymmetricCipherKeyPair;
  pubParams, RegeneratedPublicKey: IECPublicKeyParameters;
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

  keypair := generator.GenerateKeyPair();
  pubParams := keypair.Public as IECPublicKeyParameters; // for verifying

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

end;

class constructor TUsageExamples.UsageExamples;
begin
  FRandom := TSecureRandom.Create();
  FCurve := TSecNamedCurves.GetByName(CurveName);
end;

end.
