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

unit IESCipherTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpIMac,
  ClpAesEngine,
  ClpIAesEngine,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpGeneratorUtilities,
  ClpIESParameterSpec,
  ClpIAlgorithmParameterSpec,
  // ClpKeyParameter,
  // ClpIKeyParameter,
  // ClpParametersWithIV,
  // ClpIParametersWithIV,
  ClpIBufferedBlockCipher,
  // ClpParameterUtilities,
  // ClpCipherUtilities,
  ClpBlockCipherModes,
  ClpIBlockCipherModes,
  ClpPaddedBufferedBlockCipher,
  ClpECDHBasicAgreement,
  ClpIECDHBasicAgreement,
  ClpIESEngine,
  ClpIIESEngine,
  ClpPaddingModes,
  ClpIPaddingModes,
  ClpKdf2BytesGenerator,
  ClpIKdf2BytesGenerator,
  ClpIX9ECParameters,
  ClpSecNamedCurves,
  ClpIECDomainParameters,
  ClpECDomainParameters,
  ClpECKeyGenerationParameters,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpIAsymmetricCipherKeyPair,
  ClpIECPublicKeyParameters,
  ClpIECPrivateKeyParameters,
  ClpIIESCipher,
  ClpIESCipher,
  ClpDigestUtilities,
  ClpMacUtilities,
  ClpConverters,
  CryptoLibTestBase;

type

  TTestIESCipher = class(TCryptoLibAlgorithmTestCase)
  private

    function GetECIESAES256CBCEngine: IIESEngine;
    function GetECKeyPair: IAsymmetricCipherKeyPair;
    function GetIESParameterSpec: IAlgorithmParameterSpec;

    procedure DoIESCipher_Encryption_Decryption_TestWithIV
      (const KeyPair: IAsymmetricCipherKeyPair;
      const param: IAlgorithmParameterSpec; const Random: ISecureRandom;
      const PlainText: String);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestIESCipher_Random_Values_Encryption_Decryption_AES256_CBC_PKCS7PADDING;

  end;

implementation

{ TTestIESCipher }

procedure TTestIESCipher.DoIESCipher_Encryption_Decryption_TestWithIV
  (const KeyPair: IAsymmetricCipherKeyPair;
  const param: IAlgorithmParameterSpec; const Random: ISecureRandom;
  const PlainText: String);
var
  PlainTextBytes, CipherTextBytes, DecryptionResultBytes: TBytes;
  CipherEncrypt, CipherDecrypt: IIESCipher;
begin
  PlainTextBytes := TConverters.ConvertStringToBytes(PlainText, TEncoding.UTF8);
  // Encryption
  CipherEncrypt := TIESCipher.Create(GetECIESAES256CBCEngine);
  CipherEncrypt.Init(True, KeyPair.Public as IECPublicKeyParameters,
    param, Random);
  CipherTextBytes := CipherEncrypt.DoFinal(PlainTextBytes);

  // Decryption
  CipherDecrypt := TIESCipher.Create(GetECIESAES256CBCEngine);
  CipherDecrypt.Init(False, KeyPair.Private as IECPrivateKeyParameters,
    param, Random);
  DecryptionResultBytes := CipherDecrypt.DoFinal(CipherTextBytes);

  if (not AreEqual(PlainTextBytes, DecryptionResultBytes)) then
  begin
    Fail(Format('Decryption Failed - Expected %s but got %s',
      [EncodeHex(PlainTextBytes), EncodeHex(DecryptionResultBytes)]));
  end;
end;

function TTestIESCipher.GetECIESAES256CBCEngine: IIESEngine;
var
  Cipher: IBufferedBlockCipher;
  AesEngine: IAesEngine;
  blockCipher: ICbcBlockCipher;
  ECDHBasicAgreementInstance: IECDHBasicAgreement;
  KDFInstance: IKdf2BytesGenerator;
  DigestMACInstance: IMac;

begin
  // // Set up IES Cipher Engine

  ECDHBasicAgreementInstance := TECDHBasicAgreement.Create();

  KDFInstance := TKdf2BytesGenerator.Create
    (TDigestUtilities.GetDigest('SHA-256'));

  DigestMACInstance := TMacUtilities.GetMac('HMAC-SHA-256');

  // Method 1: Set Up Block Cipher
  // Cipher := TCipherUtilities.GetCipher('AES/CBC/PKCS7PADDING') as IBufferedBlockCipher;

  // Method 2: Set Up Block Cipher
  AesEngine := TAesEngine.Create(); // AES Engine

  blockCipher := TCbcBlockCipher.Create(AesEngine); // CBC

  Cipher := TPaddedBufferedBlockCipher.Create(blockCipher,
    TPkcs7Padding.Create() as IPkcs7Padding); // Pkcs7Padding

  // Cipher := TPaddedBufferedBlockCipher.Create(blockCipher,
  // TZeroBytePadding.Create() as IZeroBytePadding); // ZeroBytePadding

  result := TIESEngine.Create(ECDHBasicAgreementInstance, KDFInstance,
    DigestMACInstance, Cipher);
end;

function TTestIESCipher.GetECKeyPair: IAsymmetricCipherKeyPair;
var
  CurveName: string;
  KeyPairGeneratorInstance: IAsymmetricCipherKeyPairGenerator;
  RandomInstance: ISecureRandom;
  Lcurve: IX9ECParameters;
  ecSpec: IECDomainParameters;
begin
  // Set Up EC Key Pair

  CurveName := 'secp256k1';
  Lcurve := TSecNamedCurves.GetByName(CurveName);
  KeyPairGeneratorInstance := TGeneratorUtilities.GetKeyPairGenerator('ECDSA');
  ecSpec := TECDomainParameters.Create(Lcurve.Curve, Lcurve.G, Lcurve.N,
    Lcurve.H, Lcurve.GetSeed);
  RandomInstance := TSecureRandom.Create();
  KeyPairGeneratorInstance.Init(TECKeyGenerationParameters.Create(ecSpec,
    RandomInstance));
  result := KeyPairGeneratorInstance.GenerateKeyPair();
end;

function TTestIESCipher.GetIESParameterSpec: IAlgorithmParameterSpec;
var
  Derivation, Encoding, IVBytes: TBytes;
  MacKeySizeInBits, CipherKeySizeInBits: Int32;
  UsePointCompression: Boolean;
begin
  // Setup IES With Cipher Parameters

  // The derivation and encoding vectors are used when initialising the KDF and MAC.
  // They're optional but if used then they need to be known by the other user so that
  // they can decrypt the ciphertext and verify the MAC correctly. The security is based
  // on the shared secret coming from the (static-ephemeral) ECDH key agreement.
  Derivation := Nil;

  Encoding := Nil;

  System.SetLength(IVBytes, 16); // using Zero Initialized IV for ease

  MacKeySizeInBits := 32 * 8; // Since we are using SHA2_256 for MAC

  CipherKeySizeInBits := 32 * 8; // Since we are using AES256 for Cipher

  // whether to use point compression when deriving the octets string
  // from a point or not in the EphemeralKeyPairGenerator
  UsePointCompression := False;

  result := TIESParameterSpec.Create(Derivation, Encoding, MacKeySizeInBits,
    CipherKeySizeInBits, IVBytes, UsePointCompression);

end;

procedure TTestIESCipher.SetUp;
begin
  inherited;
end;

procedure TTestIESCipher.TearDown;
begin
  inherited;

end;

procedure TTestIESCipher.
  TestIESCipher_Random_Values_Encryption_Decryption_AES256_CBC_PKCS7PADDING;
var
  RandomInstance: ISecureRandom;
  PlainText: string;
  I: Int32;
  RandomBytes: TBytes;
begin
  RandomInstance := TSecureRandom.Create();
  I := 0;
  while I <= 10 do
  begin
    System.SetLength(RandomBytes, Byte(RandomInstance.NextInt32));
    RandomInstance.NextBytes(RandomBytes);
    PlainText := EncodeHex(RandomBytes);

    // Call IESCipher Encryption and Decryption Method

    DoIESCipher_Encryption_Decryption_TestWithIV(GetECKeyPair,
      GetIESParameterSpec, RandomInstance, PlainText);

    System.Inc(I);
  end;

end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestIESCipher);
{$ELSE}
  RegisterTest(TTestIESCipher.Suite);
{$ENDIF FPC}

end.
