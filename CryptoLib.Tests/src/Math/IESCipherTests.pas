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
  ClpICipherParameters,
  ClpIIESParameters,
  ClpIIESWithCipherParameters,
  ClpIESParameters,
  ClpIESWithCipherParameters,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  // ClpKeyParameter,
  // ClpIKeyParameter,
  // ClpParametersWithIV,
  // ClpIParametersWithIV,
  ClpIBufferedBlockCipher,
  // ClpParameterUtilities,
  // ClpCipherUtilities,
  ClpCbcBlockCipher,
  ClpCfbBlockCipher,
  ClpCtsBlockCipher,
  ClpOfbBlockCipher,
  ClpSicBlockCipher,
  ClpICbcBlockCipher,
  ClpICfbBlockCipher,
  ClpICtsBlockCipher,
  ClpIOfbBlockCipher,
  ClpISicBlockCipher,
  ClpPaddedBufferedBlockCipher,
  ClpECDHBasicAgreement,
  ClpIECDHBasicAgreement,
  ClpIESEngine,
  ClpIIESEngine,
  ClpISO10126d2Padding,
  ClpISO7816d4Padding,
  ClpPkcs7Padding,
  ClpTBCPadding,
  ClpX923Padding,
  ClpZeroBytePadding,
  ClpIISO10126d2Padding,
  ClpIISO7816d4Padding,
  ClpIPkcs7Padding,
  ClpITBCPadding,
  ClpIX923Padding,
  ClpIZeroBytePadding,
  ClpKdf2BytesGenerator,
  ClpIKdf2BytesGenerator,
  ClpIX9ECAsn1Objects,
  ClpSecNamedCurves,
  ClpIECDomainParameters,
  ClpECDomainParameters,
  ClpECKeyGenerationParameters,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpIAsymmetricCipherKeyPair,
  ClpIECPublicKeyParameters,
  ClpIECPrivateKeyParameters,
  ClpIIesCipherParameters,
  ClpIesCipherParameters,
  ClpIBufferedCipher,
  ClpBufferedIesCipher,
  ClpDigestUtilities,
  ClpMacUtilities,
  ClpConverters,
  CryptoLibTestBase;

type

  TTestIESCipher = class(TCryptoLibAlgorithmTestCase)
  private

    function GetECIESAES256CBCEngine: IIesEngine;
    function GetECKeyPair: IAsymmetricCipherKeyPair;
    function GetIESParameters: ICipherParameters;

    procedure DoIESCipher_Encryption_Decryption_TestWithIV
      (const KeyPair: IAsymmetricCipherKeyPair;
      const AParams: ICipherParameters; const Random: ISecureRandom;
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
  const AParams: ICipherParameters; const Random: ISecureRandom;
  const PlainText: String);
var
  PlainTextBytes, CipherTextBytes, DecryptionResultBytes: TBytes;
  CipherEncrypt, CipherDecrypt: IBufferedCipher;
  LParamsWithIV: IParametersWithIV;
  LIesParams: IIesParameters;
  LCipherParams: IIesCipherParameters;
begin
  PlainTextBytes := TConverters.ConvertStringToBytes(PlainText, TEncoding.UTF8);
  if not Supports(AParams, IParametersWithIV, LParamsWithIV) or
     not Supports(LParamsWithIV.Parameters, IIesParameters, LIesParams) then
    Fail('GetIESParameters must return IParametersWithIV wrapping IIESParameters');
  LCipherParams := TIesCipherParameters.Create(KeyPair.Private, KeyPair.Public, LIesParams);

  CipherEncrypt := TBufferedIesCipher.Create(GetECIESAES256CBCEngine);
  CipherEncrypt.Init(True, LCipherParams);
  CipherTextBytes := CipherEncrypt.DoFinal(PlainTextBytes);

  CipherDecrypt := TBufferedIesCipher.Create(GetECIESAES256CBCEngine);
  CipherDecrypt.Init(False, LCipherParams);
  DecryptionResultBytes := CipherDecrypt.DoFinal(CipherTextBytes);

  if (not AreEqual(PlainTextBytes, DecryptionResultBytes)) then
  begin
    Fail(Format('Decryption Failed - Expected %s but got %s',
      [EncodeHex(PlainTextBytes), EncodeHex(DecryptionResultBytes)]));
  end;
end;

function TTestIESCipher.GetECIESAES256CBCEngine: IIesEngine;
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

  result := TIesEngine.Create(ECDHBasicAgreementInstance, KDFInstance,
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

function TTestIESCipher.GetIESParameters: ICipherParameters;
var
  Derivation, Encoding, IVBytes: TBytes;
  MacKeySizeInBits, CipherKeySizeInBits: Int32;
  LIesParams: IIesWithCipherParameters;
begin
  Derivation := nil;
  Encoding := nil;
  System.SetLength(IVBytes, 16); // Zero-initialized IV
  MacKeySizeInBits := 32 * 8;   // SHA2_256 for MAC
  CipherKeySizeInBits := 32 * 8; // AES256
  LIesParams := TIesWithCipherParameters.Create(Derivation, Encoding,
    MacKeySizeInBits, CipherKeySizeInBits);
  Result := TParametersWithIV.Create(LIesParams, IVBytes);
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
      GetIESParameters, RandomInstance, PlainText);

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
