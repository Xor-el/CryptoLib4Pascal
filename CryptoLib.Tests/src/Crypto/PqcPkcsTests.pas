{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit PqcPkcsTests;

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
  CryptoLibTestBase,
  ClpMlDsaParameters,
  ClpIMlDsaParameters,
  ClpMlDsaGenerators,
  ClpMlKemParameters,
  ClpIMlKemParameters,
  ClpMlKemGenerators,
  ClpSlhDsaParameters,
  ClpISlhDsaParameters,
  ClpSlhDsaGenerators,
  ClpSignerUtilities,
  ClpISigner,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIKeyGenerationParameters,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpPrivateKeyFactory,
  ClpPublicKeyFactory,
  ClpPrivateKeyInfoFactory,
  ClpSubjectPublicKeyInfoFactory,
  ClpIX509Asn1Objects,
  ClpIPkcsAsn1Objects,
  ClpIAsn1Objects,
  ClpAsn1Objects,
  ClpCryptoLibTypes;

type
  TTestPqcPkcs = class(TCryptoLibAlgorithmTestCase)
  private
    FRandom: ISecureRandom;
    procedure ImplMlDsaPkcs(const AParameters: IMlDsaParameters; const ALabel: string);
    procedure ImplMlKemPkcs(const AParameters: IMlKemParameters; const ALabel: string);
    procedure ImplSlhDsaPkcs(const AParameters: ISlhDsaParameters; const ALabel: string);
  published
    procedure TestMlDsaPkcs44;
    procedure TestMlDsaPkcs65;
    procedure TestMlDsaPkcs87;
    procedure TestHashMlDsaPkcs44Sha512;
    procedure TestHashMlDsaPkcs65Sha512;
    procedure TestHashMlDsaPkcs87Sha512;
    procedure TestMlKemPkcs512;
    procedure TestMlKemPkcs768;
    procedure TestMlKemPkcs1024;
    procedure TestSlhDsaPkcs128f;
    procedure TestHashSlhDsaPkcs128fSha256;
    procedure TestSlhDsaSignerUtilities;
  public
    procedure SetUp; override;
  end;

implementation

{ TTestPqcPkcs }

procedure TTestPqcPkcs.SetUp;
begin
  inherited;
  FRandom := TSecureRandom.Create as ISecureRandom;
end;

procedure TTestPqcPkcs.ImplMlDsaPkcs(const AParameters: IMlDsaParameters; const ALabel: string);
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LPrivateKey: IMlDsaPrivateKeyParameters;
  LPublicKey: IMlDsaPublicKeyParameters;
  LPrivateKeyRT: IMlDsaPrivateKeyParameters;
  LPublicKeyRT: IMlDsaPublicKeyParameters;
  LPubInfo: ISubjectPublicKeyInfo;
  LPrivInfo: IPrivateKeyInfo;
  LSeedAndEncodingSeq: IAsn1Sequence;
  LSeedOctetString: IAsn1OctetString;
  LOriginalPub, LOriginalSk, LRoundTripPub, LRoundTripSk: TCryptoLibByteArray;
begin
  LKpg := TMlDsaKeyPairGenerator.Create;
  LKpg.Init(TMlDsaKeyGenerationParameters.Create(FRandom, AParameters) as IKeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair();
  LPrivateKey := LKp.Private as IMlDsaPrivateKeyParameters;
  LPublicKey := LKp.Public as IMlDsaPublicKeyParameters;
  LOriginalPub := LPublicKey.GetEncoded();
  LOriginalSk := LPrivateKey.GetEncoded();

  LPubInfo := TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(LPublicKey);
  CheckTrue(AreEqual(LOriginalPub, LPubInfo.PublicKey.GetOctets), ALabel + ': SPKI public key octets');

  LPrivInfo := TPrivateKeyInfoFactory.CreatePrivateKeyInfo(LPrivateKey);
  LSeedAndEncodingSeq := TAsn1Sequence.GetInstance(LPrivInfo.PrivateKey.GetOctets);
  LSeedOctetString := TAsn1OctetString.GetInstance(LSeedAndEncodingSeq[0]);
  CheckTrue(AreEqual(LPrivateKey.GetSeed(), LSeedOctetString.GetOctets), ALabel + ': PKCS seed');

  LPublicKeyRT := TPublicKeyFactory.CreateKey(LPubInfo) as IMlDsaPublicKeyParameters;
  LPrivateKeyRT := TPrivateKeyFactory.CreateKey(LPrivInfo) as IMlDsaPrivateKeyParameters;
  LRoundTripPub := LPublicKeyRT.GetEncoded();
  LRoundTripSk := LPrivateKeyRT.GetEncoded();
  CheckTrue(AreEqual(LOriginalPub, LRoundTripPub), ALabel + ': public key round-trip');
  CheckTrue(AreEqual(LOriginalSk, LRoundTripSk), ALabel + ': secret key round-trip');
end;

procedure TTestPqcPkcs.ImplMlKemPkcs(const AParameters: IMlKemParameters; const ALabel: string);
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LPrivateKey: IMlKemPrivateKeyParameters;
  LPublicKey: IMlKemPublicKeyParameters;
  LPrivateKeyRT: IMlKemPrivateKeyParameters;
  LPublicKeyRT: IMlKemPublicKeyParameters;
  LPubInfo: ISubjectPublicKeyInfo;
  LPrivInfo: IPrivateKeyInfo;
  LOriginalPub, LOriginalSk, LRoundTripPub, LRoundTripSk: TCryptoLibByteArray;
begin
  LKpg := TMlKemKeyPairGenerator.Create;
  LKpg.Init(TMlKemKeyGenerationParameters.Create(FRandom, AParameters) as IKeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair();
  LPrivateKey := LKp.Private as IMlKemPrivateKeyParameters;
  LPublicKey := LKp.Public as IMlKemPublicKeyParameters;
  LOriginalPub := LPublicKey.GetEncoded();
  LOriginalSk := LPrivateKey.GetEncoded();

  LPubInfo := TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(LPublicKey);
  CheckTrue(AreEqual(LOriginalPub, LPubInfo.PublicKey.GetOctets), ALabel + ': SPKI public key octets');

  LPrivInfo := TPrivateKeyInfoFactory.CreatePrivateKeyInfo(LPrivateKey);
  CheckNotNull(LPrivInfo.PrivateKey, ALabel + ': PKCS private key');

  LPublicKeyRT := TPublicKeyFactory.CreateKey(LPubInfo) as IMlKemPublicKeyParameters;
  LPrivateKeyRT := TPrivateKeyFactory.CreateKey(LPrivInfo) as IMlKemPrivateKeyParameters;
  LRoundTripPub := LPublicKeyRT.GetEncoded();
  LRoundTripSk := LPrivateKeyRT.GetEncoded();
  CheckTrue(AreEqual(LOriginalPub, LRoundTripPub), ALabel + ': public key round-trip');
  CheckTrue(AreEqual(LOriginalSk, LRoundTripSk), ALabel + ': secret key round-trip');
end;

procedure TTestPqcPkcs.ImplSlhDsaPkcs(const AParameters: ISlhDsaParameters; const ALabel: string);
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LPrivateKey: ISlhDsaPrivateKeyParameters;
  LPublicKey: ISlhDsaPublicKeyParameters;
  LPrivateKeyRT: ISlhDsaPrivateKeyParameters;
  LPublicKeyRT: ISlhDsaPublicKeyParameters;
  LPubInfo: ISubjectPublicKeyInfo;
  LPrivInfo: IPrivateKeyInfo;
  LOriginalPub, LOriginalSk, LRoundTripPub, LRoundTripSk: TCryptoLibByteArray;
begin
  LKpg := TSlhDsaKeyPairGenerator.Create;
  LKpg.Init(TSlhDsaKeyGenerationParameters.Create(FRandom, AParameters) as IKeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair();
  LPrivateKey := LKp.Private as ISlhDsaPrivateKeyParameters;
  LPublicKey := LKp.Public as ISlhDsaPublicKeyParameters;
  LOriginalPub := LPublicKey.GetEncoded();
  LOriginalSk := LPrivateKey.GetEncoded();

  LPubInfo := TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(LPublicKey);
  CheckTrue(AreEqual(LOriginalPub, LPubInfo.PublicKey.GetOctets), ALabel + ': SPKI public key octets');

  LPrivInfo := TPrivateKeyInfoFactory.CreatePrivateKeyInfo(LPrivateKey);
  CheckNotNull(LPrivInfo.PrivateKey, ALabel + ': PKCS private key');

  LPublicKeyRT := TPublicKeyFactory.CreateKey(LPubInfo) as ISlhDsaPublicKeyParameters;
  LPrivateKeyRT := TPrivateKeyFactory.CreateKey(LPrivInfo) as ISlhDsaPrivateKeyParameters;
  LRoundTripPub := LPublicKeyRT.GetEncoded();
  LRoundTripSk := LPrivateKeyRT.GetEncoded();
  CheckTrue(AreEqual(LOriginalPub, LRoundTripPub), ALabel + ': public key round-trip');
  CheckTrue(AreEqual(LOriginalSk, LRoundTripSk), ALabel + ': secret key round-trip');
end;

procedure TTestPqcPkcs.TestMlDsaPkcs44;
begin
  ImplMlDsaPkcs(TMlDsaParameters.MlDsa44, 'ML-DSA-44');
end;

procedure TTestPqcPkcs.TestMlDsaPkcs65;
begin
  ImplMlDsaPkcs(TMlDsaParameters.MlDsa65, 'ML-DSA-65');
end;

procedure TTestPqcPkcs.TestMlDsaPkcs87;
begin
  ImplMlDsaPkcs(TMlDsaParameters.MlDsa87, 'ML-DSA-87');
end;

procedure TTestPqcPkcs.TestHashMlDsaPkcs44Sha512;
begin
  ImplMlDsaPkcs(TMlDsaParameters.MlDsa44WithSha512, 'ML-DSA-44-WITH-SHA512');
end;

procedure TTestPqcPkcs.TestHashMlDsaPkcs65Sha512;
begin
  ImplMlDsaPkcs(TMlDsaParameters.MlDsa65WithSha512, 'ML-DSA-65-WITH-SHA512');
end;

procedure TTestPqcPkcs.TestHashMlDsaPkcs87Sha512;
begin
  ImplMlDsaPkcs(TMlDsaParameters.MlDsa87WithSha512, 'ML-DSA-87-WITH-SHA512');
end;

procedure TTestPqcPkcs.TestMlKemPkcs512;
begin
  ImplMlKemPkcs(TMlKemParameters.MlKem512, 'ML-KEM-512');
end;

procedure TTestPqcPkcs.TestMlKemPkcs768;
begin
  ImplMlKemPkcs(TMlKemParameters.MlKem768, 'ML-KEM-768');
end;

procedure TTestPqcPkcs.TestMlKemPkcs1024;
begin
  ImplMlKemPkcs(TMlKemParameters.MlKem1024, 'ML-KEM-1024');
end;

procedure TTestPqcPkcs.TestSlhDsaPkcs128f;
begin
  ImplSlhDsaPkcs(TSlhDsaParameters.SlhDsaSha2_128f, 'SLH-DSA-SHA2-128F');
end;

procedure TTestPqcPkcs.TestHashSlhDsaPkcs128fSha256;
begin
  ImplSlhDsaPkcs(TSlhDsaParameters.SlhDsaSha2_128fWithSha256, 'SLH-DSA-SHA2-128F-WITH-SHA256');
end;

procedure TTestPqcPkcs.TestSlhDsaSignerUtilities;
var
  LSigner: ISigner;
begin
  LSigner := TSignerUtilities.GetSigner('SLH-DSA-SHA2-128F');
  CheckEquals('SLH-DSA-SHA2-128F', LSigner.GetAlgorithmName);
  LSigner := TSignerUtilities.GetSigner('SLH-DSA-SHA2-128F-WITH-SHA256');
  CheckEquals('SLH-DSA-SHA2-128F-WITH-SHA256', LSigner.GetAlgorithmName);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestPqcPkcs);
{$ELSE}
  RegisterTest(TTestPqcPkcs.Suite);
{$ENDIF FPC}

end.
