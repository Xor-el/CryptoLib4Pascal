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

unit SignerUtilitiesTests;

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
  ClpBigInteger,
  ClpISigner,
  ClpECCurve,
  ClpIECCommon,
  ClpIECFieldElement,
  ClpIRandom,
  ClpSignerUtilities,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpECParameters,
  ClpICipherParameters,
  ClpIECParameters,
  ClpIDsaParameters,
  ClpDsaParameters,
  ClpRsaParameters,
  ClpIRsaParameters,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpEd25519Parameters,
  ClpIEd25519Parameters,
  ClpIAsymmetricCipherKeyPair,
  ClpGeneratorUtilities,
  CryptoLibTestBase;

type

  TTestSignerUtilities = class(TCryptoLibAlgorithmTestCase)
  private

  var
    // ECDSA parameters
    FECParraGX, FECParraGY, FECParraH, FECParraN, FECPubQX, FECPubQY, FECPrivD,
    // DSA parameters
    FDSAParaG, FDSAParaP, FDSAParaQ, FDSAPublicY, FDsaPrivateX,
    // RSA parameters
    FRsaMod, FRsaPubExp, FRsaPrivExp, FRsaPrivP, FRsaPrivQ,
    FRsaPrivDP, FRsaPrivDQ, FRsaPrivQinv: TBigInteger;
    Fcurve: IECCurve;
    FecDomain: IECDomainParameters;
    FecPub: IECPublicKeyParameters;
    FecPriv: IECPrivateKeyParameters;
    Fpara: IDsaParameters;
    FdsaPriv: IDsaPrivateKeyParameters;
    FdsaPub: IDsaPublicKeyParameters;
    FRsaPublic: IRsaKeyParameters;
    FRsaPrivate: IRsaPrivateCrtKeyParameters;
    Fed25519Kpg: IAsymmetricCipherKeyPairGenerator;
    Fed25519Pair: IAsymmetricCipherKeyPair;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestAlgorithms;

  end;

implementation

{ TTestSignerUtilities }

procedure TTestSignerUtilities.SetUp;
begin
  inherited;

  //
  // RSA parameters
  //
  FRsaMod := TBigInteger.Create('a7295693155b1813bb84877fb45343556e0568043de5910872a3a518cc11e23e2db74eaf4545068c4e3d258a2718fbacdcc3eafa457695b957e88fbf110aed049a992d9c430232d02f3529c67a3419' + '935ea9b569f85b1bcd37de6b899cd62697e843130ff0529d09c97d813cb15f293751ff56f943fbdabb63971cc7f4f6d5bff1594416b1f5907bde5a84a44f9802ef29b43bda1960f948f8afb8766c1ab80d32eec88ed66d0b65aebe44a6d0b3c5e0ab051aaa1b912' + 'fbcc17b8e751ddecc5365b6db6dab0020c3057db4013a51213a5798a3aab67985b0f4d88627a54a0f3f0285fbcb4afdfeb65cb153af66825656d43238b75503231500753f4e421e3c57', 16);
  FRsaPubExp := TBigInteger.Create('10001', 16);
  FRsaPrivExp := TBigInteger.Create('65dad56ac7df7abb434e4cb5eeadb16093aa6da7f0033aad3815289b04757d32bfee6ade7749c8e4a323b5050a2fb9e2a99e23469e1ed4ba5bab54336af20a5bfccb8b3424cc6923db2ffca5787' + 'ed87aa87aa614cd04cedaebc8f623a2d2063017910f436dff18bb06f01758610787f8b258f0a8efd8bd7de30007c47b2a1031696c7d6523bc191d4d918927a7e0b09584ed205bd2ff4fc4382678df82353f7532b3bbb81d69e3f39070aed3fb64fce032a089e8e6' + '4955afa5213a6eb241231bd98d702fba725a9b205952fda186412d9e0d9344d2998c455ad8c2bae85ee672751466d5288304032b5b7e02f7e558c7af82c7fbf58eea0bb4ef0f001e6cd0a9', 16);
  FRsaPrivP := TBigInteger.Create('d4fd9ac3474fb83aaf832470643609659e511b322632b239b688f3cd2aad87527d6cf652fb9c9ca67940e84789444f2e99b0cb0cfabbd4de95396106c865f38e2fb7b82b231260a94df0e01756bf73' + 'ce0386868d9c41645560a81af2f53c18e4f7cdf3d51d80267372e6e0216afbf67f655c9450769cca494e4f6631b239ce1b', 16);
  FRsaPrivQ := TBigInteger.Create('c8eaa0e2a1b3a4412a702bccda93f4d150da60d736c99c7c566fdea4dd1b401cbc0d8c063daaf0b579953d36343aa18b33dbf8b9eae94452490cc905245f8f7b9e29b1a288bc66731a29e1dd1a45c9f' + 'd7f8238ff727adc49fff73991d0dc096206b9d3a08f61e7462e2b804d78cb8c5eccdb9b7fbd2ad6a8fea46c1053e1be75', 16);
  FRsaPrivDP := TBigInteger.Create('10edcb544421c0f9e123624d1099feeb35c72a8b34e008ac6fa6b90210a7543f293af4e5299c8c12eb464e70092805c7256e18e5823455ba0f504d36f5ccacac1b7cd5c58ff710f9c3f92646949d88f' + 'dd1e7ea5fed1081820bb9b0d2a8cd4b093fecfdb96dabd6e28c3a6f8c186dc86cddc89afd3e403e0fcf8a9e0bcb27af0b', 16);
  FRsaPrivDQ := TBigInteger.Create('97fc25484b5a415eaa63c03e6efa8dafe9a1c8b004d9ee6e80548fefd6f2ce44ee5cb117e77e70285798f57d137566ce8ea4503b13e0f1b5ed5ca6942537c4aa96b2a395782a4cb5b58d0936e0b0fa6' + '3b1192954d39ced176d71ef32c6f42c84e2e19f9d4dd999c2151b032b97bd22aa73fd8c5bcd15a2dca4046d5acc997021', 16);
  FRsaPrivQinv := TBigInteger.Create('4bb8064e1eff7e9efc3c4578fcedb59ca4aef0993a8312dfdcb1b3decf458aa6650d3d0866f143cbf0d3825e9381181170a0a1651eefcd7def786b8eb356555d9fa07c85b5f5cbdd74382f1129b5e' + '36b4166b6cc9157923699708648212c484958351fdc9cf14f218dbe7fbf7cbd93a209a4681fe23ceb44bab67d66f45d1c9d', 16);

  FRsaPublic := TRsaKeyParameters.Create(false, FRsaMod, FRsaPubExp);
  FRsaPrivate := TRsaPrivateCrtKeyParameters.Create(FRsaMod, FRsaPubExp, FRsaPrivExp,
    FRsaPrivP, FRsaPrivQ, FRsaPrivDP, FRsaPrivDQ, FRsaPrivQinv);

  //
  // ECDSA parameters
  //

  FECParraGX := TBigInteger.Create
    (DecodeBase64('D/qWPNyogWzMM7hkK+35BcPTWFc9Pyf7vTs8uaqv'));
  FECParraGY := TBigInteger.Create
    (DecodeBase64('AhQXGxb1olGRv6s1LPRfuatMF+cx3ZTGgzSE/Q5R'));
  FECParraH := TBigInteger.Create(DecodeBase64('AQ=='));
  FECParraN := TBigInteger.Create
    (DecodeBase64('f///////////////f///nl6an12QcfvRUiaIkJ0L'));
  FECPubQX := TBigInteger.Create
    (DecodeBase64('HWWi17Yb+Bm3PYr/DMjLOYNFhyOwX1QY7ZvqqM+l'));
  FECPubQY := TBigInteger.Create
    (DecodeBase64('JrlJfxu3WGhqwtL/55BOs/wsUeiDFsvXcGhB8DGx'));
  FECPrivD := TBigInteger.Create
    (DecodeBase64('GYQmd/NF1B+He1iMkWt3by2Az6Eu07t0ynJ4YCAo'));

  Fcurve := TFpCurve.Create
    (TBigInteger.Create
    ('883423532389192164791648750360308885314476597252960362792450860609699839'),
    // q
    TBigInteger.Create
    ('7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc', 16), // a
    TBigInteger.Create
    ('6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a', 16), // b
    FECParraN, FECParraH);

  FecDomain := TECDomainParameters.Create(Fcurve,
    Fcurve.ValidatePoint(FECParraGX, FECParraGY), FECParraN, FECParraH);

  FecPub := TECPublicKeyParameters.Create(Fcurve.ValidatePoint(FECPubQX,
    FECPubQY), FecDomain);

  FecPriv := TECPrivateKeyParameters.Create(FECPrivD, FecDomain);

  //
  // DSA parameters
  //

  FDSAParaG := TBigInteger.Create
    (DecodeBase64
    ('AL0fxOTq10OHFbCf8YldyGembqEu08EDVzxyLL29Zn/t4It661YNol1rnhPIs+cirw+yf9zeCe+KL1IbZ/qIMZM=')
    );
  FDSAParaP := TBigInteger.Create
    (DecodeBase64
    ('AM2b/UeQA+ovv3dL05wlDHEKJ+qhnJBsRT5OB9WuyRC830G79y0R8wuq8jyIYWCYcTn1TeqVPWqiTv6oAoiEeOs=')
    );
  FDSAParaQ := TBigInteger.Create(DecodeBase64('AIlJT7mcKL6SUBMmvm24zX1EvjNx'));
  FDSAPublicY := TBigInteger.Create
    (DecodeBase64
    ('TtWy2GuT9yGBWOHi1/EpCDa/bWJCk2+yAdr56rAcqP0eHGkMnA9s9GJD2nGU8sFjNHm55swpn6JQb8q0agrCfw==')
    );
  FDsaPrivateX := TBigInteger.Create
    (DecodeBase64('MMpBAxNlv7eYfxLTZ2BItJeD31A='));

  Fpara := TDsaParameters.Create(FDSAParaP, FDSAParaQ, FDSAParaG);
  FdsaPriv := TDsaPrivateKeyParameters.Create(FDsaPrivateX, Fpara);
  FdsaPub := TDsaPublicKeyParameters.Create(FDSAPublicY, Fpara);

  //
  // EdDSA parameters
  //

  Fed25519Kpg := TGeneratorUtilities.GetKeyPairGenerator('Ed25519');
  Fed25519Kpg.Init(TEd25519KeyGenerationParameters.Create(TSecureRandom.Create()
    as ISecureRandom) as IEd25519KeyGenerationParameters);
  Fed25519Pair := Fed25519Kpg.GenerateKeyPair();

end;

procedure TTestSignerUtilities.TearDown;
begin
  inherited;

end;

procedure TTestSignerUtilities.TestAlgorithms;
var
  shortMsg, longMsg, sig: TBytes;
  LRandom: IRandom;
  algorithm, upper, cipherName: string;
  signer: ISigner;
  withPos: Int32;
  signParams, verifyParams: ICipherParameters;
  b: Byte;
begin
  //
  // signer loop
  //
  shortMsg := TBytes.Create(1, 4, 5, 6, 8, 8, 4, 2, 1, 3);
  System.SetLength(longMsg, 100);

  LRandom := TSecureRandom.Create();
  LRandom.NextBytes(longMsg);

  for algorithm in TSignerUtilities.Algorithms do
  begin

    signer := TSignerUtilities.GetSigner(algorithm);

    upper := UpperCase(algorithm);
    withPos := System.Pos('WITH', upper);

    if withPos = 0 then

    begin
      cipherName := upper;
    end
    else
    begin
      cipherName := System.Copy(upper, withPos + System.length('WITH'),
        System.length(upper) - withPos + System.length('WITH'));
    end;

    signParams := nil;
    verifyParams := nil;

    if (cipherName = 'RSA') or (cipherName = 'RSAANDMGF1') then
    begin
      signParams := FRsaPrivate;
      verifyParams := FRsaPublic;
    end
    else if ((cipherName = 'ECDSA') or (cipherName = 'CVC-ECDSA') or
      (cipherName = 'PLAIN-ECDSA')) then
    begin
      signParams := FecPriv;
      verifyParams := FecPub;
    end
    else if (cipherName = 'DSA') then
    begin
      signParams := FdsaPriv;
      verifyParams := FdsaPub;
    end
    else if (cipherName = 'ED25519') then
    begin
      signParams := Fed25519Pair.Private;
      verifyParams := Fed25519Pair.Public;
    end
    else
    begin
      Fail('Unknown algorithm encountered: ' + cipherName);
    end;

    signer.Init(true, signParams);
    for b in shortMsg do
    begin
      signer.Update(b);
    end;
    signer.BlockUpdate(longMsg, 0, System.length(longMsg));
    sig := signer.GenerateSignature();

    signer.Init(false, verifyParams);
    for b in shortMsg do
    begin
      signer.Update(b);
    end;
    signer.BlockUpdate(longMsg, 0, System.length(longMsg));

    CheckTrue(signer.VerifySignature(sig), cipherName + ' signer ' + algorithm +
      ' failed.');
  end;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestSignerUtilities);
{$ELSE}
  RegisterTest(TTestSignerUtilities.Suite);
{$ENDIF FPC}

end.
