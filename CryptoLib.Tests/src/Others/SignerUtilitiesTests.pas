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
  Classes,
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpBigInteger,
  ClpISigner,
  ClpECC,
  ClpIRandom,
  ClpSignerUtilities,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpECDomainParameters,
  ClpICipherParameters,
  ClpIECDomainParameters,
  ClpECPublicKeyParameters,
  ClpECPrivateKeyParameters,
  ClpIECPublicKeyParameters,
  ClpIECPrivateKeyParameters,
  ClpIECC,
  ClpIDsaParameters,
  ClpIDsaPrivateKeyParameters,
  ClpIDsaPublicKeyParameters,
  ClpDsaParameters,
  ClpDsaPrivateKeyParameters,
  ClpDsaPublicKeyParameters,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpEd25519KeyGenerationParameters,
  ClpIEd25519KeyGenerationParameters,
  ClpIAsymmetricCipherKeyPair,
  ClpGeneratorUtilities,
  CryptoLibTestBase;

type

  TTestSignerUtilities = class(TCryptoLibAlgorithmTestCase)
  private

  var
    FECParraGX, FECParraGY, FECParraH, FECParraN, FECPubQX, FECPubQY, FECPrivD,
      FDSAParaG, FDSAParaP, FDSAParaQ, FDSAPublicY, FDsaPrivateX: TBigInteger;
    Fcurve: IECCurve;
    FecDomain: IECDomainParameters;
    FecPub: IECPublicKeyParameters;
    FecPriv: IECPrivateKeyParameters;
    Fpara: IDsaParameters;
    FdsaPriv: IDsaPrivateKeyParameters;
    FdsaPub: IDsaPublicKeyParameters;
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

    if ((cipherName = 'ECDSA') or (cipherName = 'CVC-ECDSA') or
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
