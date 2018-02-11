{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                    Copyright (c) 2018 Ugochukwu Mmaduekwe                       * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *        Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring        * }
{ *                        the development of this library                          * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ECSchnorrTests;

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
  ClpSecureRandom,
  ClpISecureRandom,
  ClpECSchnorrSigner,
  ClpIECSchnorrSigner,
  ClpISigner,
  ClpECPublicKeyParameters,
  ClpIECPublicKeyParameters,
  ClpECPrivateKeyParameters,
  ClpIECPrivateKeyParameters,
  ClpECDomainParameters,
  ClpIECDomainParameters,
  ClpIECKeyPairGenerator,
  ClpECKeyPairGenerator,
  ClpIECKeyGenerationParameters,
  ClpECKeyGenerationParameters,
  ClpIAsymmetricCipherKeyPair,
  ClpIX9ECParameters,
  ClpIECInterface,
  ClpSecNamedCurves,
  ClpCryptoLibTypes,
  ClpBigInteger,
  ClpSignerUtilities,
  ClpBigIntegers;

type

  TCryptoLibTestCase = class abstract(TTestCase)

  end;

type

  /// <summary>
  /// ECSchnorr tests.
  /// </summary>
  TTestECSchnorr = class(TCryptoLibTestCase)
  private

  var
    FRandom: ISecureRandom;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestECSchnorrWithCustomK;
    procedure TestECSchnorrBSI;
    procedure TestECSchnorrISO;
    procedure TestECSchnorrISOx;
    procedure TestECSchnorrLIBSECP;

  end;

implementation

{ TTestECSchnorr }

procedure TTestECSchnorr.SetUp;
begin
  inherited;
  FRandom := TSecureRandom.Create();
end;

procedure TTestECSchnorr.TearDown;
begin
  inherited;

end;

procedure TTestECSchnorr.TestECSchnorrBSI;
var
  LCurve: IX9ECParameters;
  domain: IECDomainParameters;
  generator: IECKeyPairGenerator;
  keygenParams: IECKeyGenerationParameters;
  keypair: IAsymmetricCipherKeyPair;
  privParams: IECPrivateKeyParameters;
  pubParams: IECPublicKeyParameters;
  signer: ISigner;
  &message, sigBytes: TBytes;

begin

  LCurve := TSecNamedCurves.GetByName('secp256k1');

  domain := TECDomainParameters.Create(LCurve.Curve, LCurve.G, LCurve.N,
    LCurve.H, LCurve.GetSeed);
  generator := TECKeyPairGenerator.Create('ECSCHNORR');
  keygenParams := TECKeyGenerationParameters.Create(domain, FRandom);
  generator.Init(keygenParams);

  keypair := generator.GenerateKeyPair();
  privParams := keypair.Private as IECPrivateKeyParameters; // for signing
  pubParams := keypair.Public as IECPublicKeyParameters; // for verifying

  signer := TSignerUtilities.GetSigner('SHA-256withECSCHNORRBSI');

  // sign

  signer.Init(true, privParams);

  &message := TEncoding.UTF8.GetBytes('PascalECSCHNORR');

  signer.BlockUpdate(&message, 0, System.Length(&message));

  sigBytes := signer.GenerateSignature();

  // verify

  signer.Init(false, pubParams);

  signer.BlockUpdate(&message, 0, System.Length(&message));

  CheckTrue(signer.VerifySignature(sigBytes));

end;

procedure TTestECSchnorr.TestECSchnorrISO;
var
  LCurve: IX9ECParameters;
  domain: IECDomainParameters;
  generator: IECKeyPairGenerator;
  keygenParams: IECKeyGenerationParameters;
  keypair: IAsymmetricCipherKeyPair;
  privParams: IECPrivateKeyParameters;
  pubParams: IECPublicKeyParameters;
  signer: ISigner;
  &message, sigBytes: TBytes;

begin

  LCurve := TSecNamedCurves.GetByName('secp256k1');

  domain := TECDomainParameters.Create(LCurve.Curve, LCurve.G, LCurve.N,
    LCurve.H, LCurve.GetSeed);
  generator := TECKeyPairGenerator.Create('ECSCHNORR');
  keygenParams := TECKeyGenerationParameters.Create(domain, FRandom);
  generator.Init(keygenParams);

  keypair := generator.GenerateKeyPair();
  privParams := keypair.Private as IECPrivateKeyParameters; // for signing
  pubParams := keypair.Public as IECPublicKeyParameters; // for verifying

  signer := TSignerUtilities.GetSigner('SHA-256withECSCHNORRISO');

  // sign

  signer.Init(true, privParams);

  &message := TEncoding.UTF8.GetBytes('PascalECSCHNORR');

  signer.BlockUpdate(&message, 0, System.Length(&message));

  sigBytes := signer.GenerateSignature();

  // verify

  signer.Init(false, pubParams);

  signer.BlockUpdate(&message, 0, System.Length(&message));

  CheckTrue(signer.VerifySignature(sigBytes));

end;

procedure TTestECSchnorr.TestECSchnorrISOx;
var
  LCurve: IX9ECParameters;
  domain: IECDomainParameters;
  generator: IECKeyPairGenerator;
  keygenParams: IECKeyGenerationParameters;
  keypair: IAsymmetricCipherKeyPair;
  privParams: IECPrivateKeyParameters;
  pubParams: IECPublicKeyParameters;
  signer: ISigner;
  &message, sigBytes: TBytes;

begin

  LCurve := TSecNamedCurves.GetByName('secp256k1');

  domain := TECDomainParameters.Create(LCurve.Curve, LCurve.G, LCurve.N,
    LCurve.H, LCurve.GetSeed);
  generator := TECKeyPairGenerator.Create('ECSCHNORR');
  keygenParams := TECKeyGenerationParameters.Create(domain, FRandom);
  generator.Init(keygenParams);

  keypair := generator.GenerateKeyPair();
  privParams := keypair.Private as IECPrivateKeyParameters; // for signing
  pubParams := keypair.Public as IECPublicKeyParameters; // for verifying

  signer := TSignerUtilities.GetSigner('SHA-256withECSCHNORRISOx');

  // sign

  signer.Init(true, privParams);

  &message := TEncoding.UTF8.GetBytes('PascalECSCHNORR');

  signer.BlockUpdate(&message, 0, System.Length(&message));

  sigBytes := signer.GenerateSignature();

  // verify

  signer.Init(false, pubParams);

  signer.BlockUpdate(&message, 0, System.Length(&message));

  CheckTrue(signer.VerifySignature(sigBytes));

end;

procedure TTestECSchnorr.TestECSchnorrLIBSECP;
var
  LCurve: IX9ECParameters;
  domain: IECDomainParameters;
  generator: IECKeyPairGenerator;
  keygenParams: IECKeyGenerationParameters;
  keypair: IAsymmetricCipherKeyPair;
  privParams: IECPrivateKeyParameters;
  pubParams: IECPublicKeyParameters;
  signer: ISigner;
  &message, sigBytes: TBytes;

begin

  LCurve := TSecNamedCurves.GetByName('secp256k1');

  domain := TECDomainParameters.Create(LCurve.Curve, LCurve.G, LCurve.N,
    LCurve.H, LCurve.GetSeed);
  generator := TECKeyPairGenerator.Create('ECSCHNORR');
  keygenParams := TECKeyGenerationParameters.Create(domain, FRandom);
  generator.Init(keygenParams);

  keypair := generator.GenerateKeyPair();
  privParams := keypair.Private as IECPrivateKeyParameters; // for signing
  pubParams := keypair.Public as IECPublicKeyParameters; // for verifying

  signer := TSignerUtilities.GetSigner('SHA-256withECSCHNORRLIBSECP');

  // sign

  signer.Init(true, privParams);

  &message := TEncoding.UTF8.GetBytes('PascalECSCHNORR');

  signer.BlockUpdate(&message, 0, System.Length(&message));

  sigBytes := signer.GenerateSignature();

  // verify

  signer.Init(false, pubParams);

  signer.BlockUpdate(&message, 0, System.Length(&message));

  CheckTrue(signer.VerifySignature(sigBytes));

end;

procedure TTestECSchnorr.TestECSchnorrWithCustomK;
var
  domain: IECDomainParameters;
  RegeneratedPrivateKey: IECPrivateKeyParameters;
  RegeneratedPublicKey: IECPublicKeyParameters;
  BigXCoordByteArray, BigYCoordByteArray, PrivateKeyByteArray, &message,
    sigBytes: TBytes;
  point: IECPoint;
  LCurve: IX9ECParameters;
  signer: ISigner;
  k: TBigInteger;
begin

  LCurve := TSecNamedCurves.GetByName('secp256k1');

  domain := TECDomainParameters.Create(LCurve.Curve, LCurve.G, LCurve.N,
    LCurve.H, LCurve.GetSeed);

  BigXCoordByteArray := TBigInteger.Create
    ('65d5b8bf9ab1801c9f168d4815994ad35f1dcb6ae6c7a1a303966b677b813b00', 16)
    .ToByteArray;

  BigYCoordByteArray := TBigInteger.Create
    ('e6b865e529b8ecbf71cf966e900477d49ced5846d7662dd2dd11ccd55c0aff7f', 16)
    .ToByteArray;

  PrivateKeyByteArray := TBigInteger.Create
    ('fb26a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5', 16)
    .ToByteArray;

  point := LCurve.Curve.CreatePoint(TBigInteger.Create(1, BigXCoordByteArray),
    TBigInteger.Create(1, BigYCoordByteArray));

  RegeneratedPublicKey := TECPublicKeyParameters.Create('ECSCHNORR',
    point, domain);

  RegeneratedPrivateKey := TECPrivateKeyParameters.Create('ECSCHNORR',
    TBigInteger.Create(PrivateKeyByteArray), domain);

  signer := TSignerUtilities.GetSigner('SHA-256withECSCHNORRLIBSECP');

  // sign

  signer.Init(true, RegeneratedPrivateKey);

  &message := TBigInteger.Create
    ('0101010101010101010101010101010101010101010101010101010101010101', 16)
    .ToByteArray;

  signer.BlockUpdate(&message, 0, System.Length(&message));

  k := TBigInteger.Create
    ('4242424242424242424242424242424242424242424242424242424242424242', 16);

  // cast ISigner instance to be able to access specific method for test purposees.
  // do not do this.
  sigBytes := (signer as IECSchnorrSigner).Sign_K(RegeneratedPrivateKey, k);

  // verify

  signer.Init(false, RegeneratedPublicKey);

  signer.BlockUpdate(&message, 0, System.Length(&message));

  CheckTrue(signer.VerifySignature(sigBytes));

end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestECSchnorr);
{$ELSE}
  RegisterTest(TTestECSchnorr.Suite);
{$ENDIF FPC}

end.
