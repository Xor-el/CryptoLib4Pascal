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

unit ECSchnorrTests;

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
  ClpSecureRandom,
  ClpISecureRandom,
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
  ClpIParametersWithRandom,
  ClpParametersWithRandom,
  ClpECKeyGenerationParameters,
  ClpIAsymmetricCipherKeyPair,
  ClpIX9ECParameters,
  ClpIECC,
  ClpSecNamedCurves,
  ClpBigInteger,
  ClpSignerUtilities,
  ClpConverters,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  /// <summary>
  /// ECSchnorr tests.
  /// </summary>
  TTestECSchnorr = class(TCryptoLibAlgorithmTestCase)
  private

  var
    FRandom: ISecureRandom;
    FECSchnorrSipaSigningPassTestVector,
      FECSchnorrSipaVerificationPassTestVector,
      FECSchnorrSipaVerificationFailTestVector
      : TCryptoLibGenericArray<TCryptoLibStringArray>;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestECSchnorrSIPASigningShouldPass;
    procedure TestECSchnorrSIPAVerificationShouldPass;
    procedure TestECSchnorrSIPAVerificationShouldFail;
    //procedure TestECSchnorrSIPASigningandVerifyingSecp521R1;

  end;

implementation

{ TTestECSchnorr }

procedure TTestECSchnorr.SetUp;
begin
  inherited;
  FRandom := TSecureRandom.Create();
  FECSchnorrSipaSigningPassTestVector :=
    TCryptoLibGenericArray<TCryptoLibStringArray>.Create
    (TCryptoLibStringArray.Create('Test vector 1',
    '0000000000000000000000000000000000000000000000000000000000000001',
    '0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798',
    '0000000000000000000000000000000000000000000000000000000000000000',
    '787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF67031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05'),

    TCryptoLibStringArray.Create('Test vector 2',
    'B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF',
    '02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
    '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    '2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD'),
    TCryptoLibStringArray.Create('Test vector 3',
    'C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C7',
    '03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B',
    '5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C',
    '00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE00880371D01766935B92D2AB4CD5C8A2A5837EC57FED7660773A05F0DE142380')
    );

  FECSchnorrSipaVerificationPassTestVector :=
    TCryptoLibGenericArray<TCryptoLibStringArray>.Create
    (TCryptoLibStringArray.Create('Test vector 4A',
    '03DEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34',
    '4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703',
    '00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6302A8DC32E64E86A333F20EF56EAC9BA30B7246D6D25E22ADB8C6BE1AEB08D49D'),

    TCryptoLibStringArray.Create('Test vector 4B',
    '031B84C5567B126440995D3ED5AABA0565D71E1834604819FF9C17F5E9D5DD078F',
    '0000000000000000000000000000000000000000000000000000000000000000',
    '52818579ACA59767E3291D91B76B637BEF062083284992F2D95F564CA6CB4E3530B1DA849C8E8304ADC0CFE870660334B3CFC18E825EF1DB34CFAE3DFC5D8187')
    );

  FECSchnorrSipaVerificationFailTestVector :=
    TCryptoLibGenericArray<TCryptoLibStringArray>.Create(

    TCryptoLibStringArray.Create('Test vector 5',
    '03EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34',
    '4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703',
    '00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6302A8DC32E64E86A333F20EF56EAC9BA30B7246D6D25E22ADB8C6BE1AEB08D49D',
    'public key not on the curve'),

    TCryptoLibStringArray.Create('Test vector 6',
    '02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
    '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    '2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1DFA16AEE06609280A19B67A24E1977E4697712B5FD2943914ECD5F730901B4AB7',
    'incorrect R residuosity'),

    TCryptoLibStringArray.Create('Test vector 7',
    '03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B',
    '5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C',
    '00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BED092F9D860F1776A1F7412AD8A1EB50DACCC222BC8C0E26B2056DF2F273EFDEC',
    'negated message hash'),

    TCryptoLibStringArray.Create('Test vector 8',
    '0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798',
    '0000000000000000000000000000000000000000000000000000000000000000',
    '787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF68FCE5677CE7A623CB20011225797CE7A8DE1DC6CCD4F754A47DA6C600E59543C',
    'negated s value'),

    TCryptoLibStringArray.Create('Test vector 9',
    '03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
    '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    '2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD',
    'negated public key'),

    TCryptoLibStringArray.Create('Test vector 10',
    '02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
    '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    '2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D8C3428869A663ED1E954705B020CBB3E7BB6AC31965B9EA4C73E227B17C5AF5A',
    'sG - eP is infinite'),

    TCryptoLibStringArray.Create('Test vector 11',
    '02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
    '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    '4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD',
    'sig[0:32] is not an X coordinate on the curve'),

    TCryptoLibStringArray.Create('Test vector 12',
    '02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
    '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC2F1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD',
    'sig[0:32] is equal to field size'),

    TCryptoLibStringArray.Create('Test vector 13',
    '02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
    '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    '2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1DFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141',
    'sig[32:64] is equal to curve order')

    );
end;

procedure TTestECSchnorr.TearDown;
begin
  inherited;

end;

(*
procedure TTestECSchnorr.TestECSchnorrSIPASigningandVerifyingSecp521R1;
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

  LCurve := TSecNamedCurves.GetByName('secp521r1');

  domain := TECDomainParameters.Create(LCurve.Curve, LCurve.G, LCurve.N,
    LCurve.H, LCurve.GetSeed);
  generator := TECKeyPairGenerator.Create('ECSCHNORR');
  keygenParams := TECKeyGenerationParameters.Create(domain, FRandom);
  generator.Init(keygenParams);

  keypair := generator.GenerateKeyPair();
  privParams := keypair.Private as IECPrivateKeyParameters; // for signing
  pubParams := keypair.Public as IECPublicKeyParameters; // for verifying

  signer := TSignerUtilities.GetSigner('SHA-256withECSCHNORRSIPA');

  // sign

  signer.Init(true, privParams);

  &message := TConverters.ConvertStringToBytes('PascalECSCHNORR',
    TEncoding.UTF8);

  signer.BlockUpdate(&message, 0, System.Length(&message));

  sigBytes := signer.GenerateSignature();

  // verify

  signer.Init(false, pubParams);

  signer.BlockUpdate(&message, 0, System.Length(&message));

  CheckTrue(signer.VerifySignature(sigBytes));

end;
*)

procedure TTestECSchnorr.TestECSchnorrSIPASigningShouldPass;
var
  domain: IECDomainParameters;
  RegeneratedPrivateKey: IECPrivateKeyParameters;
  RegeneratedPublicKey: IECPublicKeyParameters;
  PrivateKeyByteArray, PublicKeyByteArray, &message, sigBytes,
    expectedSignature: TBytes;
  point: IECPoint;
  LCurve: IX9ECParameters;
  signer: ISigner;
  param: IParametersWithRandom;
  vector: TCryptoLibStringArray;
begin

  LCurve := TSecNamedCurves.GetByName('secp256k1');

  domain := TECDomainParameters.Create(LCurve.Curve, LCurve.G, LCurve.N,
    LCurve.H, LCurve.GetSeed);

  for vector in FECSchnorrSipaSigningPassTestVector do
  begin

    PrivateKeyByteArray := TBigInteger.Create(vector[1], 16).ToByteArray;
    PublicKeyByteArray := TBigInteger.Create(vector[2], 16).ToByteArray;
    &message := DecodeHex(vector[3]);
    expectedSignature := DecodeHex(vector[4]);

    point := LCurve.Curve.DecodePoint(PublicKeyByteArray);

    RegeneratedPrivateKey := TECPrivateKeyParameters.Create('ECSCHNORR',
      TBigInteger.Create(PrivateKeyByteArray), domain);

    RegeneratedPublicKey := TECPublicKeyParameters.Create('ECSCHNORR',
      point, domain);

    param := TParametersWithRandom.Create(RegeneratedPrivateKey, FRandom);

    signer := TSignerUtilities.GetSigner('SHA-256withECSCHNORRSIPA');

    // sign

    signer.Init(true, param);

    signer.BlockUpdate(&message, 0, System.Length(&message));

    sigBytes := signer.GenerateSignature();

    CheckTrue(AreEqual(expectedSignature, sigBytes),
      vector[0] + ' Signature did not match Output');

    // verify

    signer.Init(false, RegeneratedPublicKey);

    signer.BlockUpdate(&message, 0, System.Length(&message));

    CheckTrue(signer.VerifySignature(sigBytes),
      vector[0] + ' Signature verification Failed');
  end;

end;

procedure TTestECSchnorr.TestECSchnorrSIPAVerificationShouldFail;
var
  domain: IECDomainParameters;
  RegeneratedPublicKey: IECPublicKeyParameters;
  PublicKeyByteArray, &message, expectedSignature: TBytes;
  point: IECPoint;
  LCurve: IX9ECParameters;
  signer: ISigner;
  vector: TCryptoLibStringArray;
begin

  LCurve := TSecNamedCurves.GetByName('secp256k1');

  domain := TECDomainParameters.Create(LCurve.Curve, LCurve.G, LCurve.N,
    LCurve.H, LCurve.GetSeed);

  for vector in FECSchnorrSipaVerificationFailTestVector do
  begin

    PublicKeyByteArray := TBigInteger.Create(vector[1], 16).ToByteArray;
    &message := DecodeHex(vector[2]);
    expectedSignature := DecodeHex(vector[3]);

    if vector[0] = 'Test vector 5' then
    begin

      try
        point := LCurve.Curve.DecodePoint(PublicKeyByteArray);
        Fail(vector[4]);
      except
        on E: EArgumentCryptoLibException do
        begin

          if E.Message <> 'Invalid Point Compression' then
          begin
            Fail('Invalid Exception Thrown');
          end;
          Continue;
        end;

      end;

    end
    else
    begin
      point := LCurve.Curve.DecodePoint(PublicKeyByteArray);
    end;

    RegeneratedPublicKey := TECPublicKeyParameters.Create('ECSCHNORR',
      point, domain);

    signer := TSignerUtilities.GetSigner('SHA-256withECSCHNORRSIPA');

    // verify

    signer.Init(false, RegeneratedPublicKey);

    signer.BlockUpdate(&message, 0, System.Length(&message));

    CheckFalse(signer.VerifySignature(expectedSignature), vector[4]);
  end;

end;

procedure TTestECSchnorr.TestECSchnorrSIPAVerificationShouldPass;
var
  domain: IECDomainParameters;
  RegeneratedPublicKey: IECPublicKeyParameters;
  PublicKeyByteArray, &message, expectedSignature: TBytes;
  point: IECPoint;
  LCurve: IX9ECParameters;
  signer: ISigner;
  vector: TCryptoLibStringArray;
begin

  LCurve := TSecNamedCurves.GetByName('secp256k1');

  domain := TECDomainParameters.Create(LCurve.Curve, LCurve.G, LCurve.N,
    LCurve.H, LCurve.GetSeed);

  for vector in FECSchnorrSipaVerificationPassTestVector do
  begin

    PublicKeyByteArray := TBigInteger.Create(vector[1], 16).ToByteArray;
    &message := DecodeHex(vector[2]);
    expectedSignature := DecodeHex(vector[3]);

    point := LCurve.Curve.DecodePoint(PublicKeyByteArray);

    RegeneratedPublicKey := TECPublicKeyParameters.Create('ECSCHNORR',
      point, domain);

    signer := TSignerUtilities.GetSigner('SHA-256withECSCHNORRSIPA');

    // verify

    signer.Init(false, RegeneratedPublicKey);

    signer.BlockUpdate(&message, 0, System.Length(&message));

    CheckTrue(signer.VerifySignature(expectedSignature),
      vector[0] + ' Signature verification Failed');
  end;

end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestECSchnorr);
{$ELSE}
  RegisterTest(TTestECSchnorr.Suite);
{$ENDIF FPC}

end.
