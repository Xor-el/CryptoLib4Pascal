{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ECEncodingTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  DateUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpAsn1Core,
  ClpBigInteger,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpAsn1SignatureFactory,
  ClpISignatureFactory,
  ClpGeneratorUtilities,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIAsymmetricCipherKeyPair,
  ClpIECParameters,
  ClpECParameters,
  ClpIX9ECAsn1Objects,
  ClpX9ECAsn1Objects,
  ClpIECCommon,
  ClpECCurve,
  ClpIPkcs12StoreBuilder,
  ClpPkcs12StoreBuilder,
  ClpIPkcs12Store,
  ClpPkcs12Store,
  ClpIX509CertificateEntry,
  ClpX509CertificateEntry,
  ClpIAsymmetricKeyEntry,
  ClpAsymmetricKeyEntry,
  ClpPrivateKeyInfoFactory,
  ClpSubjectPublicKeyInfoFactory,
  ClpIX509Certificate,
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpIX509Generators,
  ClpX509Generators,
  ClpDateTimeHelper,
  ClpEncoders,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type
  TTestECEncoding = class(TCryptoLibAlgorithmTestCase)
  strict private
    FM: Int32;
    FK1, FK2, FK3: Int32;
    FHexA, FHexB: TBytes;
    FEnc: TBytes;

    procedure DoTestPointCompression;
    procedure DoTestParams(const AEcParameterEncoded: TBytes; ACompress: Boolean);
    function GenerateSelfSignedSoftECCert(const AKp: IAsymmetricCipherKeyPair;
      ACompress: Boolean): IX509Certificate;
    function SetPublicUncompressed(const AKey: IECPublicKeyParameters): IECPublicKeyParameters;
  protected
    procedure SetUp; override;
  published
    procedure TestPointCompression;
    procedure TestEcParamsFirstVector;
    procedure TestEcParamsSecondVector;
    procedure TestEcParamsThirdVector;
  end;

implementation

{ TTestECEncoding }

procedure TTestECEncoding.SetUp;
begin
  inherited SetUp;
  FM := 304;
  FK1 := 1;
  FK2 := 2;
  FK3 := 11;
  FHexA := TBytes.Create($FD, $0D, $69, $31, $49, $A1, $18, $F6, $51, $E6, $DC,
    $E6, $80, $20, $85, $37, $7E, $5F, $88, $2D, $1B, $51, $0B, $44, $16, $00,
    $74, $C1, $28, $80, $78, $36, $5A, $03, $96, $C8, $E6, $81);
  FHexB := TBytes.Create($BD, $DB, $97, $E5, $55, $A5, $0A, $90, $8E, $43, $B0,
    $1C, $79, $8E, $A5, $DA, $A6, $78, $8F, $1E, $A2, $79, $4E, $FC, $F5, $71,
    $66, $B8, $C1, $40, $39, $60, $1E, $55, $82, $73, $40, $BE);
  FEnc := TBytes.Create($02, $19, $7B, $07, $84, $5E, $9B, $E2, $D9, $6A, $DB,
    $0F, $5F, $3C, $7F, $2C, $FF, $BD, $7A, $3E, $B8, $B6, $FE, $C3, $5C, $7F,
    $D6, $7F, $26, $DD, $F6, $28, $5A, $64, $4F, $74, $0A, $26, $14);
end;

procedure TTestECEncoding.DoTestPointCompression;
var
  LCurve: IECCurve;
  LA, LB: TBigInteger;
  LKs: TCryptoLibInt32Array;
begin
  LA := TBigInteger.Create(1, FHexA);
  LB := TBigInteger.Create(1, FHexB);
  LCurve := TF2mCurve.Create(FM, FK1, FK2, FK3, LA, LB,
    TBigInteger.GetDefault(), TBigInteger.GetDefault());
  LCurve.DecodePoint(FEnc);
  LKs := TCryptoLibInt32Array.Create(FK3, FK2, FK1);
end;

procedure TTestECEncoding.DoTestParams(const AEcParameterEncoded: TBytes;
  ACompress: Boolean);
var
  LX9: IX9ECParameters;
  LEcParams: IECDomainParameters;
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LSuccess: Boolean;
  LPubKey: IECPublicKeyParameters;
  LPrivKey: IECPrivateKeyParameters;
  LX, LY: TBytes;
  LChain: TCryptoLibGenericArray<IX509CertificateEntry>;
  LBuilder: IPkcs12StoreBuilder;
  LKeyStore: IPkcs12Store;
  LOldPrivateKeyBytes, LNewPrivateKeyBytes: TBytes;
  LOldPublicKeyBytes, LNewPublicKeyBytes: TBytes;
  LOldPrivateKey, LNewPrivateKey: String;
  LOldPublicKey, LNewPublicKey: String;
  LKeyEntry: IAsymmetricKeyEntry;
  LCertEntry: IX509CertificateEntry;
  LNewKey: IECPrivateKeyParameters;
  LNewPubKey: IECPublicKeyParameters;
  LRandom: ISecureRandom;
begin
  LX9 := TX9ECParameters.GetInstance(AEcParameterEncoded);
  LRandom := TSecureRandom.Create();
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('ECDSA');
  LEcParams := TECDomainParameters.FromX9ECParameters(LX9);
  LKpg.Init(TECKeyGenerationParameters.Create(LEcParams, LRandom) as IECKeyGenerationParameters);

  LSuccess := False;
  while not LSuccess do
  begin
    LKp := LKpg.GenerateKeyPair();
    if not Supports(LKp.Public, IECPublicKeyParameters, LPubKey) then
      Fail('expected IECPublicKeyParameters');
    if not ACompress then
      LPubKey := SetPublicUncompressed(LPubKey);
    LX := LPubKey.Q.AffineXCoord.ToBigInteger().ToByteArrayUnsigned();
    LY := LPubKey.Q.AffineYCoord.ToBigInteger().ToByteArrayUnsigned();
    if System.Length(LX) = System.Length(LY) then
      LSuccess := True;
  end;

  LChain := TCryptoLibGenericArray<IX509CertificateEntry>.Create(
    TX509CertificateEntry.Create(GenerateSelfSignedSoftECCert(LKp, ACompress)));

  LBuilder := TPkcs12StoreBuilder.Create;
  LKeyStore := LBuilder.Build;
  LKeyStore.SetCertificateEntry('ECCert', LChain[0]);
  if not Supports(LKp.Private, IECPrivateKeyParameters, LPrivKey) then
    Fail('expected IECPrivateKeyParameters');
  LKeyStore.SetKeyEntry('ECPrivKey', TAsymmetricKeyEntry.Create(LPrivKey), LChain);

  LOldPrivateKeyBytes := TPrivateKeyInfoFactory.CreatePrivateKeyInfo(LPrivKey).GetEncoded(TAsn1Encodable.Der);
  LOldPrivateKey := THexEncoder.Encode(LOldPrivateKeyBytes);
  LOldPublicKeyBytes := TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(LPubKey).GetEncoded(TAsn1Encodable.Der);
  LOldPublicKey := THexEncoder.Encode(LOldPublicKeyBytes);

  LKeyEntry := LKeyStore.GetKey('ECPrivKey');
  if LKeyEntry = nil then
    Fail('GetKey ECPrivKey returned nil');
  if not Supports(LKeyEntry.Key, IECPrivateKeyParameters, LNewKey) then
    Fail('expected IECPrivateKeyParameters for stored key');

  LCertEntry := LKeyStore.GetCertificate('ECCert');
  if LCertEntry = nil then
    Fail('GetCertificate ECCert returned nil');
  LNewPubKey := nil;
  if not Supports(LCertEntry.Certificate.GetPublicKey(), IECPublicKeyParameters, LNewPubKey) then
    Fail('expected IECPublicKeyParameters for cert public key');

  if not ACompress then
    LNewPubKey := SetPublicUncompressed(LNewPubKey);

  LNewPrivateKeyBytes := TPrivateKeyInfoFactory.CreatePrivateKeyInfo(LNewKey).GetEncoded(TAsn1Encodable.Der);
  LNewPrivateKey := THexEncoder.Encode(LNewPrivateKeyBytes);
  LNewPublicKeyBytes := TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(LNewPubKey).GetEncoded(TAsn1Encodable.Der);
  LNewPublicKey := THexEncoder.Encode(LNewPublicKeyBytes);

  if LOldPrivateKey <> LNewPrivateKey then
    Fail('failed private key comparison');
  if LOldPublicKey <> LNewPublicKey then
    Fail('failed public key comparison');
end;

function TTestECEncoding.GenerateSelfSignedSoftECCert(
  const AKp: IAsymmetricCipherKeyPair; ACompress: Boolean): IX509Certificate;
var
  LCertGen: IX509V3CertificateGenerator;
  LPrivECKey: IECPrivateKeyParameters;
  LPubECKey: IECPublicKeyParameters;
  LUtc: TDateTime;
begin
  LCertGen := TX509V3CertificateGenerator.Create;
  if not Supports(AKp.Private, IECPrivateKeyParameters, LPrivECKey) then
    Fail('expected IECPrivateKeyParameters');
  if not Supports(AKp.Public, IECPublicKeyParameters, LPubECKey) then
    Fail('expected IECPublicKeyParameters');
  if not ACompress then
    LPubECKey := SetPublicUncompressed(LPubECKey);
  LCertGen.SetSerialNumber(TBigInteger.One);
  LCertGen.SetIssuerDN(TX509Name.Create('CN=Software emul (EC Cert)') as IX509Name);
  LUtc := Now.ToUniversalTime();
  LCertGen.SetNotBeforeUtc(IncSecond(LUtc, -50));
  LCertGen.SetNotAfterUtc(IncSecond(LUtc, 50000));
  LCertGen.SetSubjectDN(TX509Name.Create('CN=Software emul (EC Cert)') as IX509Name);
  LCertGen.SetPublicKey(LPubECKey);
  Result := LCertGen.Generate(TAsn1SignatureFactory.Create('ECDSAwithSHA1', LPrivECKey, nil) as ISignatureFactory);
end;

function TTestECEncoding.SetPublicUncompressed(
  const AKey: IECPublicKeyParameters): IECPublicKeyParameters;
var
  LP: IECPoint;
begin
  LP := AKey.Q.Normalize();
  Result := TECPublicKeyParameters.Create(AKey.AlgorithmName,
    AKey.Parameters.Curve.CreatePoint(LP.XCoord.ToBigInteger(), LP.YCoord.ToBigInteger()),
    AKey.Parameters);
end;

procedure TTestECEncoding.TestPointCompression;
begin
  DoTestPointCompression();
end;

procedure TTestECEncoding.TestEcParamsFirstVector;
var
  LEcParams: TBytes;
begin
  LEcParams := THexEncoder.Decode('3081C8020101302806072A8648CE3D0101021D00D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF303C' +
    '041C68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43041C2580F63CCFE44138870713B1A92369E33E21' +
    '35D266DBB372386C400B0439040D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D58AA56F772C0726F24' +
    'C6B89E4ECDAC24354B9E99CAA3F6D3761402CD021D00D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F' +
    '020101');
  DoTestParams(LEcParams, True);
  DoTestParams(LEcParams, False);
end;

procedure TTestECEncoding.TestEcParamsSecondVector;
var
  LEcParams: TBytes;
begin
  LEcParams := THexEncoder.Decode('3081C8020101302806072A8648CE3D0101021D00D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF303C' +
    '041C56E6C7E4F11A7B4B961A4DCB5BD282EB22E42E9BCBE3E7B361F18012041C4BE3E7B361F18012F2353D22975E02D8D05D' +
    '2C6F3342DD8F57D4C76F0439048D127A0C27E0DE207ED3B7FB98F83C8BD5A2A57C827F4B97874DEB2C1BAEB0C006958CE61B' +
    'B1FC81F5389E288CB3E86E2ED91FB47B08FCCA021D00D7C134AA264366862A18302575D11A5F7AABFBA3D897FF5CA727AF53' +
    '020101');
  DoTestParams(LEcParams, True);
  DoTestParams(LEcParams, False);
end;

procedure TTestECEncoding.TestEcParamsThirdVector;
var
  LEcParams: TBytes;
begin
  LEcParams := THexEncoder.Decode('30820142020101303c06072a8648ce3d0101023100ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' +
    'fffffeffffffff0000000000000000ffffffff3066043100ffffffffffffffffffffffffffffffffffffffffffffffffffff' +
    'fffffffffffeffffffff0000000000000000fffffffc043100b3312fa7e23ee7e4988e056be3f82d19181d9c6efe81411203' +
    '14088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef046104aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b98' +
    '59f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da' +
    '3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f023100ffffffffffffffffffffffffffffffffffffffffffffffffc7' +
    '634d81f4372ddf581a0db248b0a77aecec196accc52973020101');
  DoTestParams(LEcParams, True);
  DoTestParams(LEcParams, False);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestECEncoding);
{$ELSE}
  RegisterTest(TTestECEncoding.Suite);
{$ENDIF FPC}

end.
