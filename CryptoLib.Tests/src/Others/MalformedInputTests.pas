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

unit MalformedInputTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
  DateUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpBigInteger,
  ClpNullable,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIPkcsAsn1Objects,
  ClpPkcsAsn1Objects,
  ClpPkcsObjectIdentifiers,
  ClpX9ObjectIdentifiers,
  ClpIX9DHAsn1Objects,
  ClpX9DHAsn1Objects,
  ClpIPkcsDHAsn1Objects,
  ClpPkcsDHAsn1Objects,
  ClpIX509Certificate,
  ClpX509Generators,
  ClpIX509Generators,
  ClpIX509StoreSelectors,
  ClpX509StoreSelectors,
  ClpAsn1SignatureFactory,
  ClpISignatureFactory,
  ClpIStandardDsaEncoding,
  ClpStandardDsaEncoding,
  ClpPublicKeyFactory,
  ClpPrivateKeyFactory,
  ClpPrivateKeyInfoFactory,
  ClpNistObjectIdentifiers,
  ClpIPkcs12Store,
  ClpIPkcs12StoreBuilder,
  ClpPkcs12StoreBuilder,
  ClpPkcs12Utilities,
  ClpIOcspProtocolObjects,
  ClpOcspProtocolObjects,
  ClpCryptoLibTypes,
  ClpDateTimeHelper,
  ClpCryptoLibExceptions,
  CryptoLibTestBase,
  CryptoTestKeys;

type
  TTestMalformedInput = class(TCryptoLibAlgorithmTestCase)
  strict private
    function GenerateCertificate(const AExtOid: String;
      const AExtValue: TBytes): IX509Certificate;
    function EmptyAuthSafePfx: TBytes;
    function RsaAlgorithm: IAlgorithmIdentifier;
    function DsaAlgorithm: IAlgorithmIdentifier;
    procedure CheckPublicKeyWithoutParameters(const AOid: IDerObjectIdentifier);
    procedure CheckPrivateKeyWithoutParameters(const AOid: IDerObjectIdentifier;
      const APrivateKey: IAsn1Encodable);
    procedure CheckEncryptedKeyRejected(const AKdf: IKeyDerivationFunc;
      const AScheme: IEncryptionScheme);
  published
    procedure TestDsaDecodeEmptyEncoding;
    procedure TestDsaDecodeNonSequenceEncoding;
    procedure TestKeyUsageSingleByte;
    procedure TestKeyUsageEmptyBitString;
    procedure TestPublicKeyFactoryEmptyRsaKey;
    procedure TestPublicKeyFactoryEmptyDsaKey;
    procedure TestPublicKeyFactoryEmptyX942DhKey;
    procedure TestPublicKeyFactoryEmptyPkcsDhKey;
    procedure TestPublicKeyFactoryX942DhWithoutParameters;
    procedure TestPublicKeyFactoryPkcsDhWithoutParameters;
    procedure TestPublicKeyFactoryEcWithoutParameters;
    procedure TestPrivateKeyFactoryEmptyPrivateKey;
    procedure TestPrivateKeyFactoryEcWithoutParameters;
    procedure TestPrivateKeyFactoryDhWithoutParameters;
    procedure TestEncryptedKeyWithoutEncryptionSchemeParameters;
    procedure TestEncryptedKeyWithoutKdfParameters;
    procedure TestPkcs12StoreLoadEmptyAuthSafe;
    procedure TestPkcs12ConvertToDefiniteLengthEmptyAuthSafe;
    procedure TestPkcs12ConvertToDefiniteLengthEmptyPfx;
    procedure TestPkcs12ConvertToDefiniteLengthSingleArgEmptyPfx;
    procedure TestSelectorEmptyPrivateKeyUsagePeriod;
    procedure TestOcspReqEmptyEncoding;
    procedure TestOcspRespEmptyEncoding;
  end;

implementation

{ TTestMalformedInput }

function TTestMalformedInput.GenerateCertificate(const AExtOid: String;
  const AExtValue: TBytes): IX509Certificate;
var
  LCertGen: IX509V3CertificateGenerator;
  LName: IX509Name;
  LSigner: ISignatureFactory;
  LUtc: TDateTime;
begin
  LCertGen := TX509V3CertificateGenerator.Create;
  LName := TX509Name.Create('CN=Test') as IX509Name;
  LUtc := Now.ToUniversalTime();

  LCertGen.SetSerialNumber(TBigInteger.One);
  LCertGen.SetIssuerDN(LName);
  LCertGen.SetNotBeforeUtc(IncDay(LUtc, -1));
  LCertGen.SetNotAfterUtc(IncDay(LUtc, 1));
  LCertGen.SetSubjectDN(LName);
  LCertGen.SetPublicKey(TCryptoTestKeys.GetRsaDigestSignerPublic);
  LCertGen.AddExtension(AExtOid, False, AExtValue);

  LSigner := TAsn1SignatureFactory.Create('SHA256WithRSAEncryption',
    TCryptoTestKeys.GetRsaDigestSignerPrivate, nil);
  Result := LCertGen.Generate(LSigner);
end;

function TTestMalformedInput.EmptyAuthSafePfx: TBytes;
var
  LContentInfo: IPkcsContentInfo;
  LPfx: IPfx;
begin
  LContentInfo := TPkcsContentInfo.Create(TPkcsObjectIdentifiers.Data,
    TDerOctetString.FromContents(nil));
  LPfx := TPfx.Create(LContentInfo, nil);
  Result := LPfx.GetEncoded();
end;

function TTestMalformedInput.RsaAlgorithm: IAlgorithmIdentifier;
begin
  Result := TAlgorithmIdentifier.Create(TPkcsObjectIdentifiers.RsaEncryption,
    TDerNull.Instance);
end;

function TTestMalformedInput.DsaAlgorithm: IAlgorithmIdentifier;
begin
  Result := TAlgorithmIdentifier.Create(TX9ObjectIdentifiers.IdDsa);
end;

procedure TTestMalformedInput.CheckPublicKeyWithoutParameters(
  const AOid: IDerObjectIdentifier);
var
  LKeyInfo: ISubjectPublicKeyInfo;
begin
  LKeyInfo := TSubjectPublicKeyInfo.Create(TAlgorithmIdentifier.Create(AOid) as IAlgorithmIdentifier,
    TDerBitString.Create(DecodeHex('0102030405')) as IDerBitString);
  try
    TPublicKeyFactory.CreateKey(LKeyInfo);
    Fail('expected EArgumentCryptoLibException');
  except
    on E: EArgumentCryptoLibException do
      ;
  end;
end;

procedure TTestMalformedInput.CheckPrivateKeyWithoutParameters(
  const AOid: IDerObjectIdentifier; const APrivateKey: IAsn1Encodable);
var
  LKeyInfo: IPrivateKeyInfo;
begin
  LKeyInfo := TPrivateKeyInfo.Create(TAlgorithmIdentifier.Create(AOid) as IAlgorithmIdentifier,
    APrivateKey);
  try
    TPrivateKeyFactory.CreateKey(LKeyInfo);
    Fail('expected EArgumentCryptoLibException');
  except
    on E: EArgumentCryptoLibException do
      ;
  end;
end;

procedure TTestMalformedInput.CheckEncryptedKeyRejected(
  const AKdf: IKeyDerivationFunc; const AScheme: IEncryptionScheme);
var
  LParams: IPbeS2Parameters;
  LEncrypted: IEncryptedPrivateKeyInfo;
begin
  LParams := TPbeS2Parameters.Create(AKdf, AScheme);
  LEncrypted := TEncryptedPrivateKeyInfo.Create(
    TAlgorithmIdentifier.Create(TPkcsObjectIdentifiers.IdPbeS2, LParams) as IAlgorithmIdentifier,
    DecodeHex('00112233445566778899aabbccddeeff'));
  try
    TPrivateKeyInfoFactory.CreatePrivateKeyInfo(StringToCharArray('password'), LEncrypted);
    Fail('expected EArgumentCryptoLibException');
  except
    on E: EArgumentCryptoLibException do
      ;
  end;
end;

procedure TTestMalformedInput.TestPublicKeyFactoryX942DhWithoutParameters;
begin
  CheckPublicKeyWithoutParameters(TX9ObjectIdentifiers.DHPublicNumber);
end;

procedure TTestMalformedInput.TestPublicKeyFactoryPkcsDhWithoutParameters;
begin
  CheckPublicKeyWithoutParameters(TPkcsObjectIdentifiers.DhKeyAgreement);
end;

procedure TTestMalformedInput.TestPublicKeyFactoryEcWithoutParameters;
begin
  CheckPublicKeyWithoutParameters(TX9ObjectIdentifiers.IdECPublicKey);
end;

procedure TTestMalformedInput.TestPrivateKeyFactoryEcWithoutParameters;
begin
  CheckPrivateKeyWithoutParameters(TX9ObjectIdentifiers.IdECPublicKey,
    TDerSequence.Create([TDerInteger.ValueOf(1),
    TDerOctetString.FromContents(DecodeHex('0102030405'))]) as IAsn1Sequence);
end;

procedure TTestMalformedInput.TestPrivateKeyFactoryDhWithoutParameters;
begin
  CheckPrivateKeyWithoutParameters(TPkcsObjectIdentifiers.DhKeyAgreement,
    TDerInteger.ValueOf(5));
end;

procedure TTestMalformedInput.TestEncryptedKeyWithoutEncryptionSchemeParameters;
begin
  CheckEncryptedKeyRejected(
    TKeyDerivationFunc.Create(TPkcsObjectIdentifiers.IdPbkdf2,
    TPbkdf2Params.Create(DecodeHex('0102030405060708'), 1000) as IPbkdf2Params)
    as IKeyDerivationFunc,
    TEncryptionScheme.Create(TNistObjectIdentifiers.IdAes256Cbc) as IEncryptionScheme);
end;

procedure TTestMalformedInput.TestEncryptedKeyWithoutKdfParameters;
begin
  CheckEncryptedKeyRejected(
    TKeyDerivationFunc.Create(TPkcsObjectIdentifiers.IdPbkdf2, nil) as IKeyDerivationFunc,
    TEncryptionScheme.Create(TNistObjectIdentifiers.IdAes256Cbc,
    TDerOctetString.FromContents(DecodeHex('000102030405060708090a0b0c0d0e0f')))
    as IEncryptionScheme);
end;

procedure TTestMalformedInput.TestPkcs12ConvertToDefiniteLengthSingleArgEmptyPfx;
begin
  try
    TPkcs12Utilities.ConvertToDefiniteLength(nil);
    Fail('expected EAsn1ParsingCryptoLibException');
  except
    on E: EAsn1ParsingCryptoLibException do
      ;
  end;
end;

procedure TTestMalformedInput.TestDsaDecodeEmptyEncoding;
begin
  try
    TStandardDsaEncoding.Instance.Decode(TBigInteger.One, nil);
    Fail('expected EArgumentCryptoLibException');
  except
    on E: EArgumentCryptoLibException do
      ;
  end;
end;

procedure TTestMalformedInput.TestDsaDecodeNonSequenceEncoding;
begin
  try
    TStandardDsaEncoding.Instance.Decode(TBigInteger.One,
      TDerInteger.ValueOf(1).GetEncoded());
    Fail('expected EArgumentCryptoLibException');
  except
    on E: EArgumentCryptoLibException do
      ;
  end;
end;

procedure TTestMalformedInput.TestKeyUsageSingleByte;
var
  LUsage: TCryptoLibBooleanArray;
  LI: Int32;
begin
  LUsage := GenerateCertificate('2.5.29.15', DecodeHex('03020780')).GetKeyUsage();

  CheckEquals(9, System.Length(LUsage), 'key usage length');
  CheckTrue(LUsage[0], 'digitalSignature');
  for LI := 1 to System.High(LUsage) do
    CheckFalse(LUsage[LI], 'unset bit ' + IntToStr(LI));
end;

procedure TTestMalformedInput.TestKeyUsageEmptyBitString;
var
  LUsage: TCryptoLibBooleanArray;
  LI: Int32;
begin
  LUsage := GenerateCertificate('2.5.29.15', DecodeHex('030100')).GetKeyUsage();

  CheckEquals(9, System.Length(LUsage), 'key usage length');
  for LI := 0 to System.High(LUsage) do
    CheckFalse(LUsage[LI], 'unset bit ' + IntToStr(LI));
end;

procedure TTestMalformedInput.TestPublicKeyFactoryEmptyRsaKey;
var
  LKeyInfo: ISubjectPublicKeyInfo;
begin
  LKeyInfo := TSubjectPublicKeyInfo.Create(RsaAlgorithm,
    TDerBitString.CreateEmpty() as IDerBitString);
  try
    TPublicKeyFactory.CreateKey(LKeyInfo);
    Fail('expected EArgumentCryptoLibException');
  except
    on E: EArgumentCryptoLibException do
      ;
  end;
end;

procedure TTestMalformedInput.TestPublicKeyFactoryEmptyDsaKey;
var
  LKeyInfo: ISubjectPublicKeyInfo;
begin
  LKeyInfo := TSubjectPublicKeyInfo.Create(DsaAlgorithm,
    TDerBitString.CreateEmpty() as IDerBitString);
  try
    TPublicKeyFactory.CreateKey(LKeyInfo);
    Fail('expected EArgumentCryptoLibException');
  except
    on E: EArgumentCryptoLibException do
      ;
  end;
end;

procedure TTestMalformedInput.TestPublicKeyFactoryEmptyX942DhKey;
var
  LParams: IDomainParameters;
  LKeyInfo: ISubjectPublicKeyInfo;
begin
  LParams := TDomainParameters.Create(TDerInteger.ValueOf(23) as IDerInteger,
    TDerInteger.ValueOf(5) as IDerInteger, TDerInteger.ValueOf(11) as IDerInteger,
    nil, nil);
  LKeyInfo := TSubjectPublicKeyInfo.Create(
    TAlgorithmIdentifier.Create(TX9ObjectIdentifiers.DHPublicNumber, LParams)
    as IAlgorithmIdentifier,
    TDerBitString.CreateEmpty() as IDerBitString);
  try
    TPublicKeyFactory.CreateKey(LKeyInfo);
    Fail('expected EArgumentCryptoLibException');
  except
    on E: EArgumentCryptoLibException do
      ;
  end;
end;

procedure TTestMalformedInput.TestPublicKeyFactoryEmptyPkcsDhKey;
var
  LParams: IDHParameter;
  LKeyInfo: ISubjectPublicKeyInfo;
begin
  LParams := TDHParameter.Create(TBigInteger.ValueOf(23), TBigInteger.ValueOf(5), 0);
  LKeyInfo := TSubjectPublicKeyInfo.Create(
    TAlgorithmIdentifier.Create(TPkcsObjectIdentifiers.DhKeyAgreement, LParams)
    as IAlgorithmIdentifier,
    TDerBitString.CreateEmpty() as IDerBitString);
  try
    TPublicKeyFactory.CreateKey(LKeyInfo);
    Fail('expected EArgumentCryptoLibException');
  except
    on E: EArgumentCryptoLibException do
      ;
  end;
end;

procedure TTestMalformedInput.TestPrivateKeyFactoryEmptyPrivateKey;
var
  LKeyInfo: IPrivateKeyInfo;
begin
  LKeyInfo := TPrivateKeyInfo.Create(TDerSequence.Create([TDerInteger.Zero, RsaAlgorithm,
    TDerOctetString.FromContents(nil)]) as IAsn1Sequence);
  try
    TPrivateKeyFactory.CreateKey(LKeyInfo);
    Fail('expected EArgumentCryptoLibException');
  except
    on E: EArgumentCryptoLibException do
      ;
  end;
end;

procedure TTestMalformedInput.TestPkcs12StoreLoadEmptyAuthSafe;
var
  LBuilder: IPkcs12StoreBuilder;
  LStore: IPkcs12Store;
  LStream: TBytesStream;
begin
  LBuilder := TPkcs12StoreBuilder.Create;
  LStore := LBuilder.Build;
  LStream := TBytesStream.Create(EmptyAuthSafePfx());
  try
    try
      LStore.Load(LStream, nil);
      Fail('expected EIOCryptoLibException');
    except
      on E: EIOCryptoLibException do
        ;
    end;
  finally
    LStream.Free;
  end;
end;

procedure TTestMalformedInput.TestPkcs12ConvertToDefiniteLengthEmptyAuthSafe;
begin
  try
    TPkcs12Utilities.ConvertToDefiniteLength(EmptyAuthSafePfx(), nil);
    Fail('expected EAsn1ParsingCryptoLibException');
  except
    on E: EAsn1ParsingCryptoLibException do
      ;
  end;
end;

procedure TTestMalformedInput.TestPkcs12ConvertToDefiniteLengthEmptyPfx;
begin
  try
    TPkcs12Utilities.ConvertToDefiniteLength(nil, nil);
    Fail('expected EAsn1ParsingCryptoLibException');
  except
    on E: EAsn1ParsingCryptoLibException do
      ;
  end;
end;

procedure TTestMalformedInput.TestSelectorEmptyPrivateKeyUsagePeriod;
var
  LSelector: IX509CertStoreSelector;
begin
  LSelector := TX509CertStoreSelector.Create();
  LSelector.PrivateKeyValid := TNullable<TDateTime>.Some(Now.ToUniversalTime());

  CheckFalse(LSelector.Match(GenerateCertificate('2.5.29.16', nil)),
    'empty PrivateKeyUsagePeriod value must not match');
end;

procedure TTestMalformedInput.TestOcspReqEmptyEncoding;
var
  LStream: TMemoryStream;
  LReq: IOcspReq;
begin
  try
    LReq := TOcspReq.Create(TBytes(nil));
    Fail('expected EIOCryptoLibException');
  except
    on E: EIOCryptoLibException do
      ;
  end;

  LStream := TMemoryStream.Create;
  try
    try
      LReq := TOcspReq.Create(LStream);
      Fail('expected EIOCryptoLibException');
    except
      on E: EIOCryptoLibException do
        ;
    end;
  finally
    LStream.Free;
  end;
end;

procedure TTestMalformedInput.TestOcspRespEmptyEncoding;
var
  LStream: TMemoryStream;
  LResp: IOcspResp;
begin
  try
    LResp := TOcspResp.Create(TBytes(nil));
    Fail('expected EIOCryptoLibException');
  except
    on E: EIOCryptoLibException do
      ;
  end;

  LStream := TMemoryStream.Create;
  try
    try
      LResp := TOcspResp.Create(LStream);
      Fail('expected EIOCryptoLibException');
    except
      on E: EIOCryptoLibException do
        ;
    end;
  finally
    LStream.Free;
  end;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestMalformedInput);
{$ELSE}
  RegisterTest(TTestMalformedInput.Suite);
{$ENDIF FPC}

end.
