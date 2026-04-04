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

unit Pkcs10CertRequestTests;

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
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIX509Extension,
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpGeneratorUtilities,
  ClpSecureRandom,
  ClpKeyGenerationParameters,
  ClpIKeyGenerationParameters,
  ClpRsaParameters,
  ClpIRsaParameters,
  ClpRsaGenerators,
  ClpPkcsAsn1Objects,
  ClpIPkcsAsn1Objects,
  ClpPkcsObjectIdentifiers,
  ClpPkcs10CertificationRequest,
  ClpIPkcs10CertificationRequest,
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  CryptoLibTestBase;

type

  TPkcs10CertRequestTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    const
      EmptyExtensionsReqBase64 =
        'MIICVDCCATwCAQAwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKy8' +
        '4oC/QPFkRBE04LIA5njEulZx/EEh+J2spnThoRwk+oycYEVKp95NSfGTAoNjTwUv' +
        'TdB9c1PCPE1DmgZIVLEVvouB7sZbMbLSI0d//oMO/Wr/CZmvjPGB8DID7RJs0eqO' +
        'gLgSuyBVrwbcSKtxH4NrNDsS5IZXCcE3xzkxMDdz72m9jvIrl2ivi+YmJ7cJo3N+' +
        'DBEqHZW28oytOmVo+8zhxvnHb9w26GJEOxN5zYbiIVW2vU9OfeF9te+Rhnks43Pk' +
        'YDDP2U4hR7q0BYrdkeWdA1ReleYyn/haeAoIVLZMANIOXobiqASKqSusVq9tLD67' +
        '7TAywl5AVq8GOBzlXZUCAwEAAaAPMA0GCSqGSIb3DQEJDjEAMA0GCSqGSIb3DQEB' +
        'CwUAA4IBAQAXck62gJw1deVOLVFAwBNVNXgJarHtDg3pauHTHvN+pSbdOTe1aRzb' +
        'Tt4/govtuuGZsGWlUqiglLpl6qeS7Pe9m+WJwhH5yXnJ3yvy2Lc/XkeVQ0kt8uFg' +
        '30UyrgKng6LDgUGFjDSiFr3dK8S/iYpDu/qpl1bWJPWmfmnIXzZWWvBdUTKlfoD9' +
        '/NLIWINEzHQIBXGy2uLhutYOvDq0WDGOgtdFC8my/QajaJh5lo6mM/PlmcYjK286' +
        'EdGSIxdME7hoW/ljA5355S820QZDkYx1tI/Y/YaY5KVOntwfDQzQiwWZ2PtpTqSK' +
        'KYe2Ujb362yaERCE13DJC4Us9j8OOXcW';

  strict private
    var
      FReq1: TCryptoLibByteArray;
      FReq2: TCryptoLibByteArray;

    procedure SetUpTestData;
    procedure BasicPkcs10Test(const ATestName: String; const AReq: TCryptoLibByteArray);
    procedure BuildPerformRequestPair(out AReq1, AReq2: IPkcs10CertificationRequest);

  protected
    procedure SetUp; override;

  published
    procedure TestBasicCR;
    procedure TestUniversalCR;
    procedure TestEmptyExtRequest;
    procedure TestBrokenRequestWithDuplicateExtension;
    procedure TestPerformRoundTrip;
    procedure TestPerformVerify;
    procedure TestPerformPublicKeyMatch;

  end;

implementation

{ TPkcs10CertRequestTest }

procedure TPkcs10CertRequestTest.SetUpTestData;
begin
  FReq1 := DecodeBase64('MIHoMIGTAgEAMC4xDjAMBgNVBAMTBVRlc3QyMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNF' +
    'MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALlEt31Tzt2MlcOljvacJgzQVhmlMoqAOgqJ9Pgd3Gux' +
    'Z7/WcIlgW4QCB7WZT21O1YoghwBhPDMcNGrHei9kHQkCAwEAAaAAMA0GCSqGSIb3DQEBBQUAA0EA' +
    'NDEI4ecNtJ3uHwGGlitNFq9WxcoZ0djbQJ5hABMotav6gtqlrwKXY2evaIrsNwkJtNdwwH18aQDU' +
    'KCjOuBL38Q==');

  FReq2 := DecodeBase64('MIIB6TCCAVICAQAwgagxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRQwEgYDVQQH' +
    'EwtTYW50YSBDbGFyYTEMMAoGA1UEChMDQUJCMVEwTwYDVQQLHEhQAAAAAAAAAG8AAAAAAAAAdwAA' +
    'AAAAAABlAAAAAAAAAHIAAAAAAAAAIAAAAAAAAABUAAAAAAAAABxIAAAAAAAARAAAAAAAAAAxDTAL' +
    'BgNVBAMTBGJsdWUwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANETRZ+6occCOrFxNhfKIp4C' +
    'mMkxwhBNb7TnnahpbM9O0r4hrBPcfYuL7u9YX/jN0YNUP+/CiT39HhSe/bikaBPDEyNsl988I8vX' +
    'piEdgxYq/+LTgGHbjRsRYCkPtmzwBbuBldNF8bV7pu0v4UScSsExmGqqDlX1TbPU8KkPU1iTAgMB' +
    'AAGgADANBgkqhkiG9w0BAQQFAAOBgQAFbrs9qUwh93CtETk7DeUD5HcdCnxauo1bck44snSV6MZV' +
    'OCIGaYu1501kmhEvAtVVRr6SEHwimfQDDIjnrWwYsEr/DT6tkTZAbfRd3qUu3iKjT0H0vlUZp0hJ' +
    '66mINtBM84uZFBfoXiWY8M3FuAnGmvy6ah/dYtJorTxLKiGkew==');
end;

procedure TPkcs10CertRequestTest.SetUp;
begin
  inherited SetUp;
  SetUpTestData;
end;

procedure TPkcs10CertRequestTest.BasicPkcs10Test(const ATestName: String; const AReq: TCryptoLibByteArray);
var
  LCertReq: ICertificationRequest;
  LBytes: TCryptoLibByteArray;
begin
  try
    LCertReq := TCertificationRequest.GetInstance(AReq);

    LBytes := LCertReq.GetDerEncoded();

    if not AreEqual(LBytes, AReq) then
    begin
      Fail(Format('Pkcs10: %s failed comparison test', [ATestName]));
    end;
  except
    on E: Exception do
    begin
      Fail(Format('Pkcs10: Exception - %s %s', [ATestName, E.Message]));
    end;
  end;
end;

procedure TPkcs10CertRequestTest.TestBasicCR;
begin
  BasicPkcs10Test('Basic CR', FReq1);
end;

procedure TPkcs10CertRequestTest.TestUniversalCR;
begin
  BasicPkcs10Test('Universal CR', FReq2);
end;

procedure TPkcs10CertRequestTest.TestEmptyExtRequest;
var
  LReq: IPkcs10CertificationRequest;
  LEncoded: TCryptoLibByteArray;
begin
  LEncoded := DecodeBase64(EmptyExtensionsReqBase64);
  LReq := TPkcs10CertificationRequest.Create(LEncoded);
  try
    LReq.GetRequestedExtensions();
    Fail('no exception thrown');
  except
    on E: EInvalidOperationCryptoLibException do
      CheckEquals('pkcs_9_at_extensionRequest present but has no value', E.Message, 'Exception message');
    on E: Exception do
      Fail('Expected EInvalidOperationCryptoLibException, got ' + E.ClassName + ': ' + E.Message);
  end;
end;

procedure TPkcs10CertRequestTest.TestBrokenRequestWithDuplicateExtension;
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LOrder: TCryptoLibGenericArray<IDerObjectIdentifier>;
  LValues: TCryptoLibStringArray;
  LSubject: IX509Name;
  LName1, LName2: IGeneralName;
  LGenNames1, LGenNames2: IGeneralNames;
  LExtSeq: IAsn1Sequence;
  LAttrSet: IAsn1Set;
  LAttr: IAttributePkcs;
  LAttrs: IAsn1Set;
  LReq1, LReq2: IPkcs10CertificationRequest;
  LBytes: TCryptoLibByteArray;
  LExtensions: IX509Extensions;
  LExt: IX509Extension;
  LReturnedNames: IGeneralNames;
  LEnc1, LEnc2: TCryptoLibByteArray;
  LRsaPub1, LRsaPub2: IRsaKeyParameters;
  LKeyGenParams: IKeyGenerationParameters;
begin
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('RSA');
  LKeyGenParams := TKeyGenerationParameters.Create(TSecureRandom.MasterRandom, 2048);
  LKpg.Init(LKeyGenParams);
  LKp := LKpg.GenerateKeyPair();

  SetLength(LOrder, 5);
  LOrder[0] := TX509Name.C;
  LOrder[1] := TX509Name.O;
  LOrder[2] := TX509Name.L;
  LOrder[3] := TX509Name.ST;
  LOrder[4] := TX509Name.EmailAddress;
  SetLength(LValues, 5);
  LValues[0] := 'NG';
  LValues[1] := 'CryptoLib4Pascal';
  LValues[2] := 'Alausa';
  LValues[3] := 'Lagos';
  LValues[4] := 'feedback-crypto@cryptolib4pascal.org';
  LSubject := TX509Name.Create(LOrder, LValues);

  LName1 := TGeneralName.Create(TGeneralName.DnsName, 'bc1.local');
  LName2 := TGeneralName.Create(TGeneralName.DnsName, 'bc2.local');

  LGenNames1 := TGeneralNames.Create(LName1);
  LGenNames2 := TGeneralNames.Create(LName2);
  LExtSeq := TDerSequence.FromElements(
    TDerSequence.Create([
      TX509Extensions.SubjectAlternativeName,
      TDerOctetString.Create(LGenNames1.GetEncoded()) as IDerOctetString
    ]) as IDerSequence,
    TDerSequence.Create([
      TX509Extensions.SubjectAlternativeName,
      TDerOctetString.Create(LGenNames2.GetEncoded()) as IDerOctetString
    ]) as IDerSequence
  );
  LAttrSet := TDerSet.FromElement(LExtSeq);
  LAttr := TAttributePkcs.Create(TPkcsObjectIdentifiers.Pkcs9AtExtensionRequest, LAttrSet);
  LAttrs := TDerSet.FromElement(LAttr);

  LReq1 := TPkcs10CertificationRequest.Create(
    'SHA256withRSA', LSubject, LKp.Public, LAttrs, LKp.Private);
  LBytes := LReq1.GetEncoded();
  LReq2 := TPkcs10CertificationRequest.Create(LBytes);

  CheckTrue(LReq2.Verify(), 'SHA256withRSA: Failed Verify check');

  if Supports(LReq2.GetPublicKey(), IRsaKeyParameters, LRsaPub2) and
     Supports(LReq1.GetPublicKey(), IRsaKeyParameters, LRsaPub1) then
    CheckTrue(LRsaPub1.Equals(LRsaPub2), 'RSA: Failed public key check')
  else
    Fail('RSA: Failed to get RSA public keys');

  LExtensions := LReq2.GetRequestedExtensions();
  Check(LExtensions <> nil, 'expected extensions');
  LExt := LExtensions.GetExtension(TX509Extensions.SubjectAlternativeName);
  Check(LExt <> nil, 'expected SubjectAlternativeName extension');
  LReturnedNames := TGeneralNames.GetInstance(LExt.GetParsedValue());
  CheckEquals(2, LReturnedNames.GetCount(), 'expected 2 names');
  LEnc1 := LName1.GetEncoded();
  LEnc2 := LName2.GetEncoded();
  CheckTrue(AreEqual(LReturnedNames.GetNames[0].GetEncoded(), LEnc1), 'expected name 1');
  CheckTrue(AreEqual(LReturnedNames.GetNames[1].GetEncoded(), LEnc2), 'expected name 2');
end;

procedure TPkcs10CertRequestTest.BuildPerformRequestPair(out AReq1, AReq2: IPkcs10CertificationRequest);
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LOrder: TCryptoLibGenericArray<IDerObjectIdentifier>;
  LValues: TCryptoLibStringArray;
  LSubject: IX509Name;
  LBytes: TCryptoLibByteArray;
  LKeyGenParams: IKeyGenerationParameters;
begin
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('RSA');
  LKeyGenParams := TRsaKeyGenerationParameters.Create(
    TBigInteger.ValueOf($10001), TSecureRandom.MasterRandom, 512, 25);
  LKpg.Init(LKeyGenParams);
  LKp := LKpg.GenerateKeyPair();

  SetLength(LOrder, 5);
  LOrder[0] := TX509Name.C;
  LOrder[1] := TX509Name.O;
  LOrder[2] := TX509Name.L;
  LOrder[3] := TX509Name.ST;
  LOrder[4] := TX509Name.EmailAddress;
  SetLength(LValues, 5);
  LValues[0] := 'NG';
  LValues[1] := 'CryptoLib4Pascal';
  LValues[2] := 'Alausa';
  LValues[3] := 'Lagos';
  LValues[4] := 'feedback-crypto@cryptolib4pascal.org';
  LSubject := TX509Name.Create(LOrder, LValues);

  AReq1 := TPkcs10CertificationRequest.Create(
    'SHA1withRSA', LSubject, LKp.Public, nil, LKp.Private);
  LBytes := AReq1.GetEncoded();
  AReq2 := TPkcs10CertificationRequest.Create(LBytes);
end;

procedure TPkcs10CertRequestTest.TestPerformRoundTrip;
var
  LReq1, LReq2: IPkcs10CertificationRequest;
begin
  BuildPerformRequestPair(LReq1, LReq2);
  Check(LReq1 <> nil, 'request before round-trip');
  Check(LReq2 <> nil, 'request after round-trip');
end;

procedure TPkcs10CertRequestTest.TestPerformVerify;
var
  LReq1, LReq2: IPkcs10CertificationRequest;
begin
  BuildPerformRequestPair(LReq1, LReq2);
  CheckTrue(LReq2.Verify(), 'Failed verify check');
end;

procedure TPkcs10CertRequestTest.TestPerformPublicKeyMatch;
var
  LReq1, LReq2: IPkcs10CertificationRequest;
  LRsaPub1, LRsaPub2: IRsaKeyParameters;
begin
  BuildPerformRequestPair(LReq1, LReq2);
  if Supports(LReq2.GetPublicKey(), IRsaKeyParameters, LRsaPub2) and
     Supports(LReq1.GetPublicKey(), IRsaKeyParameters, LRsaPub1) then
    CheckTrue(LRsaPub1.Equals(LRsaPub2), 'Failed public key check')
  else
    Fail('Failed to get RSA public keys for comparison');
end;

initialization

{$IFDEF FPC}
RegisterTest(TPkcs10CertRequestTest);
{$ELSE}
RegisterTest(TPkcs10CertRequestTest.Suite);
{$ENDIF FPC}

end.
