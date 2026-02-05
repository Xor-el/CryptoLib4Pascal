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

unit X509CertGenTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  DateUtils,
  Generics.Collections,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpBigInteger,
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpIX509Certificate,
  ClpX509CertificateParser,
  ClpIX509CertificateParser,
  ClpX509Generators,
  ClpIX509Generators,
  ClpAsn1SignatureFactory,
  ClpISignatureFactory,
  ClpRsaKeyParameters,
  ClpIRsaKeyParameters,
  ClpRsaPrivateCrtKeyParameters,
  ClpIRsaPrivateCrtKeyParameters,
  ClpDsaParameters,
  ClpIDsaParameters,
  ClpDsaPrivateKeyParameters,
  ClpIDsaPrivateKeyParameters,
  ClpDsaPublicKeyParameters,
  ClpIDsaPublicKeyParameters,
  ClpIECDomainParameters,
  ClpIECPublicKeyParameters,
  ClpIECPrivateKeyParameters,
  ClpIX9ECAsn1Objects,
  ClpRsaDigestSigner,
  ClpIRsaDigestSigner,
  ClpDigestUtilities,
  ClpIAsn1Objects,
  ClpCryptoLibTypes,
  ClpAsn1Comparers,
  CryptoLibTestBase;

type

  TX509CertGenTest = class(TCryptoLibAlgorithmTestCase)
  strict private
  var
    FRsaPublic: IRsaKeyParameters;
    FRsaPrivate: IRsaPrivateCrtKeyParameters;
    FDsaPara: IDsaParameters;
    FDsaPriv: IDsaPrivateKeyParameters;
    FDsaPub: IDsaPublicKeyParameters;
    FEcDomain: IECDomainParameters;
    FEcPub: IECPublicKeyParameters;
    FEcPriv: IECPrivateKeyParameters;

    procedure SetUpKeys;
    function CreateX509Name: IX509Name;

  protected
    procedure SetUp; override;
    procedure TestCreationECDSA; // Enable when we implement prime239v1 curve in TECNamedCurveTable
  published
    procedure TestRsaDigestSigner;
    procedure TestCreationRSA;
    procedure TestCreationDSA;
    procedure TestCertLoading;

  end;

implementation

{ TX509CertGenTest }

procedure TX509CertGenTest.SetUpKeys;
var
  LRsaPubMod, LRsaPubExp, LRsaPrivMod, LRsaPrivExp: TBigInteger;
  LRsaPrivP, LRsaPrivQ, LRsaPrivDP, LRsaPrivDQ, LRsaPrivQinv: TBigInteger;
  LDSAParaG, LDSAParaP, LDSAParaQ, LDSAPublicY, LDsaPrivateX: TBigInteger;
  LX9: IX9ECParameters;
  LECParraGX, LECParraGY, LECParraH, LECParraN: TBigInteger;
  LECPubQX, LECPubQY, LECPrivD: TBigInteger;
begin
  // RSA keys
  LRsaPubMod := TBigInteger.Create(1, DecodeBase64(
    'AIASoe2PQb1IP7bTyC9usjHP7FvnUMVpKW49iuFtrw/dMpYlsMMoIU2jupfifDpdFxIktSB4P+6Ymg5WjvHKTIrvQ7SR4zV4jaPTu56Ys0pZ9EDA6gb3HLjtU+8Bb1mfWM+yjKxcPDuFjwEtjGlPHg1Vq+CA9HNcMSKNn2+tW6qt'));
  LRsaPubExp := TBigInteger.Create(1, DecodeBase64('EQ=='));

  LRsaPrivMod := TBigInteger.Create(1, DecodeBase64(
    'AIASoe2PQb1IP7bTyC9usjHP7FvnUMVpKW49iuFtrw/dMpYlsMMoIU2jupfifDpdFxIktSB4P+6Ymg5WjvHKTIrvQ7SR4zV4jaPTu56Ys0pZ9EDA6gb3HLjtU+8Bb1mfWM+yjKxcPDuFjwEtjGlPHg1Vq+CA9HNcMSKNn2+tW6qt'));
  LRsaPrivExp := TBigInteger.Create(1, DecodeBase64(
    'DxFAOhDajr00rBjqX+7nyZ/9sHWRCCp9WEN5wCsFiWVRPtdB+NeLcou7mWXwf1Y+8xNgmmh//fPV45G2dsyBeZbXeJwB7bzx9NMEAfedchyOwjR8PYdjK3NpTLKtZlEJ6Jkh4QihrXpZMO4fKZWUm9bid3+lmiq43FwW+Hof8/E='));

  LRsaPrivP := TBigInteger.Create(1, DecodeBase64(
    'AJ9StyTVW+AL/1s7RBtFwZGFBgd3zctBqzzwKPda6LbtIFDznmwDCqAlIQH9X14X7UPLokCDhuAa76OnDXb1OiE='));
  LRsaPrivQ := TBigInteger.Create(1, DecodeBase64(
    'AM3JfD79dNJ5A3beScSzPtWxx/tSLi0QHFtkuhtSizeXdkv5FSba7lVzwEOGKHmW829bRoNxThDy4ds1IihW1w0='));
  LRsaPrivDP := TBigInteger.Create(1, DecodeBase64(
    'JXzfzG5v+HtLJIZqYMUefJfFLu8DPuJGaLD6lI3cZ0babWZ/oPGoJa5iHpX4Ul/7l3s1PFsuy1GhzCdOdlfRcQ=='));
  LRsaPrivDQ := TBigInteger.Create(1, DecodeBase64(
    'YNdJhw3cn0gBoVmMIFRZzflPDNthBiWy/dUMSRfJCxoZjSnr1gysZHK01HteV1YYNGcwPdr3j4FbOfri5c6DUQ=='));
  LRsaPrivQinv := TBigInteger.Create(1, DecodeBase64(
    'Lt0g7wrsNsQxuDdB8q/rH8fSFeBXMGLtCIqfOec1j7FEIuYA/ACiRDgXkHa0WgN7nLXSjHoy630wC5Toq8vvUg=='));

  FRsaPublic := TRsaKeyParameters.Create(False, LRsaPubMod, LRsaPubExp);
  FRsaPrivate := TRsaPrivateCrtKeyParameters.Create(LRsaPrivMod, LRsaPubExp,
    LRsaPrivExp, LRsaPrivP, LRsaPrivQ, LRsaPrivDP, LRsaPrivDQ, LRsaPrivQinv);

  // DSA parameters
  LDSAParaG := TBigInteger.Create(1, DecodeBase64(
    'AL0fxOTq10OHFbCf8YldyGembqEu08EDVzxyLL29Zn/t4It661YNol1rnhPIs+cirw+yf9zeCe+KL1IbZ/qIMZM='));
  LDSAParaP := TBigInteger.Create(1, DecodeBase64(
    'AM2b/UeQA+ovv3dL05wlDHEKJ+qhnJBsRT5OB9WuyRC830G79y0R8wuq8jyIYWCYcTn1TeqVPWqiTv6oAoiEeOs='));
  LDSAParaQ := TBigInteger.Create(1, DecodeBase64('AIlJT7mcKL6SUBMmvm24zX1EvjNx'));
  LDSAPublicY := TBigInteger.Create(1, DecodeBase64(
    'TtWy2GuT9yGBWOHi1/EpCDa/bWJCk2+yAdr56rAcqP0eHGkMnA9s9GJD2nGU8sFjNHm55swpn6JQb8q0agrCfw=='));
  LDsaPrivateX := TBigInteger.Create(1, DecodeBase64('MMpBAxNlv7eYfxLTZ2BItJeD31A='));

  FDsaPara := TDsaParameters.Create(LDSAParaP, LDSAParaQ, LDSAParaG);
  FDsaPriv := TDsaPrivateKeyParameters.Create(LDsaPrivateX, FDsaPara);
  FDsaPub := TDsaPublicKeyParameters.Create(LDSAPublicY, FDsaPara);

 (* // EC parameters (prime239v1)
  LX9 := TECNamedCurveTable.GetByName('prime239v1');
  LECParraGX := TBigInteger.Create(1, DecodeBase64('D/qWPNyogWzMM7hkK+35BcPTWFc9Pyf7vTs8uaqv'));
  LECParraGY := TBigInteger.Create(1, DecodeBase64('AhQXGxb1olGRv6s1LPRfuatMF+cx3ZTGgzSE/Q5R'));
  LECParraH := TBigInteger.Create(1, DecodeBase64('AQ=='));
  LECParraN := TBigInteger.Create(1, DecodeBase64('f///////////////f///nl6an12QcfvRUiaIkJ0L'));
  LECPubQX := TBigInteger.Create(1, DecodeBase64('HWWi17Yb+Bm3PYr/DMjLOYNFhyOwX1QY7ZvqqM+l'));
  LECPubQY := TBigInteger.Create(1, DecodeBase64('JrlJfxu3WGhqwtL/55BOs/wsUeiDFsvXcGhB8DGx'));
  LECPrivD := TBigInteger.Create(1, DecodeBase64('GYQmd/NF1B+He1iMkWt3by2Az6Eu07t0ynJ4YCAo'));

  FEcDomain := TECDomainParameters.Create(LX9.Curve,
    LX9.Curve.ValidatePoint(LECParraGX, LECParraGY), LECParraN, LECParraH);
  FEcPub := TECPublicKeyParameters.Create('ECDSA',
    LX9.Curve.ValidatePoint(LECPubQX, LECPubQY), FEcDomain);
  FEcPriv := TECPrivateKeyParameters.Create('ECDSA', LECPrivD, FEcDomain); *)
end;

function TX509CertGenTest.CreateX509Name: IX509Name;
var
  LAttrs: TDictionary<IDerObjectIdentifier, String>;
  LOrd: TList<IDerObjectIdentifier>;
begin
  LAttrs := TDictionary<IDerObjectIdentifier, String>.Create(TAsn1Comparers.OidEqualityComparer);
  LOrd := TList<IDerObjectIdentifier>.Create(TAsn1Comparers.OidComparer);
  try
    LAttrs.Add(TX509Name.C, 'NG');
    LAttrs.Add(TX509Name.O, 'CryptoLib4Pascal');
    LAttrs.Add(TX509Name.L, 'Alausa');
    LAttrs.Add(TX509Name.ST, 'Lagos');
    LAttrs.Add(TX509Name.E, 'feedback-crypto@cryptolib4pascal.org');

    LOrd.Add(TX509Name.C);
    LOrd.Add(TX509Name.O);
    LOrd.Add(TX509Name.L);
    LOrd.Add(TX509Name.ST);
    LOrd.Add(TX509Name.E);

    Result := TX509Name.Create(LOrd, LAttrs);
  finally
    LAttrs.Free;
    LOrd.Free;
  end;
end;

procedure TX509CertGenTest.SetUp;
begin
  inherited SetUp;
  if FRsaPublic = nil then
    SetUpKeys;
end;

procedure TX509CertGenTest.TestRsaDigestSigner;
var
  LMsg, LSig: TCryptoLibByteArray;
  LSigner: IRsaDigestSigner;
begin
  LMsg := TCryptoLibByteArray.Create(1, 6, 3, 32, 7, 43, 2, 5, 7, 78, 4, 23);

  LSigner := TRsaDigestSigner.Create(TDigestUtilities.GetDigest('SHA-1'));
  LSigner.Init(True, FRsaPrivate);
  LSigner.BlockUpdate(LMsg, 0, System.Length(LMsg));
  LSig := LSigner.GenerateSignature();

  LSigner.Init(False, FRsaPublic);
  LSigner.BlockUpdate(LMsg, 0, System.Length(LMsg));
  CheckTrue(LSigner.VerifySignature(LSig), 'RSA IDigest Signer failed.');
end;

procedure TX509CertGenTest.TestCreationRSA;
var
  LCertGen: IX509V3CertificateGenerator;
  LName: IX509Name;
  LCert: IX509Certificate;
  LSigner: ISignatureFactory;
  LUtc: TDateTime;
begin
  LCertGen := TX509V3CertificateGenerator.Create;
  LName := CreateX509Name;
  LUtc := TTimeZone.Local.ToUniversalTime(Now);

  LCertGen.SetSerialNumber(TBigInteger.One);
  LCertGen.SetIssuerDN(LName);
  LCertGen.SetNotBeforeUtc(IncDay(LUtc, -1));
  LCertGen.SetNotAfterUtc(IncDay(LUtc, 1));
  LCertGen.SetSubjectDN(LName);
  LCertGen.SetPublicKey(FRsaPublic);

  LSigner := TAsn1SignatureFactory.Create('MD5WithRSAEncryption', FRsaPrivate, nil);
  LCert := LCertGen.Generate(LSigner);

  LCert.CheckValidity();
  LCert.Verify(FRsaPublic);
end;

procedure TX509CertGenTest.TestCreationDSA;
var
  LCertGen: IX509V3CertificateGenerator;
  LName: IX509Name;
  LCert: IX509Certificate;
  LSigner: ISignatureFactory;
  LUtc: TDateTime;
begin
  LCertGen := TX509V3CertificateGenerator.Create;
  LName := CreateX509Name;
  LUtc := TTimeZone.Local.ToUniversalTime(Now);

  LCertGen.SetSerialNumber(TBigInteger.One);
  LCertGen.SetIssuerDN(LName);
  LCertGen.SetNotBeforeUtc(IncDay(LUtc, -1));
  LCertGen.SetNotAfterUtc(IncDay(LUtc, 1));
  LCertGen.SetSubjectDN(LName);
  LCertGen.SetPublicKey(FDsaPub);

  LSigner := TAsn1SignatureFactory.Create('SHA1WITHDSA', FDsaPriv, nil);
  LCert := LCertGen.Generate(LSigner);

  LCert.CheckValidity();
  LCert.Verify(FDsaPub);
end;

procedure TX509CertGenTest.TestCreationECDSA;
var
  LCertGen: IX509V3CertificateGenerator;
  LName: IX509Name;
  LCert: IX509Certificate;
  LSigner: ISignatureFactory;
  LExtOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
  LUtc: TDateTime;
begin
  LCertGen := TX509V3CertificateGenerator.Create;
  LName := CreateX509Name;
  LUtc := TTimeZone.Local.ToUniversalTime(Now);

  LCertGen.SetSerialNumber(TBigInteger.One);
  LCertGen.SetIssuerDN(LName);
  LCertGen.SetNotBeforeUtc(IncDay(LUtc, -1));
  LCertGen.SetNotAfterUtc(IncDay(LUtc, 1));
  LCertGen.SetSubjectDN(LName);
  LCertGen.SetPublicKey(FEcPub);

  LCertGen.AddExtension(TX509Extensions.BasicConstraints, True, TBasicConstraints.Create(False) as IBasicConstraints);

  LSigner := TAsn1SignatureFactory.Create('SHA1WITHECDSA', FEcPriv, nil);
  LCert := LCertGen.Generate(LSigner);

  LCert.CheckValidity();
  LCert.Verify(FEcPub);

  LExtOids := LCert.CertificateStructure.Extensions.GetCriticalExtensionOids();
  if System.Length(LExtOids) <> 1 then
    Fail('wrong number of oids');
end;

procedure TX509CertGenTest.TestCertLoading;
var
  LParser: IX509CertificateParser;
  LCertBytes: TCryptoLibByteArray;
  LCert: IX509Certificate;
begin
  LParser := TX509CertificateParser.Create;

  // cert1 - server.crt
  LCertBytes := DecodeBase64(
    'MIIDXjCCAsegAwIBAgIBBzANBgkqhkiG9w0BAQQFADCBtzELMAkGA1UEBhMCQVUx' +
    'ETAPBgNVBAgTCFZpY3RvcmlhMRgwFgYDVQQHEw9Tb3V0aCBNZWxib3VybmUxGjAY' +
    'BgNVBAoTEUNvbm5lY3QgNCBQdHkgTHRkMR4wHAYDVQQLExVDZXJ0aWZpY2F0ZSBB' +
    'dXRob3JpdHkxFTATBgNVBAMTDENvbm5lY3QgNCBDQTEoMCYGCSqGSIb3DQEJARYZ' +
    'd2VibWFzdGVyQGNvbm5lY3Q0LmNvbS5hdTAeFw0wMDA2MDIwNzU2MjFaFw0wMTA2' +
    'MDIwNzU2MjFaMIG4MQswCQYDVQQGEwJBVTERMA8GA1UECBMIVmljdG9yaWExGDAW' +
    'BgNVBAcTD1NvdXRoIE1lbGJvdXJuZTEaMBgGA1UEChMRQ29ubmVjdCA0IFB0eSBM' +
    'dGQxFzAVBgNVBAsTDldlYnNlcnZlciBUZWFtMR0wGwYDVQQDExR3d3cyLmNvbm5l' +
    'Y3Q0LmNvbS5hdTEoMCYGCSqGSIb3DQEJARYZd2VibWFzdGVyQGNvbm5lY3Q0LmNv' +
    'bS5hdTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEArvDxclKAhyv7Q/Wmr2re' +
    'Gw4XL9Cnh9e+6VgWy2AWNy/MVeXdlxzd7QAuc1eOWQkGQEiLPy5XQtTY+sBUJ3AO' +
    'Rvd2fEVJIcjf29ey7bYua9J/vz5MG2KYo9/WCHIwqD9mmG9g0xLcfwq/s8ZJBswE' +
    '7sb85VU+h94PTvsWOsWuKaECAwEAAaN3MHUwJAYDVR0RBB0wG4EZd2VibWFzdGVy' +
    'QGNvbm5lY3Q0LmNvbS5hdTA6BglghkgBhvhCAQ0ELRYrbW9kX3NzbCBnZW5lcmF0' +
    'ZWQgY3VzdG9tIHNlcnZlciBjZXJ0aWZpY2F0ZTARBglghkgBhvhCAQEEBAMCBkAw' +
    'DQYJKoZIhvcNAQEEBQADgYEAotccfKpwSsIxM1Hae8DR7M/Rw8dg/RqOWx45HNVL' +
    'iBS4/3N/TO195yeQKbfmzbAA2jbPVvIvGgTxPgO1MP4ZgvgRhasaa0qCJCkWvpM4' +
    'yQf33vOiYQbpv4rTwzU8AmRlBG45WdjyNIigGV+oRc61aKCTnLq7zB8N3z1TF/bF' +
    '5/8=');
  LCert := LParser.ReadCertificate(LCertBytes);
  Check(LCert <> nil, 'Reading first test certificate.');

  // cert2 - ca.crt
  LCertBytes := DecodeBase64(
    'MIIDbDCCAtWgAwIBAgIBADANBgkqhkiG9w0BAQQFADCBtzELMAkGA1UEBhMCQVUx' +
    'ETAPBgNVBAgTCFZpY3RvcmlhMRgwFgYDVQQHEw9Tb3V0aCBNZWxib3VybmUxGjAY' +
    'BgNVBAoTEUNvbm5lY3QgNCBQdHkgTHRkMR4wHAYDVQQLExVDZXJ0aWZpY2F0ZSBB' +
    'dXRob3JpdHkxFTATBgNVBAMTDENvbm5lY3QgNCBDQTEoMCYGCSqGSIb3DQEJARYZ' +
    'd2VibWFzdGVyQGNvbm5lY3Q0LmNvbS5hdTAeFw0wMDA2MDIwNzU1MzNaFw0wMTA2' +
    'MDIwNzU1MzNaMIG3MQswCQYDVQQGEwJBVTERMA8GA1UECBMIVmljdG9yaWExGDAW' +
    'BgNVBAcTD1NvdXRoIE1lbGJvdXJuZTEaMBgGA1UEChMRQ29ubmVjdCA0IFB0eSBM' +
    'dGQxHjAcBgNVBAsTFUNlcnRpZmljYXRlIEF1dGhvcml0eTEVMBMGA1UEAxMMQ29u' +
    'bmVjdCA0IENBMSgwJgYJKoZIhvcNAQkBFhl3ZWJtYXN0ZXJAY29ubmVjdDQuY29t' +
    'LmF1MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDgs5ptNG6Qv1ZpCDuUNGmv' +
    'rhjqMDPd3ri8JzZNRiiFlBA4e6/ReaO1U8ASewDeQMH6i9R6degFdQRLngbuJP0s' +
    'xcEE+SksEWNvygfzLwV9J/q+TQDyJYK52utb++lS0b48A1KPLwEsyL6kOAgelbur' +
    'ukwxowprKUIV7Knf1ajetQIDAQABo4GFMIGCMCQGA1UdEQQdMBuBGXdlYm1hc3Rl' +
    'ckBjb25uZWN0NC5jb20uYXUwDwYDVR0TBAgwBgEB/wIBADA2BglghkgBhvhCAQ0E' +
    'KRYnbW9kX3NzbCBnZW5lcmF0ZWQgY3VzdG9tIENBIGNlcnRpZmljYXRlMBEGCWCG' +
    'SAGG+EIBAQQEAwICBDANBgkqhkiG9w0BAQQFAAOBgQCsGvfdghH8pPhlwm1r3pQk' +
    'msnLAVIBb01EhbXm2861iXZfWqGQjrGAaA0ZpXNk9oo110yxoqEoSJSzniZa7Xtz' +
    'soTwNUpE0SLHvWf/SlKdFWlzXA+vOZbzEv4UmjeelekTm7lc01EEa5QRVzOxHFtQ' +
    'DhkaJ8VqOMajkQFma2r9iA==');
  LCert := LParser.ReadCertificate(LCertBytes);
  Check(LCert <> nil, 'Reading second test certificate.');

  // cert3 - testx509.pem
  LCertBytes := DecodeBase64(
    'MIIBWzCCAQYCARgwDQYJKoZIhvcNAQEEBQAwODELMAkGA1UEBhMCQVUxDDAKBgNV' +
    'BAgTA1FMRDEbMBkGA1UEAxMSU1NMZWF5L3JzYSB0ZXN0IENBMB4XDTk1MDYxOTIz' +
    'MzMxMloXDTk1MDcxNzIzMzMxMlowOjELMAkGA1UEBhMCQVUxDDAKBgNVBAgTA1FM' +
    'RDEdMBsGA1UEAxMUU1NMZWF5L3JzYSB0ZXN0IGNlcnQwXDANBgkqhkiG9w0BAQEF' +
    'AANLADBIAkEAqtt6qS5GTxVxGZYWa0/4u+IwHf7p2LNZbcPBp9/OfIcYAXBQn8hO' +
    '/Re1uwLKXdCjIoaGs4DLdG88rkzfyK5dPQIDAQABMAwGCCqGSIb3DQIFBQADQQAE' +
    'Wc7EcF8po2/ZO6kNCwK/ICH6DobgLekA5lSLr5EvuioZniZp5lFzAw4+YzPQ7XKJ' +
    'zl9HYIMxATFyqSiD9jsx');
  LCert := LParser.ReadCertificate(LCertBytes);
  Check(LCert <> nil, 'Reading third test certificate. (X509.pem)');

  // cert4 - v3-cert1.pem
  LCertBytes := DecodeBase64(
    'MIICjTCCAfigAwIBAgIEMaYgRzALBgkqhkiG9w0BAQQwRTELMAkGA1UEBhMCVVMx' +
    'NjA0BgNVBAoTLU5hdGlvbmFsIEFlcm9uYXV0aWNzIGFuZCBTcGFjZSBBZG1pbmlz' +
    'dHJhdGlvbjAmFxE5NjA1MjgxMzQ5MDUrMDgwMBcROTgwNTI4MTM0OTA1KzA4MDAw' +
    'ZzELMAkGA1UEBhMCVVMxNjA0BgNVBAoTLU5hdGlvbmFsIEFlcm9uYXV0aWNzIGFu' +
    'ZCBTcGFjZSBBZG1pbmlzdHJhdGlvbjEgMAkGA1UEBRMCMTYwEwYDVQQDEwxTdGV2' +
    'ZSBTY2hvY2gwWDALBgkqhkiG9w0BAQEDSQAwRgJBALrAwyYdgxmzNP/ts0Uyf6Bp' +
    'miJYktU/w4NG67ULaN4B5CnEz7k57s9o3YY3LecETgQ5iQHmkwlYDTL2fTgVfw0C' +
    'AQOjgaswgagwZAYDVR0ZAQH/BFowWDBWMFQxCzAJBgNVBAYTAlVTMTYwNAYDVQQK' +
    'Ey1OYXRpb25hbCBBZXJvbmF1dGljcyBhbmQgU3BhY2UgQWRtaW5pc3RyYXRpb24x' +
    'DTALBgNVBAMTBENSTDEwFwYDVR0BAQH/BA0wC4AJODMyOTcwODEwMBgGA1UdAgQR' +
    'MA8ECTgzMjk3MDgyM4ACBSAwDQYDVR0KBAYwBAMCBkAwCwYJKoZIhvcNAQEEA4GB' +
    'AH2y1VCEw/A4zaXzSYZJTTUi3uawbbFiS2yxHvgf28+8Js0OHXk1H1w2d6qOHH21' +
    'X82tZXd/0JtG0g1T9usFFBDvYK8O0ebgz/P5ELJnBL2+atObEuJy1ZZ0pBDWINR3' +
    'WkDNLCGiTkCKp0F5EWIrVDwh54NNevkCQRZita+z4IBO');
  LCert := LParser.ReadCertificate(LCertBytes);
  Check(LCert <> nil, 'Reading fourth test certificate. (X509 V3 Pem)');

  // cert5 - v3-cert2.pem
  LCertBytes := DecodeBase64(
    'MIICiTCCAfKgAwIBAgIEMeZfHzANBgkqhkiG9w0BAQQFADB9MQswCQYDVQQGEwJD' +
    'YTEPMA0GA1UEBxMGTmVwZWFuMR4wHAYDVQQLExVObyBMaWFiaWxpdHkgQWNjZXB0' +
    'ZWQxHzAdBgNVBAoTFkZvciBEZW1vIFB1cnBvc2VzIE9ubHkxHDAaBgNVBAMTE0Vu' +
    'dHJ1c3QgRGVtbyBXZWIgQ0EwHhcNOTYwNzEyMTQyMDE1WhcNOTYxMDEyMTQyMDE1' +
    'WjB0MSQwIgYJKoZIhvcNAQkBExVjb29rZUBpc3NsLmF0bC5ocC5jb20xCzAJBgNV' +
    'BAYTAlVTMScwJQYDVQQLEx5IZXdsZXR0IFBhY2thcmQgQ29tcGFueSAoSVNTTCkx' +
    'FjAUBgNVBAMTDVBhdWwgQS4gQ29va2UwXDANBgkqhkiG9w0BAQEFAANLADBIAkEA' +
    '6ceSq9a9AU6g+zBwaL/yVmW1/9EE8s5you1mgjHnj0wAILuoB3L6rm6jmFRy7QZT' +
    'G43IhVZdDua4e+5/n1ZslwIDAQABo2MwYTARBglghkgBhvhCAQEEBAMCB4AwTAYJ' +
    'YIZIAYb4QgENBD8WPVRoaXMgY2VydGlmaWNhdGUgaXMgb25seSBpbnRlbmRlZCBm' +
    'b3IgZGVtb25zdHJhdGlvbiBwdXJwb3Nlcy4wDQYJKoZIhvcNAQEEBQADgYEAi8qc' +
    'F3zfFqy1sV8NhjwLVwOKuSfhR/Z8mbIEUeSTlnH3QbYt3HWZQ+vXI8mvtZoBc2Fz' +
    'lexKeIkAZXCesqGbs6z6nCt16P6tmdfbZF3I3AWzLquPcOXjPf4HgstkyvVBn0Ap' +
    'jAFN418KF/Cx4qyHB4cjdvLrRjjQLnb2+ibo7QU=');
  LCert := LParser.ReadCertificate(LCertBytes);
  Check(LCert <> nil, 'Reading fifth test certificate. (X509 V3 Pem)');

  // cert6 - pem encoded pkcs7
  LCertBytes := DecodeBase64(
    'MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAQAAoIIJbzCCAj0w'
    + 'ggGmAhEAzbp/VvDf5LxU/iKss3KqVTANBgkqhkiG9w0BAQIFADBfMQswCQYDVQQGEwJVUzEXMBUG'
    + 'A1UEChMOVmVyaVNpZ24sIEluYy4xNzA1BgNVBAsTLkNsYXNzIDEgUHVibGljIFByaW1hcnkgQ2Vy'
    + 'dGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNOTYwMTI5MDAwMDAwWhcNMjgwODAxMjM1OTU5WjBfMQsw'
    + 'CQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xNzA1BgNVBAsTLkNsYXNzIDEgUHVi'
    + 'bGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwgZ8wDQYJKoZIhvcNAQEBBQADgY0A'
    + 'MIGJAoGBAOUZv22jVmEtmUhx9mfeuY3rt56GgAqRDvo4Ja9GiILlc6igmyRdDR/MZW4MsNBWhBiH'
    + 'mgabEKFz37RYOWtuwfYV1aioP6oSBo0xrH+wNNePNGeICc0UEeJORVZpH3gCgNrcR5EpuzbJY1zF'
    + '4Ncth3uhtzKwezC6Ki8xqu6jZ9rbAgMBAAEwDQYJKoZIhvcNAQECBQADgYEATD+4i8Zo3+5DMw5d'
    + '6abLB4RNejP/khv0Nq3YlSI2aBFsfELM85wuxAc/FLAPT/+Qknb54rxK6Y/NoIAK98Up8YIiXbix'
    + '3YEjo3slFUYweRb46gVLlH8dwhzI47f0EEA8E8NfH1PoSOSGtHuhNbB7Jbq4046rPzidADQAmPPR'
    + 'cZQwggMuMIICl6ADAgECAhEA0nYujRQMPX2yqCVdr+4NdTANBgkqhkiG9w0BAQIFADBfMQswCQYD'
    + 'VQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xNzA1BgNVBAsTLkNsYXNzIDEgUHVibGlj'
    + 'IFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNOTgwNTEyMDAwMDAwWhcNMDgwNTEy'
    + 'MjM1OTU5WjCBzDEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWduIFRy'
    + 'dXN0IE5ldHdvcmsxRjBEBgNVBAsTPXd3dy52ZXJpc2lnbi5jb20vcmVwb3NpdG9yeS9SUEEgSW5j'
    + 'b3JwLiBCeSBSZWYuLExJQUIuTFREKGMpOTgxSDBGBgNVBAMTP1ZlcmlTaWduIENsYXNzIDEgQ0Eg'
    + 'SW5kaXZpZHVhbCBTdWJzY3JpYmVyLVBlcnNvbmEgTm90IFZhbGlkYXRlZDCBnzANBgkqhkiG9w0B'
    + 'AQEFAAOBjQAwgYkCgYEAu1pEigQWu1X9A3qKLZRPFXg2uA1Ksm+cVL+86HcqnbnwaLuV2TFBcHqB'
    + 'S7lIE1YtxwjhhEKrwKKSq0RcqkLwgg4C6S/7wju7vsknCl22sDZCM7VuVIhPh0q/Gdr5FegPh7Yc'
    + '48zGmo5/aiSS4/zgZbqnsX7vyds3ashKyAkG5JkCAwEAAaN8MHowEQYJYIZIAYb4QgEBBAQDAgEG'
    + 'MEcGA1UdIARAMD4wPAYLYIZIAYb4RQEHAQEwLTArBggrBgEFBQcCARYfd3d3LnZlcmlzaWduLmNv'
    + 'bS9yZXBvc2l0b3J5L1JQQTAPBgNVHRMECDAGAQH/AgEAMAsGA1UdDwQEAwIBBjANBgkqhkiG9w0B'
    + 'AQIFAAOBgQCIuDc73dqUNwCtqp/hgQFxHpJqbS/28Z3TymQ43BuYDAeGW4UVag+5SYWklfEXfWe0'
    + 'fy0s3ZpCnsM+tI6q5QsG3vJWKvozx74Z11NMw73I4xe1pElCY+zCphcPXVgaSTyQXFWjZSAA/Rgg'
    + '5V+CprGoksVYasGNAzzrw80FopCubjCCA/gwggNhoAMCAQICEBbbn/1G1zppD6KsP01bwywwDQYJ'
    + 'KoZIhvcNAQEEBQAwgcwxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2ln'
    + 'biBUcnVzdCBOZXR3b3JrMUYwRAYDVQQLEz13d3cudmVyaXNpZ24uY29tL3JlcG9zaXRvcnkvUlBB'
    + 'IEluY29ycC4gQnkgUmVmLixMSUFCLkxURChjKTk4MUgwRgYDVQQDEz9WZXJpU2lnbiBDbGFzcyAx'
    + 'IENBIEluZGl2aWR1YWwgU3Vic2NyaWJlci1QZXJzb25hIE5vdCBWYWxpZGF0ZWQwHhcNMDAxMDAy'
    + 'MDAwMDAwWhcNMDAxMjAxMjM1OTU5WjCCAQcxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYD'
    + 'VQQLExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMUYwRAYDVQQLEz13d3cudmVyaXNpZ24uY29tL3Jl'
    + 'cG9zaXRvcnkvUlBBIEluY29ycC4gYnkgUmVmLixMSUFCLkxURChjKTk4MR4wHAYDVQQLExVQZXJz'
    + 'b25hIE5vdCBWYWxpZGF0ZWQxJzAlBgNVBAsTHkRpZ2l0YWwgSUQgQ2xhc3MgMSAtIE1pY3Jvc29m'
    + 'dDETMBEGA1UEAxQKRGF2aWQgUnlhbjElMCMGCSqGSIb3DQEJARYWZGF2aWRAbGl2ZW1lZGlhLmNv'
    + 'bS5hdTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAqxBsdeNmSvFqhMNwhQgNzM8mdjX9eSXb'
    + 'DawpHtQHjmh0AKJSa3IwUY0VIsyZHuXWktO/CgaMBVPt6OVf/n0R2sQigMP6Y+PhEiS0vCJBL9aK'
    + '0+pOo2qXrjVBmq+XuCyPTnc+BOSrU26tJsX0P9BYorwySiEGxGanBNATdVL4NdUCAwEAAaOBnDCB'
    + 'mTAJBgNVHRMEAjAAMEQGA1UdIAQ9MDswOQYLYIZIAYb4RQEHAQgwKjAoBggrBgEFBQcCARYcaHR0'
    + 'cHM6Ly93d3cudmVyaXNpZ24uY29tL3JwYTARBglghkgBhvhCAQEEBAMCB4AwMwYDVR0fBCwwKjAo'
    + 'oCagJIYiaHR0cDovL2NybC52ZXJpc2lnbi5jb20vY2xhc3MxLmNybDANBgkqhkiG9w0BAQQFAAOB'
    + 'gQBC8yIIdVGpFTf8/YiL14cMzcmL0nIRm4kGR3U59z7UtcXlfNXXJ8MyaeI/BnXwG/gD5OKYqW6R'
    + 'yca9vZOxf1uoTBl82gInk865ED3Tej6msCqFzZffnSUQvOIeqLxxDlqYRQ6PmW2nAnZeyjcnbI5Y'
    + 'syQSM2fmo7n6qJFP+GbFezGCAkUwggJBAgEBMIHhMIHMMRcwFQYDVQQKEw5WZXJpU2lnbiwgSW5j'
    + 'LjEfMB0GA1UECxMWVmVyaVNpZ24gVHJ1c3QgTmV0d29yazFGMEQGA1UECxM9d3d3LnZlcmlzaWdu'
    + 'LmNvbS9yZXBvc2l0b3J5L1JQQSBJbmNvcnAuIEJ5IFJlZi4sTElBQi5MVEQoYyk5ODFIMEYGA1UE'
    + 'AxM/VmVyaVNpZ24gQ2xhc3MgMSBDQSBJbmRpdmlkdWFsIFN1YnNjcmliZXItUGVyc29uYSBOb3Qg'
    + 'VmFsaWRhdGVkAhAW25/9Rtc6aQ+irD9NW8MsMAkGBSsOAwIaBQCggbowGAYJKoZIhvcNAQkDMQsG'
    + 'CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMDAxMDAyMTczNTE4WjAjBgkqhkiG9w0BCQQxFgQU'
    + 'gZjSaBEY2oxGvlQUIMnxSXhivK8wWwYJKoZIhvcNAQkPMU4wTDAKBggqhkiG9w0DBzAOBggqhkiG'
    + '9w0DAgICAIAwDQYIKoZIhvcNAwICAUAwBwYFKw4DAgcwDQYIKoZIhvcNAwICASgwBwYFKw4DAh0w'
    + 'DQYJKoZIhvcNAQEBBQAEgYAzk+PU91/ZFfoiuKOECjxEh9fDYE2jfDCheBIgh5gdcCo+sS1WQs8O'
    + 'HreQ9Nop/JdJv1DQMBK6weNBBDoP0EEkRm1XCC144XhXZC82jBZohYmi2WvDbbC//YN58kRMYMyy'
    + 'srrfn4Z9I+6kTriGXkrpGk9Q0LSGjmG2BIsqiF0dvwAAAAAAAA==');
  LCert := LParser.ReadCertificate(LCertBytes);
  Check(LCert <> nil, 'Reading sixth test certificate. (Pkcs7)');

  // cert7 - dsaWithSHA1 cert
  LCertBytes := DecodeBase64(
    'MIIEXAYJKoZIhvcNAQcCoIIETTCCBEkCAQExCzAJBgUrDgMCGgUAMAsGCSqG'
    + 'SIb3DQEHAaCCAsMwggK/MIIB4AIBADCBpwYFKw4DAhswgZ0CQQEkJRHP+mN7'
    + 'd8miwTMN55CUSmo3TO8WGCxgY61TX5k+7NU4XPf1TULjw3GobwaJX13kquPh'
    + 'fVXk+gVy46n4Iw3hAhUBSe/QF4BUj+pJOF9ROBM4u+FEWA8CQQD4mSJbrABj'
    + 'TUWrlnAte8pS22Tq4/FPO7jHSqjijUHfXKTrHL1OEqV3SVWcFy5j/cqBgX/z'
    + 'm8Q12PFp/PjOhh+nMA4xDDAKBgNVBAMTA0lEMzAeFw05NzEwMDEwMDAwMDBa'
    + 'Fw0zODAxMDEwMDAwMDBaMA4xDDAKBgNVBAMTA0lEMzCB8DCBpwYFKw4DAhsw'
    + 'gZ0CQQEkJRHP+mN7d8miwTMN55CUSmo3TO8WGCxgY61TX5k+7NU4XPf1TULj'
    + 'w3GobwaJX13kquPhfVXk+gVy46n4Iw3hAhUBSe/QF4BUj+pJOF9ROBM4u+FE'
    + 'WA8CQQD4mSJbrABjTUWrlnAte8pS22Tq4/FPO7jHSqjijUHfXKTrHL1OEqV3'
    + 'SVWcFy5j/cqBgX/zm8Q12PFp/PjOhh+nA0QAAkEAkYkXLYMtGVGWj9OnzjPn'
    + 'sB9sefSRPrVegZJCZbpW+Iv0/1RP1u04pHG9vtRpIQLjzUiWvLMU9EKQTThc'
    + 'eNMmWDCBpwYFKw4DAhswgZ0CQQEkJRHP+mN7d8miwTMN55CUSmo3TO8WGCxg'
    + 'Y61TX5k+7NU4XPf1TULjw3GobwaJX13kquPhfVXk+gVy46n4Iw3hAhUBSe/Q'
    + 'F4BUj+pJOF9ROBM4u+FEWA8CQQD4mSJbrABjTUWrlnAte8pS22Tq4/FPO7jH'
    + 'SqjijUHfXKTrHL1OEqV3SVWcFy5j/cqBgX/zm8Q12PFp/PjOhh+nAy8AMCwC'
    + 'FBY3dBSdeprGcqpr6wr3xbG+6WW+AhRMm/facKJNxkT3iKgJbp7R8Xd3QTGC'
    + 'AWEwggFdAgEBMBMwDjEMMAoGA1UEAxMDSUQzAgEAMAkGBSsOAwIaBQCgXTAY'
    + 'BgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0wMjA1'
    + 'MjQyMzEzMDdaMCMGCSqGSIb3DQEJBDEWBBS4WMsoJhf7CVbZYCFcjoTRzPkJ'
    + 'xjCBpwYFKw4DAhswgZ0CQQEkJRHP+mN7d8miwTMN55CUSmo3TO8WGCxgY61T'
    + 'X5k+7NU4XPf1TULjw3GobwaJX13kquPhfVXk+gVy46n4Iw3hAhUBSe/QF4BU'
    + 'j+pJOF9ROBM4u+FEWA8CQQD4mSJbrABjTUWrlnAte8pS22Tq4/FPO7jHSqji'
    + 'jUHfXKTrHL1OEqV3SVWcFy5j/cqBgX/zm8Q12PFp/PjOhh+nBC8wLQIVALID'
    + 'dt+MHwawrDrwsO1Z6sXBaaJsAhRaKssrpevmLkbygKPV07XiAKBG02Zvb2Jh'
    + 'cg==');
  LCert := LParser.ReadCertificate(LCertBytes);
  Check(LCert <> nil, 'Reading seventh test certificate. (DSAWITHSHA1)');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TX509CertGenTest);
{$ELSE}
  RegisterTest(TX509CertGenTest.Suite);
{$ENDIF FPC}

end.
