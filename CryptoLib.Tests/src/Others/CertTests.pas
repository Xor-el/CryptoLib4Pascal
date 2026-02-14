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

unit CertTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  DateUtils,
  Classes,
  Rtti,
  Generics.Collections,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpAsn1Core,
  ClpBigInteger,
  ClpIECCommon,
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpIX509Extension,
  ClpIX509Certificate,
  ClpX509CertificateParser,
  ClpIX509CertificateParser,
  ClpX509CrlParser,
  ClpIX509CrlParser,
  ClpIX509Crl,
  ClpX509Generators,
  ClpIX509Generators,
  ClpAsn1SignatureFactory,
  ClpISignatureFactory,
  ClpRsaParameters,
  ClpIRsaParameters,
  ClpDsaParameters,
  ClpIDsaParameters,
  ClpDsaGenerators,
  ClpIDsaGenerators,
  ClpIAsymmetricKeyParameter,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIAsymmetricCipherKeyPair,
  ClpAsymmetricCipherKeyPair,
  ClpAsymmetricKeyParameter,
  ClpSubjectPublicKeyInfoFactory,
  ClpGeneratorUtilities,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpX509ExtensionUtilities,
  ClpIX509CrlEntry,
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpAsn1Objects,
  ClpCryptoLibTypes,
  ClpAsn1Comparers,
  ClpIX509NameBuilder,
  ClpX509NameBuilder,
  ClpCmsObjectIdentifiers,
  ClpCmsAsn1Objects,
  ClpICmsAsn1Objects,
  ClpX509Extension,
  ClpEncoders,
  ClpX9ObjectIdentifiers,
  ClpECNamedCurveTable,
  ClpIX9ECAsn1Objects,
  ClpECParameters,
  ClpIECParameters,
  CryptoLibTestBase;

type

  TDudPublicKey = class(TAsymmetricKeyParameter)
  public
    constructor Create;
  end;

  TCertTest = class(TCryptoLibAlgorithmTestCase)
  strict private
  var
    FRsaPublic: IRsaKeyParameters;
    FRsaPrivate: IRsaPrivateCrtKeyParameters;
    FSecureRandom: ISecureRandom;

    procedure SetUpKeys;
    function CreateX509Name: IX509Name;
    function GenerateLongFixedKeys: IAsymmetricCipherKeyPair;
    procedure CheckCertificate(AId: Int32; const ACertBytes: TCryptoLibByteArray);
    procedure CheckKeyUsage(AId: Int32; const ACertBytes: TCryptoLibByteArray);
    procedure CheckSelfSignedCertificate(AId: Int32; const ACertBytes: TCryptoLibByteArray);
    procedure CheckNameCertificate(AId: Int32; const ACertBytes: TCryptoLibByteArray);
    procedure CheckCrl(AId: Int32; const ACrlBytes: TCryptoLibByteArray);
    procedure CheckCreation1;
    procedure CheckCreation2;
    procedure CheckCreation3;
    procedure CheckCreation5;
    procedure CheckCrlCreation1;
    procedure CheckCrlCreation2;
    procedure CheckCrlCreation3;
    procedure PemTest;
    procedure DoTestForgedSignature;
    procedure DoTestNullDerNullCert;
    procedure PemFileTest;
    procedure PemFileTestWithNl;
    procedure InvalidCrls;
    procedure Pkcs7Test;
    procedure CreatePssCert(const AAlgorithm: string);
    procedure CreateECCert(const AAlgorithm: string; const AAlgOid: IDerObjectIdentifier);

  protected
    procedure SetUp; override;

  published
  procedure TestX509NameBuilderMatchesRegular;
    procedure TestCert1;
    procedure TestCert2;
    procedure TestCert3;
    procedure TestCert4;
    procedure TestCert5;
    procedure TestCert6;
    procedure TestCert7;
    procedure TestKeyUsage;
    procedure TestSelfSignedUncompressedPtEC;
    procedure TestNameCert;
    procedure TestSelfSignedProbSelfSignedCert;
    procedure TestCrl1;
    procedure TestEmptyDNCert;
    procedure TestCreation1;
    procedure TestCreation2;
    procedure TestCreation3;
    procedure TestCreation5;
    procedure TestCrlCreation1;
    procedure TestCrlCreation2;
    procedure TestCrlCreation3;
    procedure TestPem;
    procedure TestDoTestForgedSignature;
    procedure TestDoTestNullDerNullCert;
    procedure TestPemFileTest;
    procedure TestPemFileTestWithNl;
    procedure TestInvalidCrls;
    procedure TestPkcs7Test;
    procedure TestCreatePssCertSha1;
    procedure TestCreatePssCertSha224;
    procedure TestCreatePssCertSha256;
    procedure TestCreatePssCertSha384;
    procedure TestCreateECCertSha1;
    procedure TestCreateECCertSha224;
    procedure TestCreateECCertSha256;
    procedure TestCreateECCertSha384;
    procedure TestCreateECCertSha512;

  end;

const

  CERTIFICATE_1_PEM =
    '-----BEGIN X509 CERTIFICATE-----' + #13 +
    'MIIDXjCCAsegAwIBAgIBBzANBgkqhkiG9w0BAQQFADCBtzELMAkGA1UEBhMCQVUx' + #13 +
    'ETAPBgNVBAgTCFZpY3RvcmlhMRgwFgYDVQQHEw9Tb3V0aCBNZWxib3VybmUxGjAY' + #13 +
    'BgNVBAoTEUNvbm5lY3QgNCBQdHkgTHRkMR4wHAYDVQQLExVDZXJ0aWZpY2F0ZSBB' + #13 +
    'dXRob3JpdHkxFTATBgNVBAMTDENvbm5lY3QgNCBDQTEoMCYGCSqGSIb3DQEJARYZ' + #13 +
    'd2VibWFzdGVyQGNvbm5lY3Q0LmNvbS5hdTAeFw0wMDA2MDIwNzU2MjFaFw0wMTA2' + #13 +
    'MDIwNzU2MjFaMIG4MQswCQYDVQQGEwJBVTERMA8GA1UECBMIVmljdG9yaWExGDAW' + #10 +
    'BgNVBAcTD1NvdXRoIE1lbGJvdXJuZTEaMBgGA1UEChMRQ29ubmVjdCA0IFB0eSBM' + #13 +
    'dGQxFzAVBgNVBAsTDldlYnNlcnZlciBUZWFtMR0wGwYDVQQDExR3d3cyLmNvbm5l' + #13 +
    'Y3Q0LmNvbS5hdTEoMCYGCSqGSIb3DQEJARYZd2VibWFzdGVyQGNvbm5lY3Q0LmNv' + #13 +
    'bS5hdTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEArvDxclKAhyv7Q/Wmr2re' + #13 +
    'Gw4XL9Cnh9e+6VgWy2AWNy/MVeXdlxzd7QAuc1eOWQkGQEiLPy5XQtTY+sBUJ3AO' + #13 +
    'Rvd2fEVJIcjf29ey7bYua9J/vz5MG2KYo9/WCHIwqD9mmG9g0xLcfwq/s8ZJBswE' + #13 +
    '7sb85VU+h94PTvsWOsWuKaECAwEAAaN3MHUwJAYDVR0RBB0wG4EZd2VibWFzdGVy' + #13 +
    'QGNvbm5lY3Q0LmNvbS5hdTA6BglghkgBhvhCAQ0ELRYrbW9kX3NzbCBnZW5lcmF0' + #13 +
    'ZWQgY3VzdG9tIHNlcnZlciBjZXJ0aWZpY2F0ZTARBglghkgBhvhCAQEEBAMCBkAw' + #13 +
    'DQYJKoZIhvcNAQEEBQADgYEAotccfKpwSsIxM1Hae8DR7M/Rw8dg/RqOWx45HNVL' + #13 +
    'iBS4/3N/TO195yeQKbfmzbAA2jbPVvIvGgTxPgO1MP4ZgvgRhasaa0qCJCkWvpM4' + #13 +
    'yQf33vOiYQbpv4rTwzU8AmRlBG45WdjyNIigGV+oRc61aKCTnLq7zB8N3z1TF/bF' + #13 +
    '5/8=' + #13 +
    '-----END X509 CERTIFICATE-----' + #13;

  CERTIFICATE_2_PEM =
    '-----BEGIN CERTIFICATE-----' + #10 +
    'MIIDXjCCAsegAwIBAgIBBzANBgkqhkiG9w0BAQQFADCBtzELMAkGA1UEBhMCQVUx' + #10 +
    'ETAPBgNVBAgTCFZpY3RvcmlhMRgwFgYDVQQHEw9Tb3V0aCBNZWxib3VybmUxGjAY' + #10 +
    'BgNVBAoTEUNvbm5lY3QgNCBQdHkgTHRkMR4wHAYDVQQLExVDZXJ0aWZpY2F0ZSBB' + #10 +
    'dXRob3JpdHkxFTATBgNVBAMTDENvbm5lY3QgNCBDQTEoMCYGCSqGSIb3DQEJARYZ' + #10 +
    'd2VibWFzdGVyQGNvbm5lY3Q0LmNvbS5hdTAeFw0wMDA2MDIwNzU2MjFaFw0wMTA2' + #10 +
    'MDIwNzU2MjFaMIG4MQswCQYDVQQGEwJBVTERMA8GA1UECBMIVmljdG9yaWExGDAW' + #10 +
    'BgNVBAcTD1NvdXRoIE1lbGJvdXJuZTEaMBgGA1UEChMRQ29ubmVjdCA0IFB0eSBM' + #10 +
    'dGQxFzAVBgNVBAsTDldlYnNlcnZlciBUZWFtMR0wGwYDVQQDExR3d3cyLmNvbm5l' + #10 +
    'Y3Q0LmNvbS5hdTEoMCYGCSqGSIb3DQEJARYZd2VibWFzdGVyQGNvbm5lY3Q0LmNv' + #10 +
    'bS5hdTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEArvDxclKAhyv7Q/Wmr2re' + #10 +
    'Gw4XL9Cnh9e+6VgWy2AWNy/MVeXdlxzd7QAuc1eOWQkGQEiLPy5XQtTY+sBUJ3AO' + #10 +
    'Rvd2fEVJIcjf29ey7bYua9J/vz5MG2KYo9/WCHIwqD9mmG9g0xLcfwq/s8ZJBswE' + #10 +
    '7sb85VU+h94PTvsWOsWuKaECAwEAAaN3MHUwJAYDVR0RBB0wG4EZd2VibWFzdGVy' + #10 +
    'QGNvbm5lY3Q0LmNvbS5hdTA6BglghkgBhvhCAQ0ELRYrbW9kX3NzbCBnZW5lcmF0' + #10 +
    'ZWQgY3VzdG9tIHNlcnZlciBjZXJ0aWZpY2F0ZTARBglghkgBhvhCAQEEBAMCBkAw' + #10 +
    'DQYJKoZIhvcNAQEEBQADgYEAotccfKpwSsIxM1Hae8DR7M/Rw8dg/RqOWx45HNVL' + #10 +
    'iBS4/3N/TO195yeQKbfmzbAA2jbPVvIvGgTxPgO1MP4ZgvgRhasaa0qCJCkWvpM4' + #10 +
    'yQf33vOiYQbpv4rTwzU8AmRlBG45WdjyNIigGV+oRc61aKCTnLq7zB8N3z1TF/bF' + #10 +
    '5/8=' + #10 +
    '-----END CERTIFICATE-----' + #10;

  CRL_1_PEM =
    '-----BEGIN X509 CRL-----' + #13#10 +
    'MIICjTCCAfowDQYJKoZIhvcNAQECBQAwXzELMAkGA1UEBhMCVVMxIDAeBgNVBAoT' + #13#10 +
    'F1JTQSBEYXRhIFNlY3VyaXR5LCBJbmMuMS4wLAYDVQQLEyVTZWN1cmUgU2VydmVy' + #13#10 +
    'IENlcnRpZmljYXRpb24gQXV0aG9yaXR5Fw05NTA1MDIwMjEyMjZaFw05NTA2MDEw' + #13#10 +
    'MDAxNDlaMIIBaDAWAgUCQQAABBcNOTUwMjAxMTcyNDI2WjAWAgUCQQAACRcNOTUw' + #13#10 +
    'MjEwMDIxNjM5WjAWAgUCQQAADxcNOTUwMjI0MDAxMjQ5WjAWAgUCQQAADBcNOTUw' + #13#10 +
    'MjI1MDA0NjQ0WjAWAgUCQQAAGxcNOTUwMzEzMTg0MDQ5WjAWAgUCQQAAFhcNOTUw' + #13#10 +
    'MzE1MTkxNjU0WjAWAgUCQQAAGhcNOTUwMzE1MTk0MDQxWjAWAgUCQQAAHxcNOTUw' + #13#10 +
    'MzI0MTk0NDMzWjAWAgUCcgAABRcNOTUwMzI5MjAwNzExWjAWAgUCcgAAERcNOTUw' + #13#10 +
    'MzMwMDIzNDI2WjAWAgUCQQAAIBcNOTUwNDA3MDExMzIxWjAWAgUCcgAAHhcNOTUw' + #13#10 +
    'NDA4MDAwMjU5WjAWAgUCcgAAQRcNOTUwNDI4MTcxNzI0WjAWAgUCcgAAOBcNOTUw' + #13#10 +
    'NDI4MTcyNzIxWjAWAgUCcgAATBcNOTUwNTAyMDIxMjI2WjANBgkqhkiG9w0BAQIF' + #13#10 +
    'AAN+AHqOEJXSDejYy0UwxxrH/9+N2z5xu/if0J6qQmK92W0hW158wpJg+ovV3+wQ' + #13#10 +
    'wvIEPRL2rocL0tKfAsVq1IawSJzSNgxG0lrcla3MrJBnZ4GaZDu4FutZh72MR3Gt' + #13#10 +
    'JaAL3iTJHJD55kK2D/VoyY1djlsPuNh6AEgdVwFAyp0v' + #13#10 +
    '-----END X509 CRL-----' + #13#10;

  CRL_2_PEM =
    '-----BEGIN CRL-----' + #13#10 +
    'MIICjTCCAfowDQYJKoZIhvcNAQECBQAwXzELMAkGA1UEBhMCVVMxIDAeBgNVBAoT' + #13#10 +
    'F1JTQSBEYXRhIFNlY3VyaXR5LCBJbmMuMS4wLAYDVQQLEyVTZWN1cmUgU2VydmVy' + #13#10 +
    'IENlcnRpZmljYXRpb24gQXV0aG9yaXR5Fw05NTA1MDIwMjEyMjZaFw05NTA2MDEw' + #13#10 +
    'MDAxNDlaMIIBaDAWAgUCQQAABBcNOTUwMjAxMTcyNDI2WjAWAgUCQQAACRcNOTUw' + #13#10 +
    'MjEwMDIxNjM5WjAWAgUCQQAADxcNOTUwMjI0MDAxMjQ5WjAWAgUCQQAADBcNOTUw' + #13#10 +
    'MjI1MDA0NjQ0WjAWAgUCQQAAGxcNOTUwMzEzMTg0MDQ5WjAWAgUCQQAAFhcNOTUw' + #13#10 +
    'MzE1MTkxNjU0WjAWAgUCQQAAGhcNOTUwMzE1MTk0MDQxWjAWAgUCQQAAHxcNOTUw' + #13#10 +
    'MzI0MTk0NDMzWjAWAgUCcgAABRcNOTUwMzI5MjAwNzExWjAWAgUCcgAAERcNOTUw' + #13#10 +
    'MzMwMDIzNDI2WjAWAgUCQQAAIBcNOTUwNDA3MDExMzIxWjAWAgUCcgAAHhcNOTUw' + #13#10 +
    'NDA4MDAwMjU5WjAWAgUCcgAAQRcNOTUwNDI4MTcxNzI0WjAWAgUCcgAAOBcNOTUw' + #13#10 +
    'NDI4MTcyNzIxWjAWAgUCcgAATBcNOTUwNTAyMDIxMjI2WjANBgkqhkiG9w0BAQIF' + #13#10 +
    'AAN+AHqOEJXSDejYy0UwxxrH/9+N2z5xu/if0J6qQmK92W0hW158wpJg+ovV3+wQ' + #13#10 +
    'wvIEPRL2rocL0tKfAsVq1IawSJzSNgxG0lrcla3MrJBnZ4GaZDu4FutZh72MR3Gt' + #13#10 +
    'JaAL3iTJHJD55kK2D/VoyY1djlsPuNh6AEgdVwFAyp0v' + #13#10 +
    '-----END CRL-----' + #13#10;

  CERT_CHAIN_CRLF =
    '-----BEGIN CERTIFICATE-----' + #13#10 +
    'MIIE+TCCAuGgAwIBAgIVAIb1Te5/365tZJu71WN94Kh2FpSoMA0GCSqGSIb3DQEB' + #13#10 +
    'DQUAMBUxEzARBgNVBAsTClJvb3QgVEUgQ0EwHhcNMTUwNzAyMTU1MDA4WhcNMzUw' + #13#10 +
    'NzA3MTU1MDA4WjAvMRQwEgYDVQQDEwsxMC4yMTEuNTUuMzEXMBUGA1UECxMOVEUg' + #13#10 +
    'Uk1JIEhvc3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCU85zq' + #13#10 +
    'Kwn80yW/QZjafyTnDiaPOr8X5u8OwTe+dbQPK2xSdT7d6FqEM8rmY9njGhue5XLH' + #13#10 +
    'xKcUweVMt6E9h581qMrf39sldWMyoHxZiquPfs0t3zfMa3hYF5AONH5I3zdTZQj4' + #13#10 +
    '+5SD0mJugeM7YQ6eRs8qBdKLN/FwRWRAWQwDe3gF1gW5mgXfuo4Z3ufVscbJziJr' + #13#10 +
    'L9gnYaqCfmI8MaDWeDNkB9biTYPXGh0oacUSpWUHyyrTlzodaKhd+m5FAgDUFlV4' + #13#10 +
    'I9iv7YO4DT9sJmxmNFMrTN+c5HZjl1QL9J74HED1B1emWvxOAQvMuSfnBkR8G70E' + #13#10 +
    'D9qd1YnrEmM84FRrYgGtC2POJGnE25Fpvb/DZOuZXpFFTvQ5yuTJqcWLEgPZu45P' + #13#10 +
    '2Wigpf1j523dkA15kwhY8+r58HTCULAsqfHedrFz1YXF8BXzecH7SzpXH2hlA36m' + #13#10 +
    'oEGjFXrqAQe9YfLGLRnUrNgC12DWX2UzTqMuM5Q8Byj8SIE2oBkKXb5aW1zXkkJX' + #13#10 +
    'U2pzzIglljQB8kjpkw4zTzZpEeoJwAMAQ4K73TkkV9YQOEdVJvqWYz5gWQI17qbm' + #13#10 +
    '2gwrkYtA50+vhuO0wrIi9cJMZBOm46owBVDcMdDePgC5SURvnNjH+j1sx23IINXV' + #13#10 +
    'ipViuv9t+YLNqO+8cPaAz225Yg7snCBnOO3RGwIDAQABoyYwJDAOBgNVHQ8BAf8E' + #13#10 +
    'BAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBATANBgkqhkiG9w0BAQ0FAAOCAgEALWmm' + #13#10 +
    's3Z8cqtzpDJFZAsceNfnhgcYl1xkWbisoMe4K7hXTcp7EKlH2gsVl3YgATR5wWBw' + #13#10 +
    'YlMc0rOqwIVdz5a5bY0QYrioxe1KyXZyhp4R/NvDMKQZ/p/wREI4smiAnEDwIN2R' + #13#10 +
    'MS42SuKl2nIytJ4mIEAcNipGpk5sHQZqhQyipZ2hN3bEdZAGLH2/PpdaihHc0Jfj' + #13#10 +
    'lBRpL1ewwORVbx9Jy6IvZoFfuzj5egalAp+VZlrXU3pBv0a+Zovo/7Q+M5tjBuIg' + #13#10 +
    'MLr0R7n0J3FKIHxCwt1CHWTQ8R/QsLzhJDa1kf+SLTztHrUXqGJ/YAfpWDJh9pb2' + #13#10 +
    'boGf7RBT0lFJhFOBpv2cEqTYP+1jWtlwGmUnfHI9bMCwO6B29bk4Xdlh57yGV6RF' + #13#10 +
    '3VZ8dlN6ZBUc45vMYcWr1tLTRUzgArztMlEbloRb7n4x/UJpPV8zjracc8PyB/tl' + #13#10 +
    'tlI2DZP/f+Gf0/Vv0M+tMu6DHjz1lSR+VNRadZ5yDRNPBh24qpPNSJ15HD26IwX+' + #13#10 +
    'UQ44zVBtDxL0Y6ZMjhdSznz67eoymxYdlNHTYvw/zrg/+txje4M08i5PFFsSYN/m' + #13#10 +
    'cEV5nSgJl14AEaXe+pS0hZgvDoLXMrqgruvCp06tO3LwNkDH3oGJOGP19jNCWGyd' + #13#10 +
    'z7eQbiXNsCJGoeLKhxLj9IsVWyrLCCNZpojJdj0=' + #13#10 +
    '-----END CERTIFICATE-----' + #13#10 +
    #13#10 +
    '-----BEGIN CERTIFICATE-----' + #13#10 +
    'MIIEyzCCArOgAwIBAgIBATANBgkqhkiG9w0BAQ0FADAVMRMwEQYDVQQLEwpSb290' + #13#10 +
    'IFRFIENBMB4XDTE1MDcwMTE1NTAwOFoXDTM1MDcwODE1NTAwOFowFTETMBEGA1UE' + #13#10 +
    'CxMKUm9vdCBURSBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAIim' + #13#10 +
    '2EeomY2b5zVgomN5EheGud1NfPbaH5h5MOrsu8c0JyaUIn3gBtJazuD4x2EJNObA' + #13#10 +
    'NMigdJebc+yKP3fL8Z0fcj2JOwlrNS8ZcGWRucytYHr0ZEC1ZrkE2AysoXX8inw5' + #13#10 +
    'ABnWzdXAW0WBfa5r1UQvZtU3oldk0UutvJ2Gc4mKhQRVsSf1QxDyZMkso/9DWJG/' + #13#10 +
    '0aDLx7dAdosP7FNICpvJZp7mUoWgNvEBMXlirM0VOmoSaGmy7C75g+GhybpmBT9d' + #13#10 +
    'UtDceWzBqH5nfR3vIIthbjdzX8szCtb307RN273zYE1n6RTPNdM54LGO4L6E6R2N' + #13#10 +
    '3FMJS8H8zn5HnwjgDlKGG8OzFsmK3o+HvpEDc4p++bgm3Gc9gxjb971qOjlPQieD' + #13#10 +
    '3jpmpSMPwg8qMuge16vbSwOOEru8vfi8c1Y9VJEZnD7rRxyDffyd9AZPnB+8sDND' + #13#10 +
    'ZZv0Z4vsocSLsJjyqjRhDijbHQx6d5W6y/9ATyIz+sgg7r9B3d4IduxPRCNm7+T7' + #13#10 +
    '9dg9NokwUJwfJrKTXDC/OofBzsGYo9TTmIdjbe01ZD9va1U2VVm87N4+J+xDdsod' + #13#10 +
    '0eyp9CJ4z3ivm7NSplt56jYtkZ4J+kFzAIjU13zKxLVGqb0GTjISi1gwa5v5JGRX' + #13#10 +
    'RTz7zEv4FDJj5A9XuxDkAVNxeEn5cBqS2xDZQTpDAgMBAAGjJjAkMA4GA1UdDwEB' + #13#10 +
    '/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgECMA0GCSqGSIb3DQEBDQUAA4ICAQB/' + #13#10 +
    'S9WHn3nBNl/PkRObDWIYutOI89IQQf9A7CRU2ndZH60Xy+eM59/CXbjU4vG2e9e6' + #13#10 +
    'JcgrtSr6W+v+GLHCoVxOTI7IxM1+gjjLoHFfHNg97bXWRuHPLMSthTmSmiGC2q1r' + #13#10 +
    'fJ/cTfs2/+cJ8gzm2CZ0hKs3GrSxQezKZ+ZJBSC1wff8VT+8giALd76I7kvywC+u' + #13#10 +
    '4TnsoOzUCAC3mCR+laoIs8kmW+TBnZfgrskr0TjPdu5zCfZmK/SJSa8hOewYvrSc' + #13#10 +
    'mUmTQeAhR4NroT9fLrKlsQglIgckhp1KgUedcJp8HmWQcaRSWsAvy9WeQaftv9TQ' + #13#10 +
    'lWjEEjgdDwZ21qfl+o3wPAavC3il8pW8r8QWS5iFdzCpljYL3yfB5qbdhHfsEWD+' + #13#10 +
    'oNWE4LCu+tq1PqgTNeSi1ff5RJCk3+sRJXDDK2Z6pCLhzUlmLSWlA1PmL3qLb3EM' + #13#10 +
    'dXdPmpsuevs3MFIxfUOiZ65BeKLCKjY87fr/Z4a3cwu9AZebv9K4/Nt07EOhbTCv' + #13#10 +
    'uAH7JcHDmRENPxUxrHIb/WIDhnPYUES+Vxr2oGVwSeNej9+22AGYxTgr7jY9A5Z4' + #13#10 +
    'O+Sqfjbz818LTwYM+BTLGmHzRmgr85ygWpBwj9I2U+uEWKge2OksbCPQD9O3WJ+1' + #13#10 +
    'DX9Bnr69S8ddGJVseNNtYsIvkE80HlyO+BqzASvuXQ==' + #13#10 +
    '-----END CERTIFICATE-----' + #13#10 +
    #13#10;

  CERT_CHAIN_NL =
    '-----BEGIN CERTIFICATE-----' + #10 +
    'MIIE+TCCAuGgAwIBAgIVAIb1Te5/365tZJu71WN94Kh2FpSoMA0GCSqGSIb3DQEB' + #10 +
    'DQUAMBUxEzARBgNVBAsTClJvb3QgVEUgQ0EwHhcNMTUwNzAyMTU1MDA4WhcNMzUw' + #10 +
    'NzA3MTU1MDA4WjAvMRQwEgYDVQQDEwsxMC4yMTEuNTUuMzEXMBUGA1UECxMOVEUg' + #10 +
    'Uk1JIEhvc3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCU85zq' + #10 +
    'Kwn80yW/QZjafyTnDiaPOr8X5u8OwTe+dbQPK2xSdT7d6FqEM8rmY9njGhue5XLH' + #10 +
    'xKcUweVMt6E9h581qMrf39sldWMyoHxZiquPfs0t3zfMa3hYF5AONH5I3zdTZQj4' + #10 +
    '+5SD0mJugeM7YQ6eRs8qBdKLN/FwRWRAWQwDe3gF1gW5mgXfuo4Z3ufVscbJziJr' + #10 +
    'L9gnYaqCfmI8MaDWeDNkB9biTYPXGh0oacUSpWUHyyrTlzodaKhd+m5FAgDUFlV4' + #10 +
    'I9iv7YO4DT9sJmxmNFMrTN+c5HZjl1QL9J74HED1B1emWvxOAQvMuSfnBkR8G70E' + #10 +
    'D9qd1YnrEmM84FRrYgGtC2POJGnE25Fpvb/DZOuZXpFFTvQ5yuTJqcWLEgPZu45P' + #10 +
    '2Wigpf1j523dkA15kwhY8+r58HTCULAsqfHedrFz1YXF8BXzecH7SzpXH2hlA36m' + #10 +
    'oEGjFXrqAQe9YfLGLRnUrNgC12DWX2UzTqMuM5Q8Byj8SIE2oBkKXb5aW1zXkkJX' + #10 +
    'U2pzzIglljQB8kjpkw4zTzZpEeoJwAMAQ4K73TkkV9YQOEdVJvqWYz5gWQI17qbm' + #10 +
    '2gwrkYtA50+vhuO0wrIi9cJMZBOm46owBVDcMdDePgC5SURvnNjH+j1sx23IINXV' + #10 +
    'ipViuv9t+YLNqO+8cPaAz225Yg7snCBnOO3RGwIDAQABoyYwJDAOBgNVHQ8BAf8E' + #10 +
    'BAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBATANBgkqhkiG9w0BAQ0FAAOCAgEALWmm' + #10 +
    's3Z8cqtzpDJFZAsceNfnhgcYl1xkWbisoMe4K7hXTcp7EKlH2gsVl3YgATR5wWBw' + #10 +
    'YlMc0rOqwIVdz5a5bY0QYrioxe1KyXZyhp4R/NvDMKQZ/p/wREI4smiAnEDwIN2R' + #10 +
    'MS42SuKl2nIytJ4mIEAcNipGpk5sHQZqhQyipZ2hN3bEdZAGLH2/PpdaihHc0Jfj' + #10 +
    'lBRpL1ewwORVbx9Jy6IvZoFfuzj5egalAp+VZlrXU3pBv0a+Zovo/7Q+M5tjBuIg' + #10 +
    'MLr0R7n0J3FKIHxCwt1CHWTQ8R/QsLzhJDa1kf+SLTztHrUXqGJ/YAfpWDJh9pb2' + #10 +
    'boGf7RBT0lFJhFOBpv2cEqTYP+1jWtlwGmUnfHI9bMCwO6B29bk4Xdlh57yGV6RF' + #10 +
    '3VZ8dlN6ZBUc45vMYcWr1tLTRUzgArztMlEbloRb7n4x/UJpPV8zjracc8PyB/tl' + #10 +
    'tlI2DZP/f+Gf0/Vv0M+tMu6DHjz1lSR+VNRadZ5yDRNPBh24qpPNSJ15HD26IwX+' + #10 +
    'UQ44zVBtDxL0Y6ZMjhdSznz67eoymxYdlNHTYvw/zrg/+txje4M08i5PFFsSYN/m' + #10 +
    'cEV5nSgJl14AEaXe+pS0hZgvDoLXMrqgruvCp06tO3LwNkDH3oGJOGP19jNCWGyd' + #10 +
    'z7eQbiXNsCJGoeLKhxLj9IsVWyrLCCNZpojJdj0=' + #10 +
    '-----END CERTIFICATE-----' + #10 +
    '-----BEGIN CERTIFICATE-----' + #10 +
    'MIIEyzCCArOgAwIBAgIBATANBgkqhkiG9w0BAQ0FADAVMRMwEQYDVQQLEwpSb290' + #10 +
    'IFRFIENBMB4XDTE1MDcwMTE1NTAwOFoXDTM1MDcwODE1NTAwOFowFTETMBEGA1UE' + #10 +
    'CxMKUm9vdCBURSBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAIim' + #10 +
    '2EeomY2b5zVgomN5EheGud1NfPbaH5h5MOrsu8c0JyaUIn3gBtJazuD4x2EJNObA' + #10 +
    'NMigdJebc+yKP3fL8Z0fcj2JOwlrNS8ZcGWRucytYHr0ZEC1ZrkE2AysoXX8inw5' + #10 +
    'ABnWzdXAW0WBfa5r1UQvZtU3oldk0UutvJ2Gc4mKhQRVsSf1QxDyZMkso/9DWJG/' + #10 +
    '0aDLx7dAdosP7FNICpvJZp7mUoWgNvEBMXlirM0VOmoSaGmy7C75g+GhybpmBT9d' + #10 +
    'UtDceWzBqH5nfR3vIIthbjdzX8szCtb307RN273zYE1n6RTPNdM54LGO4L6E6R2N' + #10 +
    '3FMJS8H8zn5HnwjgDlKGG8OzFsmK3o+HvpEDc4p++bgm3Gc9gxjb971qOjlPQieD' + #10 +
    '3jpmpSMPwg8qMuge16vbSwOOEru8vfi8c1Y9VJEZnD7rRxyDffyd9AZPnB+8sDND' + #10 +
    'ZZv0Z4vsocSLsJjyqjRhDijbHQx6d5W6y/9ATyIz+sgg7r9B3d4IduxPRCNm7+T7' + #10 +
    '9dg9NokwUJwfJrKTXDC/OofBzsGYo9TTmIdjbe01ZD9va1U2VVm87N4+J+xDdsod' + #10 +
    '0eyp9CJ4z3ivm7NSplt56jYtkZ4J+kFzAIjU13zKxLVGqb0GTjISi1gwa5v5JGRX' + #10 +
    'RTz7zEv4FDJj5A9XuxDkAVNxeEn5cBqS2xDZQTpDAgMBAAGjJjAkMA4GA1UdDwEB' + #10 +
    '/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgECMA0GCSqGSIb3DQEBDQUAA4ICAQB/' + #10 +
    'S9WHn3nBNl/PkRObDWIYutOI89IQQf9A7CRU2ndZH60Xy+eM59/CXbjU4vG2e9e6' + #10 +
    'JcgrtSr6W+v+GLHCoVxOTI7IxM1+gjjLoHFfHNg97bXWRuHPLMSthTmSmiGC2q1r' + #10 +
    'fJ/cTfs2/+cJ8gzm2CZ0hKs3GrSxQezKZ+ZJBSC1wff8VT+8giALd76I7kvywC+u' + #10 +
    '4TnsoOzUCAC3mCR+laoIs8kmW+TBnZfgrskr0TjPdu5zCfZmK/SJSa8hOewYvrSc' + #10 +
    'mUmTQeAhR4NroT9fLrKlsQglIgckhp1KgUedcJp8HmWQcaRSWsAvy9WeQaftv9TQ' + #10 +
    'lWjEEjgdDwZ21qfl+o3wPAavC3il8pW8r8QWS5iFdzCpljYL3yfB5qbdhHfsEWD+' + #10 +
    'oNWE4LCu+tq1PqgTNeSi1ff5RJCk3+sRJXDDK2Z6pCLhzUlmLSWlA1PmL3qLb3EM' + #10 +
    'dXdPmpsuevs3MFIxfUOiZ65BeKLCKjY87fr/Z4a3cwu9AZebv9K4/Nt07EOhbTCv' + #10 +
    'uAH7JcHDmRENPxUxrHIb/WIDhnPYUES+Vxr2oGVwSeNej9+22AGYxTgr7jY9A5Z4' + #10 +
    'O+Sqfjbz818LTwYM+BTLGmHzRmgr85ygWpBwj9I2U+uEWKge2OksbCPQD9O3WJ+1' + #10 +
    'DX9Bnr69S8ddGJVseNNtYsIvkE80HlyO+BqzASvuXQ==' + #10 +
    '-----END CERTIFICATE-----' + #10 +
    #10;

implementation

{ TDudPublicKey }

constructor TDudPublicKey.Create;
begin
  inherited Create(False);
end;

{ TCertTest }

function TCertTest.GenerateLongFixedKeys: IAsymmetricCipherKeyPair;
var
  LPubMod, LPubExp: TBigInteger;
  LPrivMod, LPrivExp, LPrivP, LPrivQ, LPrivDP, LPrivDQ, LPrivQinv: TBigInteger;
  LPub: IRsaKeyParameters;
  LPriv: IRsaPrivateCrtKeyParameters;
begin
  LPubMod := TBigInteger.Create(
    'a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a213' + '7', 16);
  LPubExp := TBigInteger.Create('010001', 16);
  LPrivMod := LPubMod;
  LPrivExp := TBigInteger.Create(
    '33a5042a90b27d4f5451ca9bbbd0b44771a101af884340aef9885f2a4bbe92e894a724ac3c568c8f97853ad07c0266c8c6a3ca0929f1e8f11231884429fc4d9ae55fee896a10ce707c3ed7e734e44727a39574501a532683109c2abacaba283c31b4bd2f53c3ee37e352cee34f9e503bd80c0622ad79c6dcee883547c6a3b32' + '5', 16);
  LPrivP := TBigInteger.Create('e7e8942720a877517273a356053ea2a1bc0c94aa72d55c6e86296b2dfc967948c0a72cbccca7eacb35706e09a1df55a1535bd9b3cc34160b3b6dcd3eda8e6443', 16);
  LPrivQ := TBigInteger.Create('b69dca1cf7d4d7ec81e75b90fcca874abcde123fd2700180aa90479b6e48de8d67ed24f9f19d85ba275874f542cd20dc723e6963364a1f9425452b269a6799fd', 16);
  LPrivDP := TBigInteger.Create('28fa13938655be1f8a159cbaca5a72ea190c30089e19cd274a556f36c4f6e19f554b34c077790427bbdd8dd3ede2448328f385d81b30e8e43b2fffa027861979', 16);
  LPrivDQ := TBigInteger.Create('1a8b38f398fa712049898d7fb79ee0a77668791299cdfa09efc0e507acb21ed74301ef5bfd48be455eaeb6e1678255827580a8e4e8e14151d1510a82a3f2e729', 16);
  LPrivQinv := TBigInteger.Create('27156aba4126d24a81f3a528cbfb27f56886f840a9f6e86e17a44b94fe9319584b8e22fdde1e5a2e3bd8aa5ba8d8584194eb2190acf832b847f13a3d24a79f4d', 16);
  LPub := TRsaKeyParameters.Create(False, LPubMod, LPubExp);
  LPriv := TRsaPrivateCrtKeyParameters.Create(LPrivMod, LPubExp, LPrivExp, LPrivP, LPrivQ, LPrivDP, LPrivDQ, LPrivQinv);
  Result := TAsymmetricCipherKeyPair.Create(LPub, LPriv);
end;

procedure TCertTest.SetUpKeys;
var
  LRsaPubMod, LRsaPubExp, LRsaPrivMod, LRsaPrivExp: TBigInteger;
  LRsaPrivP, LRsaPrivQ, LRsaPrivDP, LRsaPrivDQ, LRsaPrivQinv: TBigInteger;
begin
  LRsaPubMod := TBigInteger.Create('b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7', 16);
  LRsaPubExp := TBigInteger.Create('11', 16);

  LRsaPrivMod := TBigInteger.Create('b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7', 16);
  LRsaPrivExp := TBigInteger.Create('9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89', 16);
  LRsaPrivP := TBigInteger.Create('c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb', 16);
  LRsaPrivQ := TBigInteger.Create('f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5', 16);
  LRsaPrivDP := TBigInteger.Create('b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391', 16);
  LRsaPrivDQ := TBigInteger.Create('d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd', 16);
  LRsaPrivQinv := TBigInteger.Create('b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19', 16);

  FRsaPublic := TRsaKeyParameters.Create(False, LRsaPubMod, LRsaPubExp);
  FRsaPrivate := TRsaPrivateCrtKeyParameters.Create(LRsaPrivMod, LRsaPubExp,
    LRsaPrivExp, LRsaPrivP, LRsaPrivQ, LRsaPrivDP, LRsaPrivDQ, LRsaPrivQinv);
end;

function TCertTest.CreateX509Name: IX509Name;
var
  LAttrs: TDictionary<IDerObjectIdentifier, String>;
  LOrd: TList<IDerObjectIdentifier>;
begin
  LAttrs := TDictionary<IDerObjectIdentifier, String>.Create(TAsn1Comparers.OidEqualityComparer);
  LOrd := TList<IDerObjectIdentifier>.Create;
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

procedure TCertTest.CheckCertificate(AId: Int32; const ACertBytes: TCryptoLibByteArray);
var
  LParser: IX509CertificateParser;
  LCert: IX509Certificate;
  LPublicKey: IAsymmetricKeyParameter;
begin
  try
    LParser := TX509CertificateParser.Create;
    LCert := LParser.ReadCertificate(ACertBytes);
    if LCert = nil then
      Fail(Format('CertTest: %d failed - null certificate', [AId]));
    LPublicKey := LCert.GetPublicKey();
  except
    on E: Exception do
      Fail(Format('CertTest: %d failed - exception %s', [AId, E.Message]));
  end;
end;

procedure TCertTest.CheckKeyUsage(AId: Int32; const ACertBytes: TCryptoLibByteArray);
var
  LParser: IX509CertificateParser;
  LCert: IX509Certificate;
  LKeyUsage: TCryptoLibBooleanArray;
begin
  LParser := TX509CertificateParser.Create;
  LCert := LParser.ReadCertificate(ACertBytes);
  if LCert = nil then
    Fail(Format('CertTest: %d failed - null certificate', [AId]));
  LCert.GetPublicKey();
  LKeyUsage := LCert.GetKeyUsage();
  if (LKeyUsage <> nil) and (System.Length(LKeyUsage) > 7) and LKeyUsage[7] then
    Fail('error generating cert - key usage wrong.');
end;

procedure TCertTest.CheckSelfSignedCertificate(AId: Int32; const ACertBytes: TCryptoLibByteArray);
var
  LParser: IX509CertificateParser;
  LCert: IX509Certificate;
begin
  LParser := TX509CertificateParser.Create;
  LCert := LParser.ReadCertificate(ACertBytes);
  if LCert = nil then
    Fail(Format('CertTest: %d failed - null certificate', [AId]));
  LCert.Verify(LCert.GetPublicKey());
end;

procedure TCertTest.CheckNameCertificate(AId: Int32; const ACertBytes: TCryptoLibByteArray);
var
  LParser: IX509CertificateParser;
  LCert: IX509Certificate;
  LExpected: String;
begin
  LParser := TX509CertificateParser.Create;
  LCert := LParser.ReadCertificate(ACertBytes);
  if LCert = nil then
    Fail(Format('CertTest: %d failed - null certificate', [AId]));
  LCert.GetPublicKey();
  LExpected := 'C=DE,O=DATEV eG,0.2.262.1.10.7.20=1+CN=CA DATEV D03 1:PN';
  if LCert.IssuerDN.ToString <> LExpected then
    Fail(Format('CertTest: %d failed - name test', [AId]));
end;

procedure TCertTest.CheckCrl(AId: Int32; const ACrlBytes: TCryptoLibByteArray);
var
  LParser: IX509CrlParser;
  LCrl: IX509Crl;
begin
  LParser := TX509CrlParser.Create;
  LCrl := LParser.ReadCrl(ACrlBytes);
  if LCrl = nil then
    Fail(Format('CertTest CRL: %d failed - null CRL', [AId]));
end;

procedure TCertTest.SetUp;
begin
  inherited SetUp;
  FSecureRandom := TSecureRandom.Create;
  if FRsaPublic = nil then
    SetUpKeys;
end;

procedure TCertTest.TestX509NameBuilderMatchesRegular;
var
  LRegular: IX509Name;
  LBuilder: IX509NameBuilder;
  LViaBuilder: IX509Name;
begin
  LRegular := CreateX509Name;
  LBuilder := TX509NameBuilder.Create;
  LViaBuilder := LBuilder
    .AddCountry('NG')
    .AddOrganization('CryptoLib4Pascal')
    .AddLocality('Alausa')
    .AddState('Lagos')
    .AddEmailAddress('feedback-crypto@cryptolib4pascal.org')
    .Build();
  if not LRegular.Equivalent(LViaBuilder, True) then
    Fail('X509Name from builder did not match regular creation (Equivalent)');
  if LRegular.ToString <> LViaBuilder.ToString then
    Fail('X509Name from builder did not match regular creation (ToString)');
end;

procedure TCertTest.TestCert1;
begin
  CheckCertificate(1, DecodeBase64(
    'MIIDXjCCAsegAwIBAgIBBzANBgkqhkiG9w0BAQQFADCBtzELMAkGA1UEBhMCQVUx'
    + 'ETAPBgNVBAgTCFZpY3RvcmlhMRgwFgYDVQQHEw9Tb3V0aCBNZWxib3VybmUxGjAY'
    + 'BgNVBAoTEUNvbm5lY3QgNCBQdHkgTHRkMR4wHAYDVQQLExVDZXJ0aWZpY2F0ZSBB'
    + 'dXRob3JpdHkxFTATBgNVBAMTDENvbm5lY3QgNCBDQTEoMCYGCSqGSIb3DQEJARYZ'
    + 'd2VibWFzdGVyQGNvbm5lY3Q0LmNvbS5hdTAeFw0wMDA2MDIwNzU2MjFaFw0wMTA2'
    + 'MDIwNzU2MjFaMIG4MQswCQYDVQQGEwJBVTERMA8GA1UECBMIVmljdG9yaWExGDAW'
    + 'BgNVBAcTD1NvdXRoIE1lbGJvdXJuZTEaMBgGA1UEChMRQ29ubmVjdCA0IFB0eSBM'
    + 'dGQxFzAVBgNVBAsTDldlYnNlcnZlciBUZWFtMR0wGwYDVQQDExR3d3cyLmNvbm5l'
    + 'Y3Q0LmNvbS5hdTEoMCYGCSqGSIb3DQEJARYZd2VibWFzdGVyQGNvbm5lY3Q0LmNv'
    + 'bS5hdTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEArvDxclKAhyv7Q/Wmr2re'
    + 'Gw4XL9Cnh9e+6VgWy2AWNy/MVeXdlxzd7QAuc1eOWQkGQEiLPy5XQtTY+sBUJ3AO'
    + 'Rvd2fEVJIcjf29ey7bYua9J/vz5MG2KYo9/WCHIwqD9mmG9g0xLcfwq/s8ZJBswE'
    + '7sb85VU+h94PTvsWOsWuKaECAwEAAaN3MHUwJAYDVR0RBB0wG4EZd2VibWFzdGVy'
    + 'QGNvbm5lY3Q0LmNvbS5hdTA6BglghkgBhvhCAQ0ELRYrbW9kX3NzbCBnZW5lcmF0'
    + 'ZWQgY3VzdG9tIHNlcnZlciBjZXJ0aWZpY2F0ZTARBglghkgBhvhCAQEEBAMCBkAw'
    + 'DQYJKoZIhvcNAQEEBQADgYEAotccfKpwSsIxM1Hae8DR7M/Rw8dg/RqOWx45HNVL'
    + 'iBS4/3N/TO195yeQKbfmzbAA2jbPVvIvGgTxPgO1MP4ZgvgRhasaa0qCJCkWvpM4'
    + 'yQf33vOiYQbpv4rTwzU8AmRlBG45WdjyNIigGV+oRc61aKCTnLq7zB8N3z1TF/bF'
    + '5/8='));
end;

procedure TCertTest.TestCert2;
begin
  CheckCertificate(2, DecodeBase64(
    'MIIDbDCCAtWgAwIBAgIBADANBgkqhkiG9w0BAQQFADCBtzELMAkGA1UEBhMCQVUx'
    + 'ETAPBgNVBAgTCFZpY3RvcmlhMRgwFgYDVQQHEw9Tb3V0aCBNZWxib3VybmUxGjAY'
    + 'BgNVBAoTEUNvbm5lY3QgNCBQdHkgTHRkMR4wHAYDVQQLExVDZXJ0aWZpY2F0ZSBB'
    + 'dXRob3JpdHkxFTATBgNVBAMTDENvbm5lY3QgNCBDQTEoMCYGCSqGSIb3DQEJARYZ'
    + 'd2VibWFzdGVyQGNvbm5lY3Q0LmNvbS5hdTAeFw0wMDA2MDIwNzU1MzNaFw0wMTA2'
    + 'MDIwNzU1MzNaMIG3MQswCQYDVQQGEwJBVTERMA8GA1UECBMIVmljdG9yaWExGDAW'
    + 'BgNVBAcTD1NvdXRoIE1lbGJvdXJuZTEaMBgGA1UEChMRQ29ubmVjdCA0IFB0eSBM'
    + 'dGQxHjAcBgNVBAsTFUNlcnRpZmljYXRlIEF1dGhvcml0eTEVMBMGA1UEAxMMQ29u'
    + 'bmVjdCA0IENBMSgwJgYJKoZIhvcNAQkBFhl3ZWJtYXN0ZXJAY29ubmVjdDQuY29t'
    + 'LmF1MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDgs5ptNG6Qv1ZpCDuUNGmv'
    + 'rhjqMDPd3ri8JzZNRiiFlBA4e6/ReaO1U8ASewDeQMH6i9R6degFdQRLngbuJP0s'
    + 'xcEE+SksEWNvygfzLwV9J/q+TQDyJYK52utb++lS0b48A1KPLwEsyL6kOAgelbur'
    + 'ukwxowprKUIV7Knf1ajetQIDAQABo4GFMIGCMCQGA1UdEQQdMBuBGXdlYm1hc3Rl'
    + 'ckBjb25uZWN0NC5jb20uYXUwDwYDVR0TBAgwBgEB/wIBADA2BglghkgBhvhCAQ0E'
    + 'KRYnbW9kX3NzbCBnZW5lcmF0ZWQgY3VzdG9tIENBIGNlcnRpZmljYXRlMBEGCWCG'
    + 'SAGG+EIBAQQEAwICBDANBgkqhkiG9w0BAQQFAAOBgQCsGvfdghH8pPhlwm1r3pQk'
    + 'msnLAVIBb01EhbXm2861iXZfWqGQjrGAaA0ZpXNk9oo110yxoqEoSJSzniZa7Xtz'
    + 'soTwNUpE0SLHvWf/SlKdFWlzXA+vOZbzEv4UmjeelekTm7lc01EEa5QRVzOxHFtQ'
    + 'DhkaJ8VqOMajkQFma2r9iA=='));
end;

procedure TCertTest.TestCert3;
begin
  CheckCertificate(3, DecodeBase64(
    'MIIBWzCCAQYCARgwDQYJKoZIhvcNAQEEBQAwODELMAkGA1UEBhMCQVUxDDAKBgNV'
    + 'BAgTA1FMRDEbMBkGA1UEAxMSU1NMZWF5L3JzYSB0ZXN0IENBMB4XDTk1MDYxOTIz'
    + 'MzMxMloXDTk1MDcxNzIzMzMxMlowOjELMAkGA1UEBhMCQVUxDDAKBgNVBAgTA1FM'
    + 'RDEdMBsGA1UEAxMUU1NMZWF5L3JzYSB0ZXN0IGNlcnQwXDANBgkqhkiG9w0BAQEF'
    + 'AANLADBIAkEAqtt6qS5GTxVxGZYWa0/4u+IwHf7p2LNZbcPBp9/OfIcYAXBQn8hO'
    + '/Re1uwLKXdCjIoaGs4DLdG88rkzfyK5dPQIDAQABMAwGCCqGSIb3DQIFBQADQQAE'
    + 'Wc7EcF8po2/ZO6kNCwK/ICH6DobgLekA5lSLr5EvuioZniZp5lFzAw4+YzPQ7XKJ'
    + 'zl9HYIMxATFyqSiD9jsx'));
end;

procedure TCertTest.TestCert4;
begin
  CheckCertificate(4, DecodeBase64(
    'MIICjTCCAfigAwIBAgIEMaYgRzALBgkqhkiG9w0BAQQwRTELMAkGA1UEBhMCVVMx'
    + 'NjA0BgNVBAoTLU5hdGlvbmFsIEFlcm9uYXV0aWNzIGFuZCBTcGFjZSBBZG1pbmlz'
    + 'dHJhdGlvbjAmFxE5NjA1MjgxMzQ5MDUrMDgwMBcROTgwNTI4MTM0OTA1KzA4MDAw'
    + 'ZzELMAkGA1UEBhMCVVMxNjA0BgNVBAoTLU5hdGlvbmFsIEFlcm9uYXV0aWNzIGFu'
    + 'ZCBTcGFjZSBBZG1pbmlzdHJhdGlvbjEgMAkGA1UEBRMCMTYwEwYDVQQDEwxTdGV2'
    + 'ZSBTY2hvY2gwWDALBgkqhkiG9w0BAQEDSQAwRgJBALrAwyYdgxmzNP/ts0Uyf6Bp'
    + 'miJYktU/w4NG67ULaN4B5CnEz7k57s9o3YY3LecETgQ5iQHmkwlYDTL2fTgVfw0C'
    + 'AQOjgaswgagwZAYDVR0ZAQH/BFowWDBWMFQxCzAJBgNVBAYTAlVTMTYwNAYDVQQK'
    + 'Ey1OYXRpb25hbCBBZXJvbmF1dGljcyBhbmQgU3BhY2UgQWRtaW5pc3RyYXRpb24x'
    + 'DTALBgNVBAMTBENSTDEwFwYDVR0BAQH/BA0wC4AJODMyOTcwODEwMBgGA1UdAgQR'
    + 'MA8ECTgzMjk3MDgyM4ACBSAwDQYDVR0KBAYwBAMCBkAwCwYJKoZIhvcNAQEEA4GB'
    + 'AH2y1VCEw/A4zaXzSYZJTTUi3uawbbFiS2yxHvgf28+8Js0OHXk1H1w2d6qOHH21'
    + 'X82tZXd/0JtG0g1T9usFFBDvYK8O0ebgz/P5ELJnBL2+atObEuJy1ZZ0pBDWINR3'
    + 'WkDNLCGiTkCKp0F5EWIrVDwh54NNevkCQRZita+z4IBO'));
end;

procedure TCertTest.TestCert5;
begin
  CheckCertificate(5, DecodeBase64(
    'MIICiTCCAfKgAwIBAgIEMeZfHzANBgkqhkiG9w0BAQQFADB9MQswCQYDVQQGEwJD'
    + 'YTEPMA0GA1UEBxMGTmVwZWFuMR4wHAYDVQQLExVObyBMaWFiaWxpdHkgQWNjZXB0'
    + 'ZWQxHzAdBgNVBAoTFkZvciBEZW1vIFB1cnBvc2VzIE9ubHkxHDAaBgNVBAMTE0Vu'
    + 'dHJ1c3QgRGVtbyBXZWIgQ0EwHhcNOTYwNzEyMTQyMDE1WhcNOTYxMDEyMTQyMDE1'
    + 'WjB0MSQwIgYJKoZIhvcNAQkBExVjb29rZUBpc3NsLmF0bC5ocC5jb20xCzAJBgNV'
    + 'BAYTAlVTMScwJQYDVQQLEx5IZXdsZXR0IFBhY2thcmQgQ29tcGFueSAoSVNTTCkx'
    + 'FjAUBgNVBAMTDVBhdWwgQS4gQ29va2UwXDANBgkqhkiG9w0BAQEFAANLADBIAkEA'
    + '6ceSq9a9AU6g+zBwaL/yVmW1/9EE8s5you1mgjHnj0wAILuoB3L6rm6jmFRy7QZT'
    + 'G43IhVZdDua4e+5/n1ZslwIDAQABo2MwYTARBglghkgBhvhCAQEEBAMCB4AwTAYJ'
    + 'YIZIAYb4QgENBD8WPVRoaXMgY2VydGlmaWNhdGUgaXMgb25seSBpbnRlbmRlZCBm'
    + 'b3IgZGVtb25zdHJhdGlvbiBwdXJwb3Nlcy4wDQYJKoZIhvcNAQEEBQADgYEAi8qc'
    + 'F3zfFqy1sV8NhjwLVwOKuSfhR/Z8mbIEUeSTlnH3QbYt3HWZQ+vXI8mvtZoBc2Fz'
    + 'lexKeIkAZXCesqGbs6z6nCt16P6tmdfbZF3I3AWzLquPcOXjPf4HgstkyvVBn0Ap'
    + 'jAFN418KF/Cx4qyHB4cjdvLrRjjQLnb2+ibo7QU='));
end;

procedure TCertTest.TestCert6;
begin
  CheckCertificate(6, DecodeBase64(
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
    + 'srrfn4Z9I+6kTriGXkrpGk9Q0LSGjmG2BIsqiF0dvwAAAAAAAA=='));
end;

procedure TCertTest.TestCert7;
begin
  CheckCertificate(7, DecodeBase64(
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
    + 'cg=='));
end;

procedure TCertTest.TestKeyUsage;
begin
  CheckKeyUsage(8, DecodeBase64(
    'MIIE7TCCBFagAwIBAgIEOAOR7jANBgkqhkiG9w0BAQQFADCByTELMAkGA1UE'
    + 'BhMCVVMxFDASBgNVBAoTC0VudHJ1c3QubmV0MUgwRgYDVQQLFD93d3cuZW50'
    + 'cnVzdC5uZXQvQ2xpZW50X0NBX0luZm8vQ1BTIGluY29ycC4gYnkgcmVmLiBs'
    + 'aW1pdHMgbGlhYi4xJTAjBgNVBAsTHChjKSAxOTk5IEVudHJ1c3QubmV0IExp'
    + 'bWl0ZWQxMzAxBgNVBAMTKkVudHJ1c3QubmV0IENsaWVudCBDZXJ0aWZpY2F0'
    + 'aW9uIEF1dGhvcml0eTAeFw05OTEwMTIxOTI0MzBaFw0xOTEwMTIxOTU0MzBa'
    + 'MIHJMQswCQYDVQQGEwJVUzEUMBIGA1UEChMLRW50cnVzdC5uZXQxSDBGBgNV'
    + 'BAsUP3d3dy5lbnRydXN0Lm5ldC9DbGllbnRfQ0FfSW5mby9DUFMgaW5jb3Jw'
    + 'LiBieSByZWYuIGxpbWl0cyBsaWFiLjElMCMGA1UECxMcKGMpIDE5OTkgRW50'
    + 'cnVzdC5uZXQgTGltaXRlZDEzMDEGA1UEAxMqRW50cnVzdC5uZXQgQ2xpZW50'
    + 'IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIGdMA0GCSqGSIb3DQEBAQUAA4GL'
    + 'ADCBhwKBgQDIOpleMRffrCdvkHvkGf9FozTC28GoT/Bo6oT9n3V5z8GKUZSv'
    + 'x1cDR2SerYIbWtp/N3hHuzeYEpbOxhN979IMMFGpOZ5V+Pux5zDeg7K6PvHV'
    + 'iTs7hbqqdCz+PzFur5GVbgbUB01LLFZHGARS2g4Qk79jkJvh34zmAqTmT173'
    + 'iwIBA6OCAeAwggHcMBEGCWCGSAGG+EIBAQQEAwIABzCCASIGA1UdHwSCARkw'
    + 'ggEVMIHkoIHhoIHepIHbMIHYMQswCQYDVQQGEwJVUzEUMBIGA1UEChMLRW50'
    + 'cnVzdC5uZXQxSDBGBgNVBAsUP3d3dy5lbnRydXN0Lm5ldC9DbGllbnRfQ0Ff'
    + 'SW5mby9DUFMgaW5jb3JwLiBieSByZWYuIGxpbWl0cyBsaWFiLjElMCMGA1UE'
    + 'CxMcKGMpIDE5OTkgRW50cnVzdC5uZXQgTGltaXRlZDEzMDEGA1UEAxMqRW50'
    + 'cnVzdC5uZXQgQ2xpZW50IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MQ0wCwYD'
    + 'VQQDEwRDUkwxMCygKqAohiZodHRwOi8vd3d3LmVudHJ1c3QubmV0L0NSTC9D'
    + 'bGllbnQxLmNybDArBgNVHRAEJDAigA8xOTk5MTAxMjE5MjQzMFqBDzIwMTkx'
    + 'MDEyMTkyNDMwWjALBgNVHQ8EBAMCAQYwHwYDVR0jBBgwFoAUxPucKXuXzUyW'
    + '/O5bs8qZdIuV6kwwHQYDVR0OBBYEFMT7nCl7l81MlvzuW7PKmXSLlepMMAwG'
    + 'A1UdEwQFMAMBAf8wGQYJKoZIhvZ9B0EABAwwChsEVjQuMAMCBJAwDQYJKoZI'
    + 'hvcNAQEEBQADgYEAP66K8ddmAwWePvrqHEa7pFuPeJoSSJn59DXeDDYHAmsQ'
    + 'OokUgZwxpnyyQbJq5wcBoUv5nyU7lsqZwz6hURzzwy5E97BnRqqS5TvaHBkU'
    + 'ODDV4qIxJS7x7EU47fgGWANzYrAQMY9Av2TgXD7FTx/aEkP/TOYGJqibGapE'
    + 'PHayXOw='));
end;

procedure TCertTest.TestSelfSignedUncompressedPtEC;
begin
  CheckSelfSignedCertificate(9, DecodeBase64(
    'MIIDKzCCAsGgAwIBAgICA+kwCwYHKoZIzj0EAQUAMGYxCzAJBgNVBAYTAkpQ'
    + 'MRUwEwYDVQQKEwxuaXRlY2guYWMuanAxDjAMBgNVBAsTBWFpbGFiMQ8wDQYD'
    + 'VQQDEwZ0ZXN0Y2ExHzAdBgkqhkiG9w0BCQEWEHRlc3RjYUBsb2NhbGhvc3Qw'
    + 'HhcNMDExMDEzMTE1MzE3WhcNMjAxMjEyMTE1MzE3WjBmMQswCQYDVQQGEwJK'
    + 'UDEVMBMGA1UEChMMbml0ZWNoLmFjLmpwMQ4wDAYDVQQLEwVhaWxhYjEPMA0G'
    + 'A1UEAxMGdGVzdGNhMR8wHQYJKoZIhvcNAQkBFhB0ZXN0Y2FAbG9jYWxob3N0'
    + 'MIIBczCCARsGByqGSM49AgEwggEOAgEBMDMGByqGSM49AQECKEdYWnajFmnZ'
    + 'tzrukK2XWdle2v+GsD9l1ZiR6g7ozQDbhFH/bBiMDQcwVAQoJ5EQKrI54/CT'
    + 'xOQ2pMsd/fsXD+EX8YREd8bKHWiLz8lIVdD5cBNeVwQoMKSc6HfI7vKZp8Q2'
    + 'zWgIFOarx1GQoWJbMcSt188xsl30ncJuJT2OoARRBAqJ4fD+q6hbqgNSjTQ7'
    + 'htle1KO3eiaZgcJ8rrnyN8P+5A8+5K+H9aQ/NbBR4Gs7yto5PXIUZEUgodHA'
    + 'TZMSAcSq5ZYt4KbnSYaLY0TtH9CqAigEwZ+hglbT21B7ZTzYX2xj0x+qooJD'
    + 'hVTLtIPaYJK2HrMPxTw6/zfrAgEPA1IABAnvfFcFDgD/JicwBGn6vR3N8MIn'
    + 'mptZf/mnJ1y649uCF60zOgdwIyI7pVSxBFsJ7ohqXEHW0x7LrGVkdSEiipiH'
    + 'LYslqh3xrqbAgPbl93GUo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB'
    + '/wQEAwIBxjAdBgNVHQ4EFgQUAEo62Xm9H6DcsE0zUDTza4BRG90wCwYHKoZI'
    + 'zj0EAQUAA1cAMFQCKAQsCHHSNOqfJXLgt3bg5+k49hIBGVr/bfG0B9JU3rNt'
    + 'Ycl9Y2zfRPUCKAK2ccOQXByAWfsasDu8zKHxkZv7LVDTFjAIffz3HaCQeVhD'
    + 'z+fauEg='));
end;

procedure TCertTest.TestNameCert;
begin
  CheckNameCertificate(10, DecodeBase64(
    'MIIEFjCCA3+gAwIBAgIEdS8BozANBgkqhkiG9w0BAQUFADBKMQswCQYDVQQGEwJE'
    + 'RTERMA8GA1UEChQIREFURVYgZUcxKDAMBgcCggYBCgcUEwExMBgGA1UEAxQRQ0Eg'
    + 'REFURVYgRDAzIDE6UE4wIhgPMjAwMTA1MTAxMDIyNDhaGA8yMDA0MDUwOTEwMjI0'
    + 'OFowgYQxCzAJBgNVBAYTAkRFMQ8wDQYDVQQIFAZCYXllcm4xEjAQBgNVBAcUCU7I'
    + 'dXJuYmVyZzERMA8GA1UEChQIREFURVYgZUcxHTAbBgNVBAUTFDAwMDAwMDAwMDA4'
    + 'OTU3NDM2MDAxMR4wHAYDVQQDFBVEaWV0bWFyIFNlbmdlbmxlaXRuZXIwgaEwDQYJ'
    + 'KoZIhvcNAQEBBQADgY8AMIGLAoGBAJLI/LJLKaHoMk8fBECW/od8u5erZi6jI8Ug'
    + 'C0a/LZyQUO/R20vWJs6GrClQtXB+AtfiBSnyZOSYzOdfDI8yEKPEv8qSuUPpOHps'
    + 'uNCFdLZF1vavVYGEEWs2+y+uuPmg8q1oPRyRmUZ+x9HrDvCXJraaDfTEd9olmB/Z'
    + 'AuC/PqpjAgUAwAAAAaOCAcYwggHCMAwGA1UdEwEB/wQCMAAwDwYDVR0PAQH/BAUD'
    + 'AwdAADAxBgNVHSAEKjAoMCYGBSskCAEBMB0wGwYIKwYBBQUHAgEWD3d3dy56cy5k'
    + 'YXRldi5kZTApBgNVHREEIjAggR5kaWV0bWFyLnNlbmdlbmxlaXRuZXJAZGF0ZXYu'
    + 'ZGUwgYQGA1UdIwR9MHuhc6RxMG8xCzAJBgNVBAYTAkRFMT0wOwYDVQQKFDRSZWd1'
    + 'bGllcnVuZ3NiZWjIb3JkZSBmyHVyIFRlbGVrb21tdW5pa2F0aW9uIHVuZCBQb3N0'
    + 'MSEwDAYHAoIGAQoHFBMBMTARBgNVBAMUCjVSLUNBIDE6UE6CBACm8LkwDgYHAoIG'
    + 'AQoMAAQDAQEAMEcGA1UdHwRAMD4wPKAUoBKGEHd3dy5jcmwuZGF0ZXYuZGWiJKQi'
    + 'MCAxCzAJBgNVBAYTAkRFMREwDwYDVQQKFAhEQVRFViBlRzAWBgUrJAgDBAQNMAsT'
    + 'A0VVUgIBBQIBATAdBgNVHQ4EFgQUfv6xFP0xk7027folhy+ziZvBJiwwLAYIKwYB'
    + 'BQUHAQEEIDAeMBwGCCsGAQUFBzABhhB3d3cuZGlyLmRhdGV2LmRlMA0GCSqGSIb3'
    + 'DQEBBQUAA4GBAEOVX6uQxbgtKzdgbTi6YLffMftFr2mmNwch7qzpM5gxcynzgVkg'
    + 'pnQcDNlm5AIbS6pO8jTCLfCd5TZ5biQksBErqmesIl3QD+VqtB+RNghxectZ3VEs'
    + 'nCUtcE7tJ8O14qwCb3TxS9dvIUFiVi4DjbxX46TdcTbTaK8/qr6AIf+l'));
end;

procedure TCertTest.TestSelfSignedProbSelfSignedCert;
begin
  CheckSelfSignedCertificate(11, DecodeBase64(
    'MIICxTCCAi6gAwIBAgIQAQAAAAAAAAAAAAAAAAAAATANBgkqhkiG9w0BAQUFADBF'
    + 'MScwJQYDVQQKEx4gRElSRUNUSU9OIEdFTkVSQUxFIERFUyBJTVBPVFMxGjAYBgNV'
    + 'BAMTESBBQyBNSU5FRkkgQiBURVNUMB4XDTA0MDUwNzEyMDAwMFoXDTE0MDUwNzEy'
    + 'MDAwMFowRTEnMCUGA1UEChMeIERJUkVDVElPTiBHRU5FUkFMRSBERVMgSU1QT1RT'
    + 'MRowGAYDVQQDExEgQUMgTUlORUZJIEIgVEVTVDCBnzANBgkqhkiG9w0BAQEFAAOB'
    + 'jQAwgYkCgYEAveoCUOAukZdcFCs2qJk76vSqEX0ZFzHqQ6faBPZWjwkgUNwZ6m6m'
    + 'qWvvyq1cuxhoDvpfC6NXILETawYc6MNwwxsOtVVIjuXlcF17NMejljJafbPximEt'
    + 'DQ4LcQeSp4K7FyFlIAMLyt3BQ77emGzU5fjFTvHSUNb3jblx0sV28c0CAwEAAaOB'
    + 'tTCBsjAfBgNVHSMEGDAWgBSEJ4bLbvEQY8cYMAFKPFD1/fFXlzAdBgNVHQ4EFgQU'
    + 'hCeGy27xEGPHGDABSjxQ9f3xV5cwDgYDVR0PAQH/BAQDAgEGMBEGCWCGSAGG+EIB'
    + 'AQQEAwIBBjA8BgNVHR8ENTAzMDGgL6AthitodHRwOi8vYWRvbmlzLnBrNy5jZXJ0'
    + 'cGx1cy5uZXQvZGdpLXRlc3QuY3JsMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcN'
    + 'AQEFBQADgYEAmToHJWjd3+4zknfsP09H6uMbolHNGG0zTS2lrLKpzcmkQfjhQpT9'
    + 'LUTBvfs1jdjo9fGmQLvOG+Sm51Rbjglb8bcikVI5gLbclOlvqLkm77otjl4U4Z2/'
    + 'Y0vP14Aov3Sn3k+17EfReYUZI4liuB95ncobC4e8ZM++LjQcIM0s+Vs='));
end;

procedure TCertTest.TestCrl1;
begin
  CheckCrl(1, DecodeBase64(
    'MIICjTCCAfowDQYJKoZIhvcNAQECBQAwXzELMAkGA1UEBhMCVVMxIDAeBgNVBAoT'
    + 'F1JTQSBEYXRhIFNlY3VyaXR5LCBJbmMuMS4wLAYDVQQLEyVTZWN1cmUgU2VydmVy'
    + 'IENlcnRpZmljYXRpb24gQXV0aG9yaXR5Fw05NTA1MDIwMjEyMjZaFw05NTA2MDEw'
    + 'MDAxNDlaMIIBaDAWAgUCQQAABBcNOTUwMjAxMTcyNDI2WjAWAgUCQQAACRcNOTUw'
    + 'MjEwMDIxNjM5WjAWAgUCQQAADxcNOTUwMjI0MDAxMjQ5WjAWAgUCQQAADBcNOTUw'
    + 'MjI1MDA0NjQ0WjAWAgUCQQAAGxcNOTUwMzEzMTg0MDQ5WjAWAgUCQQAAFhcNOTUw'
    + 'MzE1MTkxNjU0WjAWAgUCQQAAGhcNOTUwMzE1MTk0MDQxWjAWAgUCQQAAHxcNOTUw'
    + 'MzI0MTk0NDMzWjAWAgUCcgAABRcNOTUwMzI5MjAwNzExWjAWAgUCcgAAERcNOTUw'
    + 'MzMwMDIzNDI2WjAWAgUCQQAAIBcNOTUwNDA3MDExMzIxWjAWAgUCcgAAHhcNOTUw'
    + 'NDA4MDAwMjU5WjAWAgUCcgAAQRcNOTUwNDI4MTcxNzI0WjAWAgUCcgAAOBcNOTUw'
    + 'NDI4MTcyNzIxWjAWAgUCcgAATBcNOTUwNTAyMDIxMjI2WjANBgkqhkiG9w0BAQIF'
    + 'AAN+AHqOEJXSDejYy0UwxxrH/9+N2z5xu/if0J6qQmK92W0hW158wpJg+ovV3+wQ'
    + 'wvIEPRL2rocL0tKfAsVq1IawSJzSNgxG0lrcla3MrJBnZ4GaZDu4FutZh72MR3Gt'
    + 'JaAL3iTJHJD55kK2D/VoyY1djlsPuNh6AEgdVwFAyp0v'));
end;

procedure TCertTest.TestEmptyDNCert;
begin
  CheckCertificate(18, DecodeBase64(
    'MIICfTCCAeagAwIBAgIBajANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJVUzEMMAoGA1UEChMD'
    + 'Q0RXMQkwBwYDVQQLEwAxCTAHBgNVBAcTADEJMAcGA1UECBMAMRowGAYDVQQDExFUZW1wbGFyIFRl'
    + 'c3QgMTAyNDEiMCAGCSqGSIb3DQEJARYTdGVtcGxhcnRlc3RAY2R3LmNvbTAeFw0wNjA1MjIwNTAw'
    + 'MDBaFw0xMDA1MjIwNTAwMDBaMHwxCzAJBgNVBAYTAlVTMQwwCgYDVQQKEwNDRFcxCTAHBgNVBAsT'
    + 'ADEJMAcGA1UEBxMAMQkwBwYDVQQIEwAxGjAYBgNVBAMTEVRlbXBsYXIgVGVzdCAxMDI0MSIwIAYJ'
    + 'KoZIhvcNAQkBFhN0ZW1wbGFydGVzdEBjZHcuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB'
    + 'gQDH3aJpJBfM+A3d84j5YcU6zEQaQ76u5xO9NSBmHjZykKS2kCcUqPpvVOPDA5WgV22dtKPh+lYV'
    + 'iUp7wyCVwAKibq8HIbihHceFqMKzjwC639rMoDJ7bi/yzQWz1Zg+075a4FGPlUKn7Yfu89wKkjdW'
    + 'wDpRPXc/agqBnrx5pJTXzQIDAQABow8wDTALBgNVHQ8EBAMCALEwDQYJKoZIhvcNAQEEBQADgYEA'
    + 'RRsRsjse3i2/KClFVd6YLZ+7K1BE0WxFyY2bbytkwQJSxvv3vLSuweFUbhNxutb68wl/yW4GLy4b'
    + '1QdyswNxrNDXTuu5ILKhRDDuWeocz83aG2KGtr3JlFyr3biWGEyn5WUOE6tbONoQDJ0oPYgI6CAc'
    + 'EHdUp0lioOCt6UOw7Cs='));
end;

procedure TCertTest.CheckCreation1;
var
  LCertGen: IX509V3CertificateGenerator;
  LCertGen1: IX509V1CertificateGenerator;
  LName: IX509Name;
  LCert: IX509Certificate;
  LSigner: ISignatureFactory;
  LDummySet: TCryptoLibStringArray;
  LParser: IX509CertificateParser;
  LKeyUsage: TCryptoLibBooleanArray;
  LEkus: TCryptoLibGenericArray<IDerObjectIdentifier>;
  LSanExt: IGeneralNames;
  LGns: TCryptoLibGenericArray<IGeneralName>;
  LAsn1Str: IAsn1String;
  LAltNames: TCryptoLibGenericArray<TCryptoLibGenericArray<TValue>>;
  I: Int32;
  LUtc: TDateTime;
begin
  LName := CreateX509Name;
  LUtc := TTimeZone.Local.ToUniversalTime(Now);

  LCertGen := TX509V3CertificateGenerator.Create;
  LCertGen.SetSerialNumber(TBigInteger.One);
  LCertGen.SetIssuerDN(LName);
  LCertGen.SetNotBeforeUtc(IncSecond(LUtc, -50));
  LCertGen.SetNotAfterUtc(IncSecond(LUtc, 50));
  LCertGen.SetSubjectDN(LName);
  LCertGen.SetPublicKey(FRsaPublic);

  LSigner := TAsn1SignatureFactory.Create('SHA256WithRSAEncryption', FRsaPrivate, nil);
  LCert := LCertGen.Generate(LSigner);

  LCert.CheckValidity(LUtc);
  LCert.Verify(FRsaPublic);

  LDummySet := LCert.GetNonCriticalExtensionOids();
  if LDummySet <> nil then
    Fail('non-critical oid set should be null');
  LDummySet := LCert.GetCriticalExtensionOids();
  if LDummySet <> nil then
    Fail('critical oid set should be null');

  LCertGen := TX509V3CertificateGenerator.Create;
  LCertGen.SetSerialNumber(TBigInteger.One);
  LCertGen.SetIssuerDN(LName);
  LCertGen.SetNotBeforeUtc(IncSecond(LUtc, -50));
  LCertGen.SetNotAfterUtc(IncSecond(LUtc, 50));
  LCertGen.SetSubjectDN(LName);
  LCertGen.SetPublicKey(FRsaPublic);
  LCertGen.AddExtension('2.5.29.15', True, TKeyUsage.Create(TKeyUsage.EncipherOnly) as IKeyUsage);
  LCertGen.AddExtension(TX509Extensions.ExtendedKeyUsage.ID, True, TDerSequence.Create(TKeyPurposeId.AnyExtendedKeyUsage) as IDerSequence);
  LCertGen.AddExtension('2.5.29.17', True, TGeneralNames.Create(TGeneralName.Create(TGeneralName.Rfc822Name, 'test@test.test') as IGeneralName) as IGeneralNames);

  LSigner := TAsn1SignatureFactory.Create('MD5WithRSAEncryption', FRsaPrivate, nil);
  LCert := LCertGen.Generate(LSigner);

  LCert.CheckValidity(LUtc);
  LCert.Verify(FRsaPublic);

  LParser := TX509CertificateParser.Create;
  LCert := LParser.ReadCertificate(LCert.GetEncoded());

  LKeyUsage := LCert.GetKeyUsage();
  if (LKeyUsage = nil) or (System.Length(LKeyUsage) <= 7) or (not LKeyUsage[7]) then
    Fail('error generating cert - key usage wrong.');

  LEkus := LCert.GetExtendedKeyUsage();
  if (LEkus = nil) or (System.Length(LEkus) < 1) or (not TKeyPurposeId.AnyExtendedKeyUsage.Equals(LEkus[0])) then
    Fail('failed extended key usage test');

  LSanExt := LCert.GetSubjectAlternativeNameExtension();
  if LSanExt <> nil then
  begin
    LGns := LSanExt.GetNames();
    for I := 0 to System.High(LGns) do
    begin
      if LGns[I].TagNo <> TGeneralName.Rfc822Name then
        Fail('failed subject alternative name extension test');
      if not Supports(LGns[I].Name, IAsn1String, LAsn1Str) then
        Fail('failed subject alternative name extension test');
      if LAsn1Str.GetString() <> 'test@test.test' then
        Fail('failed subject alternative name extension test');
    end;
  end;

  LAltNames := LCert.GetSubjectAlternativeNames();
  if LAltNames <> nil then
    for I := 0 to System.High(LAltNames) do
      if (System.Length(LAltNames[I]) < 2) or (LAltNames[I][0].AsInteger <> TGeneralName.Rfc822Name) or (LAltNames[I][1].AsString <> 'test@test.test') then
        Fail('failed subject alternative names test');

  LCertGen1 := TX509V1CertificateGenerator.Create;
  LCertGen1.SetSerialNumber(TBigInteger.One);
  LCertGen1.SetIssuerDN(LName);
  LCertGen1.SetNotBeforeUtc(IncSecond(LUtc, -50));
  LCertGen1.SetNotAfterUtc(IncSecond(LUtc, 50));
  LCertGen1.SetSubjectDN(LName);
  LCertGen1.SetPublicKey(FRsaPublic);

  LSigner := TAsn1SignatureFactory.Create('MD5WithRSAEncryption', FRsaPrivate, nil);
  LCert := LCertGen1.Generate(LSigner);

  LCert.CheckValidity(LUtc);
  LCert.Verify(FRsaPublic);

  LParser := TX509CertificateParser.Create;
  LCert := LParser.ReadCertificate(LCert.GetEncoded());
  if not LCert.IssuerDN.Equivalent(LCert.SubjectDN, True) then
    Fail('name comparison fails');
end;

procedure TCertTest.CheckCreation2;
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LDpg: IDsaParametersGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LCertGen: IX509V3CertificateGenerator;
  LName: IX509Name;
  LCert: IX509Certificate;
  LSigner: ISignatureFactory;
  LUtc: TDateTime;
begin
  LUtc := TTimeZone.Local.ToUniversalTime(Now);
  LDpg := TDsaParametersGenerator.Create;
  LDpg.Init(512, 25, FSecureRandom);
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('DSA');
  LKpg.Init(TDsaKeyGenerationParameters.Create(FSecureRandom, LDpg.GenerateParameters) as IDsaKeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair();

  LName := CreateX509Name;

  LCertGen := TX509V3CertificateGenerator.Create;
  LCertGen.SetSerialNumber(TBigInteger.One);
  LCertGen.SetIssuerDN(LName);
  LCertGen.SetNotBeforeUtc(IncSecond(LUtc, -50));
  LCertGen.SetNotAfterUtc(IncSecond(LUtc, 50));
  LCertGen.SetSubjectDN(LName);
  LCertGen.SetPublicKey(LKp.Public);

  LSigner := TAsn1SignatureFactory.Create('SHA1WITHDSA', LKp.Private, nil);
  LCert := LCertGen.Generate(LSigner);

  LCert.CheckValidity(LUtc);
  LCert.Verify(LKp.Public);
end;

procedure TCertTest.CheckCreation3;
var
  LX9: IX9ECParameters;
  LCurve: IECCurve;
  LSpec: IECDomainParameters;
  LPrivKey: IECPrivateKeyParameters;
  LPubKey: IECPublicKeyParameters;
  LOrd: TList<IDerObjectIdentifier>;
  LValues: TList<String>;
  LName: IX509Name;
  LS: String;
  LCertGen: IX509V3CertificateGenerator;
  LCert: IX509Certificate;
  LParser: IX509CertificateParser;
  LUtc: TDateTime;
  LQ: IECPoint;
  LPr: IX509Name;
begin
  LX9 := TECNamedCurveTable.GetByName('prime239v1');
  if LX9 = nil then
    Fail('prime239v1 curve not available (X962 named curves not found)');

  LCurve := LX9.Curve;
  LSpec := TECDomainParameters.FromX9ECParameters(LX9);

  LPrivKey := TECPrivateKeyParameters.Create('ECDSA',
    TBigInteger.Create('876300101507107567501066130761671078357010671067781776716671676178726717'),
    LSpec);

  LPubKey := TECPublicKeyParameters.Create('ECDSA',
    LCurve.DecodePoint(THexEncoder.Decode('025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70')),
    LSpec);

  LOrd := TList<IDerObjectIdentifier>.Create;
  LValues := TList<String>.Create;
  try
    LOrd.Add(TX509Name.C);
    LOrd.Add(TX509Name.O);
    LOrd.Add(TX509Name.L);
    LOrd.Add(TX509Name.ST);
    LOrd.Add(TX509Name.E);

    LValues.Add('NG');
    LValues.Add('CryptoLib4Pascal');
    LValues.Add('Alausa');
    LValues.Add('Lagos');
    LValues.Add('feedback-crypto@cryptolib4pascal.org');

    LName := TX509Name.Create(LOrd, LValues);
    LS := LName.ToString();
    if LS <> 'C=NG,O=CryptoLib4Pascal,L=Alausa,ST=Lagos,E=feedback-crypto@cryptolib4pascal.org' then
      Fail('ordered X509Principal test failed - s = ' + LS + '.');

    LCertGen := TX509V3CertificateGenerator.Create;
    LCertGen.SetSerialNumber(TBigInteger.One);
    LCertGen.SetIssuerDN(LName);
    LUtc := TTimeZone.Local.ToUniversalTime(Now);
    LCertGen.SetNotBeforeUtc(IncSecond(LUtc, -50));
    LCertGen.SetNotAfterUtc(IncSecond(LUtc, 50));
    LCertGen.SetSubjectDN(LName);
    LCertGen.SetPublicKey(LPubKey);

    try
      LCert := LCertGen.Generate(TAsn1SignatureFactory.Create('SHA1withECDSA', LPrivKey, nil) as ISignatureFactory);

      LCert.CheckValidity(LUtc);
      LCert.Verify(LPubKey);

      LParser := TX509CertificateParser.Create;
      LCert := LParser.ReadCertificate(LCert.GetEncoded());

      LQ := LPubKey.q.Normalize();
      LPubKey := TECPublicKeyParameters.Create(LPubKey.AlgorithmName,
        LCurve.CreatePoint(LQ.XCoord.ToBigInteger(), LQ.YCoord.ToBigInteger()),
        LPubKey.Parameters);

      LCertGen.SetPublicKey(LPubKey);
      LCert := LCertGen.Generate(TAsn1SignatureFactory.Create('SHA1withECDSA', LPrivKey, nil) as ISignatureFactory);

      LCert.CheckValidity(LUtc);
      LCert.Verify(LPubKey);

      LParser := TX509CertificateParser.Create;
      LCert := LParser.ReadCertificate(LCert.GetEncoded());
    except
      on E: Exception do
        Fail('error setting generating cert - ' + E.ClassName + ': ' + E.Message);
    end;

    LPr := TX509Name.Create('O="CryptoLib4Pascal, Demo",E=feedback-crypto@cryptolib4pascal.org,ST=Lagos,L=Alausa,C=NG');
    if LPr.ToString() <> 'O=CryptoLib4Pascal\, Demo,E=feedback-crypto@cryptolib4pascal.org,ST=Lagos,L=Alausa,C=NG' then
      Fail('string based X509Principal test failed.');

    LPr := TX509Name.Create('O=CryptoLib4Pascal\, Demo,E=feedback-crypto@cryptolib4pascal.org,ST=Lagos,L=Alausa,C=NG');
    if LPr.ToString() <> 'O=CryptoLib4Pascal\, Demo,E=feedback-crypto@cryptolib4pascal.org,ST=Lagos,L=Alausa,C=NG' then
      Fail('string based X509Principal test failed.');
  finally
    LOrd.Free;
    LValues.Free;
  end;
end;

procedure TCertTest.CheckCreation5;
var
  LPubKey: IRsaKeyParameters;
  LPrivKey: IRsaPrivateCrtKeyParameters;
  LPubMod, LPubExp: TBigInteger;
  LPrivMod, LPrivExp, LPrivP, LPrivQ, LPrivDP, LPrivDQ, LPrivQinv: TBigInteger;
  LOrd: TList<IDerObjectIdentifier>;
  LValues: TList<String>;
  LCertGen: IX509V3CertificateGenerator;
  LName: IX509Name;
  LBaseCert, LCert: IX509Certificate;
  LSigner: ISignatureFactory;
  LOid1, LOid2: IDerObjectIdentifier;
  LBaseVal, LCertVal: IAsn1OctetString;
  LDudKey: IAsymmetricKeyParameter;
  LUtc: TDateTime;
begin
  LUtc := TTimeZone.Local.ToUniversalTime(Now);
  LPubMod := TBigInteger.Create('b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7', 16);
  LPubExp := TBigInteger.Create('11', 16);
  LPrivMod := LPubMod;
  LPrivExp := TBigInteger.Create('9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89', 16);
  LPrivP := TBigInteger.Create('c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb', 16);
  LPrivQ := TBigInteger.Create('f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5', 16);
  LPrivDP := TBigInteger.Create('b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391', 16);
  LPrivDQ := TBigInteger.Create('d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd', 16);
  LPrivQinv := TBigInteger.Create('b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19', 16);

  LPubKey := TRsaKeyParameters.Create(False, LPubMod, LPubExp);
  LPrivKey := TRsaPrivateCrtKeyParameters.Create(LPrivMod, LPubExp, LPrivExp, LPrivP, LPrivQ, LPrivDP, LPrivDQ, LPrivQinv);

  LOrd := TList<IDerObjectIdentifier>.Create;
  LValues := TList<String>.Create;
  try
    LOrd.Add(TX509Name.C);
    LOrd.Add(TX509Name.O);
    LOrd.Add(TX509Name.L);
    LOrd.Add(TX509Name.ST);
    LOrd.Add(TX509Name.E);
    LValues.Add('NG');
    LValues.Add('CryptoLib4Pascal');
    LValues.Add('Alausa');
    LValues.Add('Lagos');
    LValues.Add('feedback-crypto@cryptolib4pascal.org');
    LName := TX509Name.Create(LOrd, LValues);

    LCertGen := TX509V3CertificateGenerator.Create;
    LCertGen.SetSerialNumber(TBigInteger.One);
    LCertGen.SetIssuerDN(LName);
    LCertGen.SetNotBeforeUtc(IncSecond(LUtc, -50));
    LCertGen.SetNotAfterUtc(IncSecond(LUtc, 50));
    LCertGen.SetSubjectDN(LName);
    LCertGen.SetPublicKey(LPubKey);
    LCertGen.AddExtension('2.5.29.15', True, TKeyUsage.Create(TKeyUsage.EncipherOnly) as IKeyUsage);
    LCertGen.AddExtension(TX509Extensions.ExtendedKeyUsage.ID, True, TDerSequence.Create(TKeyPurposeId.AnyExtendedKeyUsage) as IDerSequence);
    LCertGen.AddExtension('2.5.29.17', True, TGeneralNames.Create(TGeneralName.Create(TGeneralName.Rfc822Name, 'test@test.test') as IGeneralName) as IGeneralNames);

    LSigner := TAsn1SignatureFactory.Create('MD5WithRSAEncryption', LPrivKey, nil);
    LBaseCert := LCertGen.Generate(LSigner);

    LCertGen := TX509V3CertificateGenerator.Create;
    LCertGen.SetSerialNumber(TBigInteger.One);
    LCertGen.SetIssuerDN(LName);
    LCertGen.SetNotBeforeUtc(IncSecond(LUtc, -50));
    LCertGen.SetNotAfterUtc(IncSecond(LUtc, 50));
    LCertGen.SetSubjectDN(LName);
    LCertGen.SetPublicKey(LPubKey);
    LCertGen.CopyAndAddExtension(TDerObjectIdentifier.Create('2.5.29.15') as IDerObjectIdentifier, True, LBaseCert);
    LCertGen.CopyAndAddExtension(TX509Extensions.ExtendedKeyUsage, False, LBaseCert);

    LCert := LCertGen.Generate(LSigner);

    LCert.CheckValidity(LUtc);
    LCert.Verify(LPubKey);

    LOid1 := TDerObjectIdentifier.Create('2.5.29.15');
    LBaseVal := LBaseCert.CertificateStructure.Extensions.GetExtensionValue(LOid1);
    LCertVal := LCert.CertificateStructure.Extensions.GetExtensionValue(LOid1);
    if (LBaseVal = nil) <> (LCertVal = nil) then
      Fail('2.5.29.15 differs');
    if (LBaseVal <> nil) and (not AreEqual(LBaseVal.GetEncoded(), LCertVal.GetEncoded())) then
      Fail('2.5.29.15 differs');

    LOid2 := TX509Extensions.ExtendedKeyUsage;
    LBaseVal := LBaseCert.GetExtensionValue(LOid2);
    LCertVal := LCert.GetExtensionValue(LOid2);
    if (LBaseVal = nil) <> (LCertVal = nil) then
      Fail('2.5.29.37 differs');
    if (LBaseVal <> nil) and (not AreEqual(LBaseVal.GetEncoded(), LCertVal.GetEncoded())) then
      Fail('2.5.29.37 differs');

    { Exception test: same LCertGen - CopyAndAddExtension(unknown OID) raises "not present" }
    try
      LCertGen.CopyAndAddExtension(TDerObjectIdentifier.Create('2.5.99.99') as IDerObjectIdentifier, True, LBaseCert);
      Fail('exception not thrown on dud extension copy');
    except
      on E: EArgumentCryptoLibException do
        ; { expected }
    end;

    { Dud key test: same LCertGen, set dud key and Generate }
    LDudKey := TDudPublicKey.Create as IAsymmetricKeyParameter;
    try
      LCertGen.SetPublicKey(LDudKey);
      LCertGen.Generate(LSigner);
      Fail('key without encoding not detected in v3');
    except
      on E: EArgumentCryptoLibException do
        ; { expected }
    end;
  finally
    LOrd.Free;
    LValues.Free;
  end;
end;

procedure TCertTest.CheckCrlCreation1;
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LCrlGen: IX509V2CrlGenerator;
  LCrl: IX509Crl;
  LEntry: IX509CrlEntry;
  LAuthKeyID: IAuthorityKeyIdentifier;
  LExt: IAsn1OctetString;
  LReasonCode: IDerEnumerated;
  LReason: ICrlReason;
  LRsaParams: IRsaKeyGenerationParameters;
  LUtc: TDateTime;
begin
  LUtc := TTimeZone.Local.ToUniversalTime(Now);
  LRsaParams := TRsaKeyGenerationParameters.Create(TBigInteger.ValueOf($10001), FSecureRandom, 768, 25);
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('RSA');
  LKpg.Init(LRsaParams);
  LKp := LKpg.GenerateKeyPair();

  LCrlGen := TX509V2CrlGenerator.Create;
  LCrlGen.SetIssuerDN(TX509Name.Create('CN=Test CA') as IX509Name);
  LCrlGen.SetThisUpdateUtc(LUtc);
  LCrlGen.SetNextUpdateUtc(IncSecond(LUtc, 100));
  LCrlGen.AddCrlEntryUtc(TBigInteger.One, LUtc, TCrlReason.PrivilegeWithdrawn);
  LCrlGen.AddExtension(TX509Extensions.AuthorityKeyIdentifier, False,
    TX509ExtensionUtilities.CreateAuthorityKeyIdentifier(TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(LKp.Public)));

  LCrl := LCrlGen.Generate(TAsn1SignatureFactory.Create('SHA256WithRSAEncryption', LKp.Private, nil) as ISignatureFactory);

  if not LCrl.IssuerDN.Equivalent(TX509Name.Create('CN=Test CA') as IX509Name, True) then
    Fail('failed CRL issuer test');

  LAuthKeyID := TX509ExtensionUtilities.GetAuthorityKeyIdentifier(LCrl.CertificateList.Extensions);
  if LAuthKeyID = nil then
    Fail('failed to find CRL extension');

  LEntry := LCrl.GetRevokedCertificate(TBigInteger.One);
  if LEntry = nil then
    Fail('failed to find CRL entry');

  if not LEntry.SerialNumber.Equals(TBigInteger.One) then
    Fail('CRL cert serial number does not match');

  if not LEntry.HasExtensions then
    Fail('CRL entry extension not found');

  LExt := LEntry.GetExtensionValue(TX509Extensions.ReasonCode);
  if LExt <> nil then
  begin
    LReasonCode := TX509ExtensionUtilities.FromExtensionValue(LExt) as IDerEnumerated;
    LReason := TCrlReason.Create(LReasonCode);
    if not LReason.HasValue(TCrlReason.PrivilegeWithdrawn) then
      Fail('CRL entry reasonCode wrong');
  end
  else
    Fail('CRL entry reasonCode not found');
end;

procedure TCertTest.CheckCrlCreation2;
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LCrlGen: IX509V2CrlGenerator;
  LCrl: IX509Crl;
  LEntry: IX509CrlEntry;
  LAuthKeyID: IAuthorityKeyIdentifier;
  LExt: IAsn1OctetString;
  LReasonCode: IDerEnumerated;
  LReason: ICrlReason;
  LRsaParams: IRsaKeyGenerationParameters;
  LExtOids: TList<IDerObjectIdentifier>;
  LExtValues: TList<IX509Extension>;
  LEntryExts: IX509Extensions;
  LCrlReason: ICrlReason;
  LUtc: TDateTime;
begin
  LUtc := TTimeZone.Local.ToUniversalTime(Now);
  LRsaParams := TRsaKeyGenerationParameters.Create(TBigInteger.ValueOf($10001), FSecureRandom, 768, 25);
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('RSA');
  LKpg.Init(LRsaParams);
  LKp := LKpg.GenerateKeyPair();

  LCrlGen := TX509V2CrlGenerator.Create;
  LCrlGen.SetIssuerDN(TX509Name.Create('CN=Test CA') as IX509Name);
  LCrlGen.SetThisUpdateUtc(LUtc);
  LCrlGen.SetNextUpdateUtc(IncSecond(LUtc, 100));

  LExtOids := TList<IDerObjectIdentifier>.Create;
  LExtValues := TList<IX509Extension>.Create;
  try
    LCrlReason := TCrlReason.Create(TCrlReason.PrivilegeWithdrawn);
    LExtOids.Add(TX509Extensions.ReasonCode);
    LExtValues.Add(TX509Extension.Create(False, TDerOctetString.Create(LCrlReason.GetEncoded()) as IDerOctetString) as IX509Extension);
    LEntryExts := TX509Extensions.Create(LExtOids, LExtValues);

    LCrlGen.AddCrlEntryUtc(TBigInteger.One, LUtc, LEntryExts);
    LCrlGen.AddExtension(TX509Extensions.AuthorityKeyIdentifier, False,
      TX509ExtensionUtilities.CreateAuthorityKeyIdentifier(TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(LKp.Public)));

    LCrl := LCrlGen.Generate(TAsn1SignatureFactory.Create('SHA256WithRSAEncryption', LKp.Private, nil) as ISignatureFactory);

    if not LCrl.IssuerDN.Equivalent(TX509Name.Create('CN=Test CA') as IX509Name, True) then
      Fail('failed CRL issuer test');

    LAuthKeyID := TX509ExtensionUtilities.GetAuthorityKeyIdentifier(LCrl.CertificateList.Extensions);
    if LAuthKeyID = nil then
      Fail('failed to find CRL extension');

    LEntry := LCrl.GetRevokedCertificate(TBigInteger.One);
    if LEntry = nil then
      Fail('failed to find CRL entry');

    if not LEntry.SerialNumber.Equals(TBigInteger.One) then
      Fail('CRL cert serial number does not match');

    if not LEntry.HasExtensions then
      Fail('CRL entry extension not found');

    LExt := LEntry.GetExtensionValue(TX509Extensions.ReasonCode);
    if LExt <> nil then
    begin
      LReasonCode := TX509ExtensionUtilities.FromExtensionValue(LExt) as IDerEnumerated;
      LReason := TCrlReason.Create(LReasonCode);
      if not LReason.HasValue(TCrlReason.PrivilegeWithdrawn) then
        Fail('CRL entry reasonCode wrong');
    end
    else
      Fail('CRL entry reasonCode not found');
  finally
    LExtOids.Free;
    LExtValues.Free;
  end;
end;

procedure TCertTest.CheckCrlCreation3;
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LCrlGen: IX509V2CrlGenerator;
  LCrl, LNewCrl, LReadCrl: IX509Crl;
  LCrlParser: IX509CrlParser;
  LEntry: IX509CrlEntry;
  LExtOids: TList<IDerObjectIdentifier>;
  LExtValues: TList<IX509Extension>;
  LEntryExts: IX509Extensions;
  LCrlReason: ICrlReason;
  LRevoked: TCryptoLibGenericArray<IX509CrlEntry>;
  LExt: IAsn1OctetString;
  LReasonCode: IDerEnumerated;
  LReason: ICrlReason;
  LAuthKeyId: IAuthorityKeyIdentifier;
  LCol: TCryptoLibGenericArray<IX509Crl>;
  I: Int32;
  LCount: Int32;
  LOneFound, LTwoFound: Boolean;
  LUtc: TDateTime;
begin
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('RSA');
  LKpg.Init(TRsaKeyGenerationParameters.Create(TBigInteger.ValueOf($10001), FSecureRandom, 768, 25) as IRsaKeyGenerationParameters);
  LUtc := TTimeZone.Local.ToUniversalTime(Now);
  LKp := LKpg.GenerateKeyPair();

  LExtOids := TList<IDerObjectIdentifier>.Create;
  LExtValues := TList<IX509Extension>.Create;
  try
    LCrlReason := TCrlReason.Create(TCrlReason.PrivilegeWithdrawn);
    LExtOids.Add(TX509Extensions.ReasonCode);
    LExtValues.Add(TX509Extension.Create(False, TDerOctetString.Create(LCrlReason.GetEncoded()) as IDerOctetString) as IX509Extension);
    LEntryExts := TX509Extensions.Create(LExtOids, LExtValues);

    LCrlGen := TX509V2CrlGenerator.Create;
    LCrlGen.SetIssuerDN(TX509Name.Create('CN=Test CA') as IX509Name);
    LCrlGen.SetThisUpdateUtc(LUtc);
    LCrlGen.SetNextUpdateUtc(IncSecond(LUtc, 100));
    LCrlGen.AddCrlEntryUtc(TBigInteger.One, LUtc, LEntryExts);
    LCrlGen.AddExtension(TX509Extensions.AuthorityKeyIdentifier, False,
      TX509ExtensionUtilities.CreateAuthorityKeyIdentifier(TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(LKp.Public)));
    LCrl := LCrlGen.Generate(TAsn1SignatureFactory.Create('SHA256WithRSAEncryption', LKp.Private, nil) as ISignatureFactory);

    if not LCrl.IssuerDN.Equivalent(TX509Name.Create('CN=Test CA') as IX509Name, True) then
      Fail('failed CRL issuer test');

    LAuthKeyId := TX509ExtensionUtilities.GetAuthorityKeyIdentifier(LCrl.GetCertificateList.Extensions);
    if LAuthKeyId = nil then
      Fail('failed to find CRL extension');

    LEntry := LCrl.GetRevokedCertificate(TBigInteger.One);
    if LEntry = nil then
      Fail('failed to find CRL entry');

    if not LEntry.SerialNumber.Equals(TBigInteger.One) then
      Fail('CRL cert serial number does not match');

    if not LEntry.HasExtensions then
      Fail('CRL entry extension not found');

    LExt := LEntry.GetExtensionValue(TX509Extensions.ReasonCode);
    if LExt = nil then
      Fail('CRL entry reasonCode not found');
    LReasonCode := TX509ExtensionUtilities.FromExtensionValue(LExt) as IDerEnumerated;
    LReason := TCrlReason.Create(LReasonCode);
    if not LReason.HasValue(TCrlReason.PrivilegeWithdrawn) then
      Fail('CRL entry reasonCode wrong');

    LUtc := TTimeZone.Local.ToUniversalTime(Now);
    LCrlGen := TX509V2CrlGenerator.Create;
    LCrlGen.SetIssuerDN(TX509Name.Create('CN=Test CA') as IX509Name);
    LCrlGen.SetThisUpdateUtc(LUtc);
    LCrlGen.SetNextUpdateUtc(IncSecond(LUtc, 100));
    LCrlGen.AddCrl(LCrl);
    LCrlGen.AddCrlEntryUtc(TBigInteger.Two, LUtc, LEntryExts);
    LCrlGen.AddExtension(TX509Extensions.AuthorityKeyIdentifier, False,
      TX509ExtensionUtilities.CreateAuthorityKeyIdentifier(TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(LKp.Public)));
    LNewCrl := LCrlGen.Generate(TAsn1SignatureFactory.Create('SHA256WithRSAEncryption', LKp.Private, nil) as ISignatureFactory);

    LCount := 0;
    LOneFound := False;
    LTwoFound := False;
    LRevoked := LNewCrl.GetRevokedCertificates();
    if LRevoked <> nil then
      for I := 0 to System.High(LRevoked) do
      begin
        if LRevoked[I].SerialNumber.Equals(TBigInteger.One) then
        begin
          LOneFound := True;
          LExt := LEntry.GetExtensionValue(TX509Extensions.ReasonCode);
          if LExt = nil then
            Fail('CRL entry reasonCode not found');
          LReasonCode := TX509ExtensionUtilities.FromExtensionValue(LExt) as IDerEnumerated;
          LReason := TCrlReason.Create(LReasonCode);
          if not LReason.HasValue(TCrlReason.PrivilegeWithdrawn) then
            Fail('CRL entry reasonCode wrong');
        end
        else if LRevoked[I].SerialNumber.Equals(TBigInteger.Two) then
          LTwoFound := True;
        Inc(LCount);
      end;

    if LCount <> 2 then
      Fail('wrong number of CRLs found');

    if not (LOneFound and LTwoFound) then
      Fail('wrong CRLs found in copied list');

    LCrlParser := TX509CrlParser.Create;
    LReadCrl := LCrlParser.ReadCrl(LNewCrl.GetEncoded());
    if LReadCrl = nil then
      Fail('crl not returned!');

    LCol := LCrlParser.ReadCrls(LNewCrl.GetEncoded());
    if Length(LCol) <> 1 then
      Fail('wrong number of CRLs found in collection');
  finally
    LExtOids.Free;
    LExtValues.Free;
  end;
end;

procedure TCertTest.PemTest;
var
  LParser: IX509CertificateParser;
  LCrlParser: IX509CrlParser;
  LCert: IX509Certificate;
  LCrl: IX509Crl;
  LCertList: TCryptoLibGenericArray<IX509Certificate>;
  LCrlList: TCryptoLibGenericArray<IX509Crl>;
  LBytes: TBytes;
begin
  LBytes := TEncoding.ASCII.GetBytes(CERTIFICATE_1_PEM);
  LParser := TX509CertificateParser.Create;
  LCert := LParser.ReadCertificate(LBytes);
  if LCert = nil then
    Fail('PEM cert not read');

  LCert := LParser.ReadCertificate(TEncoding.ASCII.GetBytes('-----BEGIN CERTIFICATE-----' + CERTIFICATE_2_PEM));
  if LCert = nil then
    Fail('PEM cert with extraneous header not read');

  LCrlParser := TX509CrlParser.Create;
  LCrl := LCrlParser.ReadCrl(TEncoding.ASCII.GetBytes(CRL_1_PEM));
  if LCrl = nil then
    Fail('PEM crl not read');

  LCertList := LParser.ReadCertificates(TEncoding.ASCII.GetBytes(CERTIFICATE_2_PEM));
  if (System.Length(LCertList) <> 1) or (not AreEqual(LCert.GetEncoded(), LCertList[0].GetEncoded())) then
    Fail('PEM cert collection not right');

  LCrlList := LCrlParser.ReadCrls(TEncoding.ASCII.GetBytes(CRL_2_PEM));
  if (System.Length(LCrlList) <> 1) or (not AreEqual(LCrl.GetEncoded(), LCrlList[0].GetEncoded())) then
    Fail('PEM crl collection not right');
end;

procedure TCertTest.DoTestForgedSignature;
const
  LForgedCertB64 = 'MIIBsDCCAVoCAQYwDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UEBhMCQVUxEzARBgNV'
    + 'BAgTClF1ZWVuc2xhbmQxGjAYBgNVBAoTEUNyeXB0U29mdCBQdHkgTHRkMSMwIQYD'
    + 'VQQDExpTZXJ2ZXIgdGVzdCBjZXJ0ICg1MTIgYml0KTAeFw0wNjA5MTEyMzU4NTVa'
    + 'Fw0wNjEwMTEyMzU4NTVaMGMxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpRdWVlbnNs'
    + 'YW5kMRowGAYDVQQKExFDcnlwdFNvZnQgUHR5IEx0ZDEjMCEGA1UEAxMaU2VydmVy'
    + 'IHRlc3QgY2VydCAoNTEyIGJpdCkwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAn7PD'
    + 'hCeV/xIxUg8V70YRxK2A5jZbD92A12GN4PxyRQk0/lVmRUNMaJdq/qigpd9feP/u'
    + '12S4PwTLb/8q/v657QIDAQABMA0GCSqGSIb3DQEBBQUAA0EAbynCRIlUQgaqyNgU'
    + 'DF6P14yRKUtX8akOP2TwStaSiVf/akYqfLFm3UGka5XbPj4rifrZ0/sOoZEEBvHQ'
    + 'e20sRA==';
var
  LParser: IX509CertificateParser;
  LX509: IX509Certificate;
begin
  LParser := TX509CertificateParser.Create;
  LX509 := LParser.ReadCertificate(DecodeBase64(LForgedCertB64));
  try
    LX509.Verify(LX509.GetPublicKey());
    Fail('forged RSA signature passed');
  except
    { expected }
  end;
end;

procedure TCertTest.DoTestNullDerNullCert;
var
  LKp: IAsymmetricCipherKeyPair;
  LCertGen: IX509V3CertificateGenerator;
  LCert: IX509Certificate;
  LCertStruct: IX509CertificateStructure;
  LTbs: IAsn1Encodable;
  LSigAlg: IAlgorithmIdentifier;
  LSeq: IAsn1Sequence;
  LEncoded: TCryptoLibByteArray;
  LParser: IX509CertificateParser;
  LUtc: TDateTime;
begin
  LUtc := TTimeZone.Local.ToUniversalTime(Now);
  LKp := GenerateLongFixedKeys();
  LCertGen := TX509V3CertificateGenerator.Create;
  LCertGen.SetSerialNumber(TBigInteger.One);
  LCertGen.SetIssuerDN(TX509Name.Create('CN=Test') as IX509Name);
  LCertGen.SetNotBeforeUtc(IncSecond(LUtc, -50));
  LCertGen.SetNotAfterUtc(IncSecond(LUtc, 50));
  LCertGen.SetSubjectDN(TX509Name.Create('CN=Test') as IX509Name);
  LCertGen.SetPublicKey(LKp.Public);
  LCert := LCertGen.Generate(TAsn1SignatureFactory.Create('MD5WithRSAEncryption', LKp.Private, nil) as ISignatureFactory);

  LCertStruct := TX509CertificateStructure.GetInstance(TAsn1Object.FromByteArray(LCert.GetEncoded()));
  LTbs := LCertStruct.TbsCertificate;
  LSigAlg := LCertStruct.SignatureAlgorithm;
  LSeq := TDerSequence.Create([LTbs, TAlgorithmIdentifier.Create(LSigAlg.Algorithm) as IAlgorithmIdentifier, LCertStruct.Signature]);
  try
    LEncoded := LSeq.GetEncoded();
    LParser := TX509CertificateParser.Create;
    LCert := LParser.ReadCertificate(LEncoded);
    LCert.Verify(LCert.GetPublicKey());
  except
    on E: Exception do
      Fail('doTestNullDerNull failed - exception ' + E.ClassName + ': ' + E.Message);
  end;
end;

procedure TCertTest.PemFileTest;
var
  LFact: IX509CertificateParser;
  LCerts1: TCryptoLibGenericArray<IX509Certificate>;
  LStream: TStringStream;
  LC: IX509Certificate;
  I, J: Int32;
  LSet2: TList<IX509Certificate>;
  LEnc: TCryptoLibByteArray;
  LMatched: array of Boolean;
  LFound: Boolean;
begin
  LFact := TX509CertificateParser.Create;
  LStream := TStringStream.Create(CERT_CHAIN_CRLF, TEncoding.ASCII);
  try
    LCerts1 := LFact.ReadCertificates(LStream);
    if System.Length(LCerts1) <> 2 then
      Fail('certs wrong <cr><nl>');
  finally
    LStream.Free;
  end;

  LStream := TStringStream.Create(CERT_CHAIN_CRLF, TEncoding.ASCII);
  try
    LSet2 := TList<IX509Certificate>.Create;
    try
      repeat
        LC := LFact.ReadCertificate(LStream);
        if LC <> nil then
          LSet2.Add(LC);
      until LC = nil;
      if System.Length(LCerts1) <> LSet2.Count then
        Fail('certs size <cr><nl>');
      SetLength(LMatched, System.Length(LCerts1));
      for I := 0 to System.High(LMatched) do
        LMatched[I] := False;
      for J := 0 to LSet2.Count - 1 do
      begin
        LEnc := LSet2[J].GetEncoded();
        LFound := False;
        for I := 0 to System.High(LCerts1) do
          if (not LMatched[I]) and AreEqual(LCerts1[I].GetEncoded(), LEnc) then
          begin
            LMatched[I] := True;
            LFound := True;
            Break;
          end;
        if not LFound then
          Fail('collection not empty');
      end;
      for I := 0 to System.High(LMatched) do
        if not LMatched[I] then
          Fail('collection not empty');
    finally
      LSet2.Free;
    end;
  finally
    LStream.Free;
  end;
end;

procedure TCertTest.InvalidCrls;
var
  LCrlParser: IX509CrlParser;
  LCrls: TCryptoLibGenericArray<IX509Crl>;
  LCrl: IX509Crl;
  LStream: TStringStream;
begin
  LCrlParser := TX509CrlParser.Create;
  LStream := TStringStream.Create(CERT_CHAIN_CRLF, TEncoding.ASCII);
  try
    LCrls := LCrlParser.ReadCrls(LStream);
    if System.Length(LCrls) <> 0 then
      Fail('multi crl');
  finally
    LStream.Free;
  end;
  LStream := TStringStream.Create(CERT_CHAIN_CRLF, TEncoding.ASCII);
  try
    LCrl := LCrlParser.ReadCrl(LStream);
    if LCrl <> nil then
      Fail('single crl');
  finally
    LStream.Free;
  end;
end;

procedure TCertTest.PemFileTestWithNl;
var
  LFact: IX509CertificateParser;
  LCerts1: TCryptoLibGenericArray<IX509Certificate>;
  LStream: TStringStream;
  LC: IX509Certificate;
  I, J: Int32;
  LSet2: TList<IX509Certificate>;
  LEnc: TCryptoLibByteArray;
  LMatched: array of Boolean;
  LFound: Boolean;
begin
  LFact := TX509CertificateParser.Create;
  LStream := TStringStream.Create(CERT_CHAIN_NL, TEncoding.ASCII);
  try
    LCerts1 := LFact.ReadCertificates(LStream);
    if System.Length(LCerts1) <> 2 then
      Fail('certs wrong <nl>');
  finally
    LStream.Free;
  end;

  LStream := TStringStream.Create(CERT_CHAIN_NL, TEncoding.ASCII);
  try
    LSet2 := TList<IX509Certificate>.Create;
    try
      repeat
        LC := LFact.ReadCertificate(LStream);
        if LC <> nil then
          LSet2.Add(LC);
      until LC = nil;
      if System.Length(LCerts1) <> LSet2.Count then
        Fail('certs size <nl>');
      SetLength(LMatched, System.Length(LCerts1));
      for I := 0 to System.High(LMatched) do
        LMatched[I] := False;
      for J := 0 to LSet2.Count - 1 do
      begin
        LEnc := LSet2[J].GetEncoded();
        LFound := False;
        for I := 0 to System.High(LCerts1) do
          if (not LMatched[I]) and AreEqual(LCerts1[I].GetEncoded(), LEnc) then
          begin
            LMatched[I] := True;
            LFound := True;
            Break;
          end;
        if not LFound then
          Fail('collection not empty');
      end;
      for I := 0 to System.High(LMatched) do
        if not LMatched[I] then
          Fail('collection not empty');
    finally
      LSet2.Free;
    end;
  finally
    LStream.Free;
  end;
end;

procedure TCertTest.Pkcs7Test;
var
  LRootCertBin, LRootCrlBin, LAttrCert: TCryptoLibByteArray;
  LContentInfo: ICmsContentInfo;
  LSigData: ICmsSignedData;
  LCertSet, LCrlSet: IAsn1Set;
  LTaggedAttr: IAsn1Encodable;
  LInfoEnc: TCryptoLibByteArray;
  LCertParser: IX509CertificateParser;
  LCrlParser: IX509CrlParser;
  LCert: IX509Certificate;
  LCrl: IX509Crl;
  LCertList: TCryptoLibGenericArray<IX509Certificate>;
  LCrlList: TCryptoLibGenericArray<IX509Crl>;
  LCrlProblemBin: TCryptoLibByteArray;
  LRootCertObj, LRootCrlObj: IAsn1Encodable;
const
  RootCertB64 = 'MIIBqzCCARQCAQEwDQYJKoZIhvcNAQEFBQAwHjEcMBoGA1UEAxMTVGVzdCBDQSBDZXJ0aWZpY2F0ZTAeFw0wODA5MDQwNDQ1MDhaFw0wODA5MTEwNDQ1MDhaMB4xHDAaBgNVBAMTE1Rlc3QgQ0EgQ2VydGlmaWNhdGUwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMRLUjhPe4YUdLo6EcjKcWUOG7CydFTH53Pr1lWjOkbmszYDpkhCTT'
    + '9LOsI+disk18nkBxSl8DAHTqV+VxtuTPt64iyi10YxyDeep+DwZG/f8cVQv97U3hA9cLurZ2CofkMLGr6JpSGCMZ9FcstcTdHB4lbErIJ54YqfF4pNOs4/AgMBAAEwD'
    + 'QYJKoZIhvcNAQEFBQADgYEAgyrTEFY7ALpeY59jL6xFOLpuPqoBOWrUWv6O+zy5BCU0qiX71r3BpigtxRj+DYcfLIM9FNERDoHu3TthD3nwYWUBtFX8N0QUJIdJabxq'
    + 'AMhLjSC744koiFpCYse5Ye3ZvEdFwDzgAQsJTp5eFGgTZPkPzcdhkFJ2p9+OWs+cb24=';
  RootCrlB64 = 'MIIBYjCBzAIBATANBgkqhkiG9w0BAQsFADAeMRwwGgYDVQQDExNUZXN0IENBIENlcnRpZmljYXRlFw0wODA5MDQwNDQ1MDhaFw0wODA5MDQwNzMxNDhaMCIwIAIBAhc'
    + 'NMDgwOTA0MDQ0NTA4WjAMMAoGA1UdFQQDCgEJoFYwVDBGBgNVHSMEPzA9gBSG/wE5PbsQH0loJxwkPhgBI8/ldaEipCAwHjEcMBoGA1UEAxMTVGVzdCBDQSBDZXJ0aW'
    + 'ZpY2F0ZYIBATAKBgNVHRQEAwIBATANBgkqhkiG9w0BAQsFAAOBgQCAbaFCo0BNG4AktVf6jjBLeawP1u0ELYkOCEGvYZE0mBpQ+OvFg7subZ6r3lRIj030nUli28sPF'
    + 'tu5ZQMBNcpE4nS1ziF44RfT3Lp5UgHx9x17Krz781iEyV+7zU8YxYMY9wULD+DCuK294kGKIssVNbmTYXZatBNoXQN5CLIocA==';
  AttrCertB64 = 'MIIHQDCCBqkCAQEwgZChgY2kgYowgYcxHDAaBgkqhkiG9w0BCQEWDW1sb3JjaEB2'
    + 'dC5lZHUxHjAcBgNVBAMTFU1hcmt1cyBMb3JjaCAobWxvcmNoKTEbMBkGA1UECxMS'
    + 'VmlyZ2luaWEgVGVjaCBVc2VyMRAwDgYDVQQLEwdDbGFzcyAyMQswCQYDVQQKEwJ2'
    + 'dDELMAkGA1UEBhMCVVMwgYmkgYYwgYMxGzAZBgkqhkiG9w0BCQEWDHNzaGFoQHZ0'
    + 'LmVkdTEbMBkGA1UEAxMSU3VtaXQgU2hhaCAoc3NoYWgpMRswGQYDVQQLExJWaXJn'
    + 'aW5pYSBUZWNoIFVzZXIxEDAOBgNVBAsTB0NsYXNzIDExCzAJBgNVBAoTAnZ0MQsw'
    + 'CQYDVQQGEwJVUzANBgkqhkiG9w0BAQQFAAIBBTAiGA8yMDAzMDcxODE2MDgwMloY'
    + 'DzIwMDMwNzI1MTYwODAyWjCCBU0wggVJBgorBgEEAbRoCAEBMYIFORaCBTU8UnVs'
    + 'ZSBSdWxlSWQ9IkZpbGUtUHJpdmlsZWdlLVJ1bGUiIEVmZmVjdD0iUGVybWl0Ij4K'
    + 'IDxUYXJnZXQ+CiAgPFN1YmplY3RzPgogICA8U3ViamVjdD4KICAgIDxTdWJqZWN0'
    + 'TWF0Y2ggTWF0Y2hJZD0idXJuOm9hc2lzOm5hbWVzOnRjOnhhY21sOjEuMDpmdW5j'
    + 'dGlvbjpzdHJpbmctZXF1YWwiPgogICAgIDxBdHRyaWJ1dGVWYWx1ZSBEYXRhVHlw'
    + 'ZT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjc3RyaW5nIj4KICAg'
    + 'ICAgIENOPU1hcmt1cyBMb3JjaDwvQXR0cmlidXRlVmFsdWU+CiAgICAgPFN1Ympl'
    + 'Y3RBdHRyaWJ1dGVEZXNpZ25hdG9yIEF0dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFt'
    + 'ZXM6dGM6eGFjbWw6MS4wOnN1YmplY3Q6c3ViamVjdC1pZCIgRGF0YVR5cGU9Imh0'
    + 'dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hI3N0cmluZyIgLz4gCiAgICA8'
    + 'L1N1YmplY3RNYXRjaD4KICAgPC9TdWJqZWN0PgogIDwvU3ViamVjdHM+CiAgPFJl'
    + 'c291cmNlcz4KICAgPFJlc291cmNlPgogICAgPFJlc291cmNlTWF0Y2ggTWF0Y2hJ'
    + 'ZD0idXJuOm9hc2lzOm5hbWVzOnRjOnhhY21sOjEuMDpmdW5jdGlvbjpzdHJpbmct'
    + 'ZXF1YWwiPgogICAgIDxBdHRyaWJ1dGVWYWx1ZSBEYXRhVHlwZT0iaHR0cDovL3d3'
    + 'dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjYW55VVJJIj4KICAgICAgaHR0cDovL3p1'
    + 'bmkuY3MudnQuZWR1PC9BdHRyaWJ1dGVWYWx1ZT4KICAgICA8UmVzb3VyY2VBdHRy'
    + 'aWJ1dGVEZXNpZ25hdG9yIEF0dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFtZXM6dGM6'
    + 'eGFjbWw6MS4wOnJlc291cmNlOnJlc291cmNlLWlkIiBEYXRhVHlwZT0iaHR0cDov'
    + 'L3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjYW55VVJJIiAvPiAKICAgIDwvUmVz'
    + 'b3VyY2VNYXRjaD4KICAgPC9SZXNvdXJjZT4KICA8L1Jlc291cmNlcz4KICA8QWN0'
    + 'aW9ucz4KICAgPEFjdGlvbj4KICAgIDxBY3Rpb25NYXRjaCBNYXRjaElkPSJ1cm46'
    + 'b2FzaXM6bmFtZXM6dGM6eGFjbWw6MS4wOmZ1bmN0aW9uOnN0cmluZy1lcXVhbCI+'
    + 'CiAgICAgPEF0dHJpYnV0ZVZhbHVlIERhdGFUeXBlPSJodHRwOi8vd3d3LnczLm9y'
    + 'Zy8yMDAxL1hNTFNjaGVtYSNzdHJpbmciPgpEZWxlZ2F0ZSBBY2Nlc3MgICAgIDwv'
    + 'QXR0cmlidXRlVmFsdWU+CgkgIDxBY3Rpb25BdHRyaWJ1dGVEZXNpZ25hdG9yIEF0'
    + 'dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFtZXM6dGM6eGFjbWw6MS4wOmFjdGlvbjph'
    + 'Y3Rpb24taWQiIERhdGFUeXBlPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNj'
    + 'aGVtYSNzdHJpbmciIC8+IAogICAgPC9BY3Rpb25NYXRjaD4KICAgPC9BY3Rpb24+'
    + 'CiAgPC9BY3Rpb25zPgogPC9UYXJnZXQ+CjwvUnVsZT4KMA0GCSqGSIb3DQEBBAUA'
    + 'A4GBAGiJSM48XsY90HlYxGmGVSmNR6ZW2As+bot3KAfiCIkUIOAqhcphBS23egTr'
    + '6asYwy151HshbPNYz+Cgeqs45KkVzh7bL/0e1r8sDVIaaGIkjHK3CqBABnfSayr3'
    + 'Rd1yBoDdEv8Qb+3eEPH6ab9021AsLEnJ6LWTmybbOpMNZ3tv';
  { full Base64 required for 4 certs / 0 CRLs }
  PKCS7_CRL_PROBLEM_B64 =   'MIIwSAYJKoZIhvcNAQcCoIIwOTCCMDUCAQExCzAJBgUrDgMCGgUAMAsGCSqG'
    + 'SIb3DQEHAaCCEsAwggP4MIIC4KADAgECAgF1MA0GCSqGSIb3DQEBBQUAMEUx'
    + 'CzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMR4wHAYDVQQD'
    + 'ExVHZW9UcnVzdCBDQSBmb3IgQWRvYmUwHhcNMDQxMjAyMjEyNTM5WhcNMDYx'
    + 'MjMwMjEyNTM5WjBMMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMR2VvVHJ1c3Qg'
    + 'SW5jMSYwJAYDVQQDEx1HZW9UcnVzdCBBZG9iZSBPQ1NQIFJlc3BvbmRlcjCB'
    + 'nzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA4gnNYhtw7U6QeVXZODnGhHMj'
    + '+OgZ0DB393rEk6a2q9kq129IA2e03yKBTfJfQR9aWKc2Qj90dsSqPjvTDHFG'
    + 'Qsagm2FQuhnA3fb1UWhPzeEIdm6bxDsnQ8nWqKqxnWZzELZbdp3I9bBLizIq'
    + 'obZovzt60LNMghn/unvvuhpeVSsCAwEAAaOCAW4wggFqMA4GA1UdDwEB/wQE'
    + 'AwIE8DCB5QYDVR0gAQH/BIHaMIHXMIHUBgkqhkiG9y8BAgEwgcYwgZAGCCsG'
    + 'AQUFBwICMIGDGoGAVGhpcyBjZXJ0aWZpY2F0ZSBoYXMgYmVlbiBpc3N1ZWQg'
    + 'aW4gYWNjb3JkYW5jZSB3aXRoIHRoZSBBY3JvYmF0IENyZWRlbnRpYWxzIENQ'
    + 'UyBsb2NhdGVkIGF0IGh0dHA6Ly93d3cuZ2VvdHJ1c3QuY29tL3Jlc291cmNl'
    + 'cy9jcHMwMQYIKwYBBQUHAgEWJWh0dHA6Ly93d3cuZ2VvdHJ1c3QuY29tL3Jl'
    + 'c291cmNlcy9jcHMwEwYDVR0lBAwwCgYIKwYBBQUHAwkwOgYDVR0fBDMwMTAv'
    + 'oC2gK4YpaHR0cDovL2NybC5nZW90cnVzdC5jb20vY3Jscy9hZG9iZWNhMS5j'
    + 'cmwwHwYDVR0jBBgwFoAUq4BZw2WDbR19E70Zw+wajw1HaqMwDQYJKoZIhvcN'
    + 'AQEFBQADggEBAENJf1BD7PX5ivuaawt90q1OGzXpIQL/ClzEeFVmOIxqPc1E'
    + 'TFRq92YuxG5b6+R+k+tGkmCwPLcY8ipg6ZcbJ/AirQhohzjlFuT6YAXsTfEj'
    + 'CqEZfWM2sS7crK2EYxCMmKE3xDfPclYtrAoz7qZvxfQj0TuxHSstHZv39wu2'
    + 'ZiG1BWiEcyDQyTgqTOXBoZmfJtshuAcXmTpgkrYSrS37zNlPTGh+pMYQ0yWD'
    + 'c8OQRJR4OY5ZXfdna01mjtJTOmj6/6XPoLPYTq2gQrc2BCeNJ4bEhLb7sFVB'
    + 'PbwPrpzTE/HRbQHDrzj0YimDxeOUV/UXctgvYwHNtEkcBLsOm/uytMYwggSh'
    + 'MIIDiaADAgECAgQ+HL0oMA0GCSqGSIb3DQEBBQUAMGkxCzAJBgNVBAYTAlVT'
    + 'MSMwIQYDVQQKExpBZG9iZSBTeXN0ZW1zIEluY29ycG9yYXRlZDEdMBsGA1UE'
    + 'CxMUQWRvYmUgVHJ1c3QgU2VydmljZXMxFjAUBgNVBAMTDUFkb2JlIFJvb3Qg'
    + 'Q0EwHhcNMDMwMTA4MjMzNzIzWhcNMjMwMTA5MDAwNzIzWjBpMQswCQYDVQQG'
    + 'EwJVUzEjMCEGA1UEChMaQWRvYmUgU3lzdGVtcyBJbmNvcnBvcmF0ZWQxHTAb'
    + 'BgNVBAsTFEFkb2JlIFRydXN0IFNlcnZpY2VzMRYwFAYDVQQDEw1BZG9iZSBS'
    + 'b290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzE9UhPen'
    + 'ouczU38/nBKIayyZR2d+Dx65rRSI+cMQ2B3w8NWfaQovWTWwzGypTJwVoJ/O'
    + 'IL+gz1Ti4CBmRT85hjh+nMSOByLGJPYBErA131XqaZCw24U3HuJOB7JCoWoT'
    + 'aaBm6oCREVkqmwh5WiBELcm9cziLPC/gQxtdswvwrzUaKf7vppLdgUydPVmO'
    + 'rTE8QH6bkTYG/OJcjdGNJtVcRc+vZT+xqtJilvSoOOq6YEL09BxKNRXO+E4i'
    + 'Vg+VGMX4lp+f+7C3eCXpgGu91grwxnSUnfMPUNuad85LcIMjjaDKeCBEXDxU'
    + 'ZPHqojAZn+pMBk0GeEtekt8i0slns3rSAQIDAQABo4IBTzCCAUswEQYJYIZI'
    + 'AYb4QgEBBAQDAgAHMIGOBgNVHR8EgYYwgYMwgYCgfqB8pHoweDELMAkGA1UE'
    + 'BhMCVVMxIzAhBgNVBAoTGkFkb2JlIFN5c3RlbXMgSW5jb3Jwb3JhdGVkMR0w'
    + 'GwYDVQQLExRBZG9iZSBUcnVzdCBTZXJ2aWNlczEWMBQGA1UEAxMNQWRvYmUg'
    + 'Um9vdCBDQTENMAsGA1UEAxMEQ1JMMTArBgNVHRAEJDAigA8yMDAzMDEwODIz'
    + 'MzcyM1qBDzIwMjMwMTA5MDAwNzIzWjALBgNVHQ8EBAMCAQYwHwYDVR0jBBgw'
    + 'FoAUgrc4SpOqmxDvgLvZVOLxD/uAnN4wHQYDVR0OBBYEFIK3OEqTqpsQ74C7'
    + '2VTi8Q/7gJzeMAwGA1UdEwQFMAMBAf8wHQYJKoZIhvZ9B0EABBAwDhsIVjYu'
    + 'MDo0LjADAgSQMA0GCSqGSIb3DQEBBQUAA4IBAQAy2p9DdcH6b8lv26sdNjc+'
    + 'vGEZNrcCPB0jWZhsnu5NhedUyCAfp9S74r8Ad30ka3AvXME6dkm10+AjhCpx'
    + 'aiLzwScpmBX2NZDkBEzDjbyfYRzn/SSM0URDjBa6m02l1DUvvBHOvfdRN42f'
    + 'kOQU8Rg/vulZEjX5M5LznuDVa5pxm5lLyHHD4bFhCcTl+pHwQjo3fTT5cujN'
    + 'qmIcIenV9IIQ43sFti1oVgt+fpIsb01yggztVnSynbmrLSsdEF/bJ3Vwj/0d'
    + '1+ICoHnlHOX/r2RAUS2em0fbQqV8H8KmSLDXvpJpTaT2KVfFeBEY3IdRyhOy'
    + 'Yp1PKzK9MaXB+lKrBYjIMIIEyzCCA7OgAwIBAgIEPhy9tTANBgkqhkiG9w0B'
    + 'AQUFADBpMQswCQYDVQQGEwJVUzEjMCEGA1UEChMaQWRvYmUgU3lzdGVtcyBJ'
    + 'bmNvcnBvcmF0ZWQxHTAbBgNVBAsTFEFkb2JlIFRydXN0IFNlcnZpY2VzMRYw'
    + 'FAYDVQQDEw1BZG9iZSBSb290IENBMB4XDTA0MDExNzAwMDMzOVoXDTE1MDEx'
    + 'NTA4MDAwMFowRTELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUdlb1RydXN0IElu'
    + 'Yy4xHjAcBgNVBAMTFUdlb1RydXN0IENBIGZvciBBZG9iZTCCASIwDQYJKoZI'
    + 'hvcNAQEBBQADggEPADCCAQoCggEBAKfld+BkeFrnOYW8r9L1WygTDlTdSfrO'
    + 'YvWS/Z6Ye5/l+HrBbOHqQCXBcSeCpz7kB2WdKMh1FOE4e9JlmICsHerBLdWk'
    + 'emU+/PDb69zh8E0cLoDfxukF6oVPXj6WSThdSG7H9aXFzRr6S3XGCuvgl+Qw'
    + 'DTLiLYW+ONF6DXwt3TQQtKReJjOJZk46ZZ0BvMStKyBaeB6DKZsmiIo89qso'
    + '13VDZINH2w1KvXg0ygDizoNtbvgAPFymwnsINS1klfQlcvn0x0RJm9bYQXK3'
    + '5GNZAgL3M7Lqrld0jMfIUaWvuHCLyivytRuzq1dJ7E8rmidjDEk/G+27pf13'
    + 'fNZ7vR7M+IkCAwEAAaOCAZ0wggGZMBIGA1UdEwEB/wQIMAYBAf8CAQEwUAYD'
    + 'VR0gBEkwRzBFBgkqhkiG9y8BAgEwODA2BggrBgEFBQcCARYqaHR0cHM6Ly93'
    + 'd3cuYWRvYmUuY29tL21pc2MvcGtpL2Nkc19jcC5odG1sMBQGA1UdJQQNMAsG'
    + 'CSqGSIb3LwEBBTCBsgYDVR0fBIGqMIGnMCKgIKAehhxodHRwOi8vY3JsLmFk'
    + 'b2JlLmNvbS9jZHMuY3JsMIGAoH6gfKR6MHgxCzAJBgNVBAYTAlVTMSMwIQYD'
    + 'VQQKExpBZG9iZSBTeXN0ZW1zIEluY29ycG9yYXRlZDEdMBsGA1UECxMUQWRv'
    + 'YmUgVHJ1c3QgU2VydmljZXMxFjAUBgNVBAMTDUFkb2JlIFJvb3QgQ0ExDTAL'
    + 'BgNVBAMTBENSTDEwCwYDVR0PBAQDAgEGMB8GA1UdIwQYMBaAFIK3OEqTqpsQ'
    + '74C72VTi8Q/7gJzeMB0GA1UdDgQWBBSrgFnDZYNtHX0TvRnD7BqPDUdqozAZ'
    + 'BgkqhkiG9n0HQQAEDDAKGwRWNi4wAwIEkDANBgkqhkiG9w0BAQUFAAOCAQEA'
    + 'PzlZLqIAjrFeEWEs0uC29YyJhkXOE9mf3YSaFGsITF+Gl1j0pajTjyH4R35Q'
    + 'r3floW2q3HfNzTeZ90Jnr1DhVERD6zEMgJpCtJqVuk0sixuXJHghS/KicKf4'
    + 'YXJJPx9epuIRF1siBRnznnF90svmOJMXApc0jGnYn3nQfk4kaShSnDaYaeYR'
    + 'DJKcsiWhl6S5zfwS7Gg8hDeyckhMQKKWnlG1CQrwlSFisKCduoodwRtWgft8'
    + 'kx13iyKK3sbalm6vnVc+5nufS4vI+TwMXoV63NqYaSroafBWk0nL53zGXPEy'
    + '+A69QhzEViJKn2Wgqt5gt++jMMNImbRObIqgfgF1VjCCBUwwggQ0oAMCAQIC'
    + 'AgGDMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1H'
    + 'ZW9UcnVzdCBJbmMuMR4wHAYDVQQDExVHZW9UcnVzdCBDQSBmb3IgQWRvYmUw'
    + 'HhcNMDYwMzI0MTU0MjI5WhcNMDkwNDA2MTQ0MjI5WjBzMQswCQYDVQQGEwJV'
    + 'UzELMAkGA1UECBMCTUExETAPBgNVBAoTCEdlb1RydXN0MR0wGwYDVQQDExRN'
    + 'YXJrZXRpbmcgRGVwYXJ0bWVudDElMCMGCSqGSIb3DQEJARYWbWFya2V0aW5n'
    + 'QGdlb3RydXN0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB'
    + 'ANmvajTO4XJvAU2nVcLmXeCnAQX7RZt+7+ML3InmqQ3LCGo1weop09zV069/'
    + '1x/Nmieol7laEzeXxd2ghjGzwfXafqQEqHn6+vBCvqdNPoSi63fSWhnuDVWp'
    + 'KVDOYgxOonrXl+Cc43lu4zRSq+Pi5phhrjDWcH74a3/rdljUt4c4GFezFXfa'
    + 'w2oTzWkxj2cTSn0Szhpr17+p66UNt8uknlhmu4q44Speqql2HwmCEnpLYJrK'
    + 'W3fOq5D4qdsvsLR2EABLhrBezamLI3iGV8cRHOUTsbTMhWhv/lKfHAyf4XjA'
    + 'z9orzvPN5jthhIfICOFq/nStTgakyL4Ln+nFAB/SMPkCAwEAAaOCAhYwggIS'
    + 'MA4GA1UdDwEB/wQEAwIF4DCB5QYDVR0gAQH/BIHaMIHXMIHUBgkqhkiG9y8B'
    + 'AgEwgcYwgZAGCCsGAQUFBwICMIGDGoGAVGhpcyBjZXJ0aWZpY2F0ZSBoYXMg'
    + 'YmVlbiBpc3N1ZWQgaW4gYWNjb3JkYW5jZSB3aXRoIHRoZSBBY3JvYmF0IENy'
    + 'ZWRlbnRpYWxzIENQUyBsb2NhdGVkIGF0IGh0dHA6Ly93d3cuZ2VvdHJ1c3Qu'
    + 'Y29tL3Jlc291cmNlcy9jcHMwMQYIKwYBBQUHAgEWJWh0dHA6Ly93d3cuZ2Vv'
    + 'dHJ1c3QuY29tL3Jlc291cmNlcy9jcHMwOgYDVR0fBDMwMTAvoC2gK4YpaHR0'
    + 'cDovL2NybC5nZW90cnVzdC5jb20vY3Jscy9hZG9iZWNhMS5jcmwwHwYDVR0j'
    + 'BBgwFoAUq4BZw2WDbR19E70Zw+wajw1HaqMwRAYIKwYBBQUHAQEEODA2MDQG'
    + 'CCsGAQUFBzABhihodHRwOi8vYWRvYmUtb2NzcC5nZW90cnVzdC5jb20vcmVz'
    + 'cG9uZGVyMBQGA1UdJQQNMAsGCSqGSIb3LwEBBTA8BgoqhkiG9y8BAQkBBC4w'
    + 'LAIBAYYnaHR0cDovL2Fkb2JlLXRpbWVzdGFtcC5nZW90cnVzdC5jb20vdHNh'
    + 'MBMGCiqGSIb3LwEBCQIEBTADAgEBMAwGA1UdEwQFMAMCAQAwDQYJKoZIhvcN'
    + 'AQEFBQADggEBAAOhy6QxOo+i3h877fvDvTa0plGD2bIqK7wMdNqbMDoSWied'
    + 'FIcgcBOIm2wLxOjZBAVj/3lDq59q2rnVeNnfXM0/N0MHI9TumHRjU7WNk9e4'
    + '+JfJ4M+c3anrWOG3NE5cICDVgles+UHjXetHWql/LlP04+K2ZOLb6LE2xGnI'
    + 'YyLW9REzCYNAVF+/WkYdmyceHtaBZdbyVAJq0NAJPsfgY1pWcBo31Mr1fpX9'
    + 'WrXNTYDCqMyxMImJTmN3iI68tkXlNrhweQoArKFqBysiBkXzG/sGKYY6tWKU'
    + 'pzjLc3vIp/LrXC5zilROes8BSvwu1w9qQrJNcGwo7O4uijoNtyYil1Exgh1Q'
    + 'MIIdTAIBATBLMEUxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1HZW9UcnVzdCBJ'
    + 'bmMuMR4wHAYDVQQDExVHZW9UcnVzdCBDQSBmb3IgQWRvYmUCAgGDMAkGBSsO'
    + 'AwIaBQCgggxMMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwIwYJKoZIhvcN'
    + 'AQkEMRYEFP4R6qIdpQJzWyzrqO8X1ZfJOgChMIIMCQYJKoZIhvcvAQEIMYIL'
    + '+jCCC/agggZ5MIIGdTCCA6gwggKQMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV'
    + 'BAYTAlVTMRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMR4wHAYDVQQDExVHZW9U'
    + 'cnVzdCBDQSBmb3IgQWRvYmUXDTA2MDQwNDE3NDAxMFoXDTA2MDQwNTE3NDAx'
    + 'MFowggIYMBMCAgC5Fw0wNTEwMTEyMDM2MzJaMBICAVsXDTA0MTEwNDE1MDk0'
    + 'MVowEwICALgXDTA1MTIxMjIyMzgzOFowEgIBWhcNMDQxMTA0MTUwOTMzWjAT'
    + 'AgIA5hcNMDUwODI3MDQwOTM4WjATAgIAtxcNMDYwMTE2MTc1NTEzWjATAgIA'
    + 'hhcNMDUxMjEyMjIzODU1WjATAgIAtRcNMDUwNzA2MTgzODQwWjATAgIA4BcN'
    + 'MDYwMzIwMDc0ODM0WjATAgIAgRcNMDUwODAyMjIzMTE1WjATAgIA3xcNMDUx'
    + 'MjEyMjIzNjUwWjASAgFKFw0wNDExMDQxNTA5MTZaMBICAUQXDTA0MTEwNDE1'
    + 'MDg1M1owEgIBQxcNMDQxMDAzMDEwMDQwWjASAgFsFw0wNDEyMDYxOTQ0MzFa'
    + 'MBMCAgEoFw0wNjAzMDkxMjA3MTJaMBMCAgEkFw0wNjAxMTYxNzU1MzRaMBIC'
    + 'AWcXDTA1MDMxODE3NTYxNFowEwICAVEXDTA2MDEzMTExMjcxMVowEgIBZBcN'
    + 'MDQxMTExMjI0ODQxWjATAgIA8RcNMDUwOTE2MTg0ODAxWjATAgIBThcNMDYw'
    + 'MjIxMjAxMDM2WjATAgIAwRcNMDUxMjEyMjIzODE2WjASAgFiFw0wNTAxMTAx'
    + 'NjE5MzRaMBICAWAXDTA1MDExMDE5MDAwNFowEwICAL4XDTA1MDUxNzE0NTYx'
    + 'MFowDQYJKoZIhvcNAQEFBQADggEBAEKhRMS3wVho1U3EvEQJZC8+JlUngmZQ'
    + 'A78KQbHPWNZWFlNvPuf/b0s7Lu16GfNHXh1QAW6Y5Hi1YtYZ3YOPyMd4Xugt'
    + 'gCdumbB6xtKsDyN5RvTht6ByXj+CYlYqsL7RX0izJZ6mJn4fjMkqzPKNOjb8'
    + 'kSn5T6rn93BjlATtCE8tPVOM8dnqGccRE0OV59+nDBXc90UMt5LdEbwaUOap'
    + 'snVB0oLcNm8d/HnlVH6RY5LnDjrT4vwfe/FApZtTecEWsllVUXDjSpwfcfD/'
    + '476/lpGySB2otALqzImlA9R8Ok3hJ8dnF6hhQ5Oe6OJMnGYgdhkKbxsKkdib'
    + 'tTVl3qmH5QAwggLFMIIBrQIBATANBgkqhkiG9w0BAQUFADBpMQswCQYDVQQG'
    + 'EwJVUzEjMCEGA1UEChMaQWRvYmUgU3lzdGVtcyBJbmNvcnBvcmF0ZWQxHTAb'
    + 'BgNVBAsTFEFkb2JlIFRydXN0IFNlcnZpY2VzMRYwFAYDVQQDEw1BZG9iZSBS'
    + 'b290IENBFw0wNjAxMjcxODMzMzFaFw0wNzAxMjcwMDAwMDBaMIHeMCMCBD4c'
    + 'vUAXDTAzMDEyMTIzNDY1NlowDDAKBgNVHRUEAwoBBDAjAgQ+HL1BFw0wMzAx'
    + 'MjEyMzQ3MjJaMAwwCgYDVR0VBAMKAQQwIwIEPhy9YhcNMDMwMTIxMjM0NzQy'
    + 'WjAMMAoGA1UdFQQDCgEEMCMCBD4cvWEXDTA0MDExNzAxMDg0OFowDDAKBgNV'
    + 'HRUEAwoBBDAjAgQ+HL2qFw0wNDAxMTcwMTA5MDVaMAwwCgYDVR0VBAMKAQQw'
    + 'IwIEPhy9qBcNMDQwMTE3MDEzOTI5WjAMMAoGA1UdFQQDCgEEoC8wLTAKBgNV'
    + 'HRQEAwIBDzAfBgNVHSMEGDAWgBSCtzhKk6qbEO+Au9lU4vEP+4Cc3jANBgkq'
    + 'hkiG9w0BAQUFAAOCAQEAwtXF9042wG39icUlsotn5tpE3oCusLb/hBpEONhx'
    + 'OdfEQOq0w5hf/vqaxkcf71etA+KpbEUeSVaHMHRPhx/CmPrO9odE139dJdbt'
    + '9iqbrC9iZokFK3h/es5kg73xujLKd7C/u5ngJ4mwBtvhMLjFjF2vJhPKHL4C'
    + 'IgMwdaUAhrcNzy16v+mw/VGJy3Fvc6oCESW1K9tvFW58qZSNXrMlsuidgunM'
    + 'hPKG+z0SXVyCqL7pnqKiaGddcgujYGOSY4S938oVcfZeZQEODtSYGlzldojX'
    + 'C1U1hCK5+tHAH0Ox/WqRBIol5VCZQwJftf44oG8oviYq52aaqSejXwmfT6zb'
    + '76GCBXUwggVxMIIFbQoBAKCCBWYwggViBgkrBgEFBQcwAQEEggVTMIIFTzCB'
    + 'taIWBBS+8EpykfXdl4h3z7m/NZfdkAQQERgPMjAwNjA0MDQyMDIwMTVaMGUw'
    + 'YzA7MAkGBSsOAwIaBQAEFEb4BuZYkbjBjOjT6VeA/00fBvQaBBT3fTSQniOp'
    + 'BbHBSkz4xridlX0bsAICAYOAABgPMjAwNjA0MDQyMDIwMTVaoBEYDzIwMDYw'
    + 'NDA1MDgyMDE1WqEjMCEwHwYJKwYBBQUHMAECBBIEEFqooq/R2WltD7TposkT'
    + 'BhMwDQYJKoZIhvcNAQEFBQADgYEAMig6lty4b0JDsT/oanfQG5x6jVKPACpp'
    + '1UA9SJ0apJJa7LeIdDFmu5C2S/CYiKZm4A4P9cAu0YzgLHxE4r6Op+HfVlAG'
    + '6bzUe1P/hi1KCJ8r8wxOZAktQFPSzs85RAZwkHMfB0lP2e/h666Oye+Zf8VH'
    + 'RaE+/xZ7aswE89HXoumgggQAMIID/DCCA/gwggLgoAMCAQICAXUwDQYJKoZI'
    + 'hvcNAQEFBQAwRTELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUdlb1RydXN0IElu'
    + 'Yy4xHjAcBgNVBAMTFUdlb1RydXN0IENBIGZvciBBZG9iZTAeFw0wNDEyMDIy'
    + 'MTI1MzlaFw0wNjEyMzAyMTI1MzlaMEwxCzAJBgNVBAYTAlVTMRUwEwYDVQQK'
    + 'EwxHZW9UcnVzdCBJbmMxJjAkBgNVBAMTHUdlb1RydXN0IEFkb2JlIE9DU1Ag'
    + 'UmVzcG9uZGVyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDiCc1iG3Dt'
    + 'TpB5Vdk4OcaEcyP46BnQMHf3esSTprar2SrXb0gDZ7TfIoFN8l9BH1pYpzZC'
    + 'P3R2xKo+O9MMcUZCxqCbYVC6GcDd9vVRaE/N4Qh2bpvEOydDydaoqrGdZnMQ'
    + 'tlt2ncj1sEuLMiqhtmi/O3rQs0yCGf+6e++6Gl5VKwIDAQABo4IBbjCCAWow'
    + 'DgYDVR0PAQH/BAQDAgTwMIHlBgNVHSABAf8EgdowgdcwgdQGCSqGSIb3LwEC'
    + 'ATCBxjCBkAYIKwYBBQUHAgIwgYMagYBUaGlzIGNlcnRpZmljYXRlIGhhcyBi'
    + 'ZWVuIGlzc3VlZCBpbiBhY2NvcmRhbmNlIHdpdGggdGhlIEFjcm9iYXQgQ3Jl'
    + 'ZGVudGlhbHMgQ1BTIGxvY2F0ZWQgYXQgaHR0cDovL3d3dy5nZW90cnVzdC5j'
    + 'b20vcmVzb3VyY2VzL2NwczAxBggrBgEFBQcCARYlaHR0cDovL3d3dy5nZW90'
    + 'cnVzdC5jb20vcmVzb3VyY2VzL2NwczATBgNVHSUEDDAKBggrBgEFBQcDCTA6'
    + 'BgNVHR8EMzAxMC+gLaArhilodHRwOi8vY3JsLmdlb3RydXN0LmNvbS9jcmxz'
    + 'L2Fkb2JlY2ExLmNybDAfBgNVHSMEGDAWgBSrgFnDZYNtHX0TvRnD7BqPDUdq'
    + 'ozANBgkqhkiG9w0BAQUFAAOCAQEAQ0l/UEPs9fmK+5prC33SrU4bNekhAv8K'
    + 'XMR4VWY4jGo9zURMVGr3Zi7Eblvr5H6T60aSYLA8txjyKmDplxsn8CKtCGiH'
    + 'OOUW5PpgBexN8SMKoRl9YzaxLtysrYRjEIyYoTfEN89yVi2sCjPupm/F9CPR'
    + 'O7EdKy0dm/f3C7ZmIbUFaIRzINDJOCpM5cGhmZ8m2yG4BxeZOmCSthKtLfvM'
    + '2U9MaH6kxhDTJYNzw5BElHg5jlld92drTWaO0lM6aPr/pc+gs9hOraBCtzYE'
    + 'J40nhsSEtvuwVUE9vA+unNMT8dFtAcOvOPRiKYPF45RX9Rdy2C9jAc20SRwE'
    + 'uw6b+7K0xjANBgkqhkiG9w0BAQEFAASCAQC7a4yICFGCEMPlJbydK5qLG3rV'
    + 'sip7Ojjz9TB4nLhC2DgsIHds8jjdq2zguInluH2nLaBCVS+qxDVlTjgbI2cB'
    + 'TaWS8nglC7nNjzkKAsa8vThA8FZUVXTW0pb74jNJJU2AA27bb4g+4WgunCrj'
    + 'fpYp+QjDyMmdrJVqRmt5eQN+dpVxMS9oq+NrhOSEhyIb4/rejgNg9wnVK1ms'
    + 'l5PxQ4x7kpm7+Ua41//owkJVWykRo4T1jo4eHEz1DolPykAaKie2VKH/sMqR'
    + 'Spjh4E5biKJLOV9fKivZWKAXByXfwUbbMsJvz4v/2yVHFy9xP+tqB5ZbRoDK'
    + 'k8PzUyCprozn+/22oYIPijCCD4YGCyqGSIb3DQEJEAIOMYIPdTCCD3EGCSqG'
    + 'SIb3DQEHAqCCD2Iwgg9eAgEDMQswCQYFKw4DAhoFADCB+gYLKoZIhvcNAQkQ'
    + 'AQSggeoEgecwgeQCAQEGAikCMCEwCQYFKw4DAhoFAAQUoT97qeCv3FXYaEcS'
    + 'gY8patCaCA8CAiMHGA8yMDA2MDQwNDIwMjA1N1owAwIBPAEB/wIIO0yRre3L'
    + '8/6ggZCkgY0wgYoxCzAJBgNVBAYTAlVTMRYwFAYDVQQIEw1NYXNzYWNodXNl'
    + 'dHRzMRAwDgYDVQQHEwdOZWVkaGFtMRUwEwYDVQQKEwxHZW9UcnVzdCBJbmMx'
    + 'EzARBgNVBAsTClByb2R1Y3Rpb24xJTAjBgNVBAMTHGFkb2JlLXRpbWVzdGFt'
    + 'cC5nZW90cnVzdC5jb22gggzJMIIDUTCCAjmgAwIBAgICAI8wDQYJKoZIhvcN'
    + 'AQEFBQAwRTELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUdlb1RydXN0IEluYy4x'
    + 'HjAcBgNVBAMTFUdlb1RydXN0IENBIGZvciBBZG9iZTAeFw0wNTAxMTAwMTI5'
    + 'MTBaFw0xNTAxMTUwODAwMDBaMIGKMQswCQYDVQQGEwJVUzEWMBQGA1UECBMN'
    + 'TWFzc2FjaHVzZXR0czEQMA4GA1UEBxMHTmVlZGhhbTEVMBMGA1UEChMMR2Vv'
    + 'VHJ1c3QgSW5jMRMwEQYDVQQLEwpQcm9kdWN0aW9uMSUwIwYDVQQDExxhZG9i'
    + 'ZS10aW1lc3RhbXAuZ2VvdHJ1c3QuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GN'
    + 'ADCBiQKBgQDRbxJotLFPWQuuEDhKtOMaBUJepGxIvWxeahMbq1DVmqnk88+j'
    + 'w/5lfPICPzQZ1oHrcTLSAFM7Mrz3pyyQKQKMqUyiemzuG/77ESUNfBNSUfAF'
    + 'PdtHuDMU8Is8ABVnFk63L+wdlvvDIlKkE08+VTKCRdjmuBVltMpQ6QcLFQzm'
    + 'AQIDAQABo4GIMIGFMDoGA1UdHwQzMDEwL6AtoCuGKWh0dHA6Ly9jcmwuZ2Vv'
    + 'dHJ1c3QuY29tL2NybHMvYWRvYmVjYTEuY3JsMB8GA1UdIwQYMBaAFKuAWcNl'
    + 'g20dfRO9GcPsGo8NR2qjMA4GA1UdDwEB/wQEAwIGwDAWBgNVHSUBAf8EDDAK'
    + 'BggrBgEFBQcDCDANBgkqhkiG9w0BAQUFAAOCAQEAmnyXjdtX+F79Nf0KggTd'
    + '6YC2MQD9s09IeXTd8TP3rBmizfM+7f3icggeCGakNfPRmIUMLoa0VM5Kt37T'
    + '2X0TqzBWusfbKx7HnX4v1t/G8NJJlT4SShSHv+8bjjU4lUoCmW2oEcC5vXwP'
    + 'R5JfjCyois16npgcO05ZBT+LLDXyeBijE6qWmwLDfEpLyILzVRmyU4IE7jvm'
    + 'rgb3GXwDUvd3yQXGRRHbPCh3nj9hBGbuzyt7GnlqnEie3wzIyMG2ET/wvTX5'
    + '4BFXKNe7lDLvZj/MXvd3V7gMTSVW0kAszKao56LfrVTgp1VX3UBQYwmQqaoA'
    + 'UwFezih+jEvjW6cYJo/ErDCCBKEwggOJoAMCAQICBD4cvSgwDQYJKoZIhvcN'
    + 'AQEFBQAwaTELMAkGA1UEBhMCVVMxIzAhBgNVBAoTGkFkb2JlIFN5c3RlbXMg'
    + 'SW5jb3Jwb3JhdGVkMR0wGwYDVQQLExRBZG9iZSBUcnVzdCBTZXJ2aWNlczEW'
    + 'MBQGA1UEAxMNQWRvYmUgUm9vdCBDQTAeFw0wMzAxMDgyMzM3MjNaFw0yMzAx'
    + 'MDkwMDA3MjNaMGkxCzAJBgNVBAYTAlVTMSMwIQYDVQQKExpBZG9iZSBTeXN0'
    + 'ZW1zIEluY29ycG9yYXRlZDEdMBsGA1UECxMUQWRvYmUgVHJ1c3QgU2Vydmlj'
    + 'ZXMxFjAUBgNVBAMTDUFkb2JlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUA'
    + 'A4IBDwAwggEKAoIBAQDMT1SE96ei5zNTfz+cEohrLJlHZ34PHrmtFIj5wxDY'
    + 'HfDw1Z9pCi9ZNbDMbKlMnBWgn84gv6DPVOLgIGZFPzmGOH6cxI4HIsYk9gES'
    + 'sDXfVeppkLDbhTce4k4HskKhahNpoGbqgJERWSqbCHlaIEQtyb1zOIs8L+BD'
    + 'G12zC/CvNRop/u+mkt2BTJ09WY6tMTxAfpuRNgb84lyN0Y0m1VxFz69lP7Gq'
    + '0mKW9Kg46rpgQvT0HEo1Fc74TiJWD5UYxfiWn5/7sLd4JemAa73WCvDGdJSd'
    + '8w9Q25p3zktwgyONoMp4IERcPFRk8eqiMBmf6kwGTQZ4S16S3yLSyWezetIB'
    + 'AgMBAAGjggFPMIIBSzARBglghkgBhvhCAQEEBAMCAAcwgY4GA1UdHwSBhjCB'
    + 'gzCBgKB+oHykejB4MQswCQYDVQQGEwJVUzEjMCEGA1UEChMaQWRvYmUgU3lz'
    + 'dGVtcyBJbmNvcnBvcmF0ZWQxHTAbBgNVBAsTFEFkb2JlIFRydXN0IFNlcnZp'
    + 'Y2VzMRYwFAYDVQQDEw1BZG9iZSBSb290IENBMQ0wCwYDVQQDEwRDUkwxMCsG'
    + 'A1UdEAQkMCKADzIwMDMwMTA4MjMzNzIzWoEPMjAyMzAxMDkwMDA3MjNaMAsG'
    + 'A1UdDwQEAwIBBjAfBgNVHSMEGDAWgBSCtzhKk6qbEO+Au9lU4vEP+4Cc3jAd'
    + 'BgNVHQ4EFgQUgrc4SpOqmxDvgLvZVOLxD/uAnN4wDAYDVR0TBAUwAwEB/zAd'
    + 'BgkqhkiG9n0HQQAEEDAOGwhWNi4wOjQuMAMCBJAwDQYJKoZIhvcNAQEFBQAD'
    + 'ggEBADLan0N1wfpvyW/bqx02Nz68YRk2twI8HSNZmGye7k2F51TIIB+n1Lvi'
    + 'vwB3fSRrcC9cwTp2SbXT4COEKnFqIvPBJymYFfY1kOQETMONvJ9hHOf9JIzR'
    + 'REOMFrqbTaXUNS+8Ec6991E3jZ+Q5BTxGD++6VkSNfkzkvOe4NVrmnGbmUvI'
    + 'ccPhsWEJxOX6kfBCOjd9NPly6M2qYhwh6dX0ghDjewW2LWhWC35+kixvTXKC'
    + 'DO1WdLKduastKx0QX9sndXCP/R3X4gKgeeUc5f+vZEBRLZ6bR9tCpXwfwqZI'
    + 'sNe+kmlNpPYpV8V4ERjch1HKE7JinU8rMr0xpcH6UqsFiMgwggTLMIIDs6AD'
    + 'AgECAgQ+HL21MA0GCSqGSIb3DQEBBQUAMGkxCzAJBgNVBAYTAlVTMSMwIQYD'
    + 'VQQKExpBZG9iZSBTeXN0ZW1zIEluY29ycG9yYXRlZDEdMBsGA1UECxMUQWRv'
    + 'YmUgVHJ1c3QgU2VydmljZXMxFjAUBgNVBAMTDUFkb2JlIFJvb3QgQ0EwHhcN'
    + 'MDQwMTE3MDAwMzM5WhcNMTUwMTE1MDgwMDAwWjBFMQswCQYDVQQGEwJVUzEW'
    + 'MBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEeMBwGA1UEAxMVR2VvVHJ1c3QgQ0Eg'
    + 'Zm9yIEFkb2JlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp+V3'
    + '4GR4Wuc5hbyv0vVbKBMOVN1J+s5i9ZL9nph7n+X4esFs4epAJcFxJ4KnPuQH'
    + 'ZZ0oyHUU4Th70mWYgKwd6sEt1aR6ZT788Nvr3OHwTRwugN/G6QXqhU9ePpZJ'
    + 'OF1Ibsf1pcXNGvpLdcYK6+CX5DANMuIthb440XoNfC3dNBC0pF4mM4lmTjpl'
    + 'nQG8xK0rIFp4HoMpmyaIijz2qyjXdUNkg0fbDUq9eDTKAOLOg21u+AA8XKbC'
    + 'ewg1LWSV9CVy+fTHREmb1thBcrfkY1kCAvczsuquV3SMx8hRpa+4cIvKK/K1'
    + 'G7OrV0nsTyuaJ2MMST8b7bul/Xd81nu9Hsz4iQIDAQABo4IBnTCCAZkwEgYD'
    + 'VR0TAQH/BAgwBgEB/wIBATBQBgNVHSAESTBHMEUGCSqGSIb3LwECATA4MDYG'
    + 'CCsGAQUFBwIBFipodHRwczovL3d3dy5hZG9iZS5jb20vbWlzYy9wa2kvY2Rz'
    + 'X2NwLmh0bWwwFAYDVR0lBA0wCwYJKoZIhvcvAQEFMIGyBgNVHR8Egaowgacw'
    + 'IqAgoB6GHGh0dHA6Ly9jcmwuYWRvYmUuY29tL2Nkcy5jcmwwgYCgfqB8pHow'
    + 'eDELMAkGA1UEBhMCVVMxIzAhBgNVBAoTGkFkb2JlIFN5c3RlbXMgSW5jb3Jw'
    + 'b3JhdGVkMR0wGwYDVQQLExRBZG9iZSBUcnVzdCBTZXJ2aWNlczEWMBQGA1UE'
    + 'AxMNQWRvYmUgUm9vdCBDQTENMAsGA1UEAxMEQ1JMMTALBgNVHQ8EBAMCAQYw'
    + 'HwYDVR0jBBgwFoAUgrc4SpOqmxDvgLvZVOLxD/uAnN4wHQYDVR0OBBYEFKuA'
    + 'WcNlg20dfRO9GcPsGo8NR2qjMBkGCSqGSIb2fQdBAAQMMAobBFY2LjADAgSQ'
    + 'MA0GCSqGSIb3DQEBBQUAA4IBAQA/OVkuogCOsV4RYSzS4Lb1jImGRc4T2Z/d'
    + 'hJoUawhMX4aXWPSlqNOPIfhHflCvd+Whbarcd83NN5n3QmevUOFUREPrMQyA'
    + 'mkK0mpW6TSyLG5ckeCFL8qJwp/hhckk/H16m4hEXWyIFGfOecX3Sy+Y4kxcC'
    + 'lzSMadifedB+TiRpKFKcNphp5hEMkpyyJaGXpLnN/BLsaDyEN7JySExAopae'
    + 'UbUJCvCVIWKwoJ26ih3BG1aB+3yTHXeLIorextqWbq+dVz7me59Li8j5PAxe'
    + 'hXrc2phpKuhp8FaTScvnfMZc8TL4Dr1CHMRWIkqfZaCq3mC376Mww0iZtE5s'
    + 'iqB+AXVWMYIBgDCCAXwCAQEwSzBFMQswCQYDVQQGEwJVUzEWMBQGA1UEChMN'
    + 'R2VvVHJ1c3QgSW5jLjEeMBwGA1UEAxMVR2VvVHJ1c3QgQ0EgZm9yIEFkb2Jl'
    + 'AgIAjzAJBgUrDgMCGgUAoIGMMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB'
    + 'BDAcBgkqhkiG9w0BCQUxDxcNMDYwNDA0MjAyMDU3WjAjBgkqhkiG9w0BCQQx'
    + 'FgQUp7AnXBqoNcarvO7fMJut1og2U5AwKwYLKoZIhvcNAQkQAgwxHDAaMBgw'
    + 'FgQU1dH4eZTNhgxdiSABrat6zsPdth0wDQYJKoZIhvcNAQEBBQAEgYCinr/F'
    + 'rMiQz/MRm9ZD5YGcC0Qo2dRTPd0Aop8mZ4g1xAhKFLnp7lLsjCbkSDpVLDBh'
    + 'cnCk7CV+3FT5hlvt8OqZlR0CnkSnCswLFhrppiWle6cpxlwGqyAteC8uKtQu'
    + 'wjE5GtBKLcCOAzQYyyuNZZeB6oCZ+3mPhZ62FxrvvEGJCgAAAAAAAAAAAAAA'
    + 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    + 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    + 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    + 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    + 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    + 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    + 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    + 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    + 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==';
begin
  LRootCertBin := DecodeBase64(RootCertB64);
  LRootCrlBin := DecodeBase64(RootCrlB64);
  LAttrCert := DecodeBase64(AttrCertB64);

  LContentInfo := TCmsContentInfo.Create(TCmsObjectIdentifiers.Data, nil);
  LRootCertObj := TAsn1Object.FromByteArray(LRootCertBin) as IAsn1Encodable;
  LTaggedAttr := TDerTaggedObject.Create(False, 2, TAsn1Object.FromByteArray(LAttrCert) as IAsn1Encodable);
  LCertSet := TDerSet.Create([LRootCertObj, LTaggedAttr]);
  LRootCrlObj := TAsn1Object.FromByteArray(LRootCrlBin) as IAsn1Encodable;
  LCrlSet := TDerSet.Create(LRootCrlObj);
  LSigData := TCmsSignedData.Create(
    TDerSet.Empty,
    LContentInfo,
    LCertSet,
    LCrlSet,
    TDerSet.Empty);
  LContentInfo := TCmsContentInfo.Create(TCmsObjectIdentifiers.SignedData, LSigData);
  LInfoEnc := LContentInfo.GetEncoded();

  LCertParser := TX509CertificateParser.Create;
  LCrlParser := TX509CrlParser.Create;

  LCert := LCertParser.ReadCertificate(LInfoEnc);
  if (LCert = nil) or (not AreEqual(LCert.GetEncoded(), LRootCertBin)) then
    Fail('PKCS7 cert not read');

  LCrl := LCrlParser.ReadCrl(LInfoEnc);
  if (LCrl = nil) or (not AreEqual(LCrl.GetEncoded(), LRootCrlBin)) then
    Fail('PKCS7 crl not read');

  LCertList := LCertParser.ReadCertificates(LInfoEnc);
  if (System.Length(LCertList) <> 1) or (not AreEqual(LCertList[0].GetEncoded(), LRootCertBin)) then
    Fail('PKCS7 cert collection not right');

  LCrlList := LCrlParser.ReadCrls(LInfoEnc);
  if (System.Length(LCrlList) <> 1) or (not AreEqual(LCrlList[0].GetEncoded(), LRootCrlBin)) then
    Fail('PKCS7 crl collection not right');

  { empty certs and crls }
  LSigData := TCmsSignedData.Create(TDerSet.Empty, LContentInfo, TDerSet.Empty, TDerSet.Empty, TDerSet.Empty);
  LContentInfo := TCmsContentInfo.Create(TCmsObjectIdentifiers.SignedData, LSigData);
  LInfoEnc := LContentInfo.GetEncoded();
  LCert := LCertParser.ReadCertificate(LInfoEnc);
  if LCert <> nil then
    Fail('PKCS7 cert present');
  LCrl := LCrlParser.ReadCrl(LInfoEnc);
  if LCrl <> nil then
    Fail('PKCS7 crl present');

  { absent certs and crls - use nil for optional }
  LSigData := TCmsSignedData.Create(TDerSet.Empty, TCmsContentInfo.Create(TCmsObjectIdentifiers.Data, nil) as ICmsContentInfo, nil, nil, TDerSet.Empty);
  LContentInfo := TCmsContentInfo.Create(TCmsObjectIdentifiers.SignedData, LSigData);
  LInfoEnc := LContentInfo.GetEncoded();
  LCert := LCertParser.ReadCertificate(LInfoEnc);
  if LCert <> nil then
    Fail('PKCS7 cert present');
  LCrl := LCrlParser.ReadCrl(LInfoEnc);
  if LCrl <> nil then
    Fail('PKCS7 crl present');

  { sample message: pkcs7CrlProblem - expect 4 certs, 0 CRLs }
  LCrlProblemBin := DecodeBase64(PKCS7_CRL_PROBLEM_B64);
  LCertList := LCertParser.ReadCertificates(LCrlProblemBin);
  LCrlList := LCrlParser.ReadCrls(LCrlProblemBin);
  if System.Length(LCrlList) <> 0 then
    Fail(Format('wrong number of CRLs: %d', [System.Length(LCrlList)]));
  if System.Length(LCertList) <> 4 then
    Fail(Format('wrong number of Certs: %d', [System.Length(LCertList)]));
end;

procedure TCertTest.CreatePssCert(const AAlgorithm: string);
var
  LKp: IAsymmetricCipherKeyPair;
  LOrd: TList<IDerObjectIdentifier>;
  LValues: TList<String>;
  LName: IX509Name;
  LCertGen: IX509V3CertificateGenerator;
  LBaseCert: IX509Certificate;
  LSigner: ISignatureFactory;
  LUtc: TDateTime;
begin
  LUtc := TTimeZone.Local.ToUniversalTime(Now);
  LKp := GenerateLongFixedKeys();
  LOrd := TList<IDerObjectIdentifier>.Create;
  LValues := TList<String>.Create;
  try
    LOrd.Add(TX509Name.C);
    LOrd.Add(TX509Name.O);
    LOrd.Add(TX509Name.L);
    LOrd.Add(TX509Name.ST);
    LOrd.Add(TX509Name.E);

    LValues.Add('NG');
    LValues.Add('CryptoLib4Pascal');
    LValues.Add('Alausa');
    LValues.Add('Lagos');
    LValues.Add('feedback-crypto@cryptolib4pascal.org');

    LName := TX509Name.Create(LOrd, LValues);

    LCertGen := TX509V3CertificateGenerator.Create;
    LCertGen.SetSerialNumber(TBigInteger.One);
    LCertGen.SetIssuerDN(LName);
    LCertGen.SetNotBeforeUtc(IncSecond(LUtc, -50));
    LCertGen.SetNotAfterUtc(IncSecond(LUtc, 50));
    LCertGen.SetSubjectDN(LName);
    LCertGen.SetPublicKey(LKp.Public);
    LCertGen.AddExtension('2.5.29.15', True, TKeyUsage.Create(TKeyUsage.EncipherOnly) as IKeyUsage);
    LCertGen.AddExtension(TX509Extensions.ExtendedKeyUsage.ID, True, TDerSequence.Create(TKeyPurposeId.AnyExtendedKeyUsage) as IDerSequence);
    LCertGen.AddExtension('2.5.29.17', True, TGeneralNames.Create(TGeneralName.Create(TGeneralName.Rfc822Name, 'test@test.test') as IGeneralName) as IGeneralNames);

    LSigner := TAsn1SignatureFactory.Create(AAlgorithm, LKp.Private, nil);
    LBaseCert := LCertGen.Generate(LSigner);

    LBaseCert.Verify(LKp.Public);
  finally
    LOrd.Free;
    LValues.Free;
  end;
end;

procedure TCertTest.CreateECCert(const AAlgorithm: string; const AAlgOid: IDerObjectIdentifier);
var
  LX9: IX9ECParameters;
  LCurve: IECCurve;
  LSpec: IECDomainParameters;
  LPrivKey: IECPrivateKeyParameters;
  LPubKey: IECPublicKeyParameters;
  LOrd: TList<IDerObjectIdentifier>;
  LValues: TList<String>;
  LName: IX509Name;
  LCertGen: IX509V3CertificateGenerator;
  LCert: IX509Certificate;
  LParser: IX509CertificateParser;
  LUtc: TDateTime;
  LQ: IECPoint;
begin
  LX9 := TECNamedCurveTable.GetByName('secp521r1');
  LCurve := LX9.Curve;
  LSpec := TECDomainParameters.FromX9ECParameters(LX9);

  LPrivKey := TECPrivateKeyParameters.Create('ECDSA',
    TBigInteger.Create('5769183828869504557786041598510887460263120754767955773309066354712783118202294874205844512909370791582896372147797293913785865682804434049019366394746072023'),
    LSpec);

  LPubKey := TECPublicKeyParameters.Create('ECDSA',
    LCurve.DecodePoint(THexEncoder.Decode('02006BFDD2C9278B63C92D6624F151C9D7A822CC75BD983B17D25D74C26740380022D3D8FAF304781E416175EADF4ED6E2B47142D2454A7AC7801DD803CF44A4D1F0AC')),
    LSpec);

  LOrd := TList<IDerObjectIdentifier>.Create;
  LValues := TList<String>.Create;
  try
    LOrd.Add(TX509Name.C);
    LOrd.Add(TX509Name.O);
    LOrd.Add(TX509Name.L);
    LOrd.Add(TX509Name.ST);
    LOrd.Add(TX509Name.E);

    LValues.Add('NG');
    LValues.Add('CryptoLib4Pascal');
    LValues.Add('Alausa');
    LValues.Add('Lagos');
    LValues.Add('feedback-crypto@cryptolib4pascal.org');

    LName := TX509Name.Create(LOrd, LValues);

    LCertGen := TX509V3CertificateGenerator.Create;
    LCertGen.SetSerialNumber(TBigInteger.One);
    LCertGen.SetIssuerDN(LName);
    LUtc := TTimeZone.Local.ToUniversalTime(Now);
    LCertGen.SetNotBeforeUtc(IncSecond(LUtc, -50));
    LCertGen.SetNotAfterUtc(IncSecond(LUtc, 50));
    LCertGen.SetSubjectDN(LName);
    LCertGen.SetPublicKey(LPubKey);

    LCert := LCertGen.Generate(TAsn1SignatureFactory.Create(AAlgorithm, LPrivKey, nil) as ISignatureFactory);

    LCert.CheckValidity(LUtc);
    LCert.Verify(LPubKey);

    LParser := TX509CertificateParser.Create;
    LCert := LParser.ReadCertificate(LCert.GetEncoded());

    LQ := LPubKey.q.Normalize();
    LPubKey := TECPublicKeyParameters.Create(LPubKey.AlgorithmName,
      LCurve.CreatePoint(LQ.XCoord.ToBigInteger(), LQ.YCoord.ToBigInteger()),
      LPubKey.Parameters);

    LCertGen.SetPublicKey(LPubKey);
    LCert := LCertGen.Generate(TAsn1SignatureFactory.Create(AAlgorithm, LPrivKey, nil) as ISignatureFactory);

    LCert.CheckValidity(LUtc);
    LCert.Verify(LPubKey);

    LParser := TX509CertificateParser.Create;
    LCert := LParser.ReadCertificate(LCert.GetEncoded());

    if LCert.GetSigAlgOid <> AAlgOid.Id then
      Fail('ECDSA oid incorrect.');

    if LCert.GetSigAlgParams <> nil then
      Fail('sig parameters present');
  finally
    LOrd.Free;
    LValues.Free;
  end;
end;

procedure TCertTest.TestCreation1;
begin
  CheckCreation1;
end;

procedure TCertTest.TestCreation2;
begin
  CheckCreation2;
end;

procedure TCertTest.TestCreation3;
begin
  CheckCreation3;
end;

procedure TCertTest.TestCreation5;
begin
  CheckCreation5;
end;

procedure TCertTest.TestCrlCreation1;
begin
  CheckCrlCreation1;
end;

procedure TCertTest.TestCrlCreation2;
begin
  CheckCrlCreation2;
end;

procedure TCertTest.TestCrlCreation3;
begin
  CheckCrlCreation3;
end;

procedure TCertTest.TestPem;
begin
  PemTest;
end;

procedure TCertTest.TestDoTestForgedSignature;
begin
  DoTestForgedSignature;
end;

procedure TCertTest.TestDoTestNullDerNullCert;
begin
  DoTestNullDerNullCert;
end;

procedure TCertTest.TestPemFileTest;
begin
  PemFileTest;
end;

procedure TCertTest.TestPemFileTestWithNl;
begin
  PemFileTestWithNl;
end;

procedure TCertTest.TestInvalidCrls;
begin
  InvalidCrls;
end;

procedure TCertTest.TestPkcs7Test;
begin
  Pkcs7Test;
end;

procedure TCertTest.TestCreatePssCertSha1;
begin
  CreatePssCert('SHA1withRSAandMGF1');
end;

procedure TCertTest.TestCreatePssCertSha224;
begin
  CreatePssCert('SHA224withRSAandMGF1');
end;

procedure TCertTest.TestCreatePssCertSha256;
begin
  CreatePssCert('SHA256withRSAandMGF1');
end;

procedure TCertTest.TestCreatePssCertSha384;
begin
  CreatePssCert('SHA384withRSAandMGF1');
end;

procedure TCertTest.TestCreateECCertSha1;
begin
  CreateECCert('SHA1withECDSA', TX9ObjectIdentifiers.ECDsaWithSha1);
end;

procedure TCertTest.TestCreateECCertSha224;
begin
  CreateECCert('SHA224withECDSA', TX9ObjectIdentifiers.ECDsaWithSha224);
end;

procedure TCertTest.TestCreateECCertSha256;
begin
  CreateECCert('SHA256withECDSA', TX9ObjectIdentifiers.ECDsaWithSha256);
end;

procedure TCertTest.TestCreateECCertSha384;
begin
  CreateECCert('SHA384withECDSA', TX9ObjectIdentifiers.ECDsaWithSha384);
end;

procedure TCertTest.TestCreateECCertSha512;
begin
  CreateECCert('SHA512withECDSA', TX9ObjectIdentifiers.ECDsaWithSha512);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TCertTest);
{$ELSE}
  RegisterTest(TCertTest.Suite);
{$ENDIF FPC}

end.
