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

unit PemReaderTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpPemObjects,
  ClpIPemObjects,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpPkcsAsn1Objects,
  ClpIPkcsAsn1Objects,
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpConverters,
  ClpEncoders,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TPemReaderTest = class(TCryptoLibAlgorithmTestCase)
  published
    procedure TestMalformedInput;
    procedure TestSaneInput;
    procedure TestWithHeaders;
    procedure TestNoWhiteSpace;

  end;

implementation

{ TPemReaderTest }

procedure TPemReaderTest.TestMalformedInput;
var
  LRaw: String;
  LStream: TStringStream;
  LPemReader: IPemReader;
  LPemObject: IPemObject;
  LPkcs10: ICertificationRequest;
  LSubject: String;
begin
  LRaw := '-----BEGIN CERTIFICATE REQUEST----- MIIBkTCB+wIBADAUMRIwEAYDVQQDDAlUZXN0MlNBTnMwgZ8wDQYJKoZIhvcNAQEB' +
    ' BQADgY0AMIGJAoGBAPPPH7W8LqBMCwSu/MsmCeSCfBzMEp4k+aZmeKw8EQD1R3FK' +
    ' WtPy/LcaUyQhyIeNPFAH8JEz0dJRJjleFL8G5pv7c2YXjBmIfbF/W2eETBIohMDP' +
    ' pWOqKYiT1mqzw25rP1VuXGXaSfN22RReomUd9O2GuEkaqz5x5iTRD6aLmDoJAgMB' +
    ' AAGgPjA8BgkqhkiG9w0BCQ4xLzAtMCsGA1UdEQQkMCKCD3NhbjEudGVzdC5sb2Nh' +
    ' bIIPc2FuMi50ZXN0LmxvY2FsMA0GCSqGSIb3DQEBCwUAA4GBAOacp+9s7/jpmSTA' +
    ' ORvx4nsDwBsY4VLeuPUc2gYmHqfVgrCCSHKPQtQge0P5atudbo+q8Fn+/5JnJR6/' +
    ' JaooICY3M+/QVrvzvV30i5W8aEIERfXsEIcFyVxv24p6SbrGAcSjwpqvgAf0z82F' +
    ' D3f1qdFATb9HAFsuD/J0HexTFDvB -----END CERTIFICATE REQUEST-----';

  LStream := TStringStream.Create(LRaw, TEncoding.ASCII);
  try
    LPemReader := TPemReader.Create(LStream);
    LPemObject := LPemReader.ReadPemObject();

    LPkcs10 := TCertificationRequest.GetInstance(
      TAsn1Sequence.GetInstance(LPemObject.Content) as TObject);
    LSubject := LPkcs10.GetCertificationRequestInfo().Subject.ToString();

    CheckEquals('CERTIFICATE REQUEST', LPemObject.&Type, 'PEM type should be CERTIFICATE REQUEST');
    CheckEquals('CN=Test2SANs', LSubject, 'Subject should match');
  finally
    LStream.Free;
  end;
end;

procedure TPemReaderTest.TestSaneInput;
var
  LTest: String;
  LStream: TStringStream;
  LPemReader: IPemReader;
  LPemObject: IPemObject;
  LCert: IX509CertificateStructure;
  LIssuer: String;
begin
  LTest := 'Certificate:' + sLineBreak +
    '    Data:' + sLineBreak +
    '        Version: 3 (0x2)' + sLineBreak +
    '        Serial Number: 865 (0x361)' + sLineBreak +
    '    Signature Algorithm: ecdsa-with-SHA1' + sLineBreak +
    '        Issuer: CN=estExampleCA' + sLineBreak +
    '        Validity' + sLineBreak +
    '            Not Before: Sep 29 12:41:31 2014 GMT' + sLineBreak +
    '            Not After : Dec 16 12:41:31 2022 GMT' + sLineBreak +
    '        Subject: CN=*.cisco.com' + sLineBreak +
    '        Subject Public Key Info:' + sLineBreak +
    '            Public Key Algorithm: rsaEncryption' + sLineBreak +
    '                Public-Key: (1024 bit)' + sLineBreak +
    '                Modulus:' + sLineBreak +
    '                    00:b7:08:e6:18:f2:32:d7:07:44:4b:f3:b1:83:01:' + sLineBreak +
    '                    59:f8:bc:ec:26:71:92:9a:53:70:f2:c0:be:2a:d6:' + sLineBreak +
    '                    26:6f:45:11:86:d7:ee:37:9d:d3:2f:22:b2:8b:9b:' + sLineBreak +
    '                    c5:96:00:36:73:97:c3:4c:f2:7a:0b:2c:e0:cc:d9:' + sLineBreak +
    '                    f0:ec:ba:1b:75:8c:66:b1:86:10:fd:be:df:6b:67:' + sLineBreak +
    '                    9c:0e:6b:2a:0e:d0:80:a8:dc:7a:d4:df:6e:79:28:' + sLineBreak +
    '                    a7:60:1a:11:b7:ae:40:94:bb:b4:11:ed:1b:6f:a7:' + sLineBreak +
    '                    91:ae:33:ec:bf:9c:30:f3:dc:91:2c:b4:3e:8c:c9:' + sLineBreak +
    '                    bd:f1:d1:aa:f6:c2:1d:6a:cd' + sLineBreak +
    '                Exponent: 65537 (0x10001)' + sLineBreak +
    '        X509v3 extensions:' + sLineBreak +
    '            X509v3 Basic Constraints: ' + sLineBreak +
    '                CA:FALSE' + sLineBreak +
    '            X509v3 Key Usage: ' + sLineBreak +
    '                Digital Signature, Non Repudiation, Key Encipherment' + sLineBreak +
    '    Signature Algorithm: ecdsa-with-SHA1' + sLineBreak +
    '         30:44:02:20:76:4f:3a:6c:b4:99:cb:1e:37:f4:0d:6e:e1:74:' + sLineBreak +
    '         4b:99:bb:f5:c4:b6:3d:c1:61:df:8c:d7:1f:9f:e7:d3:64:d6:' + sLineBreak +
    '         02:20:64:38:8f:6f:32:37:2b:7d:cf:28:93:e5:e6:e7:70:c5:' + sLineBreak +
    '         a9:12:04:b0:4b:a5:29:7b:23:df:85:f2:18:44:8b:d2' + sLineBreak +
    '-----BEGIN CERTIFICATE-----' + sLineBreak +
    'MIIBezCCASOgAwIBAgICA2EwCQYHKoZIzj0EATAXMRUwEwYDVQQDEwxlc3RFeGFt' + sLineBreak +
    'cGxlQ0EwHhcNMTQwOTI5MTI0MTMxWhcNMjIxMjE2MTI0MTMxWjAWMRQwEgYDVQQD' + sLineBreak +
    'DAsqLmNpc2NvLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAtwjmGPIy' + sLineBreak +
    '1wdES/OxgwFZ+LzsJnGSmlNw8sC+KtYmb0URhtfuN53TLyKyi5vFlgA2c5fDTPJ6' + sLineBreak +
    'CyzgzNnw7LobdYxmsYYQ/b7fa2ecDmsqDtCAqNx61N9ueSinYBoRt65AlLu0Ee0b' + sLineBreak +
    'b6eRrjPsv5ww89yRLLQ+jMm98dGq9sIdas0CAwEAAaMaMBgwCQYDVR0TBAIwADAL' + sLineBreak +
    'BgNVHQ8EBAMCBeAwCQYHKoZIzj0EAQNHADBEAiB2TzpstJnLHjf0DW7hdEuZu/XE' + sLineBreak +
    'tj3BYd+M1x+f59Nk1gIgZDiPbzI3K33PKJPl5udwxakSBLBLpSl7I9+F8hhEi9I=' + sLineBreak +
    '-----END CERTIFICATE-----' + sLineBreak;

  LStream := TStringStream.Create(LTest, TEncoding.ASCII);
  try
    LPemReader := TPemReader.Create(LStream);
    LPemObject := LPemReader.ReadPemObject();
    
    LCert := TX509CertificateStructure.GetInstance(
      TAsn1Sequence.GetInstance(LPemObject.Content) as TObject);
    LIssuer := LCert.Issuer.ToString();

    CheckEquals('CERTIFICATE', LPemObject.&Type, 'PEM type should be CERTIFICATE');
    CheckEquals('CN=estExampleCA', LIssuer, 'Issuer should match');
  finally
    LStream.Free;
  end;
end;

procedure TPemReaderTest.TestWithHeaders;
var
  LHdr, LHdr2, LHdr3, LHdr4, LHdr5, LTest: String;
  LStream: TStringStream;
  LPemReader: IPemReader;
  LPemObject: IPemObject;
  LCert: IX509CertificateStructure;
  LIssuer: String;
  LHeaders: TCryptoLibGenericArray<IPemHeader>;
  LExpectedHeaders: array[0..4] of array[0..1] of String;
  I: Int32;
begin
  LHdr := 'Proc-Type: 4,CRL' + sLineBreak;
  LHdr2 := 'CRL: CRL Header' + sLineBreak;
  LHdr3 := 'Originator-Certificate: originator certificate' + sLineBreak;
  LHdr4 := 'CRL: crl header' + sLineBreak;
  LHdr5 := 'Originator-Certificate: next originator certificate' + sLineBreak;

  LTest := '-----BEGIN CERTIFICATE-----' + sLineBreak + LHdr + LHdr2 + '    ' + #9 + #13 + #0 + LHdr3 + LHdr4 + LHdr5 +
    'MIIBezCCASOgAwIBAgICA2EwCQYHKoZIzj0EATAXMRUwEwYDVQQDEwxlc3RFeGFt' + sLineBreak +
    'cGxlQ0EwHhcNMTQwOTI5MTI0MTMxWhcNMjIxMjE2MTI0MTMxWjAWMRQwEgYDVQQD' + sLineBreak +
    'DAsqLmNpc2NvLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAtwjmGPIy' + sLineBreak +
    '1wdES/OxgwFZ+LzsJnGSmlNw8sC+KtYmb0URhtfuN53TLyKyi5vFlgA2c5fDTPJ6' + sLineBreak +
    'CyzgzNnw7LobdYxmsYYQ/b7fa2ecDmsqDtCAqNx61N9ueSinYBoRt65AlLu0Ee0b' + sLineBreak +
    'b6eRrjPsv5ww89yRLLQ+jMm98dGq9sIdas0CAwEAAaMaMBgwCQYDVR0TBAIwADAL' + sLineBreak +
    'BgNVHQ8EBAMCBeAwCQYHKoZIzj0EAQNHADBEAiB2TzpstJnLHjf0DW7hdEuZu/XE' + sLineBreak +
    'tj3BYd+M1x+f59Nk1gIgZDiPbzI3K33PKJPl5udwxakSBLBLpSl7I9+F8hhEi9I=' + sLineBreak +
    '-----END CERTIFICATE-----' + sLineBreak;

  LStream := TStringStream.Create(LTest, TEncoding.ASCII);
  try
    LPemReader := TPemReader.Create(LStream);
    LPemObject := LPemReader.ReadPemObject();

    LCert := TX509CertificateStructure.GetInstance(
      TAsn1Sequence.GetInstance(LPemObject.Content) as TObject);
    LIssuer := LCert.Issuer.ToString();

    CheckEquals('CERTIFICATE', LPemObject.&Type, 'PEM type should be CERTIFICATE');
    CheckEquals('CN=estExampleCA', LIssuer, 'Issuer should match');

    LHeaders := LPemObject.Headers;
    LExpectedHeaders[0][0] := 'Proc-Type';
    LExpectedHeaders[0][1] := '4,CRL';
    LExpectedHeaders[1][0] := 'CRL';
    LExpectedHeaders[1][1] := 'CRL Header';
    LExpectedHeaders[2][0] := 'Originator-Certificate';
    LExpectedHeaders[2][1] := 'originator certificate';
    LExpectedHeaders[3][0] := 'CRL';
    LExpectedHeaders[3][1] := 'crl header';
    LExpectedHeaders[4][0] := 'Originator-Certificate';
    LExpectedHeaders[4][1] := 'next originator certificate';

    CheckEquals(5, System.Length(LHeaders), 'Should have 5 headers');
    for I := 0 to System.Length(LExpectedHeaders) - 1 do
    begin
      CheckEquals(LExpectedHeaders[I][0], LHeaders[I].Name, 
        Format('Header %d name should match', [I]));
      CheckEquals(LExpectedHeaders[I][1], LHeaders[I].Value, 
        Format('Header %d value should match', [I]));
    end;
  finally
    LStream.Free;
  end;
end;

procedure TPemReaderTest.TestNoWhiteSpace;
var
  LTest: String;
  LStream: TStringStream;
  LPemReader: IPemReader;
  LPemObject: IPemObject;
  LCert: IX509CertificateStructure;
  LIssuer: String;
begin
  LTest := '-----BEGIN CERTIFICATE-----' +
    'MIIBezCCASOgAwIBAgICA2EwCQYHKoZIzj0EATAXMRUwEwYDVQQDEwxlc3RFeGFt' +
    'cGxlQ0EwHhcNMTQwOTI5MTI0MTMxWhcNMjIxMjE2MTI0MTMxWjAWMRQwEgYDVQQD' +
    'DAsqLmNpc2NvLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAtwjmGPIy' +
    '1wdES/OxgwFZ+LzsJnGSmlNw8sC+KtYmb0URhtfuN53TLyKyi5vFlgA2c5fDTPJ6' +
    'CyzgzNnw7LobdYxmsYYQ/b7fa2ecDmsqDtCAqNx61N9ueSinYBoRt65AlLu0Ee0b' +
    'b6eRrjPsv5ww89yRLLQ+jMm98dGq9sIdas0CAwEAAaMaMBgwCQYDVR0TBAIwADAL' +
    'BgNVHQ8EBAMCBeAwCQYHKoZIzj0EAQNHADBEAiB2TzpstJnLHjf0DW7hdEuZu/XE' +
    'tj3BYd+M1x+f59Nk1gIgZDiPbzI3K33PKJPl5udwxakSBLBLpSl7I9+F8hhEi9I=' +
    '-----END CERTIFICATE-----';

  LStream := TStringStream.Create(LTest, TEncoding.ASCII);
  try
    LPemReader := TPemReader.Create(LStream);
    LPemObject := LPemReader.ReadPemObject();
    
    LCert := TX509CertificateStructure.GetInstance(
      TAsn1Sequence.GetInstance(LPemObject.Content) as TObject);
    LIssuer := LCert.Issuer.ToString();

    CheckEquals('CERTIFICATE', LPemObject.&Type, 'PEM type should be CERTIFICATE');
    CheckEquals('CN=estExampleCA', LIssuer, 'Issuer should match');
  finally
    LStream.Free;
  end;
end;

initialization

{$IFDEF FPC}
RegisterTest(TPemReaderTest);
{$ELSE}
RegisterTest(TPemReaderTest.Suite);
{$ENDIF FPC}

end.
