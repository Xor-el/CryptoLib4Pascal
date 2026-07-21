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
  ClpPemHeader,
  ClpPemObject,
  ClpIPemHeader,
  ClpIPemObject,
  ClpIPemReader,
  ClpPemReader,
  ClpIPemWriter,
  ClpPemWriter,
  ClpAsn1Objects,
  ClpPkcsAsn1Objects,
  ClpIPkcsAsn1Objects,
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  CryptoLibTestBase,
  PemReaderVectors;

type

  TPemReaderTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    procedure LengthTest(const AType: String;
      const AHeaders: TCryptoLibGenericArray<IPemHeader>;
      const AData: TCryptoLibByteArray);
  published
    procedure TestMalformedInput;
    procedure TestSaneInput;
    procedure TestWithHeaders;
    procedure TestNoWhiteSpace;
    procedure TestPemLength;
    procedure TestMalformed;
    procedure TestMalformedBase64;
    procedure TestHeaderLineBreakRejected;
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
  LRaw := TPemReaderVectors.LoadFixtureText('MalformedInput');
  LStream := TStringStream.Create(LRaw, TEncoding.ASCII);
  try
    LPemReader := TPemReader.Create(LStream);
    LPemObject := LPemReader.ReadPemObject();

    LPkcs10 := TCertificationRequest.GetInstance(
      TAsn1Sequence.GetInstance(LPemObject.Content));
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
  LTest := TPemReaderVectors.LoadFixtureText('SaneInput');
  LStream := TStringStream.Create(LTest, TEncoding.ASCII);
  try
    LPemReader := TPemReader.Create(LStream);
    LPemObject := LPemReader.ReadPemObject();

    LCert := TX509CertificateStructure.GetInstance(
      TAsn1Sequence.GetInstance(LPemObject.Content));
    LIssuer := LCert.Issuer.ToString();

    CheckEquals('CERTIFICATE', LPemObject.&Type, 'PEM type should be CERTIFICATE');
    CheckEquals('CN=estExampleCA', LIssuer, 'Issuer should match');
  finally
    LStream.Free;
  end;
end;

procedure TPemReaderTest.TestWithHeaders;
var
  LTest: String;
  LStream: TStringStream;
  LPemReader: IPemReader;
  LPemObject: IPemObject;
  LCert: IX509CertificateStructure;
  LIssuer: String;
  LHeaders: TCryptoLibGenericArray<IPemHeader>;
  LExpectedHeaders: array[0..4] of array[0..1] of String;
  I: Int32;
begin
  LTest := TPemReaderVectors.LoadFixtureText('WithHeaders');
  LStream := TStringStream.Create(LTest, TEncoding.ASCII);
  try
    LPemReader := TPemReader.Create(LStream);
    LPemObject := LPemReader.ReadPemObject();

    LCert := TX509CertificateStructure.GetInstance(
      TAsn1Sequence.GetInstance(LPemObject.Content));
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
  LTest := TPemReaderVectors.LoadFixtureText('NoWhiteSpace');
  LStream := TStringStream.Create(LTest, TEncoding.ASCII);
  try
    LPemReader := TPemReader.Create(LStream);
    LPemObject := LPemReader.ReadPemObject();

    LCert := TX509CertificateStructure.GetInstance(
      TAsn1Sequence.GetInstance(LPemObject.Content));
    LIssuer := LCert.Issuer.ToString();

    CheckEquals('CERTIFICATE', LPemObject.&Type, 'PEM type should be CERTIFICATE');
    CheckEquals('CN=estExampleCA', LIssuer, 'Issuer should match');
  finally
    LStream.Free;
  end;
end;

procedure TPemReaderTest.LengthTest(const AType: String;
  const AHeaders: TCryptoLibGenericArray<IPemHeader>;
  const AData: TCryptoLibByteArray);
var
  LPemObj: IPemObject;
  LStream: TStringStream;
  LWriter: IPemWriter;
  LOutputLen: Int32;
begin
  LPemObj := TPemObject.Create(AType, AHeaders, AData);
  LStream := TStringStream.Create('', TEncoding.ASCII);
  try
    LWriter := TPemWriter.Create(LStream);
    LWriter.WriteObject(LPemObj as IPemObjectGenerator);
    LOutputLen := LWriter.GetOutputSize(LPemObj);
    CheckEquals(LStream.Size, LOutputLen,
      Format('PEM output length should match GetOutputSize for type %s', [AType]));
  finally
    LStream.Free;
  end;
end;

procedure TPemReaderTest.TestPemLength;
var
  I: Int32;
  LEmptyHeaders: TCryptoLibGenericArray<IPemHeader>;
  LHeaders: TCryptoLibGenericArray<IPemHeader>;
  LData: TCryptoLibByteArray;
begin
  LEmptyHeaders := nil;
  for I := 1 to 59 do
  begin
    SetLength(LData, I);
    LengthTest('CERTIFICATE', LEmptyHeaders, LData);
  end;

  SetLength(LData, 100);
  LengthTest('CERTIFICATE', LEmptyHeaders, LData);
  SetLength(LData, 101);
  LengthTest('CERTIFICATE', LEmptyHeaders, LData);
  SetLength(LData, 102);
  LengthTest('CERTIFICATE', LEmptyHeaders, LData);
  SetLength(LData, 103);
  LengthTest('CERTIFICATE', LEmptyHeaders, LData);

  SetLength(LData, 1000);
  LengthTest('CERTIFICATE', LEmptyHeaders, LData);
  SetLength(LData, 1001);
  LengthTest('CERTIFICATE', LEmptyHeaders, LData);
  SetLength(LData, 1002);
  LengthTest('CERTIFICATE', LEmptyHeaders, LData);
  SetLength(LData, 1003);
  LengthTest('CERTIFICATE', LEmptyHeaders, LData);

  SetLength(LHeaders, 2);
  LHeaders[0] := TPemHeader.Create('Proc-Type', '4,ENCRYPTED');
  LHeaders[1] := TPemHeader.Create('DEK-Info', 'DES3,0001020304050607');
  SetLength(LData, 103);
  LengthTest('RSA PRIVATE KEY', LHeaders, LData);
end;

procedure TPemReaderTest.TestMalformedBase64;
var
  LStream: TStringStream;
  LPemReader: IPemReader;
begin
  // A PEM block with valid framing but a corrupt base64 body must surface as an I/O error,
  // not a raw format exception from callers parsing untrusted PEM.
  LStream := TStringStream.Create(
    '-----BEGIN CERTIFICATE-----' + sLineBreak +
    '!!!not base64!!!' + sLineBreak +
    '-----END CERTIFICATE-----' + sLineBreak, TEncoding.ASCII);
  try
    LPemReader := TPemReader.Create(LStream);
    try
      LPemReader.ReadPemObject();
      Fail('must fail on malformed base64');
    except
      on E: EIOCryptoLibException do
        CheckEquals(1, Pos('malformed PEM data:', E.Message), 'unexpected message: ' + E.Message);
      on E: Exception do
        Fail('Expected EIOCryptoLibException, got ' + E.ClassName + ': ' + E.Message);
    end;
  finally
    LStream.Free;
  end;
end;

procedure TPemReaderTest.TestMalformed;
var
  LStream: TStringStream;
  LPemReader: IPemReader;
begin
  LStream := TStringStream.Create('-----BEGIN ' + sLineBreak, TEncoding.ASCII);
  try
    LPemReader := TPemReader.Create(LStream);
    try
      LPemReader.ReadPemObject();
      Fail('must fail on malformed');
    except
      on E: EIOCryptoLibException do
        CheckEquals('ran out of data before consuming PEM type', E.Message, 'Exception message');
      on E: Exception do
        Fail('Expected EIOCryptoLibException, got ' + E.ClassName + ': ' + E.Message);
    end;
  finally
    LStream.Free;
  end;
end;

procedure TPemReaderTest.TestHeaderLineBreakRejected;
var
  LHeaders: TCryptoLibGenericArray<IPemHeader>;
  LPemObj: IPemObject;
  LStream: TStringStream;
  LWriter: IPemWriter;
begin
  SetLength(LHeaders, 1);
  LHeaders[0] := TPemHeader.Create('Proc-Type', '4,ENCRYPTED' + sLineBreak + 'injected')
    as IPemHeader;
  LPemObj := TPemObject.Create('CERTIFICATE', LHeaders, TBytes.Create($01))
    as IPemObject;
  LStream := TStringStream.Create('', TEncoding.ASCII);
  try
    LWriter := TPemWriter.Create(LStream);
    try
      LWriter.WriteObject(LPemObj as IPemObjectGenerator);
      Fail('must reject PEM header containing CR/LF');
    except
      on E: EArgumentCryptoLibException do
        CheckEquals('PEM header must not contain CR/LF', E.Message, 'exception message');
      on E: Exception do
        Fail('Expected EArgumentCryptoLibException, got ' + E.ClassName + ': ' + E.Message);
    end;
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
