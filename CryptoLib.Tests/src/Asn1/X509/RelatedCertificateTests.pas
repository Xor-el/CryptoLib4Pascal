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

unit RelatedCertificateTests;

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
  ClpAsn1Objects,
  ClpAsn1Core,
  ClpIAsn1Objects,
  ClpCmsAsn1Objects,
  ClpICmsAsn1Objects,
  ClpPkcsObjectIdentifiers,
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpX509ObjectIdentifiers,
  ClpDateTimeUtilities,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TRelatedCertificateTest = class(TCryptoLibAlgorithmTestCase)
  published
    procedure TestOidValues;
    procedure TestBinaryTimeRoundTrip;
    procedure TestBinaryTimeRejectsNegative;
  end;

implementation

{ TRelatedCertificateTest }

procedure TRelatedCertificateTest.TestOidValues;
begin
  CheckEquals('1.3.6.1.5.5.7.1.36', TX509ObjectIdentifiers.IdPeRelatedCert.Id);
  CheckEquals('1.3.6.1.5.5.7.1.36', TX509Extensions.RelatedCertificate.Id);
  CheckTrue(TX509ObjectIdentifiers.IdPeRelatedCert.Equals(TX509Extensions.RelatedCertificate),
    'RelatedCertificate extension OID should match id-pe-relatedCert');
  CheckEquals('1.2.840.113549.1.9.16.2.60', TPkcsObjectIdentifiers.IdAARelatedCertRequest.Id);
end;

procedure TRelatedCertificateTest.TestBinaryTimeRoundTrip;
var
  LSec: Int64;
  LTime, LReparsed, LFromDateTime: IBinaryTime;
  LTryDateTime: TDateTime;
begin
  LSec := 1700000000;
  LTime := TBinaryTime.Create(LSec);
  CheckTrue(LTime.Time.HasValue(LSec), 'BinaryTime should carry expected seconds');

  LReparsed := TBinaryTime.GetInstance(TAsn1Object.FromByteArray(LTime.GetEncoded()));
  CheckTrue(LReparsed.Time.HasValue(LSec), 'reparsed BinaryTime should carry expected seconds');

  LFromDateTime := TBinaryTime.Create(TDateTimeUtilities.UnixMsToDateTime(LSec * 1000));
  CheckTrue(LFromDateTime.Time.HasValue(LSec), 'DateTime-constructed BinaryTime should match seconds');
  CheckEquals(LSec * 1000,
    TDateTimeUtilities.DateTimeToUnixMs(LFromDateTime.GetDateTime),
    'GetDateTime round-trip to Unix ms failed');
  CheckTrue(LFromDateTime.TryGetDateTime(LTryDateTime),
    'TryGetDateTime should succeed for in-range value');
  CheckEquals(LSec * 1000,
    TDateTimeUtilities.DateTimeToUnixMs(LTryDateTime),
    'TryGetDateTime round-trip to Unix ms failed');
end;

procedure TRelatedCertificateTest.TestBinaryTimeRejectsNegative;
var
  LPreEpoch: TDateTime;
  LTime: IBinaryTime;
begin
  try
    LTime := TBinaryTime.Create(-1);
    Fail('BinaryTime accepted negative seconds');
  except
    on EArgumentOutOfRangeCryptoLibException do
      ; // expected
  end;

  try
    LTime := TBinaryTime.Create(TDerInteger.ValueOf(-1));
    Fail('BinaryTime accepted negative DerInteger');
  except
    on EArgumentOutOfRangeCryptoLibException do
      ; // expected
  end;

  LPreEpoch := IncSecond(TDateTimeUtilities.UnixEpoch, -1);
  try
    LTime := TBinaryTime.Create(LPreEpoch);
    Fail('BinaryTime accepted pre-epoch DateTime');
  except
    on E: Exception do
      ; // expected (ArgumentOutOfRange from DateTimeToUnixMs or BinaryTime guard)
  end;
end;

initialization

{$IFDEF FPC}
RegisterTest(TRelatedCertificateTest);
{$ELSE}
RegisterTest(TRelatedCertificateTest.Suite);
{$ENDIF FPC}

end.
