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

unit X509CertificatePairTests;

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
  ClpIX509CertificateParser,
  ClpX509CertificateParser,
  ClpIX509Certificate,
  ClpIX509CertificatePair,
  ClpX509CertificatePair,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TX509CertificatePairTest = class(TCryptoLibAlgorithmTestCase)
  strict private
  var
    FRootCertBin: TCryptoLibByteArray;
    FInterCertBin: TCryptoLibByteArray;
    FFinalCertBin: TCryptoLibByteArray;

    procedure SetUpTestData;

  protected
    procedure SetUp; override;

  published
    procedure TestX509CertificatePair;

  end;

implementation

{ TX509CertificatePairTest }

procedure TX509CertificatePairTest.SetUpTestData;
begin
  // root cert, intermediate cert, final cert
  FRootCertBin := DecodeBase64(
    'MIIBqzCCARQCAQEwDQYJKoZIhvcNAQEFBQAwHjEcMBoGA1UEAxMTVGVzdCBDQSBDZXJ0aWZpY2F0ZTAeFw0wODA5MDQwNDQ1MDha' +
    'Fw0wODA5MTEwNDQ1MDhaMB4xHDAaBgNVBAMTE1Rlc3QgQ0EgQ2VydGlmaWNhdGUwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB' +
    'AMRLUjhPe4YUdLo6EcjKcWUOG7CydFTH53Pr1lWjOkbmszYDpkhCTT9LOsI+disk18nkBxSl8DAHTqV+VxtuTPt64iyi10YxyDee' +
    'p+DwZG/f8cVQv97U3hA9cLurZ2CofkMLGr6JpSGCMZ9FcstcTdHB4lbErIJ54YqfF4pNOs4/AgMBAAEwDQYJKoZIhvcNAQEFBQAD' +
    'gYEAgyrTEFY7ALpeY59jL6xFOLpuPqoBOWrUWv6O+zy5BCU0qiX71r3BpigtxRj+DYcfLIM9FNERDoHu3TthD3nwYWUBtFX8N0QU' +
    'JIdJabxqAMhLjSC744koiFpCYse5Ye3ZvEdFwDzgAQsJTp5eFGgTZPkPzcdhkFJ2p9+OWs+cb24=');

  FInterCertBin := DecodeBase64(
    'MIICSzCCAbSgAwIBAgIBATANBgkqhkiG9w0BAQUFADAeMRwwGgYDVQQDExNUZXN0IENBIENlcnRpZmljYXRlMB4XDTA4MDkwNDA0' +
    'NDUwOFoXDTA4MDkxMTA0NDUwOFowKDEmMCQGA1UEAxMdVGVzdCBJbnRlcm1lZGlhdGUgQ2VydGlmaWNhdGUwgZ8wDQYJKoZIhvcN' +
    'AQEBBQADgY0AMIGJAoGBAISS9OOZ2wxzdWny9aVvk4Joq+dwSJ+oqvHUxX3PflZyuiLiCBUOUE4q59dGKdtNX5fIfwyK3cpV0e73' +
    'Y/0fwfM3m9rOWFrCKOhfeswNTes0w/2PqPVVDDsF/nj7NApuqXwioeQlgTL251RDF4sVoxXqAU7lRkcqwZt3mwqS4KTJAgMBAAGj' +
    'gY4wgYswRgYDVR0jBD8wPYAUhv8BOT27EB9JaCccJD4YASPP5XWhIqQgMB4xHDAaBgNVBAMTE1Rlc3QgQ0EgQ2VydGlmaWNhdGWC' +
    'AQEwHQYDVR0OBBYEFL/IwAGOkHzaQyPZegy79CwM5oTFMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMA0GCSqG' +
    'SIb3DQEBBQUAA4GBAE4TRgUz4sUvZyVdZxqV+XyNRnqXAeLOOqFGYv2D96tQrS+zjd0elVlT6lFrtchZdOmmX7R6/H/tjMWMcTBI' +
    'CZyRYrvK8cCAmDOI+EIdq5p6lj2Oq6Pbw/wruojAqNrpaR6IkwNpWtdOSSupv4IJL+YU9q2YFTh4R1j3tOkPoFGr');

  FFinalCertBin := DecodeBase64(
    'MIICRjCCAa+gAwIBAgIBATANBgkqhkiG9w0BAQUFADAoMSYwJAYDVQQDEx1UZXN0IEludGVybWVkaWF0ZSBDZXJ0aWZpY2F0ZTAe' +
    'Fw0wODA5MDQwNDQ1MDhaFw0wODA5MTEwNDQ1MDhaMB8xHTAbBgNVBAMTFFRlc3QgRW5kIENlcnRpZmljYXRlMIGfMA0GCSqGSIb3' +
    'DQEBAQUAA4GNADCBiQKBgQChpUeo0tPYywWKiLlbWKNJBcCpSaLSlaZ+4+yer1AxI5yJIVHP6SAlBghlbD5Qne5ImnN/15cz1xwY' +
    'Aiul6vGKJkVPlFEe2Mr+g/J/WJPQQPsjbZ1G+vxbAwXEDA4KaQrnpjRZFq+CdKHwOjuPLYS/MYQNgdIvDVEQcTbPQ8GaiQIDAQAB' +
    'o4GIMIGFMEYGA1UdIwQ/MD2AFL/IwAGOkHzaQyPZegy79CwM5oTFoSKkIDAeMRwwGgYDVQQDExNUZXN0IENBIENlcnRpZmljYXRl' +
    'ggEBMB0GA1UdDgQWBBSVkw+VpqBf3zsLc/9GdkK9TzHPwDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDANBgkqhkiG9w0B' +
    'AQUFAAOBgQBLv/0bVDjzTs/y1vN3FUiZNknEbzupIZduTuXJjqv/vBX+LDPjUfu/+iOCXOSKoRn6nlOWhwB1z6taG2usQkFG8InM' +
    'kRcPREi2uVgFdhJ/1C3dAWhsdlubjdL926bftXvxnx/koDzyrePW5U96RlOQM2qLvbaky2Giz6hrc3Wl+w==');
end;

procedure TX509CertificatePairTest.SetUp;
begin
  inherited SetUp;
  SetUpTestData;
end;

procedure TX509CertificatePairTest.TestX509CertificatePair;
var
  LParser: IX509CertificateParser;
  LRootCert, LInterCert, LFinalCert: IX509Certificate;
  LPair1, LPair2, LPair3, LPair4, LPair5, LPair6, LPair7, LPair8: IX509CertificatePair;
begin
  LParser := TX509CertificateParser.Create();
  LRootCert := LParser.ReadCertificate(FRootCertBin);
  LInterCert := LParser.ReadCertificate(FInterCertBin);
  LFinalCert := LParser.ReadCertificate(FFinalCertBin);

  LPair1 := TX509CertificatePair.Create(LRootCert, LInterCert);
  LPair2 := TX509CertificatePair.Create(LRootCert, LInterCert);
  LPair3 := TX509CertificatePair.Create(LInterCert, LFinalCert);
  LPair4 := TX509CertificatePair.Create(LRootCert, LFinalCert);
  LPair5 := TX509CertificatePair.Create(LRootCert, nil);
  LPair6 := TX509CertificatePair.Create(LRootCert, nil);
  LPair7 := TX509CertificatePair.Create(nil, LRootCert);
  LPair8 := TX509CertificatePair.Create(nil, LRootCert);

  if not LPair1.Equals(LPair2) then
    Fail('pair1 pair2 equality test');

  if not LPair5.Equals(LPair6) then
    Fail('pair5 pair6 equality test');

  if not LPair7.Equals(LPair8) then
    Fail('pair7 pair8 equality test');

  if LPair1.Equals(nil) then
    Fail('pair1 null equality test');

  if LPair1.GetHashCode <> LPair2.GetHashCode then
    Fail('pair1 pair2 hashCode equality test');

  if LPair1.Equals(LPair3) then
    Fail('pair1 pair3 inequality test');

  if LPair1.Equals(LPair4) then
    Fail('pair1 pair4 inequality test');

  if LPair1.Equals(LPair5) then
    Fail('pair1 pair5 inequality test');

  if LPair1.Equals(LPair7) then
    Fail('pair1 pair7 inequality test');

  if LPair5.Equals(LPair1) then
    Fail('pair5 pair1 inequality test');

  if LPair7.Equals(LPair1) then
    Fail('pair7 pair1 inequality test');

  if LPair1.Forward <> LRootCert then
    Fail('pair1 forward test');

  if LPair1.Reverse <> LInterCert then
    Fail('pair1 reverse test');

  if not AreEqual(LPair1.GetEncoded(), LPair2.GetEncoded()) then
    Fail('encoding check');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TX509CertificatePairTest);
{$ELSE}
  RegisterTest(TX509CertificatePairTest.Suite);
{$ENDIF FPC}

end.
