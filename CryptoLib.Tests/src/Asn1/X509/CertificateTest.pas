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

unit CertificateTest;

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
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIX509Extension,
  ClpEncoders,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TCertificateTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    var
      FCert1, FCert2, FCert3, FCert4, FCert5, FCert6, FCert7, FDudCert, FBangerCert: TCryptoLibByteArray;
      FSubjects: TCryptoLibStringArray;

    procedure SetUpTestData;
    procedure CheckCertificate(AId: Int32; const ACert: TCryptoLibByteArray);
    procedure CheckDudCertificate;
    procedure CheckMalformed;

  protected
    procedure SetUp; override;

  published
    procedure TestCertificate1;
    procedure TestCertificate2;
    procedure TestCertificate3;
    procedure TestCertificate4;
    procedure TestCertificate5;
    procedure TestCertificate6;
    procedure TestCertificate7;
    procedure TestDudCertificate;
    procedure TestMalformedCertificate;

  end;

implementation

{ TCertificateTest }

procedure TCertificateTest.SetUpTestData;
begin
  // server.crt
  FCert1 := DecodeBase64(
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

  // ca.crt
  FCert2 := DecodeBase64(
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

  // testx509.pem
  FCert3 := DecodeBase64(
    'MIIBWzCCAQYCARgwDQYJKoZIhvcNAQEEBQAwODELMAkGA1UEBhMCQVUxDDAKBgNV' +
    'BAgTA1FMRDEbMBkGA1UEAxMSU1NMZWF5L3JzYSB0ZXN0IENBMB4XDTk1MDYxOTIz' +
    'MzMxMloXDTk1MDcxNzIzMzMxMlowOjELMAkGA1UEBhMCQVUxDDAKBgNVBAgTA1FM' +
    'RDEdMBsGA1UEAxMUU1NMZWF5L3JzYSB0ZXN0IGNlcnQwXDANBgkqhkiG9w0BAQEF' +
    'AANLADBIAkEAqtt6qS5GTxVxGZYWa0/4u+IwHf7p2LNZbcPBp9/OfIcYAXBQn8hO' +
    '/Re1uwLKXdCjIoaGs4DLdG88rkzfyK5dPQIDAQABMAwGCCqGSIb3DQIFBQADQQAE' +
    'Wc7EcF8po2/ZO6kNCwK/ICH6DobgLekA5lSLr5EvuioZniZp5lFzAw4+YzPQ7XKJ' +
    'zl9HYIMxATFyqSiD9jsx');

  // v3-cert1.pem
  FCert4 := DecodeBase64(
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

  // v3-cert2.pem
  FCert5 := DecodeBase64(
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

  FCert6 := DecodeBase64(
    'MIIEDjCCAvagAwIBAgIEFAAq2jANBgkqhkiG9w0BAQUFADBLMSowKAYDVQQDEyFT' +
    'dW4gTWljcm9zeXN0ZW1zIEluYyBDQSAoQ2xhc3MgQikxHTAbBgNVBAoTFFN1biBN' +
    'aWNyb3N5c3RlbXMgSW5jMB4XDTA0MDIyOTAwNDMzNFoXDTA5MDMwMTAwNDMzNFow' +
    'NzEdMBsGA1UEChMUU3VuIE1pY3Jvc3lzdGVtcyBJbmMxFjAUBgNVBAMTDXN0b3Jl' +
    'LnN1bi5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAP9ErzFT7MPg2bVV' +
    'LNmHTgN4kmiRNlPpuLGWS7EDIXYBbLeSSOCp/e1ANcOGnsuf0WIq9ejd/CPyEfh4' +
    'sWoVvQzpOfHZ/Jyei29PEuxzWT+4kQmCx3+sLK25lAnDFsz1KiFmB6Y3GJ/JSjpp' +
    'L0Yy1R9YlIc82I8gSw44y5JDABW5AgMBAAGjggGQMIIBjDAOBgNVHQ8BAf8EBAMC' +
    'BaAwHQYDVR0OBBYEFG1WB3PApZM7OPPVWJ31UrERaoKWMEcGA1UdIARAMD4wPAYL' +
    'YIZIAYb3AIN9k18wLTArBggrBgEFBQcCARYfaHR0cDovL3d3dy5zdW4uY29tL3Br' +
    'aS9jcHMuaHRtbDCBhQYDVR0fBH4wfDB6oCegJYYjaHR0cDovL3d3dy5zdW4uY29t' +
    'L3BraS9wa2lzbWljYS5jcmyiT6RNMEsxKjAoBgNVBAMTIVN1biBNaWNyb3N5c3Rl' +
    'bXMgSW5jIENBIChDbGFzcyBCKTEdMBsGA1UEChMUU3VuIE1pY3Jvc3lzdGVtcyBJ' +
    'bmMwHwYDVR0jBBgwFoAUT7ZnqR/EEBSgG6h1wdYMI5RiiWswVAYIKwYBBQUHAQEE' +
    'SDBGMB0GCCsGAQUFBzABhhFodHRwOi8vdmEuc3VuLmNvbTAlBggrBgEFBQcwAYYZ' +
    'aHR0cDovL3ZhLmNlbnRyYWwuc3VuLmNvbTATBgNVHSUEDDAKBggrBgEFBQcDATAN' +
    'BgkqhkiG9w0BAQUFAAOCAQEAq3byQgyU24tBpR07iQK7agm1zQyzDQ6itdbji0ln' +
    'T7fOd5Pnp99iig8ovwWliNtXKAmgtJY60jWz7nEuk38AioZJhS+RPWIWX/+2PRV7' +
    's2aWTzM3n43BypD+jU2qF9c9kDWP/NW9K9IcrS7SfU/2MZVmiCMD/9FEL+CWndwE' +
    'JJQ/oenXm44BFISI/NjV7fMckN8EayPvgtzQkD5KnEiggOD6HOrwTDFR+tmAEJ0K' +
    'ZttQNwOzCOcEdxXTg6qBHUbONdL7bjTT5NzV+JR/bnfiCqHzdnGwfbHzhmrnXw8j' +
    'QCVXcfBfL9++nmpNNRlnJMRdYGeCY6OAfh/PRo8/fXak1Q==');

  FCert7 := DecodeBase64(
    'MIIFJDCCBAygAwIBAgIKEcJZuwAAAAAABzANBgkqhkiG9w0BAQUFADAPMQ0wCwYD' +
    'VQQDEwRNU0NBMB4XDTA0MDUyMjE2MTM1OFoXDTA1MDUyMjE2MjM1OFowaTEbMBkG' +
    'CSqGSIb3DQEJCBMMMTkyLjE2OC4xLjMzMScwJQYJKoZIhvcNAQkCExhwaXhmaXJl' +
    'd2FsbC5jaXNjb3BpeC5jb20xITAfBgNVBAMTGHBpeGZpcmV3YWxsLmNpc2NvcGl4' +
    'LmNvbTB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQCbcsY7vrjweXZiFQdhUafEjJV+' +
    'HRy5UKmuCy0237ffmYrN+XNLw0h90cdCSK6KPZebd2E2Bc2UmTikc/FY8meBT3/E' +
    'O/Osmywzi++Ur8/IrDvtuR1zd0c/xEPnV1ZRezkCAwEAAaOCAs4wggLKMAsGA1Ud' +
    'DwQEAwIFoDAdBgNVHQ4EFgQUzJBSxkQiN9TKvhTMQ1/Aq4gZnHswHwYDVR0jBBgw' +
    'FoAUMsxzXVh+5UKMNpwNHmqSfcRYfJ4wgfcGA1UdHwSB7zCB7DCB6aCB5qCB44aB' +
    'r2xkYXA6Ly8vQ049TVNDQSxDTj1NQVVELENOPUNEUCxDTj1QdWJsaWMlMjBLZXkl' +
    'MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWludCxE' +
    'Qz1wcmltZWtleSxEQz1zZT9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/' +
    'b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnSGL2h0dHA6Ly9tYXVkLmlu' +
    'dC5wcmltZWtleS5zZS9DZXJ0RW5yb2xsL01TQ0EuY3JsMIIBEAYIKwYBBQUHAQEE' +
    'ggECMIH/MIGqBggrBgEFBQcwAoaBnWxkYXA6Ly8vQ049TVNDQSxDTj1BSUEsQ049' +
    'UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJh' +
    'dGlvbixEQz1pbnQsREM9cHJpbWVrZXksREM9c2U/Y0FDZXJ0aWZpY2F0ZT9iYXNl' +
    'P29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwUAYIKwYBBQUHMAKG' +
    'RGh0dHA6Ly9tYXVkLmludC5wcmltZWtleS5zZS9DZXJ0RW5yb2xsL01BVUQuaW50' +
    'LnByaW1la2V5LnNlX01TQ0EuY3J0MCwGA1UdEQEB/wQiMCCCGHBpeGZpcmV3YWxs' +
    'LmNpc2NvcGl4LmNvbYcEwKgBITA/BgkrBgEEAYI3FAIEMh4wAEkAUABTAEUAQwBJ' +
    'AG4AdABlAHIAbQBlAGQAaQBhAHQAZQBPAGYAZgBsAGkAbgBlMA0GCSqGSIb3DQEB' +
    'BQUAA4IBAQCa0asiPbObLJjpSz6ndJ7y4KOWMiuuBc/VQBnLr7RBCF3ZlZ6z1+e6' +
    'dmv8se/z11NgateKfxw69IhLCriA960HEgX9Z61MiVG+DrCFpbQyp8+hPFHoqCZN' +
    'b7upc8k2OtJW6KPaP9k0DW52YQDIky4Vb2rZeC4AMCorWN+KlndHhr1HFA14HxwA' +
    '4Mka0FM6HNWnBV2UmTjBZMDr/OrGH1jLYIceAaZK0X2R+/DWXeeqIga8jwP5empq' +
    'JetYnkXdtTbEh3xL0BX+mZl8vDI+/PGcwox/7YjFmyFWphRMxk9CZ3rF2/FQWMJP' +
    'YqQpKiQOmQg5NAhcwffLAuVjVVibPYqi');

  // bad issuer certificate
  FDudCert := DecodeBase64(
    'MIICLzCCAZgCBFp/9TowDQYJKoZIhvcNAQEFBQAwAjEAMB4XDTA4MDcyNTEzNTQ0' +
    'MFoXDTEzMDgyNTA1MDAwMFowgboxCzAJBgNVBAYTAlVTMQ0wCwYDVQQIEwRJb3dh' +
    'MRMwEQYDVQQHEwpEZXMgTW9pbmVzMT0wOwYDVQQKEzRTdGF0ZSBvZiBJb3dhLCBE' +
    'ZXBhcnRtZW50IG9mIEFkbWluaXN0cmF0aXZlIFNlcnZpY2VzMSowKAYDVQQLEyFJ' +
    'bmZvcm1hdGlvbiBUZWNobm9sb2d5IEVudGVycHJpc2UxHDAaBgNVBAMTE3d3dy5k' +
    'b20uc3RhdGUuaWEudXMwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAK0C7Jca' +
    'C0RiD0hcBcPUdGc78y815yPuHGmF/A2K+3LbwfFXDhsY7ebRxHVfL7gt+nFBvJ2r' +
    'MqDBIMHFB3vYdSnGbND41eso6cLnzkMVtSisG25Tat3F8BF/js54sa0mFEn4qMQ+' +
    '6T6jxyPflsjKpmi6L7lfRdPNbBbKSmK9ik2lAgMBAAEwDQYJKoZIhvcNAQEFBQAD' +
    'gYEAc9Rx95MiPzJiCn3nOoP+3PPQCGTyUcUWZfYKXuC7aOzMYUXes71Q3K1/W6Vy' +
    'V2Tlrbj0KT8j2/kBmy8+7d5whnUklJNsH6VJMst3V4Uxvk3os+uaW0FHsW389sNY' +
    '/5LdslDjfqV2nUc2GqDPn38PATL26SRJKlCvU2NagdID3WM=');

  // malformed cert
  FBangerCert := DecodeBase64(
    'MIIBSKADAgECAgECMA0GCSqGSIb3DQEEBAUAMCUxCzAJBgNVBAMMAkFVMRYwFAYD' +
    'VQQKDA1CaXVuYHkgQGFzdGtlMB4XDTcwMDExMTQyNjAwMVoXDTcwMDEwNzAwMDAw' +
    'MlowNjELMQkGA1UBAwwCQVUxFjAUBgNVAQwMDUJsdW5jeSZDY3Nzb2UxDzANBgNV' +
    'AQsMBlRlc3cgNTAYMBAGBisOBwMDATAGAgEBAgECAwQAAgEDoYGVMIGSMGEGA1Yd' +
    'IwEB/wRXNVWAFDZPdpTPzKi7o8EJokoQU2uqCHRRoTqkOzA2NAs2CgYDVQYDDAJ' +
    'HVTEWMBQGA1QECQwNQmhwbmR5J0Ngc3RsYDAPMA0CA1UECwwGUWVzdyA0hQECMCA' +
    'GA1UdDgEB/wQWBBQ2T3OSzciou6PBCqRJEFNrqgh2UTALBgNVHQkEBAMGBBE=');

  System.SetLength(FSubjects, 7);
  FSubjects[0] := 'C=AU,ST=Victoria,L=South Melbourne,O=Connect 4 Pty Ltd,OU=Webserver Team,CN=www2.connect4.com.au,E=webmaster@connect4.com.au';
  FSubjects[1] := 'C=AU,ST=Victoria,L=South Melbourne,O=Connect 4 Pty Ltd,OU=Certificate Authority,CN=Connect 4 CA,E=webmaster@connect4.com.au';
  FSubjects[2] := 'C=AU,ST=QLD,CN=SSLeay/rsa test cert';
  FSubjects[3] := 'C=US,O=National Aeronautics and Space Administration,SERIALNUMBER=16+CN=Steve Schoch';
  FSubjects[4] := 'E=cooke@issl.atl.hp.com,C=US,OU=Hewlett Packard Company (ISSL),CN=Paul A. Cooke';
  FSubjects[5] := 'O=Sun Microsystems Inc,CN=store.sun.com';
  FSubjects[6] := 'unstructuredAddress=192.168.1.33,unstructuredName=pixfirewall.ciscopix.com,CN=pixfirewall.ciscopix.com';
end;

procedure TCertificateTest.SetUp;
begin
  inherited SetUp;
  SetUpTestData;
end;

procedure TCertificateTest.CheckCertificate(AId: Int32; const ACert: TCryptoLibByteArray);
var
  LObj: IX509CertificateStructure;
  LTbsCert: ITbsCertificateStructure;
  LExt: IX509Extensions;
  LOid: IDerObjectIdentifier;
  LExtVal: IX509Extension;
  LExtObj: IAsn1Object;
  LExtBytes: TCryptoLibByteArray;
  LExtendedKeyUsage: IExtendedKeyUsage;
  LSeq: IAsn1Sequence;
  I: Int32;
  LGeneralNames: IGeneralNames;
  LCrlDistPoint: ICrlDistPoint;
  LPoints: TCryptoLibGenericArray<IDistributionPoint>;
  LPolicyInfo: IPolicyInformation;
  LPolicySeq: IAsn1Sequence;
begin
  LObj := TX509CertificateStructure.GetInstance(ACert);
  LTbsCert := LObj.TbsCertificate;

  if LTbsCert.Subject.ToString() <> FSubjects[AId - 1] then
  begin
    Fail(Format('failed subject test for certificate id %d got %s', [AId, LTbsCert.Subject.ToString()]));
  end;

  if LTbsCert.Version >= 3 then
  begin
    LExt := LTbsCert.Extensions;
    if LExt <> nil then
    begin
      for LOid in LExt.ExtensionOids do
      begin
        LExtVal := LExt.GetExtension(LOid);
        LExtBytes := LExtVal.Value.GetOctets();
        LExtObj := TAsn1Object.FromByteArray(LExtBytes);

        if LOid.Equals(TX509Extensions.SubjectKeyIdentifier) then
        begin
          TSubjectKeyIdentifier.GetInstance(LExtObj);
        end
        else if LOid.Equals(TX509Extensions.KeyUsage) then
        begin
          TKeyUsage.GetKeyUsageInstance(LExtObj);
        end
        else if LOid.Equals(TX509Extensions.ExtendedKeyUsage) then
        begin
          LExtendedKeyUsage := TExtendedKeyUsage.GetInstance(LExtObj);
          LSeq := LExtendedKeyUsage.ToAsn1Object() as IAsn1Sequence;
          for I := 0 to LSeq.Count - 1 do
          begin
            TDerObjectIdentifier.GetInstance(LSeq[I]);
          end;
        end
        else if LOid.Equals(TX509Extensions.SubjectAlternativeName) then
        begin
          LGeneralNames := TGeneralNames.GetInstance(LExtObj);
          LSeq := LGeneralNames.ToAsn1Object() as IAsn1Sequence;
          for I := 0 to LSeq.Count - 1 do
          begin
            TGeneralName.GetInstance(LSeq[I]);
          end;
        end
        else if LOid.Equals(TX509Extensions.IssuerAlternativeName) then
        begin
          LGeneralNames := TGeneralNames.GetInstance(LExtObj);
          LSeq := LGeneralNames.ToAsn1Object() as IAsn1Sequence;
          for I := 0 to LSeq.Count - 1 do
          begin
            TGeneralName.GetInstance(LSeq[I]);
          end;
        end
        else if LOid.Equals(TX509Extensions.CrlDistributionPoints) then
        begin
          LCrlDistPoint := TCrlDistPoint.GetInstance(LExtObj);
          LPoints := LCrlDistPoint.GetDistributionPoints();
          // do nothing - just verify it parses
        end
        else if LOid.Equals(TX509Extensions.CertificatePolicies) then
        begin
          LPolicySeq := LExtObj as IAsn1Sequence;
          for I := 0 to LPolicySeq.Count - 1 do
          begin
            LPolicyInfo := TPolicyInformation.GetInstance(LPolicySeq[I]);
          end;
        end
        else if LOid.Equals(TX509Extensions.AuthorityKeyIdentifier) then
        begin
          TAuthorityKeyIdentifier.GetInstance(LExtObj);
        end
        else if LOid.Equals(TX509Extensions.BasicConstraints) then
        begin
          TBasicConstraints.GetInstance(LExtObj);
        end;
      end;
    end;
  end;
end;

procedure TCertificateTest.CheckDudCertificate;
var
  LCert: IX509CertificateStructure;
begin
  LCert := TX509CertificateStructure.GetInstance(FDudCert);

  if LCert.Issuer.ToString() <> '' then
  begin
    Fail('empty issuer not recognised correctly');
  end;
end;

procedure TCertificateTest.CheckMalformed;
begin
  try
    TTbsCertificateStructure.GetInstance(FBangerCert);
    Fail('Expected exception for malformed certificate');
  except
    on E: EArgumentCryptoLibException do
    begin
      // expected - anything else is not!
    end;
  end;
end;

procedure TCertificateTest.TestCertificate1;
begin
  CheckCertificate(1, FCert1);
end;

procedure TCertificateTest.TestCertificate2;
begin
  CheckCertificate(2, FCert2);
end;

procedure TCertificateTest.TestCertificate3;
begin
  CheckCertificate(3, FCert3);
end;

procedure TCertificateTest.TestCertificate4;
begin
  CheckCertificate(4, FCert4);
end;

procedure TCertificateTest.TestCertificate5;
begin
  CheckCertificate(5, FCert5);
end;

procedure TCertificateTest.TestCertificate6;
begin
  CheckCertificate(6, FCert6);
end;

procedure TCertificateTest.TestCertificate7;
begin
  CheckCertificate(7, FCert7);
end;

procedure TCertificateTest.TestDudCertificate;
begin
  CheckDudCertificate();
end;

procedure TCertificateTest.TestMalformedCertificate;
begin
  CheckMalformed();
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TCertificateTest);
{$ELSE}
  RegisterTest(TCertificateTest.Suite);
{$ENDIF FPC}

end.
