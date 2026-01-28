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
  ClpPkcsAsn1Objects,
  ClpIPkcsAsn1Objects,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TPkcs10CertRequestTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    var
      FReq1: TCryptoLibByteArray;
      FReq2: TCryptoLibByteArray;

    procedure SetUpTestData;
    procedure BasicPkcs10Test(const ATestName: String; const AReq: TCryptoLibByteArray);

  protected
    procedure SetUp; override;

  published
    procedure TestBasicCR;
    procedure TestUniversalCR;

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

initialization

{$IFDEF FPC}
RegisterTest(TPkcs10CertRequestTest);
{$ELSE}
RegisterTest(TPkcs10CertRequestTest.Suite);
{$ENDIF FPC}

end.
