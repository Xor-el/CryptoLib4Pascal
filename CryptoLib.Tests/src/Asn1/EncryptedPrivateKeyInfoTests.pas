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

unit EncryptedPrivateKeyInfoTests;

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
  ClpIAsn1Objects,
  ClpIPkcsAsn1Objects,
  ClpPkcsAsn1Objects,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  /// <summary>
  /// Test the reading and writing of EncryptedPrivateKeyInfo objects using
  /// the test vectors provided at RSA's PKCS#5 page.
  /// The vectors are Base64 encoded and encrypted using the password "password"
  /// (without quotes). They should all yield the same PrivateKeyInfo object.
  /// </summary>
  TTestEncryptedPrivateKeyInfo = class(TCryptoLibAlgorithmTestCase)

  strict private
    procedure DoTestSample(AId: Int32; const ASample: TCryptoLibByteArray);

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestAsn1Sample1;
    procedure TestAsn1Sample2;
    procedure TestAsn1Sample3;

  end;

implementation

{ TTestEncryptedPrivateKeyInfo }

procedure TTestEncryptedPrivateKeyInfo.SetUp;
begin
  inherited;
end;

procedure TTestEncryptedPrivateKeyInfo.TearDown;
begin
  inherited;
end;

procedure TTestEncryptedPrivateKeyInfo.DoTestSample(AId: Int32;
  const ASample: TCryptoLibByteArray);
var
  LInfo: IEncryptedPrivateKeyInfo;
  LBytes: TCryptoLibByteArray;
begin
  LInfo := TEncryptedPrivateKeyInfo.GetInstance(ASample);
  LBytes := LInfo.GetDerEncoded();

  if not AreEqual(LBytes, ASample) then
  begin
    Fail(Format('EncryptedPrivateKeyInfo test %d: DER encoding mismatch', [AId]));
  end;
end;

procedure TTestEncryptedPrivateKeyInfo.TestAsn1Sample1;
var
  LSample: TCryptoLibByteArray;
begin
  LSample := DecodeBase64(
    'MIIBozA9BgkqhkiG9w0BBQ0wMDAbBgkqhkiG9w0BBQwwDgQIfWBDXwLp4K4CAggA'
    + 'MBEGBSsOAwIHBAiaCF/AvOgQ6QSCAWDWX4BdAzCRNSQSANSuNsT5X8mWYO27mr3Y'
    + '9c9LoBVXGNmYWKA77MI4967f7SmjNcgXj3xNE/jmnVz6hhsjS8E5VPT3kfyVkpdZ'
    + '0lr5e9Yk2m3JWpPU7++v5zBkZmC4V/MwV/XuIs6U+vykgzMgpxQg0oZKS9zgmiZo'
    + 'f/4dOCL0UtCDnyOSvqT7mCVIcMDIEKu8QbVlgZYBop08l60EuEU3gARUo8WsYQmO'
    + 'Dz/ldx0Z+znIT0SXVuOwc+RVItC5T/Qx+aijmmpt+9l14nmaGBrEkmuhmtdvU/4v'
    + 'aptewGRgmjOfD6cqK+zs0O5NrrJ3P/6ZSxXj91CQgrThGfOv72bUncXEMNtc8pks'
    + '2jpHFjGMdKufnadAD7XuMgzkkaklEXZ4f5tU6heIIwr51g0GBEGF96gYPFnjnSQM'
    + '75JE02Clo+DfcfXpcybPTwwFg2jd6JTTOfkdf6OdSlA/1XNK43FA');

  DoTestSample(0, LSample);
end;

procedure TTestEncryptedPrivateKeyInfo.TestAsn1Sample2;
var
  LSample: TCryptoLibByteArray;
begin
  LSample := DecodeBase64(
    'MIIBpjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIeFeOWl1jywYCAggA'
    + 'MBQGCCqGSIb3DQMHBAjUJ5eGBhQGtQSCAWBrHrRgqO8UUMLcWzZEtpk1l3mjxiF/'
    + 'koCMkHsFwowgyWhEbgIkTgbSViK54LVK8PskekcGNLph+rB6bGZ7pPbL5pbXASJ8'
    + '+MkQcG3FZdlS4Ek9tTJDApj3O1UubZGFG4uvTlJJFbF1BOJ3MkY3XQ9Gl1qwv7j5'
    + '6e103Da7Cq9+oIDKmznza78XXQYrUsPo8mJGjUxPskEYlzwvHjKubRnYm/K6RKhi'
    + '5f4zX4BQ/Dt3H812ZjRXrsjAJP0KrD/jyD/jCT7zNBVPH1izBds+RwizyQAHwfNJ'
    + 'BFR78TH4cgzB619X47FDVOnT0LqQNVd0O3cSwnPrXE9XR3tPayE+iOB15llFSmi8'
    + 'z0ByOXldEpkezCn92Umk++suzIVj1qfsK+bv2phZWJPbLEIWPDRHUbYf76q5ArAr'
    + 'u4xtxT/hoK3krEs/IN3d70qjlUJ36SEw1UaZ82PWhakQbdtu39ZraMJB');

  DoTestSample(1, LSample);
end;

procedure TTestEncryptedPrivateKeyInfo.TestAsn1Sample3;
var
  LSample: TCryptoLibByteArray;
begin
  LSample := DecodeBase64(
    'MIIBrjBIBgkqhkiG9w0BBQ0wOzAeBgkqhkiG9w0BBQwwEQQIrHyQPBZqWLUCAggA'
    + 'AgEQMBkGCCqGSIb3DQMCMA0CAToECEhbh7YZKiPSBIIBYCT1zp6o5jpFlIkgwPop'
    + '7bW1+8ACr4exqzkeb3WflQ8cWJ4cURxzVdvxUnXeW1VJdaQZtjS/QHs5GhPTG/0f'
    + 'wtvnaPfwrIJ3FeGaZfcg2CrYhalOFmEb4xrE4KyoEQmUN8tb/Cg94uzd16BOPw21'
    + 'RDnE8bnPdIGY7TyL95kbkqH23mK53pi7h+xWIgduW+atIqDyyt55f7WMZcvDvlj6'
    + 'VpN/V0h+qxBHL274WA4dj6GYgeyUFpi60HdGCK7By2TBy8h1ZvKGjmB9h8jZvkx1'
    + 'MkbRumXxyFsowTZawyYvO8Um6lbfEDP9zIEUq0IV8RqH2MRyblsPNSikyYhxX/cz'
    + 'tdDxRKhilySbSBg5Kr8OfcwKp9bpinN96nmG4xr3Tch1bnVvqJzOQ5+Vva2WwVvH'
    + '2JkWvYm5WaANg4Q6bRxu9vz7DuhbJjQdZbxFezIAgrJdSe92B00jO/0Kny1WjiVO'
    + '6DA=');

  DoTestSample(2, LSample);
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestEncryptedPrivateKeyInfo);
{$ELSE}
  RegisterTest(TTestEncryptedPrivateKeyInfo.Suite);
{$ENDIF FPC}

end.
