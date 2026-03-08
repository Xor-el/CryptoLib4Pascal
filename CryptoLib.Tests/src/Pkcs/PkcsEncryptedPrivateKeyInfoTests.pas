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

unit PkcsEncryptedPrivateKeyInfoTests;

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
  ClpBigInteger,
  ClpNistObjectIdentifiers,
  ClpPkcsObjectIdentifiers,
  ClpIRsaParameters,
  ClpRsaParameters,
  ClpGeneratorUtilities,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpEncryptedPrivateKeyInfoFactory,
  ClpPrivateKeyInfoFactory,
  ClpPrivateKeyFactory,
  ClpIPkcsAsn1Objects,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestPkcsEncryptedPrivateKeyInfo = class(TCryptoLibAlgorithmTestCase)

  strict private
    procedure DoTestOpensslKey(const AName: String;
      const AKeyData: TCryptoLibByteArray;
      const APassword: TCryptoLibCharArray);

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestEncryptDecryptRoundTrip;
    procedure TestOpensslPbes2AesCbcKeys;
    procedure TestOpensslPbes2AesCfbKeys;
    procedure TestOpensslPbes2AesEcbKeys;
    procedure TestOpensslPbes2AesOfbKeys;
    procedure TestOpensslPbes2AesDefaultKeys;

  end;

implementation

{ TTestPkcsEncryptedPrivateKeyInfo }

procedure TTestPkcsEncryptedPrivateKeyInfo.SetUp;
begin
  inherited;
end;

procedure TTestPkcsEncryptedPrivateKeyInfo.TearDown;
begin
  inherited;
end;

procedure TTestPkcsEncryptedPrivateKeyInfo.TestEncryptDecryptRoundTrip;
var
  LPGen: IAsymmetricCipherKeyPairGenerator;
  LGenParam: IRsaKeyGenerationParameters;
  LPair: IAsymmetricCipherKeyPair;
  LPlain, LDecrypted: IPrivateKeyInfo;
  LEncInfo: IEncryptedPrivateKeyInfo;
  LKey: IAsymmetricKeyParameter;
  LSalt: TCryptoLibByteArray;
  LPassword: TCryptoLibCharArray;
  LIterationCount: Int32;
begin
  LPGen := TGeneratorUtilities.GetKeyPairGenerator('RSA');
  LGenParam := TRsaKeyGenerationParameters.Create(
    TBigInteger.ValueOf($10001), TSecureRandom.Create() as ISecureRandom,
    1024, 25);
  LPGen.Init(LGenParam);

  LPair := LPGen.GenerateKeyPair();

  LSalt := DecodeHex('0102030405060708090A');
  LIterationCount := 100;
  LPassword := StringToCharArray('hello');

  LPlain := TPrivateKeyInfoFactory.CreatePrivateKeyInfo(LPair.Private);

  LEncInfo := TEncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
    TNistObjectIdentifiers.IdAes256Cbc, TPkcsObjectIdentifiers.IdHmacWithSha512,
    LPassword, LSalt, LIterationCount, TSecureRandom.Create() as ISecureRandom, LPlain);

  LDecrypted := TPrivateKeyInfoFactory.CreatePrivateKeyInfo(LPassword, LEncInfo);

  CheckTrue(AreEqual(LPlain.GetDerEncoded(), LDecrypted.GetDerEncoded()),
    'Private key info mismatch after decrypt');

  LKey := TPrivateKeyFactory.CreateKey(LDecrypted);

  CheckTrue(Supports(LKey, IRsaPrivateCrtKeyParameters),
    'Decrypted key is not RSA private CRT key');
end;

procedure TTestPkcsEncryptedPrivateKeyInfo.DoTestOpensslKey(
  const AName: String; const AKeyData: TCryptoLibByteArray;
  const APassword: TCryptoLibCharArray);
var
  LKey: IAsymmetricKeyParameter;
begin
  LKey := TPrivateKeyFactory.DecryptKey(APassword, AKeyData);
  CheckTrue(Supports(LKey, IRsaPrivateCrtKeyParameters),
    Format('Sample key could not be decrypted: %s', [AName]));
end;

procedure TTestPkcsEncryptedPrivateKeyInfo.TestOpensslPbes2AesCbcKeys;
var
  LPassword: TCryptoLibCharArray;
begin
  LPassword := StringToCharArray('12345678a');

  DoTestOpensslKey('pbes2.aes-128-cbc', DecodeBase64(
    'MIICzzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIESzVgDEv'
    + '13oCAggAMB0GCWCGSAFlAwQBAgQQSMtJ1UggYKKwnAoE9sufwASCAoAe'
    + 'nN4/VhqROBUgQ876Hpd/m9Ypy9+DVdihv2o/Y8I5TdMQGzYguEAEt2Tr'
    + 'vKmg2aRm76Xxbd1tw0KLiA3xNKaxVcBN23Doqxmb1t2b6BYZ2sqlT6RK'
    + 'iV/2Loqztorepv7yA8YxXgiI+wMr94VmvCK/3olmudkQoISWS6aRfs9Eo'
    + 'rePkyMXldqLTqkkf3UyqvxicipBaGpJHBMBIjqoMd4c+TZxvIWrw9baP2'
    + 'P42/O3/d5tTvPI0VyOZfrymYEnTzS4BkvQHjqQA/wyJywWhWH23aOV8Qo'
    + 'mBQqj0bQ3/dBcuUSuL1xD+IJiGtCOwGmCvfXYE3M0EBsRqiOBhPPiMIy'
    + 'L/QbXGHjfD5OCYwSjaJCeG4ldLCGIv4P0RqfQVYPZnyeMgYSnkaXhADLA'
    + 'r9NMOTEGYALuGx6hXQ8MavdMRUZWDUM8FS6cBln5tA1owFEddA7XGeQB'
    + '0L/NwoS/urK6du47RqF+FkLimBzkEKU8LyVQ0WtBOWyWjWzea0sGaPto'
    + 'cgM062IcGNkGXXI7huN/xKEu+5ctQFDz9b2HQYieIylOZZX7hoMJEiej'
    + 'uTNSlfqw3Ch8KCfGaOZnSar1dAdYsHJLF1pUOQ0Qi7dL+IVfKIBpJrjd'
    + 'txqwWyPmWrfIYsDHDSf7uH9Vahd10hrGRj+F8i54ttuGqh1tJzIITGrX9'
    + 'GTFO0pxEIZcBd/PWboNBShveK4ihpG6IA062Ob7b0T6cMr6Rf1mBq04g+'
    + 'l05rNCrU7BuUQUFlapGZauyZmrBYvXRP4Lskop70xLybUoqKjfGKppq6y'
    + 'U/6LlQcHh1OepjC6cdG1r7h+BQbG6DA7hzQEJZ+9fR8MRExAcjMpo6EK'
    + '7kALp'), LPassword);

  DoTestOpensslKey('pbes2.aes-192-cbc', DecodeBase64(
    'MIICzzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIYF4r1Gee'
    + '6QQCAggAMB0GCWCGSAFlAwQBFgQQFVwRHPUhJW+oEU7t3PV0MASCAoCc'
    + 'rJ+ZHwKWgv7y20gqlBhV+t8JFeHOJUDWVMz1GqhZRzXuDcXXGNv+ktOG'
    + 'r9O/sPIY4jdeXSVQM6F9lAL1tslSOZslT4kJB3tPDdgcUIJWHo2ydkB5'
    + '5lkqEqOGr+gK05rx+SN0uTp9eTx4pxJTzxAJa9U0YO9x7wi83Gc6WXB'
    + 'SrT36WkVWV+B6oUl5eEWowJ6GqxSOW57OwcCfqouiFQn+mu0FPcShS9o'
    + 'Z55ve4CDTEBgLwrHIxzUFe2ilrC8BerY8AVdU+Rf943+oFe11H/9dzBy4'
    + '090r35N8M5VNXPSnef6NB0ctE8vLrqqSyEXGU+lrHMcJOmOAieaq0snC'
    + 'Ac2p547ACQVQRDFmXwKSgUTM3qAqGVZyf1Xo7D/M4Q+kbECO7WPR7+/'
    + 'QlwWbuzc/DXdpNUr9vYIARxvjPDJjLGJxmiIwetbWfJYYcCekcKxDeq8t'
    + '7ES7iaFFLkWs8HVcS+nOLUcqLJyAhkrCfbxAb4me7cozfxpSrm0YJ/kx'
    + '/eyTMQxNk+Cf+cXW5yqyIuYwcHifjfrmOQ7P0FDZJiz4Vtc17rR/m/Hg'
    + 'LZsmFV60jumzEfGgkTsoFmMeZ6lKsFS2ARFbq3TnU2O/GcYsI1PuwcS9'
    + 'Et+QQ//94l0q2RuZ/48GjTPlrmRHnp+7V6RE4/bDk8N5FCTK16p/PlCK'
    + '6WUTaFob84Y1P352ClpnmqYC53hzk9Lv6I1mNJ4fYbVEzhyK7bGN65TR'
    + 'aZoMmcrBUDXULdFHB9ChdZOL0qguHvn9Qs9BF5uzNADmm3dPfYnpeqAY'
    + '7fTnDP4aYuQp5kqCMAtZl9wcmkbiGw4GbeJTpBqNNRcaKllu2XgXaM+q'
    + 'QG+5/xshfQUI'), LPassword);

  DoTestOpensslKey('pbes2.aes-256-cbc', DecodeBase64(
    'MIICzzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIn5BVRswN'
    + 'fJECAggAMB0GCWCGSAFlAwQBKgQQrGsWvyAgrlE8O85W8DqPvgSCAoAN'
    + 'CKisIl5T5fSCBb1q9HKhf5wMM/hm3mdfb1gL0FlYq1HuxPUJd/z6SRzE'
    + 'OOeA6S8SX1HLsCxWkfI2fclh3tVVMJ0V1JZddTUF9DKrOEOSjF0QOXg7'
    + 'cqw4bIsiH7avrjmbDtJ/CfQtN9GydI9IRLxFcfVWvl0iTnL8Yo+FqhGR'
    + 'ZDMdXMyYNLZ806DJm21QQPPzzGvO+fGz7LM4/873Kn48P1VeHKSnX6aW'
    + 'brI1A3mXglDoYgfMi8K/e9gMAsh5cmpT4i5yQA1ogjEt/VOLM94RY09c'
    + 'DCfoECCTdejBifJOBe7x1vhyoPEYk/fAVCYaaN3G/I8BVjEV9ZTc0WEu'
    + 'oQiB4J9ypAkc/CZdw9l0LpYh9ckDvTJRTGl0RXgAa+xd1+vSWwwCv8G'
    + 'Kwrb/6WrI+KG69LV+pBC9qTYF+xgyqdTTWtwSzvjDc6ZEtX6M8NnLyEJ'
    + 'GG/g29VRiaAgJeOXPNFK1tSpfCB7m4gVayBZd7iWzDDMCxC1NPru2Ocd'
    + 'Q5vnuH/OcVG6PYjy651D8QU4AXJs0FrIf0oZc1+yyINBnR5NPvnDo6jJ'
    + 'y8E+1l8S74Y1Ct4bjdsKyuTZRKZRiS9A1GZEORrbFCiwLniqF2OhdVJZ'
    + '2b7PKdcT06W5YjfSiEFY+j7qikFW2DYQM2ymvX2ENfS1O67IXFsN2RWs'
    + '5ml0KQXfEWUZWZEpi2AVFitjywJSSGGuxwcc5/7ZjNrPGiyu9xnKJ8m1'
    + '8whqgzMq4+Yi0kNQGCzMcwEPqrDoGIR2sy8kYnOWqp+mGnaSFN1ao1qI'
    + 'fBNWYne+71H91ueHBeh1AACFOGQzxuyb/PLNNZglJMJiVpGttx2G5JSEv'
    + 'JiWNkUpJg41h'), LPassword);
end;

procedure TTestPkcsEncryptedPrivateKeyInfo.TestOpensslPbes2AesCfbKeys;
var
  LPassword: TCryptoLibCharArray;
begin
  LPassword := StringToCharArray('12345678a');

  DoTestOpensslKey('pbes2.aes-128-cfb', DecodeBase64(
    'MIICyjBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIPTqrPyn3'
    + 'yt0CAggAMB0GCWCGSAFlAwQBBAQQhkTAC0guUpcN9f7/YoqveASCAnvg'
    + 'kG+8kQqBnTbgYcC9fCCI1OUNYFLtz6f2IkuJxveYb6Bfay0V9QPmFfC1'
    + 'cuFw+q5vXlToVoepRQftFGQXnGefXE3HUDszHPixZdtFVGi/tPvUNb5Q'
    + 'Y/knm0jzzKfwMnLcw31t2cpXNeXrZokRc/dJKJuHgpm4s66zJkt+XpYg'
    + 'tnwsORkFslDNnbjzc3KEg4vsK8M3V625GymBNjIsDxsWdKlCzg0jgTFp'
    + 'jS30nv7Lx0MxHGcjSHDyecW28aYTdlbPsIEVuBSPmWvu6do7c71OThyH'
    + '6KhIJp2Dqa18hfbAY4j3LbGiPuPr/lqJjbWCP/WEGqonokpizaj6JK9Y'
    + '5ffl0q6OZgh7+mknNrRV8ZSdR8SCzubTQdU6IoPjm/lMYBtW4ZC5ObmA'
    + '1SKCTIGb12+GY+y3SqgaQkbUDMRT3FuF6zkes6W4IKSCHm4SnVgv1CH6'
    + 'R2XKvk8dIpBd9Wh/slNGu8VOwyb+R3qT69jItaaIvpXHMhg7kGvJjlM8'
    + 'KeqaYJk5VmkpHFOzecDOdoP+e7rCKJRDX40i4Vufbf00KeQb3lQS/SAn'
    + '4fDDr0MPKgIghhvXAeTVdejr1DzO+2lUJnMHXPVUgRCRWDMGxIeXfFob'
    + 'cFCcWQHmNZrCZ+MFLwT06hSsf7nR2UejLFtzNdC2XZz0WGr/NLWGk9Qf'
    + 'C883fHvMDab2kO6uMWMpxB8wLCOinHBVHSPufpBIPjWMx8qxy4PdZ+ba'
    + 'HMncquj/r5QEdbkssbPb80rahrRjSONJslDcxlAKT62khg3jPJE4aG2Hd'
    + 'g/7Y6v/t18dnGF0/d8kVrwQBDn5HyFnoGTscRTD2QIe9DonqodRt1EBa'
    + 'xC0GQ=='), LPassword);

  DoTestOpensslKey('pbes2.aes-192-cfb', DecodeBase64(
    'MIICyjBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIXsQs09BP'
    + 's2YCAggAMB0GCWCGSAFlAwQBGAQQiLlSBaqXSTeWU29cVMv18gSCAnsU'
    + 'loTIJ5nbNPswgVhoW67iE0XxlmLglXflVZV8bcxhtDNKkwmIkP9enoHY'
    + 'xraCVHSpKMPyZh4zAjYwiHgks4gHHaL9t94sjaYW9DBYwVRlu015J8Vb'
    + 'PCLTk2lDfKaXVvoBFZ5hR+4MyG2BvyIjJuOzVtbL9+AwxGbr6/Fq1v5C'
    + 'CmWU3buFg4okst2NJQa/g2Pv2bmIRtl4C/L4J7pl1avqlzeDnboWfBzn'
    + 'PK3eGGE6AkRYKJZvdS3lYPZi0moAtkvv09pqBbekPsdtmcW6mEs4qUD8'
    + 'z8zjgNIN+/COWQ0/DfRsHpUVMH9+hNekjkb0S2Rm26ZdMRq0giVR3OpP'
    + 'JCnz8ZsybL+hsnbLUAsksmJX+czH0+NfqFr6Y+rqVLSGaCGMUcalR2CL'
    + 'DZmkn+Irq2XY/ssuB9tFLggY4q52QkKtQaiCL3oPLgodEudvaabZralt'
    + 'wqBxOWXrIHyq+mLiTEwTgPUgnnooZS0bgCSG9C7UD5v8FvhONOBbSpST'
    + 'DWKbHQ8CaPxAz6lfOhD7F9EGK4tLYXvKr2U6UBC1oAJU9yhIZ81CTJn3'
    + 'dwMYR8JNwflKmTXH8DlEyAjRMsYYJ2V2YvwjgvVlUVZz3HtuSFOgwPo'
    + '8LtVl0A+jX+eExg6a37INZaoNG1Qt0LjyoAmbCH0NT3g8yl5/ylhGUe5'
    + 'q7U58HBzP5F/cvzDhs7SI1ZXLNAhedlXzoGvokExHbyE65/dNUojD5l4g'
    + 'qHvpevB7uQGRn+N7ZIUOgO15SdVP6j0VRk8KF+Khrr0VnVdC8emCNc8'
    + '41fv+y4ZmCTFdtgv48NC+hiyzk3lMeQPw03jnQxqK7vg396fHO3k4QJ8'
    + 'ulOXpSQ=='), LPassword);

  DoTestOpensslKey('pbes2.aes-256-cfb', DecodeBase64(
    'MIICyjBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIJgD8eI7r'
    + 'j+UCAggAMB0GCWCGSAFlAwQBLAQQPJg6BqHHTx9cd+oV+hMdZgSCAnu9'
    + 'RxKJptmy4eZv/orsdNecFQnVgi4njTlstsYf4Or2PyNOfvJKy6lDTotx6'
    + 'r0c0G1N+JzhQi/EwvlIcbG6oJdhbqh6VIjjyAnWv0B9f6reOYgrM/ZO'
    + 'ZYfTuG6BbIHGUwkQMdiA2T+wSEUfT5FgCHLwg4fyn5bqW508P3WnjlyF'
    + 'YRYx0yneVt2xNiOWzafGqgOr7USqcg5jFdtvydQAOV9W6JxiEDOQo3+E'
    + 'mElMgbzNj1n/7RcfPfELrNDQev9TH4D2QJ91wjUsD9zmFEOVrmHs8JGW'
    + '0AUllhliwRvo0QfzFiucVJmuEy6A1HBfmB0KF87Km1SRB9XvqTevAXlo'
    + 'DAY4hQ3IunMuvvb4UQGgRzzAxLdQUQsvSvVI+/Z6qh4Kutkei9jHE7mj'
    + 'W3ROUFKMEIqdU2MRTp51b5OL0BUZspAwOAgj1LAYP1TYwmVpoA8X6bOx'
    + 'ZaFBb/OR3JmFS0sxDsSyq1l6m1dQGSGiEdJTH7Q7WG2tNAgdH6ZR0zI2'
    + 'u2D3a/pJIBdGudSf/nUlxXl/Lhr0blTlb6Mr0BRu1k3PpyQEKYbVHFMB'
    + 'sWf2W2EOxcOG8qYWyJpZf9QK6z6DRvCde6RA3Al0+biDYH/ZVqPQWrm3'
    + 'llbDvU8ALhrfqeZfgnOVUbskTr+FtWvyrf6/UDizhzlCVc1eyAsxnshf6'
    + 'kFEAp8Pzxq5XGKAWKfLtBc4H6tNKWtG9GGuszlN/N44uMNnOlvVRFDi'
    + 'jbBFjJ693Ishlug4K0EZeKsk35jxm5nXJV86BXqKQgmYuX0QNiWaC2oC'
    + '8gBtUIABotPdRAL2U/px1CnhFr7GVvMsNf4PaRrx3GG45cbLGbZB5DVt'
    + 'fhx0Kg=='), LPassword);
end;

procedure TTestPkcsEncryptedPrivateKeyInfo.TestOpensslPbes2AesEcbKeys;
var
  LPassword: TCryptoLibCharArray;
begin
  LPassword := StringToCharArray('12345678a');

  DoTestOpensslKey('pbes2.aes-128-ecb', DecodeBase64(
    'MIICzzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQI2rnpwtJV'
    + 'WocCAggAMB0GCWCGSAFlAwQBAQQQAAAAAAAAAAAAAAAAAAAAAASCAoADJO'
    + 'XVmq+LxqWcpwFRZwE/UmoqcdJ/fSTirH7sVcXebTSYpH+mjZsTOV3Ody'
    + '/N4o1cjgtrZNb/1+MHVh3uLMvIeEXWr/1kjaBB/NxHp72Fu+c9Yb4+hf'
    + 'JuDVY5lpF9MS1bHKksWjKHQvevw9QL8ze2iYFFHKbBCx/rMuQqDihIda'
    + 'uxUmdR1h7xoyUzYBM7jZDbJsIxLeDoLtdMFSCxs04a//6ikccefNgITK'
    + 'kLYs7j9di8nhV22d3iBV4oXjNOf7RLG5+SdIq5rPoorwM9X4szquiBOn'
    + 'ZS0hnc++nDZhjJBK5KQFZuX83OoNOGm3B84eIe0GXFvgK+Bmx4l0m0Ne'
    + 'NNEvd+CxyZ/z5sUu08YiBiJFaNOMz/Xu4t4kz63a04SragcPkJSWanp4'
    + '5XGAU0CYgLYof/dwGyCqClVZzj/w6X8kRExJf9OqNibwFaKrBnX5zkFR'
    + '2k9ZyY/YHdS2BWg6FBbul3A7Cf9P8hJc9HuTUmUhWkdZXsgoOG67DUM'
    + '73537uEMdBkFu9HozSllBS+7HpWKP3C5o7pHyqBPXHPlJ+CbKGZZRzqX'
    + 'NbqeumBuh5GfMdH3LVxN1J6NEWMc0Cas3OLZMijbpZR1Ele2Nt0owRLy'
    + '2YShkdTGp9brrEclq9vxA69YLfxKVDnuACjZ1nkGmv3em9WS6jDqbxR+'
    + 'aR61kP0O3fOQktL0p6+hgQSL40Y8L+jzczWLJ69b6eE3AZRxux+KyBnL'
    + 'Lb2IQAqXNz6+VY8W2JEtHafmPPTVxWA797/b1QM+u70bYvI7YRSYNLZ6'
    + 'sXgG2IBo8YmYJkyZ23V+2QTqlGUkgZOGfidLF/J9EdSo29uyyD5nyeTx'
    + 'idewiq6Ntto'), LPassword);

  DoTestOpensslKey('pbes2.aes-192-ecb', DecodeBase64(
    'MIICzzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIgsjFtXWY'
    + 'ixQCAggAMB0GCWCGSAFlAwQBFQQQAAAAAAAAAAAAAAAAAAAAAASCAoBiXa'
    + 'Mv94S2M9k6pSiskqf6vYTxcU1r9KU30kil/fpa7nx7jnZGU+0VRMokJU'
    + 'jHG5SMzXZxp49ch8EZ/yQMyMW4AQVOyETpp8oD6+1Hk++s23W2E6sdKs'
    + 'kErNPZkuFeHmRSjDDNsT+2t9ow7juabYYXcdDh26hfKG00YF+uh9Up/L'
    + 'tuW6SCTg+E6MuRR12RXu5F/MDGntz9rKYD9HfBXtERRXi18a+Oxtw8L/'
    + 'DmRMZBy5jal1s0Ic5Ih4QKj7GhGs/c5p1PTvlmGqDjPTmHUNJQ2jeQ7t'
    + 'SdUAd2I+x9kWOGzjAZLri7dDcu7vdwJ0bXR8599x11brTV3K+3kQur91'
    + 'Z/jysJKm2HBnjPmJmUoDQKe3jcQ57RQkAlfcnx6XPfu3khcU4aBSrtw0'
    + 'VPL1EJ5xf4+Acp6UENzoUk0EMHFA2KyI4w4OVn2RsAPI6e2ge88lE5k'
    + '68oTfqEooJLcSJZMJrCDevzEszD3QkZeoVIfUVMSg04a6y7fsQSbxXOp'
    + 'YgXIjLAixrr9OU/Q0ScGy3YyabJE9a26DLMOgV0j5ksxuXru8fATV0EE'
    + 'foi+Ax3fB0PblOvICelvc7Ho0+sQDRtEF0Jfsn94/+wbDhjZX1q2ptfv'
    + 'Ts1wYItiveCWjGEwwA5wT5FbkuK8LEUuZePOct6k2s3jNBH2ESnyw/s6'
    + 'yxomUsE1+xqpIoZh+BDFCrc4WMh40mkvQXf09IYSGtN+EqLUzwY0d2u7'
    + 'xy+LRPAhfdX+sL+0+zFcu4zq7Ijq7dppFJoj68E2UXCom0QsU780HS3k'
    + 'noa7XTJqEvWwf3adS945h5qakQQrb/bKlcvxPCHxaOE1kQRq9pUTFbsU'
    + 'nE5qqNuZYi8'), LPassword);

  DoTestOpensslKey('pbes2.aes-256-ecb', DecodeBase64(
    'MIICzzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIrspNBPGs'
    + 'mn4CAggAMB0GCWCGSAFlAwQBKQQQAAAAAAAAAAAAAAAAAAAAAASCAoC+AI'
    + 'PD5hQW3KIpmP5wuM3DprOuncNpKnP9CT6UCW1Q+QQH+vNub5jt/KFogz'
    + 'PDEXsnct5jWP6uN4a2on5dZsfkT71wyIWBOr6AI8QkIHcqmGwidtMDrO'
    + 'N3Ns0rvP8kYae3+zyGO0L6yJyRX/7gASVWfREaWIx8pu5CSzQuoOo1Qn'
    + '+j7bfIZKVFDfnB5RExmAH+cIOngDCLWJh7DxHGZkuYtUKhLRBz9cZv3R'
    + 'EHFhat/bfriPGvM4vWzmFhDa+n2tAJKdZtxmfgME6D8w/Rpr/Is7Ly6Z'
    + 'WucXDmgsyVW+8AgLm51SuSYqx6n2ybBQBDZIz1u6RQgV7wnGTamZatYi'
    + 'Auo+OQg+2osNCy/IOg0JPX08ZJB0Nv5WMo76OhPCUH38nrjTmAMJa8pH'
    + 'oS9JDGRD4SXxCg0T73bk/EGr3KNvMWhSoAQoveMlB8G2K0VyywCLTb63'
    + '17wjJhBqm0Man/vwJuIod8r0drzWUxate2JmCFpALKOasabuc1roCu/N3'
    + 'GfDaveRV1MrmG2KI1bj2HUHgcUhjEQWTeuD0EWZowIJsx099/+Igk6ru'
    + 'GCtBoieSr/K6QQsAZ0bNddR7jm/TW9wMV+WdxIHCYaDR1ESJ+18kn05l'
    + 'vKiVsHFAgRac+2J+tVT483I/LIfW6pJJk+SPIke+jQ4JASv9WlY4TFh1'
    + 'xrMU74n/D+NeuS+zr+hvmVxLBuKFeAxwQCjZZ88mboLZyk53647IrS4Xj'
    + 'NdEQo4pefhjc79gHuNp3JJdgo/XNsnV+YMNInx7u5Z0rU8PcFmfYQkCa'
    + 'oR4VmnMxxVJJbfBch9YWfqmpAhRyNedzfVQguKbR7YskOs/CJzzroBvO'
    + '/o3Fb+54'), LPassword);
end;

procedure TTestPkcsEncryptedPrivateKeyInfo.TestOpensslPbes2AesOfbKeys;
var
  LPassword: TCryptoLibCharArray;
begin
  LPassword := StringToCharArray('12345678a');

  DoTestOpensslKey('pbes2.aes-128-ofb', DecodeBase64(
    'MIICyjBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIa1AMM9+K'
    + 'DvsCAggAMB0GCWCGSAFlAwQBAwQQKOC8jCeXQw5frraqyljC2QSCAnv8'
    + 'wbFNmcFsfpG92CoM9Zkh2MS3SXEWc3TJbH18pTNIngkgQDA8OdiqUpxR'
    + 'hJgS5awnqfqgLt8Z6qgiUCFyZQ+zofmzbPQkn0+/4hL/4DFen1RYD/Zi'
    + 'dO3K3Q2re1JHxw+3GYgamJem70dR9ThuRS+1hw8rzjNyhuFnMxC2pe2M'
    + 'qC9LgDwS1MqeTFWmyWUNkwatBySC9htH4n0+9hKum9KFfAIHZdwMPbiS'
    + 'qyFx1rmAQmvh8ouXozK3HauJOBt9Ta2SYHi6fTVXuP0Lrom+0RBF2Xp0'
    + 'ZGaMQd2zFQZDH62ftow+MGgk/A9/GdndQ5F4Oc7HqewVEF1/ldfbIdDa'
    + '3IUMEWFd6pH/RwefCvlpVnyhzwNJnhKbvEtUMMvpJCt3H5iMW7QDPH8m'
    + 'ZZoUahUyZemBtsUrH0ShL23qF6HVaaE53zgBTtipLFB3k5wTf86pZLfx'
    + '9mQ/mAAZqai76OfUGpqSlhAxkE67SYJKSaAQjhqnAScEOUSRIGSAKl1d'
    + 'RTgipaDgb1hHv7Hbu9HjiHWHSRTcHq/RpuPtOeF0ce+ieSE5GOMnhzua'
    + 'XjxHBHZp0Miz2h2ndeK9W9mr0vbHG8vYgIY2S/UfqhTP+0d+crDmqZVu'
    + 'ucHbcjTzEnoOeER3EBjlnr0oT0v0xpyqhAFIoWWfPgRdQdmQKfzc+NMp'
    + '8BMK36/mJaB71j0xWjqYOy/vqbXO8jA3BVfr/Wskd7z3Ne9bJCFKG9Ki'
    + 'QRQ+nXwes5MRpAfn44vl4o1Ks4sH0/6imQ9R+cvPKgDUb1Aw8F/DLTd8'
    + 'sgdbsnE0jgLhkTbi4V6+INWzjnEx/M586w02kwTYD0rPAL4OrzYtef6K'
    + 'DxENyA=='), LPassword);

  DoTestOpensslKey('pbes2.aes-192-ofb', DecodeBase64(
    'MIICyjBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQId/cpwKiQ'
    + 'gEgCAggAMB0GCWCGSAFlAwQBFwQQSBIBzZWy09ip7PwKCgMm2wSCAnuL'
    + 'ISLRCsbnD7Bm/M2FHDMvMBtiOXI6DEgOvfuu8abOKjKPxq3mDfvSfTFB'
    + 'viWCzRR+l1pS2380B7OLydPUx0CvMdRqLNSD4kb3Z5gKUJ2zIXOlQkqj'
    + 'IJyTzaDqotjlIzTqk0ptB9gNtLM4Wbok4cgwn2ozFmvuy2vwtetb/EG9'
    + 'FVcHfAgXOEbYfMrJ3avJsAmmMryvar1G6HTcRrrHD0WKSa3byiTBvgFq'
    + '3s2XfPl4FwclJLd9BR5Uhq/lwjou5ryVBzKMlK0pdWZFPyokkGTl83bn'
    + 'mGxGYdG9cSEsj4YI+uc6UOebe/Gb5+1wXSSu/SB5KLhFxIZkoODAc2rX'
    + '3aZ6mnTrtRVmN9VMcgVZeVUwrMXuya1kkbwfXK4RyAEVfOEsE7wBu4aM'
    + 'VfDN7NhAd8VXwcr1pnCUprAiLWkI1h6rKwSH3E3Wc63+p1urRqmXjaKj'
    + 'YwzEKln7KdXDeO0Npqt3MbrR8wkbpfe1DJQExuxnSRlGO5EQbCY7EB/4'
    + 'bakG8QjKw87wmPt6V9Mow27BlUCNKmY01/3gz5Ke23zjB8AcqVr9XRqIs'
    + 'I8wZQPSqRM+/igg3qyKKoqeKzmVqfSxp+zrH7pv9e+wdZwg+wmA4ZiU'
    + 'QdePPO7cfLBFBSukfP0WBd3kkDf/F81RRPAE43adDnCpqzL1i+rwN5Qr'
    + 'Op01jEhNrKj1TlfvlDjj+ZgpLwsS8Ig+bK7xLCw6kYjZP7zC3T2pmpK'
    + 'Uf620lpTCTpSQLr0fMzsRQpAoJr61ty1iD/S53hzwonl8imQZDkFJMJe'
    + 'vqZ4LSw4pOt+1sj0XSDAVyR3+dRSooPRV6j1X9bDYwCoRzGtxGAf/YvA'
    + '7V4osRw=='), LPassword);

  DoTestOpensslKey('pbes2.aes-256-ofb', DecodeBase64(
    'MIICyjBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIKH/YFcjw'
    + 'FfcCAggAMB0GCWCGSAFlAwQBKwQQm5UtN9p4D9QmkQXZhz7PxASCAnvJ'
    + '2nf1fjqFRjVY5OBmJToSg/REDB6qb4MNXvpZhLUUWiF2zxlL9hVYEgam'
    + 'l5kfue36FUXfuIaSJ3XKZvD1q0SarNNvVnlt/4uoblyHqAUdzPRpwM43'
    + 'xYf+7jnim5Le5ZlFIn0UDQG9icycKPhuPwafxGJZKyDzn/i8rNvprM5w'
    + '++uxfEX66vLLysytrclvku0TYjazjiCXagqtrszdyGBEowHoHNB3sEIXV'
    + '5mBpJByEipebI9NkLxcYNLf5LAPoCY4KF5R8Zg72pTz58ek7UpZ56ATH'
    + '04ODimhGl9O13N337nMcSXVu4p+ifk7tRRjkOdUXHyIgK/QV//plu5j+'
    + '6iHA5Ie92z/yA7W5W0iTTJxpIpDeVmwRCVxJwn8xJqy/ao/9UPAPesQb'
    + 'h1g4EAajQKCsd6dzZI6SPo/yDZnL8yGJ7+0M1xejEhoEDYUAMYTm+Nau'
    + '8zSd/3bfMyYhMjihHGQyggEl+03AcJ3Nfz92DrTXvOo2CKApZgzA86x2'
    + 'jEztkAJOB5GWx3etXGuRxbu0Bduz411j3jUgYfMlgVs42FXXt2tz8ZMW'
    + 'XsIhRGDkNQ0COg15pJKg1PX/pOlQD3Auc/zaLR359XsTKzNo21RNI6ns'
    + 'A994G7CX00V4AxEngu56WcbQ2eg9QcuD9PCDuI0Q2I7FkAydf2qZp1b0'
    + 'n9/0AjqDWqAeR6XCFT450iypMwclVWvLKJzzOzmU49ADSFzKLsxj2Lv/'
    + 'gHOrYHypl/eY+QWtOPv6tDkHB3L0SmWUJtXlwM4T9/o1H7TeGw29t5Sm'
    + 'SEDBjc7x4rEM0/hIdc0Gpqt6FtPo2l4gcm9AhYZ1/sR66LpYxF9G5N+5'
    + 'rzo5Q=='), LPassword);
end;

procedure TTestPkcsEncryptedPrivateKeyInfo.TestOpensslPbes2AesDefaultKeys;
var
  LPassword: TCryptoLibCharArray;
begin
  LPassword := StringToCharArray('12345678a');

  DoTestOpensslKey('pbes2.aes128', DecodeBase64(
    'MIICzzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQImUGYYvCX'
    + 'EgoCAggAMB0GCWCGSAFlAwQBAgQQt2A9Em1hPQa5U+n2MzS9wASCAoB7'
    + 'KI4QRIIhBoXrSgwQQCge5Pw8v8UpZOH1rHfb3MYdVMmhJK3rXDBn+eG+'
    + 'xGsLxglKYRna+87R2BkzWxI3ikVvwzGs8EXkjHrpLbQPMq1tkYXcH7Cb'
    + 'UHPFFMdum1C1g07A/WiaRIHnFjOOkfcmdWH4CkvJ07llBFkJt/m8oTxu'
    + 'GzD7j8bSNNElZZ9S8LAnYkxjB8Nfhd+OAf0cS8qNhLRp/wHTfwOhLSH'
    + 'yR5LTJRibkwZHfxVE/9HqsU7dD2rCU+7EnAtvzyzPgQrPhPPJp/B6xTa'
    + 'ZaG9BUnRozj0I+VNmD4+qYPe21mt8f4vM9NHshJfrFZBCsUZDyEvXEHj'
    + 'iJNvP3TKzg97eqg9J+Aw6FFI/9gSuhTMWk55Of6lN3XAYTvcS+yHKy0'
    + 'XbeL1C7EOWAR2DqtKfhHcJ3jQd2/wjz2Wk5EpufZ3yzNpM2uswHi27p'
    + 'GYWJNL1RxTnsw/o131MHvMUzQaqra4A6LM1J8Yk5wDpBe1uGPNy51Sf0'
    + '7q+X7nHbT2RBswJhf00Fq8TAunU1ZL7LuSZlAA9M/0rC2vH/RSiz9kI'
    + 'DO74P0LDtShPnDj3bx9HO3AqaxvxIjZ4hvipKOaukVpiBhZrW1UnzLdp'
    + '9UX4acz0j90ziM4hXeLhRZIDsyCitPBDuN1MHspbE1do5MfqW2NNwCNti'
    + 'YfQMONj66mavEfV1vRgChJG04QAuMfpLTfGdBTyX+LAdkRDWVj/4rG3c'
    + 'jaaI/172WoRYP+gtYQCYkntSy7GgCYrC6RAD7BRSLSAV3QtRjjvRkpPM'
    + '6BXUDL4oebKbfzXrBictvGEewHSoVrYUFWkj5cJ55qHDZ1W0TfIhhebO'
    + 'mb7eL9uWJkZ0e4f'), LPassword);

  DoTestOpensslKey('pbes2.aes192', DecodeBase64(
    'MIICzzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIPcNBn3lL'
    + 'uewCAggAMB0GCWCGSAFlAwQBFgQQiDOIdIftt67oxgD2JjdSngSCAoAY'
    + 'C2EPnURswyBO2rol1w8DlgOe4tW2OZy5HWNE0jnunR3nbCp2rmAeOZn/'
    + 'V1FnTv6rJWCQ+kDzTRjKGgeCUHh+BChNhdGthxPiVxVNrNmjY/lSB4n0'
    + '9BOHezwdrc/UcBIRuci57n9lNCG+50WnhyYXaK3+/Es/950qCj7WtcON'
    + 'pzm0r8a4/I4sjNsWWB27g32YtT2vdVmmbO2yY6w/z7tWQW0zRoiRN95i'
    + 'hiBHB2/Nqo7xDKbgqEzGoPSNWeGWsQwEUz3qfVOjPhl7owYQQR5w8oo'
    + 'xEQHtTcm59XMcODojnhY7+XJiotyjA+2k1bDTaMuwFT/77EI2kGNx9ek'
    + 'OeMsLJeR9G6gX1x6p5fF8Y3+MRvS8XA7NFq3ArPtYPRQ/VQhVznIgA8'
    + 'DBRJuC1bWTClLAn1yH8rhhxKk6BKaj4uTQgRccy2pXj0l7ZKtHftaAx7'
    + '3/PIug2MzuJtmFPx9T8YI4VAh1afv5ZmCnGzdxJE95PiFRoygN8q/53m'
    + 'ZhnFW/yh1PqflsDSRJwQFZ3AF22TNQMWzFMWPX0A/9Slha8pSz+P2rxZ'
    + 'NHmlV7l1yEbd+wzVQwxEXT8gnu+X1D+sfMh1xwP+tIt5gv3zQurPd2fF'
    + '37Yrlik+gFu7/E7y7RTmFFCdnpCwjCxibhutZEqM0M8S+dc6O9s2AVgg'
    + 'fenN3qQx7Z1FW/MHnG6vJJ4FxXgBO3ZBLYq0LM8RzgIOORVxb1i96SW'
    + '/KsNGH8IPULj0RVQiKaAbzclXpCn29pXn98areww/i9BqIIhnnMZLf5s'
    + 'Zp/cqfNNSn37DNLax6bVARfgq9HYAqDPt+HRmsBt1Uid8Y4EJS3d35MF'
    + 'fttNfMV6YrQztnD'), LPassword);

  DoTestOpensslKey('pbes2.aes256', DecodeBase64(
    'MIICzzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIz6ljlTVi'
    + 'p8QCAggAMB0GCWCGSAFlAwQBKgQQbZUtcm+tcBcFpEPNW1s0KASCAoBg'
    + 'jtO/svAFRqa8Xr2wWJY3OcWucHd10YzX9aEjV1A5a/4v9d/h0j+9Mw1q'
    + 'obuyTP6UCNG7LaLgCaZCzdD0cZ9tEYNvnlFYMHA+wdDpxIv2pp5ru+9K'
    + 'wrrRUoQsAmmXYQQTpIAHje3XMwNfSZzRAWcC+EVjyCDjT337Iuysh6Bz'
    + 'VKp4lw/U+4ypJ0WMCahDnwEiwVSZ6eO2vPX2F9YBPXjsXN9Mu+IIbk0'
    + 'bbmM98Fhv+IVmEEfe+ekmdBBd8aEKticNoTFLPPOacdMkCzEps2LNcW0'
    + 'wRxP0HKizZF05Bc4mECyRUBcVBWwIzV1StzOeNtfux65yFo1OFC6QoLH'
    + 'm40e/0ttnmAWed8qZyf+MVVe6v2cI+oA3IVb/WmVYC7UbUORgUQEovn6'
    + '0fIW0jESvSlQ9TWpqcOFqor86n+6JcLuHyFRb2QCqnzarox0vHIy6pi4'
    + 'ZO9HdnCFe9B4X0xLRkiWQHAoFx3HKTHZDe0emZL/QASL2dFEtgXelnGV'
    + 'MYkbb6iQYwtmdXLuFoBWYY0gvfB/bEae+uCWJjNL+OW9Rh+JKc/doe1v'
    + 'J6YfW8T4EXp5kK6HoxF51Y1nZbQLxBjsUZfGHuCKWWmBoB88Z4A5bj4i'
    + 'M1OHjNWNWfqFW46wT6mZ8DSDb1NAifMYG+h0MZx6B5mOhLEIC+Wyk+cg'
    + '98R1WxvHqk0Y2hX+hHe5077yIpEcuKBR3gT4Q6kC/Qd+jMzaIDDctkTe'
    + 'Sh1KFiqp9KjLNEda9jKMqRPBAA2MzSRw0Ogg/ox20xsoEANZCh2lXIsO'
    + 'dd+eND4tnqNYC5vn8CmcxE3RR1qyMcfoCWSJ935ggmJCReVAreSSmDVB'
    + 'y4pFcdNz+ra5G'), LPassword);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestPkcsEncryptedPrivateKeyInfo);
{$ELSE}
  RegisterTest(TTestPkcsEncryptedPrivateKeyInfo.Suite);
{$ENDIF FPC}

end.
