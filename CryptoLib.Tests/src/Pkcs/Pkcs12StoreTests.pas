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

unit Pkcs12StoreTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
  Generics.Collections,
  DateUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpBigInteger,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpIPkcs12StoreBuilder,
  ClpPkcs12StoreBuilder,
  ClpIPkcs12Store,
  ClpPkcs12Store,
  ClpIX509CertificateEntry,
  ClpX509CertificateEntry,
  ClpIAsymmetricKeyEntry,
  ClpAsymmetricKeyEntry,
  ClpISignatureFactory,
  ClpIPkcs12Entry,
  ClpIPkcsAsn1Objects,
  ClpIAsn1Core,
  ClpBcObjectIdentifiers,
  ClpPkcsObjectIdentifiers,
  ClpEncoders,
  ClpCryptoLibTypes,
  ClpAsn1Objects,
  ClpAsn1Core,
  ClpIAsn1Objects,
  ClpRsaParameters,
  ClpIRsaParameters,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpX509Generators,
  ClpIX509Generators,
  ClpAsn1SignatureFactory,
  ClpGeneratorUtilities,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpIX509Certificate,
  ClpPkcsAsn1Objects,
  ClpNistObjectIdentifiers,
  ClpAsn1Comparers,
  TypInfo,
  CryptoLibTestBase;

type
  TTestPkcs12Store = class(TCryptoLibAlgorithmTestCase)
  strict private
    FPasswd: TCryptoLibCharArray;
    FNoFriendlyPassword: TCryptoLibCharArray;
    FStoragePassword: TCryptoLibCharArray;
    FHmacSha384TestPassword: TCryptoLibCharArray;
    FRandom: ISecureRandom;
    FCertsOnly: TBytes;
    FRepeatedLocalKeyIdPfx: TBytes;
    FHmacSha384Test: TBytes;
    FFriendlyNameStore: TBytes;
    FFriendlyNamePassword: TCryptoLibCharArray;
    FPkcs12: TBytes;
    FCertUTF: TBytes;
    FPkcs12NoFriendly: TBytes;
    FPkcs12StorageIssue: TBytes;
    FPkcs12NoPass: TBytes;
    FSentrixHard: TBytes;
    FSentrixSoft: TBytes;
    FSentrix1: TBytes;
    FSentrix2: TBytes;
    FSentrix3: TBytes;

    function CreateCert(const APubKey, APrivKey: IAsymmetricKeyParameter;
      const AIssuerEmail, ASubjectEmail: String; const ALocalKeyId: TBytes): IX509CertificateEntry;
    procedure CreateTestCertificateAndKey(out APrivKey: IAsymmetricKeyEntry;
      out AChain: TCryptoLibGenericArray<IX509CertificateEntry>);
    procedure DoTestNoExtraLocalKeyID(const AStore1Data: TBytes);
    procedure CheckPKCS12(const AStore: IPkcs12Store);
    procedure BasicStoreTest(const APrivKey: IAsymmetricKeyEntry;
      const AChain: TCryptoLibGenericArray<IX509CertificateEntry>;
      ACertAlgorithm, ACertPrfAlgorithm, AKeyAlgorithm, AKeyPrfAlgorithm: IDerObjectIdentifier);
    procedure CheckEncryptionAlgorithm(const AType: String; const AEncAlgID: IAlgorithmIdentifier;
      AExpectedEncAlgorithm, AExpectedPrfAlgorithm: IDerObjectIdentifier);
    function GetFirst(const AAliases: TCryptoLibStringArray): String;
    function GetFirstKeyEntryAlias(const AStore: IPkcs12Store): String;
    function BuildPkcs12Store: IPkcs12Store; overload;
    function BuildPkcs12Store(AOverwriteFriendlyName: Boolean): IPkcs12Store; overload;
    procedure LoadStoreFromBytes(const AStore: IPkcs12Store; const AData: TBytes;
      const APassword: TCryptoLibCharArray);
    function SaveStoreToBytes(const AStore: IPkcs12Store; const APassword: TCryptoLibCharArray): TBytes;
    procedure LoadSentrixStoreAndCheck(const AData: TBytes; const APassword: TCryptoLibCharArray);
    function GetExpectedPkcs12Modulus: TBigInteger;
    function GetExpectedPkcs12ChainSerial(AIndex: Int32): TBigInteger;
  protected
    procedure SetUp; override;
  published
    procedure TestCertsOnly;
    procedure TestPkcs12Store_LoadAndVerifyKeyAndChain;
    procedure TestPkcs12Store_SaveAndReload;
    procedure TestPkcs12Store_DeleteEntry;
    procedure TestPkcs12Store_CertificateEntry_HasNoChain;
    procedure TestPkcs12Store_LoadUtfCert;
    procedure TestPkcs12Store_KeyEntry_AliasAndTypeChecks;
    procedure TestPkcs12Store_NoExtraLocalKeyId;
    procedure TestPkcs12Store_LoadNoFriendly_SingleCertAndDummyAlias;
    procedure TestPkcs12Store_LoadStorageIssue_Save;
    procedure TestPkcs12Store_CertificateEntry_AliasAndTypeChecks;
    procedure TestPkcs12Store_CertificateOnlyEntry_RestoreChecks;
    procedure TestPkcs12Store_LoadEmptyPassword;
    procedure TestPkcs12Store_SentrixStores;
    procedure TestLoadRepeatedLocalKeyID;
    procedure TestHmacSha384;
    procedure TestSupportedTypes;
    procedure TestNoDuplicateOracleTrustedCertAttribute;
    procedure TestFriendlyName_OverwriteFalse_KeepsNull;
    procedure TestFriendlyName_OverwriteTrue_WritesDefault;
    procedure TestFriendlyName_OverwriteTrue_CustomName_StillWritesDefault;
    procedure TestFriendlyName_OverwriteFalse_AddedFriendlyName_Persisted;
  end;

implementation

{ TTestPkcs12Store }

procedure TTestPkcs12Store.SetUp;
begin
  inherited SetUp;
  FPasswd := StringToCharArray('hello world');
  FNoFriendlyPassword := StringToCharArray('sschette12');
  FStoragePassword := StringToCharArray('pass');
  FHmacSha384TestPassword := StringToCharArray('changeit');
  FFriendlyNamePassword := StringToCharArray('Axw9eE51lKEx0IuqHbzlJ+sx');
  FRandom := TSecureRandom.Create();

  FCertsOnly := DecodeBase64('MIICnwIBAzCCApgGCSqGSIb3DQEHAaCCAokEggKFMIICgTCCAn0GCSqGSIb3DQEHAaCCAm4EggJqMIICZjCCAmIGCyqGSIb3DQEM' +
    'CgEDoIICHDCCAhgGCiqGSIb3DQEJFgGgggIIBIICBDCCAgAwggFpoAMCAQICBHcheqIwDQYJKoZIhvcNAQELBQAwMjENMAsGA1UE' +
    'ChMERGVtbzENMAsGA1UECxMERGVtbzESMBAGA1UEAxMJRGVtbyBjZXJ0MCAXDTE5MDgzMTEzMDgzNloYDzIxMDkwNTE5MTMwODM2' +
    'WjAyMQ0wCwYDVQQKEwREZW1vMQ0wCwYDVQQLEwREZW1vMRIwEAYDVQQDEwlEZW1vIGNlcnQwgZ8wDQYJKoZIhvcNAQEBBQADgY0A' +
    'MIGJAoGBAKOVC4Qeg0KPAPRB9WcZdvXitiJ+E6rd3czQGNzEFC6FesAllH3PHSWuUZ2YjhiVMYJyzwVP1II04iCRaIc65R45oVrH' +
    'Z2ybWAOda2hBtySjQ2pIQQpoKE7nvL3jJcHoCIBJVf3c3xpfh7RucCOGiZDjU9CYPG8yznsazb5+fPF/AgMBAAGjITAfMB0GA1Ud' +
    'DgQWBBR/7wUDwa7T0vNzNgjOKdjz2Up9RzANBgkqhkiG9w0BAQsFAAOBgQADzPFsaLhVYD/k9qMueYKi8Ftwijr37niF98cgAHEt' +
    'q6TGsh3Se8gEK3dNJL18vm7NXgGsl8jUWsE9hCF9ar+/cDZ+KrZlZ5PLfifXJJKFqVAhsOORef0NRIVcTCoyQTW4pNpNZP9Ul5LJ' +
    '3iIDjafgJMyEkRbavqdyfSqVTvYNpjEzMBkGCSqGSIb3DQEJFDEMHgoAYQBsAGkAYQBzMBYGDGCGSAGG+WatynsBATEGBgRVHSUA');

  FRepeatedLocalKeyIdPfx := DecodeBase64('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');

  FHmacSha384Test := DecodeBase64('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' +
    'cf9IBAgdTcmL1rwzgQICBAA=');

  FFriendlyNameStore := DecodeBase64('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');

  FPkcs12 := DecodeBase64('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');

  FCertUTF := DecodeBase64('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');

  FPkcs12NoFriendly := DecodeBase64('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');

  FPkcs12StorageIssue := DecodeBase64('MIACAQMwgAYJKoZIhvcNAQcBoIAEghTFMIAwgAYJKoZIhvcNAQcBoIAEggPwMIID7DCCA+gGCyqGSIb3DQEMCgECoIICtTCCArEw' +
    'KwYNKwYBBAGBsBoBAQIBKjAaBBQ47CM+r5s3UQX04zTVMEGw+NeZuAICBAAEggKADl0KV0UrPvuX5QEEvmVB98KVNkKfXnItG4e5' +
    'qoj/XIftsP3xzcvwq2/pLSqou5jmKoV8FrqoLj0ekg1au6FBFk+VYnlF0ONd1+ySkhlBf58bPOo77QjgSfD6/NxwdK+xKoowzAqY' +
    '1Is1f1QIYV1Sl2NtfIfM+jBsyTmEGAC9Sp4ymYI9esxTJ78gzzMTQyzzw88Nm+lJiIf182M85+nIkKxCJMGEKjZMN6AZT7PC8d27' +
    '6y24ERxgHUSJRp0v4HotMcUKJzf0Gmh68QvOBD6IpVu6ktXbIB5crlpCcqnYarDZ2y/9S9tY58UvkZFMAic0OWaJQoZ4zkPjRD3H' +
    'I0LBe1JynxFVSgnHJlI7URVQhAnvdgW3fQDATG8VSlzTtHko0yd5UCB7kvQgCmdkY9fkzmWxX3TjKUDzLf1A/DtgIkoJbwpj6BDB' +
    'jQMehN2MtZyLfSMyhLReSEeswJbBU09faCb/4ags7PgkiMYaUx6NGq7kcICkjH4FR8DQbLXChMdDIlzffFZuumF1AFgrzEwhs89N' +
    '8M6dMp7EDbmReXJnY+Pwo2WgTn56QmYcW0/EFxlLu+oEueSbbDK5vY+m8792ABWRwQVndV+xzgo5z43oDr/IoAgFCDXJCNrlXA8C' +
    'H6ybyfeWeCjC/AlDzFk2VNPma5r9iOWNpFnIuJSptZlVt74nkhMpgRthF0s5JAjpN6zrdnKqW354C2Bw0+zXs+sqQsU7Tyygaq0v' +
    '4RUYqLGpKx81514wp5jI9vEShpqcqEX1W9ywgwESTZqu9AV+3aIr9zfqQ6DOx1A3Zka1QSyvxc8Iwosujx7egAXRAmSWw5NBqXGK' +
    'cGDGH0e6SWARPolHuzGCAR4wEwYJKoZIhvcNAQkVMQYEBAEAAAAwaQYJKwYBBAGCNxEBMVweWgBNAGkAYwByAG8AcwBvAGYAdAAg' +
    'AFIAUwBBACAAUwBDAGgAYQBuAG4AZQBsACAAQwByAHkAcAB0AG8AZwByAGEAcABoAGkAYwAgAFAAcgBvAHYAaQBkAGUAcjCBmwYJ' +
    'KoZIhvcNAQkUMYGNHoGKADcAZABlAGYANQBiADQAMwA2AGMAYQBiAGQAMAAwADIAZABkADIAOQAwADMAYgAxADYAOAA2AGMANwA5' +
    'ADQAOABfADQANgBmADIANgBmAGQANAAtADgAMQAyAGQALQA0AGUAZgBiAC0AOAAwADgAOAAtADQANQBhAGIAOQAxADkAMQAwADcA' +
    'YwBjAAAAADCABgkqhkiG9w0BBwaggDCAAgEAMIAGCSqGSIb3DQEHATArBg0rBgEEAYGwGgEBAgECMBoEFAeOc/5UUO0JXWsyjo3G' +
    'T7ykYrB4AgIEAICCEGBG4EqWgMf0hNau9bK97FRo/u6SI1xniCAAGY88Uo/VMiCUqpl5kKyDNnayB44T0GFz7DuLK74J0N+cB85q' +
    'NGdlkl21abCsy8NAJ+BO7wyXRTSPE3+d1IPKOqHZDyejQINnbJZbCyTCvhsDbkYSZoPtoW0mw0yU89BI7wZHuG7bV2YgyO8xvs+5' +
    'uQTNEncqkq73jHV16+4xUv3oUIg6mcbGPwhxyiWlj4ZfMX46JCcMzfov/cMWjhyptCbMaAwLQOnsxhXbDjAZDEvEYHE9YU+tYGY5' +
    'iR0UJyBxrPTbrCB2LVhWx+eFDNqGqAgVGIXN3WjeGgfy9u58g4TcaF16UQ7+OzHI07RvFSvL8xBdNGPineexB9d/QadFXiarUPJm' +
    'tBbiuLoiHSGKbDUMpDflmj5IHN0larkW/E3gJfYV+heJ1oBw6VGReXmlwOQUVXWqojy37x7fgE4ej1O8+kXN3f24q2D/rmQB2Mcg' +
    'MDlDANn1egF9Hh4fcnrhelPBg6g80b75trbT1p465hzY71iDTwaCw/YXjJUjXVv+9NfQSgUIGNqOzKuiC3RqkaUzLbW3UlGQ/wrh' +
    'oE/RIqQ0pD23+Alhrwgc9GmC0Zid8aYSisZhwjyfty0KlAbyPaPpKV3CcttnvdWufmZwHbWWk3Gi9EZPYpXGLxxuJhhfWt8Xp8fo' +
    'YqxGgMNbNOOzJB55B4cTsGAe/XhSHh17iIYOhcKcQpEDoJGckbIBh77aV0E0z8BwvUgkRBnnwj9D4HSvbuigI5lfl9Gz+KTi/lzc' +
    'Q2yZjQ96R3C7NpKuzdxf9FWeMtWVOf6uoYyEXmxzDmporQbtmAuuj7QB1hA23Lg6BOuVrFyEl+8H+UHhX9Z/t7ILoiafjBjc4yTf' +
    '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' +
    'cDSLqQICBAAAAA==');

  FPkcs12NoPass := DecodeBase64('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' +
    'btoDncdA2Jh/GAICBAAAAA==');

  FSentrixHard := DecodeBase64('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');

  FSentrixSoft := DecodeBase64('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');

  FSentrix1 := DecodeBase64('MIACAQMwgAYJKoZIhvcNAQcBoIAEggrkMIAwgAYJKoZIhvcNAQcBoIAEggG/MIIBuzCCAbcGCyqGSIb3DQEMCgECoIHTMIHQMCsG' +
    'DSsGAQQBgbAaAQECASowGgQUmqO7d3VpDjDHo8jNKG5HXE7Kq2QCAgQABIGg9XptQih4fxDca1hR8sLHesXxt/C99xNM4r7POyRV' +
    'FT8RPjAJUNNxFm3JpimMhUajdy5r2oIHXg5FSShSyBcC4x8s+rcIrSwYokSUQT8HUhtpgIkzI/p6idzNBnY5lDo2BUIpzsPPdRIp' +
    'zcADA43f8Hopj+G93GeRH+tYBRGShn6ULsniI5AcTQVfC2uUDFifiL7vjrAtTNn2Rz0mGJ9IjDGB0TATBgkqhkiG9w0BCRUxBgQE' +
    'AQAAADBbBgkqhkiG9w0BCRQxTh5MAHsANgBEAEEANgBEAEUARgAwAC0ARQAwAEUAQwAtADQAMQBGADcALQBBADUANgBDAC0ARQAz' +
    'ADUAOQBCADIARQAxAEYAQQA0ADUAfTBdBgkrBgEEAYI3EQExUB5OAE0AaQBjAHIAbwBzAG8AZgB0ACAAUwBvAGYAdAB3AGEAcgBl' +
    'ACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAAUAByAG8AdgBpAGQAZQByAAAAADCABgkqhkiG9w0BBwaggDCAAgEAMIAGCSqGSIb3' +
    'DQEHATArBg0rBgEEAYGwGgEBAgECMBoEFLITyPeDuIUJAtlRslWMW4o+xkuhAgIEAICCCLA5zVznm9RIdDcIfi6yltqY+S0u8hca' +
    'P+LYC3KBuUxPX1FWPc7I7R2Bakt6UDebLsmIK3gYkj6MmBjQMK/y3m87TImL3MzTjS8KJPAfztrdhLxOMXRpLfok+87A4Fww6vrN' +
    'UX4C2NbuQYNxb5CRd3kd7ZNfB9uGiIA5QZxc+mcUubaQUkMfPCsbNGyZRsk9ki1ba+sTZgcW1j2JLeLeoVej9TbJhJqz8DLrl5mi' +
    'zoOX4R2PNLRfnsgq0HlXVLw4qbDHCNe0y8ZiqVZiI1R25Wl7ouZuWMN3ndEF6pMtLZi2vTpUOXoe7BmXjRI/vHRyb9t/mAfIXP9B' +
    'U7iEutfPpJFt8ngnjQR6pPwlJZys982rmbDHr/+hyr6nq27Kr/KQaIOFmaNB71VH4ddjWIAPMosxS+a8JcdKB8TxOH4N6ARLgWes' +
    'MfzvSCTMJ+Hm6ZDPHRfTRwxXkaaPqFIbD00TVTwqq48d1uQ326mlm3D2M5Wd3yoU2u5K+O4w+k6SZpPLoe9OMHcF7T75HyAcMheZ' +
    '2mXIhvpu8ER8IQu8ZYEWFWFdM1KY3H5osDHIjmrptyeMJXgN4z3Vlkk4Sa37PGkUVJb+4sx4NUhaa4fcj7pOEpn4mNnWYEb8XUVw' +
    'wfZGYtwnK5I/So2XzBkzvxR5DPeMP6Q/+yXgwBZuSNtV5oyUpDHRPep41ZixmBNVViGbbi9y0KZJsdSIg/CxATp4nPM22S4BoIPT' +
    '9Mh83s9yds0oFdpaeH0bzK/aXNXZgzoN+Rdd02zoXd1oAxfU6Q4Fix1ujQeakCDpZqCgaVkpZD6TOJE6TFfW4JGs9I1HNoJgm3dg' +
    'RrmVt0LMUkRZhnnRCelA5W87tjF02LRe2ssbXwkafBqsPu9PtMqkXSz1PfusSF84aNnPtTvFl6k82xeVu62z30x9oKYZpef+0H+0' +
    'qqJiNVHWKLvIs9Dn5qXC5ooJQmX/1ACUnucZJVyoeWWZ69o/Njf6yqe3LaIfN22mSlS480sBb1f9kY8IUjwmWtLsYBVeASXrZpe2' +
    'BTiXjn0ONayisRQfcsclSorm22wq5I5ViX0VOLhJj08cneMFK4lqJXpnafwCnAaksNtVFoDaU27UduwVd1vTKTwz8woSgkV2KNe7' +
    'CfjdUvkaS8dhNH8BGjmo9oOQ8ip5NXf5nvNpcTqPvnZXdq/IohICBvT8QBY2CrT2ErCjHhpOgEvTKrFSlXaV+a6zLQSEKpZfH6wN' +
    'XZsovc1hQyjGvAWdZR+FVsUEHhW5r+P620DFzUCl3MVz5u4iERojkDXl8nMUXO3S+6iHCW187c4oV1Rea3vcL4McLHpnRhp7VgQl' +
    'OSleZ6kycuKcV+WRnUmYXNDactRg5u3O8HT6fP7XIK7tdyFT9d5lmN8J8MLAnHzto7l/lPyCHlHzgxJfxukbWPok8cO3X2c5MQg6' +
    'LbRz8abTXm6yhZM1zy3qhH4O9Im1p+6p9jGgAhxrEQJy498OJ26TEzH3v7Wnj1QmZfvUo7zX0apdMuugSsB7NJmtac1SXeq7Vr1D' +
    '6OlHsVjzpMpR1ab5yHBIAnrOQJS82nMAlOOIpl9xIw8n65kNX8VF3KYu2OD5Qk3Exle4Ht5p38XuGrApkq9Yl5aapVUv88+JtraA' +
    '/zNwfUhIyfUJGYfOJQ2slmTQ0KBtaIiVK70IffxO71zsDbdfI0D4vnTOFSwrf+6416bv8Qi8txM74IkPqY/yTjJUq9eOetKdtPai' +
    'EynxdzrYFN7eg+bVWFyvSkKXQtqGxveZ/WOn2SnHa/ROQr1XLeD4Bq6XGcsjtmdv+HWLAsZRlZ61f+jorI1PV3qPakl/od1Pj0ZD' +
    'l52/h9M6XmUBbcxqQcs/f+/mqcVEVcmsTFpkG6w2bPvcZj9TX0+pAH4kij7BVvpaF0zj6pKWX6CHms8pGaPK3sbhUf8OEUvgzeGL' +
    'UdqCxkI6G0dONRb32e7LrCm1TNb3xaiubr4xCzQ9/jSMED94y7cvRR5QEIvra07NiEwodQbsLj1iRF9CVbrc8CUmiq3701QK/l5E' +
    'OdOmTvJcfEeZKhSb0JRqbCu6g352DuIJllE5KuI/ThSfDdg78t5pVqCbDtKHeq49SXvAa8rY9njMHr0wp/VpJnPuxXP3SWCDZ4M+' +
    'g3NLwAlNstzschqiu5HyGi4ikdSlwncllhL6XHnhQVsrFx0ekacYrThO5SU454wVgSaaHm1SoVHExT8qrZ6VO1Jyp2OgaxFnZk5q' +
    'Zb1siAJgNiN1mUuulBjfXzkSjTh42LH+NnsPNS8GZ+rQrpfITNIazESA4DUHc1Z0HPqqfAfrcici2XlCSssUh8gx2hvedihwTeJm' +
    'hkc1OgjkAj1z5xGgHhJGDgez7Wz+pyEZ49Ntx89me6QZ+QADqA73S6pAs5qyweZ69k2MTtCUQNmCFsWxDYzU3TAJz6utNxuXB/36' +
    'lwzYvDmISP67gnwMos3Bbuu2YdFHl3o7a+Do/j9SrRvAGeAvLCxk31Yvd/T8Kh2A7kwC2wO1CN97sE591I7ANF/MzFQONAni3o0U' +
    'jh2ygqeVSA95DhIVNRpfznWuzSEHcSwxByk8n4sD1Sio6vSFS0qqscjaRDN7nlbmKudzFo0Fi4B2iIMdKYlwUEOaBVf18FCq00Eo' +
    'l0muiie/ks4YAOXoJgdleFJClQxfIeTVgU7SoIBSX9lpnsWlHoIAYs/DmzBveJdzrXCN0VfUkbZbBYn691H1OdH5x56S6CyPAa2I' +
    'T2F5mIuDrsOs0LekhKGEYZ/Yh+pZJWnYmMDCpmhLveCzwLEBXxfGAXHLVm8HtsELdGTu9WOB8xPuhjmVuab0CYP54t7tKiMBYV5i' +
    'kPL8arV1IP4E9CQR8AQvUvBMcf2OjVD1mtQwKz34fOgrZKfaJ2r9QYVhGeDfoLXN14mKa8YZtbgRGltgFY1sR9/598u9VQG4u3fx' +
    'voZ2/TVgIVbGHYlaShy+ou2sqAe8kU60EPfaAAAAAAAAAAAAAAAAAAAwPTAhMAkGBSsOAwIaBQAEFHlY6ybvhBel1ZdQijdXWzVB' +
    'jFtnBBTOR22ns6+9pjHUzZVSfVTUibAD8QICBAAAAA==');

  FSentrix2 := DecodeBase64('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');

  FSentrix3 := DecodeBase64('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');
end;

function TTestPkcs12Store.GetFirst(const AAliases: TCryptoLibStringArray): String;
begin
  if (AAliases = nil) or (System.Length(AAliases) = 0) then
    Fail('GetFirst: aliases empty');
  Result := AAliases[0];
end;

function TTestPkcs12Store.GetFirstKeyEntryAlias(const AStore: IPkcs12Store): String;
var
  LAliases: TCryptoLibStringArray;
  I: Int32;
begin
  Result := '';
  LAliases := AStore.Aliases;
  if LAliases <> nil then
  begin
    for I := 0 to System.Length(LAliases) - 1 do
    begin
      if AStore.IsKeyEntry(LAliases[I]) then
      begin
        Result := LAliases[I];
        Exit;
      end;
    end;
  end;
  if Result = '' then
    Fail('GetFirstKeyEntryAlias: no key entry found');
end;

function TTestPkcs12Store.BuildPkcs12Store: IPkcs12Store;
var
  LBuilder: IPkcs12StoreBuilder;
begin
  LBuilder := TPkcs12StoreBuilder.Create;
  Result := LBuilder.Build;
end;

function TTestPkcs12Store.BuildPkcs12Store(AOverwriteFriendlyName: Boolean): IPkcs12Store;
var
  LBuilder: IPkcs12StoreBuilder;
begin
  LBuilder := TPkcs12StoreBuilder.Create;
  Result := LBuilder.SetOverwriteFriendlyName(AOverwriteFriendlyName).Build;
end;

procedure TTestPkcs12Store.LoadStoreFromBytes(const AStore: IPkcs12Store; const AData: TBytes;
  const APassword: TCryptoLibCharArray);
var
  LStream: TBytesStream;
begin
  LStream := TBytesStream.Create(AData);
  try
    AStore.Load(LStream, APassword);
  finally
    LStream.Free;
  end;
end;

function TTestPkcs12Store.SaveStoreToBytes(const AStore: IPkcs12Store; const APassword: TCryptoLibCharArray): TBytes;
var
  LOut: TMemoryStream;
begin
  LOut := TMemoryStream.Create;
  try
    AStore.Save(LOut, APassword, FRandom);
    SetLength(Result, LOut.Size);
    if LOut.Size > 0 then
      Move(LOut.Memory^, Result[0], LOut.Size);
  finally
    LOut.Free;
  end;
end;

procedure TTestPkcs12Store.LoadSentrixStoreAndCheck(const AData: TBytes; const APassword: TCryptoLibCharArray);
var
  LStore: IPkcs12Store;
begin
  if System.Length(AData) = 0 then
    Exit;
  LStore := BuildPkcs12Store;
  LoadStoreFromBytes(LStore, AData, APassword);
  CheckPKCS12(LStore);
end;

function TTestPkcs12Store.GetExpectedPkcs12Modulus: TBigInteger;
begin
  Result := TBigInteger.Create('bb1be8074e4787a8d77967f1575ef72dd7582f9b3347724413c021beafad8f32dba5168e280cbf284df722283dad2fd4abc7' +
    '50e3d6487c2942064e2d8d80641aa5866d1f6f1f83eec26b9b46fecb3b1c9856a303148a5cc899c642fb16f3d9d72f52526c' +
    '751dc81622c420c82e2cfda70fe8d13f16cc7d6a613a5b2a2b5894d1', 16);
end;

function TTestPkcs12Store.GetExpectedPkcs12ChainSerial(AIndex: Int32): TBigInteger;
const
  ChainSerials: array [0 .. 2] of String = (
    '96153094170511488342715101755496684211',
    '279751514312356623147411505294772931957',
    '11341398017');
begin
  if (AIndex < 0) or (AIndex > 2) then
    Fail('GetExpectedPkcs12ChainSerial: index out of range');
  Result := TBigInteger.Create(ChainSerials[AIndex]);
end;

function TTestPkcs12Store.CreateCert(const APubKey, APrivKey: IAsymmetricKeyParameter;
  const AIssuerEmail, ASubjectEmail: String; const ALocalKeyId: TBytes): IX509CertificateEntry;
var
  LIssuerAttrs, LSubjectAttrs: TDictionary<IDerObjectIdentifier, String>;
  LOrder: TList<IDerObjectIdentifier>;
  LCertGen: IX509V3CertificateGenerator;
  LCert: IX509Certificate;
  LSigner: ISignatureFactory;
  LBagAttrs: TDictionary<IDerObjectIdentifier, IAsn1Encodable>;
  LUtc: TDateTime;
begin
  LIssuerAttrs := TDictionary<IDerObjectIdentifier, String>.Create(TAsn1Comparers.OidEqualityComparer);
  LSubjectAttrs := TDictionary<IDerObjectIdentifier, String>.Create(TAsn1Comparers.OidEqualityComparer);
  LOrder := TList<IDerObjectIdentifier>.Create(TAsn1Comparers.OidComparer);
  try
    LIssuerAttrs.Add(TX509Name.C, 'NG');
    LIssuerAttrs.Add(TX509Name.O, 'CryptoLib4Pascal');
    LIssuerAttrs.Add(TX509Name.L, 'Alausa');
    LIssuerAttrs.Add(TX509Name.ST, 'Lagos');
    LIssuerAttrs.Add(TX509Name.EmailAddress, AIssuerEmail);

    LSubjectAttrs.Add(TX509Name.C, 'NG');
    LSubjectAttrs.Add(TX509Name.O, 'CryptoLib4Pascal');
    LSubjectAttrs.Add(TX509Name.L, 'Alausa');
    LSubjectAttrs.Add(TX509Name.ST, 'Lagos');
    LSubjectAttrs.Add(TX509Name.EmailAddress, ASubjectEmail);

    LOrder.Add(TX509Name.C);
    LOrder.Add(TX509Name.O);
    LOrder.Add(TX509Name.L);
    LOrder.Add(TX509Name.ST);
    LOrder.Add(TX509Name.EmailAddress);

    LCertGen := TX509V3CertificateGenerator.Create;
    LCertGen.SetSerialNumber(TBigInteger.One);
    LCertGen.SetIssuerDN(TX509Name.Create(LOrder, LIssuerAttrs) as IX509Name);
    LUtc := TTimeZone.Local.ToUniversalTime(Now);
    LCertGen.SetNotBeforeUtc(IncDay(LUtc, -30));
    LCertGen.SetNotAfterUtc(IncDay(LUtc, 30));
    LCertGen.SetSubjectDN(TX509Name.Create(LOrder, LSubjectAttrs) as IX509Name);
    LCertGen.SetPublicKey(APubKey);

    LSigner := TAsn1SignatureFactory.Create('MD5WithRSAEncryption', APrivKey, FRandom);
    LCert := LCertGen.Generate(LSigner);

    LBagAttrs := TDictionary<IDerObjectIdentifier, IAsn1Encodable>.Create(TAsn1Comparers.OidEqualityComparer);
    if (ALocalKeyId <> nil) and (System.Length(ALocalKeyId) > 0) then
     LBagAttrs.Add(TPkcsObjectIdentifiers.Pkcs9AtLocalKeyID, TDerOctetString.Create(ALocalKeyId) as IDerOctetString);
    Result := TX509CertificateEntry.Create(LCert, LBagAttrs);
  finally
    LIssuerAttrs.Free;
    LSubjectAttrs.Free;
    LOrder.Free;
  end;
end;

procedure TTestPkcs12Store.CreateTestCertificateAndKey(out APrivKey: IAsymmetricKeyEntry;
  out AChain: TCryptoLibGenericArray<IX509CertificateEntry>);
var
  LPubKey: IRsaKeyParameters;
  LPrivKeyParams: IRsaPrivateCrtKeyParameters;
  LMod, LExp: TBigInteger;
  LLocalKeyId: TBytes;
  LPrivKeyAttrs: TDictionary<IDerObjectIdentifier, IAsn1Encodable>;
begin
  LMod := TBigInteger.Create('b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7', 16);
  LExp := TBigInteger.Create('11', 16);
  LPubKey := TRsaKeyParameters.Create(False, LMod, LExp) as IRsaKeyParameters;

  LPrivKeyParams := TRsaPrivateCrtKeyParameters.Create(
    TBigInteger.Create('b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7', 16),
    TBigInteger.Create('11', 16),
    TBigInteger.Create('9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89', 16),
    TBigInteger.Create('c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb', 16),
    TBigInteger.Create('f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5', 16),
    TBigInteger.Create('b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391', 16),
    TBigInteger.Create('d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd', 16),
    TBigInteger.Create('b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19', 16)) as IRsaPrivateCrtKeyParameters;

  LLocalKeyId := TBytes.Create(4, 2, 4, 6, 13);
  LPrivKeyAttrs := TDictionary<IDerObjectIdentifier, IAsn1Encodable>.Create(TAsn1Comparers.OidEqualityComparer);
  LPrivKeyAttrs.Add(TPkcsObjectIdentifiers.Pkcs9AtLocalKeyID, TDerOctetString.Create(LLocalKeyId) as IDerOctetString);
  APrivKey := TAsymmetricKeyEntry.Create(LPrivKeyParams as IAsymmetricKeyParameter, LPrivKeyAttrs);

  SetLength(AChain, 1);
  AChain[0] := CreateCert(LPubKey as IAsymmetricKeyParameter, LPrivKeyParams as IAsymmetricKeyParameter,
    'issuer@cryptolib4pascal.org', 'subject@cryptolib4pascal.org', LLocalKeyId);
end;

procedure TTestPkcs12Store.DoTestNoExtraLocalKeyID(const AStore1Data: TBytes);
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKeyPair: IAsymmetricCipherKeyPair;
  LStore1, LStore2: IPkcs12Store;
  LK1: IAsymmetricKeyEntry;
  LChain1, LChain2: TCryptoLibGenericArray<IX509CertificateEntry>;
  LChain2Arr: TCryptoLibGenericArray<IX509CertificateEntry>;
  I: Int32;
  LPkcs12Entry: IPkcs12Entry;
  LAttr: IAsn1Encodable;
  LBytes: TBytes;
begin
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('RSA');
  LKpg.Init(TRsaKeyGenerationParameters.Create(TBigInteger.ValueOf(Int64($10001)), FRandom, 512, 25));
  LKeyPair := LKpg.GenerateKeyPair;

  LStore1 := BuildPkcs12Store;
  LoadStoreFromBytes(LStore1, AStore1Data, FPasswd);

  LStore2 := BuildPkcs12Store;
  LK1 := LStore1.GetKey('privatekey');
  LChain1 := LStore1.GetCertificateChain('privatekey');
  SetLength(LChain2Arr, System.Length(LChain1) + 1);
  for I := 0 to System.Length(LChain1) - 1 do
    LChain2Arr[I + 1] := LChain1[I];
  LChain2Arr[0] := CreateCert(LKeyPair.Public as IAsymmetricKeyParameter, LK1.Key,
    'subject@cryptolib4pascal.org', 'extra@cryptolib4pascal.org', nil);

  if not Supports(LChain1[0], IPkcs12Entry, LPkcs12Entry) then
    Fail('chain[0] is not IPkcs12Entry');
  if not LPkcs12Entry.TryGetAttribute(TPkcsObjectIdentifiers.Pkcs9AtLocalKeyID, LAttr) then
    Fail('localKeyID not found initially');

  LStore2.SetKeyEntry('new', TAsymmetricKeyEntry.Create(LKeyPair.Private as IAsymmetricKeyParameter), LChain2Arr);

  LBytes := SaveStoreToBytes(LStore2, FPasswd);
  LoadStoreFromBytes(LStore2, LBytes, FPasswd);
  LChain2 := LStore2.GetCertificateChain('new');
  if Supports(LChain2[1], IPkcs12Entry, LPkcs12Entry) and
    LPkcs12Entry.TryGetAttribute(TPkcsObjectIdentifiers.Pkcs9AtLocalKeyID, LAttr) then
    Fail('localKeyID found after save');
end;

procedure TTestPkcs12Store.CheckPKCS12(const AStore: IPkcs12Store);
var
  LAlias: String;
  LAliases: TCryptoLibStringArray;
  I: Int32;
begin
  LAliases := AStore.Aliases;
  if LAliases = nil then
    Exit;
  for I := 0 to System.Length(LAliases) - 1 do
  begin
    LAlias := LAliases[I];
    if AStore.IsKeyEntry(LAlias) then
    begin
      AStore.GetKey(LAlias);
      AStore.GetCertificateChain(LAlias);
    end
    else if AStore.IsCertificateEntry(LAlias) then
      AStore.GetCertificate(LAlias);
  end;
end;

procedure TTestPkcs12Store.CheckEncryptionAlgorithm(const AType: String; const AEncAlgID: IAlgorithmIdentifier;
  AExpectedEncAlgorithm, AExpectedPrfAlgorithm: IDerObjectIdentifier);
var
  LPbeS2: IPbeS2Parameters;
  LKdf: IAlgorithmIdentifier;
  LPbkdf2: IPbkdf2Params;
begin
  if AExpectedPrfAlgorithm = nil then
  begin
    if not AExpectedEncAlgorithm.Equals(AEncAlgID.Algorithm) then
      Fail(AType + ' legacy encryption algorithm wrong');
    Exit;
  end;

  if not TPkcsObjectIdentifiers.IdPbeS2.Equals(AEncAlgID.Algorithm) then
    Fail(AType + ' encryption PBES2 expected, but it is different');

  LPbeS2 := TPbeS2Parameters.GetInstance(AEncAlgID.Parameters);
  if not AExpectedEncAlgorithm.Equals(LPbeS2.EncryptionScheme.Algorithm) then
    Fail(AType + ' encryption algorithm within PBES2 wrong');

  LKdf := LPbeS2.KeyDerivationFunc;
  if not TPkcsObjectIdentifiers.IdPbkdf2.Equals(LKdf.Algorithm) then
    Fail(AType + ' derivation algorithm within PBES2 should be Pbkdf2');

  LPbkdf2 := TPbkdf2Params.GetInstance(LKdf.Parameters);
  if not AExpectedPrfAlgorithm.Equals(LPbkdf2.Prf.Algorithm) then
    Fail(AType + ' derivation PRF algorithm within PBES2 wrong');
end;

procedure TTestPkcs12Store.BasicStoreTest(const APrivKey: IAsymmetricKeyEntry;
  const AChain: TCryptoLibGenericArray<IX509CertificateEntry>;
  ACertAlgorithm, ACertPrfAlgorithm, AKeyAlgorithm, AKeyPrfAlgorithm: IDerObjectIdentifier);
var
  LBuilder: IPkcs12StoreBuilder;
  LStore: IPkcs12Store;
  LBytes: TBytes;
  LKey: IAsymmetricKeyEntry;
  LC: TCryptoLibGenericArray<IX509CertificateEntry>;
  LPkcs12Entry: IPkcs12Entry;
  LAttr, LAttr2: IAsn1Encodable;
  LOctetStr: IAsn1OctetString;
  LPfx: IPfx;
  LAuthSafe: IPkcsContentInfo;
  LAuthOctets: TBytes;
  LSeq: IAsn1Sequence;
  LCi1, LCi2: IPkcsContentInfo;
  LSafeBag: ISafeBag;
  LEncKeyInfo: IEncryptedPrivateKeyInfo;
  LEncData: IPkcsEncryptedData;
begin
  LBuilder := TPkcs12StoreBuilder.Create;
  LBuilder.SetCertAlgorithm(ACertAlgorithm, ACertPrfAlgorithm);
  LBuilder.SetKeyAlgorithm(AKeyAlgorithm, AKeyPrfAlgorithm);
  LStore := LBuilder.Build;

  LStore.SetKeyEntry('key', APrivKey, AChain);

  LBytes := SaveStoreToBytes(LStore, FPasswd);
  LoadStoreFromBytes(LStore, LBytes, FPasswd);

  LKey := LStore.GetKey('key');
  if not LKey.Equals(APrivKey) then
    Fail('private key didn''t match');

  LC := LStore.GetCertificateChain('key');
  if (System.Length(LC) <> System.Length(AChain)) or (not LC[0].Equals(AChain[0])) then
    Fail('certificates didn''t match');

  if not Supports(LKey, IPkcs12Entry, LPkcs12Entry) then
    Fail('key entry is not IPkcs12Entry');
  if not LPkcs12Entry.TryGetAttribute(TPkcsObjectIdentifiers.Pkcs9AtFriendlyName, LAttr) then
    Fail('no friendly name found on key')
  else if not (LAttr as IAsn1Encodable).ToAsn1Object().Equals(TDerBmpString.Create('key').ToAsn1Object()) then
    Fail('friendly name wrong');

  if not LPkcs12Entry.TryGetAttribute(TPkcsObjectIdentifiers.Pkcs9AtLocalKeyID, LAttr) then
    Fail('no local key id found')
  else
  begin
    if not Supports(LC[0], IPkcs12Entry, LPkcs12Entry) then
      Fail('chain[0] is not IPkcs12Entry');
    if not LPkcs12Entry.TryGetAttribute(TPkcsObjectIdentifiers.Pkcs9AtLocalKeyID, LAttr2) then
      Fail('chain[0] has no local key id');
    if not LAttr.ToAsn1Object().Equals(LAttr2.ToAsn1Object()) then
      Fail('local key id mismatch');
  end;

  LPfx := TPfx.GetInstance(LBytes);
  LAuthSafe := LPfx.AuthSafe;
  if not Supports(LAuthSafe.Content, IAsn1OctetString, LOctetStr) then
    Fail('AuthSafe content is not octet string');
  LAuthOctets := LOctetStr.GetOctets();
  LSeq := TAsn1Sequence.GetInstance(LAuthOctets);
  LCi1 := TPkcsContentInfo.GetInstance(LSeq.GetItem(0));
  LCi2 := TPkcsContentInfo.GetInstance(LSeq.GetItem(1));

  if not Supports(LCi1.Content, IAsn1OctetString, LOctetStr) then
    Fail('first ContentInfo content is not octet string');
  LSeq := TAsn1Sequence.GetInstance(LOctetStr.GetOctets());
  LSafeBag := TSafeBag.GetInstance(LSeq.GetItem(0));

  if AKeyAlgorithm = nil then
  begin
    if not TPkcsObjectIdentifiers.KeyBag.Equals(LSafeBag.BagID) then
      Fail('Without key encryption, expected ''KeyBag''');
  end
  else
  begin
    if not TPkcsObjectIdentifiers.Pkcs8ShroudedKeyBag.Equals(LSafeBag.BagID) then
      Fail('With key encryption, expected ''Pkcs8ShroudedKeyBag''');
    LEncKeyInfo := TEncryptedPrivateKeyInfo.GetInstance(LSafeBag.BagValueEncodable);
    CheckEncryptionAlgorithm('key', LEncKeyInfo.EncryptionAlgorithm, AKeyAlgorithm, AKeyPrfAlgorithm);
  end;

  if ACertAlgorithm = nil then
  begin
    if not TPkcsObjectIdentifiers.Data.Equals(LCi2.ContentType) then
      Fail('Without cert encryption, expected ''Data''');
  end
  else
  begin
    if not TPkcsObjectIdentifiers.EncryptedData.Equals(LCi2.ContentType) then
      Fail('With cert encryption, expected ''EncryptedData''');
    LEncData := TPkcsEncryptedData.GetInstance(LCi2.Content);
    CheckEncryptionAlgorithm('cert', LEncData.EncryptionAlgorithm, ACertAlgorithm, ACertPrfAlgorithm);
  end;
end;

procedure TTestPkcs12Store.TestCertsOnly;
var
  LStore: IPkcs12Store;
  LBytes: TBytes;
  LPass: TCryptoLibCharArray;
begin
  LStore := BuildPkcs12Store;
  LoadStoreFromBytes(LStore, FCertsOnly, nil);
  Check(LStore.ContainsAlias('alias'), 'certsOnly: expected alias ''alias''');

  LBytes := SaveStoreToBytes(LStore, nil);
  LStore := BuildPkcs12Store;
  LoadStoreFromBytes(LStore, LBytes, nil);
  Check(LStore.ContainsAlias('alias'), 'certsOnly round-trip: expected alias ''alias''');

  LPass := StringToCharArray('1');
  try
    LoadStoreFromBytes(LStore, FCertsOnly, LPass);
    Fail('expected exception when loading certs-only store with password');
  except
    on E: EIOCryptoLibException do
      CheckEquals('password supplied for keystore that does not require one', E.Message);
  end;
end;

procedure TTestPkcs12Store.TestPkcs12Store_LoadAndVerifyKeyAndChain;
var
  LStore: IPkcs12Store;
  LPName: String;
  LKey: IAsymmetricKeyEntry;
  LRsaKey: IRsaKeyParameters;
  LCh: TCryptoLibGenericArray<IX509CertificateEntry>;
begin
  LStore := BuildPkcs12Store;
  LoadStoreFromBytes(LStore, FPkcs12, FPasswd);
  LPName := GetFirstKeyEntryAlias(LStore);
  LKey := LStore.GetKey(LPName);
  if LKey = nil then
    Fail('key entry not found');
  if not Supports(LKey.Key, IRsaKeyParameters, LRsaKey) then
    Fail('key is not RSA');
  if not LRsaKey.Modulus.Equals(GetExpectedPkcs12Modulus) then
    Fail('Modulus doesn''t match.');
  LCh := LStore.GetCertificateChain(LPName);
  if System.Length(LCh) <> 3 then
    Fail('chain was wrong length');
  if not LCh[0].Certificate.SerialNumber.Equals(GetExpectedPkcs12ChainSerial(0)) then
    Fail('chain[0] wrong certificate.');
  if not LCh[1].Certificate.SerialNumber.Equals(GetExpectedPkcs12ChainSerial(1)) then
    Fail('chain[1] wrong certificate.');
  if not LCh[2].Certificate.SerialNumber.Equals(GetExpectedPkcs12ChainSerial(2)) then
    Fail('chain[2] wrong certificate.');
end;

procedure TTestPkcs12Store.TestPkcs12Store_SaveAndReload;
var
  LStore: IPkcs12Store;
  LBytes: TBytes;
  LPName: String;
  LKey: IAsymmetricKeyEntry;
begin
  LStore := BuildPkcs12Store;
  LoadStoreFromBytes(LStore, FPkcs12, FPasswd);
  LPName := GetFirstKeyEntryAlias(LStore);
  LBytes := SaveStoreToBytes(LStore, FPasswd);
  LoadStoreFromBytes(LStore, LBytes, FPasswd);
  LKey := LStore.GetKey(LPName);
  if not (LKey.Key as IRsaKeyParameters).Modulus.Equals(GetExpectedPkcs12Modulus) then
    Fail('Modulus doesn''t match.');
end;

procedure TTestPkcs12Store.TestPkcs12Store_DeleteEntry;
var
  LStore: IPkcs12Store;
  LPName: String;
begin
  LStore := BuildPkcs12Store;
  LoadStoreFromBytes(LStore, FPkcs12, FPasswd);
  LPName := GetFirstKeyEntryAlias(LStore);
  LStore.DeleteEntry(LPName);
  if LStore.GetKey(LPName) <> nil then
    Fail('Failed deletion test.');
end;

procedure TTestPkcs12Store.TestPkcs12Store_CertificateEntry_HasNoChain;
var
  LStore: IPkcs12Store;
  LPName: String;
  LCh: TCryptoLibGenericArray<IX509CertificateEntry>;
begin
  LStore := BuildPkcs12Store;
  LoadStoreFromBytes(LStore, FPkcs12, FPasswd);
  LPName := GetFirstKeyEntryAlias(LStore);
  LCh := LStore.GetCertificateChain(LPName);
  LStore.DeleteEntry(LPName);
  LStore.SetCertificateEntry('testCert', LCh[2]);
  if LStore.GetCertificateChain('testCert') <> nil then
    Fail('Failed null chain test.');
end;

procedure TTestPkcs12Store.TestPkcs12Store_LoadUtfCert;
var
  LStore: IPkcs12Store;
  LUserPass: TCryptoLibCharArray;
begin
  LStore := BuildPkcs12Store;
  LUserPass := StringToCharArray('user');
  LoadStoreFromBytes(LStore, FCertUTF, LUserPass);
  if LStore.GetCertificate('37') = nil then
    Fail('Failed to find UTF cert.');
end;

procedure TTestPkcs12Store.TestPkcs12Store_KeyEntry_AliasAndTypeChecks;
var
  LStore: IPkcs12Store;
  LPrivKey: IAsymmetricKeyEntry;
  LChain: TCryptoLibGenericArray<IX509CertificateEntry>;
begin
  CreateTestCertificateAndKey(LPrivKey, LChain);
  LStore := BuildPkcs12Store;
  LStore.SetKeyEntry('privateKey', LPrivKey, LChain);
  if (not LStore.ContainsAlias('privateKey')) or (not LStore.ContainsAlias('PRIVATEKEY')) then
    Fail('couldn''t find alias privateKey');
  if LStore.IsCertificateEntry('privateKey') then
    Fail('key identified as certificate entry');
  if (not LStore.IsKeyEntry('privateKey')) or (not LStore.IsKeyEntry('PRIVATEKEY')) then
    Fail('key not identified as key entry');
  if LStore.GetCertificateAlias(LChain[0].Certificate) <> 'privateKey' then
    Fail('Did not return alias for key certificate privateKey');
end;

procedure TTestPkcs12Store.TestPkcs12Store_NoExtraLocalKeyId;
var
  LStore: IPkcs12Store;
  LPrivKey: IAsymmetricKeyEntry;
  LChain: TCryptoLibGenericArray<IX509CertificateEntry>;
  LBytes: TBytes;
begin
  CreateTestCertificateAndKey(LPrivKey, LChain);
  LStore := BuildPkcs12Store;
  LStore.SetKeyEntry('privateKey', LPrivKey, LChain);
  LBytes := SaveStoreToBytes(LStore, FPasswd);
  DoTestNoExtraLocalKeyID(LBytes);
end;

procedure TTestPkcs12Store.TestPkcs12Store_LoadNoFriendly_SingleCertAndDummyAlias;
var
  LStore: IPkcs12Store;
  LPName: String;
  LCh: TCryptoLibGenericArray<IX509CertificateEntry>;
begin
  LStore := BuildPkcs12Store;
  LoadStoreFromBytes(LStore, FPkcs12NoFriendly, FNoFriendlyPassword);
  LPName := GetFirstKeyEntryAlias(LStore);
  LCh := LStore.GetCertificateChain(LPName);
  if System.Length(LCh) <> 1 then
    Fail('no cert found in pkcs12noFriendly');
  LStore.GetCertificateChain('dummy');
  LStore.GetCertificateChain('DUMMY');
  LStore.GetCertificate('dummy');
  LStore.GetCertificate('DUMMY');
end;

procedure TTestPkcs12Store.TestPkcs12Store_LoadStorageIssue_Save;
var
  LStore: IPkcs12Store;
  LPName: String;
  LCh: TCryptoLibGenericArray<IX509CertificateEntry>;
begin
  LStore := BuildPkcs12Store;
  LoadStoreFromBytes(LStore, FPkcs12StorageIssue, FStoragePassword);
  LPName := GetFirstKeyEntryAlias(LStore);
  LCh := LStore.GetCertificateChain(LPName);
  if System.Length(LCh) <> 2 then
    Fail('Certificate chain wrong length');
  SaveStoreToBytes(LStore, FStoragePassword);
end;

procedure TTestPkcs12Store.TestPkcs12Store_CertificateEntry_AliasAndTypeChecks;
var
  LStore: IPkcs12Store;
  LPName: String;
  LCh: TCryptoLibGenericArray<IX509CertificateEntry>;
begin
  LStore := BuildPkcs12Store;
  LoadStoreFromBytes(LStore, FPkcs12StorageIssue, FStoragePassword);
  LPName := GetFirstKeyEntryAlias(LStore);
  LCh := LStore.GetCertificateChain(LPName);
  LStore.SetCertificateEntry('cert', LCh[1]);
  if (not LStore.ContainsAlias('cert')) or (not LStore.ContainsAlias('CERT')) then
    Fail('couldn''t find alias cert');
  if (not LStore.IsCertificateEntry('cert')) or (not LStore.IsCertificateEntry('CERT')) then
    Fail('cert not identified as certificate entry');
  if LStore.IsKeyEntry('cert') or LStore.IsKeyEntry('CERT') then
    Fail('cert identified as key entry');
  if not LStore.IsEntryOfType('cert', TypeInfo(IX509CertificateEntry)) then
    Fail('cert not identified as X509CertificateEntry');
  if not LStore.IsEntryOfType('CERT', TypeInfo(IX509CertificateEntry)) then
    Fail('CERT not identified as X509CertificateEntry');
  if LStore.IsEntryOfType('cert', TypeInfo(IAsymmetricKeyEntry)) then
    Fail('cert identified as key entry via AsymmetricKeyEntry');
  if LStore.GetCertificateAlias(LCh[1].Certificate) <> 'cert' then
    Fail('Did not return alias for certificate entry');
end;

procedure TTestPkcs12Store.TestPkcs12Store_CertificateOnlyEntry_RestoreChecks;
var
  LStore: IPkcs12Store;
  LCh: TCryptoLibGenericArray<IX509CertificateEntry>;
  LPName: String;
begin
  LStore := BuildPkcs12Store;
  LoadStoreFromBytes(LStore, FPkcs12StorageIssue, FStoragePassword);
  LPName := GetFirstKeyEntryAlias(LStore);
  LCh := LStore.GetCertificateChain(LPName);
  LStore := BuildPkcs12Store;
  LStore.SetCertificateEntry('cert', LCh[0]);
  if (not LStore.ContainsAlias('cert')) or (not LStore.ContainsAlias('CERT')) then
    Fail('restore: couldn''t find alias cert');
  if (not LStore.IsCertificateEntry('cert')) or (not LStore.IsCertificateEntry('CERT')) then
    Fail('restore: cert not identified as certificate entry');
  if LStore.IsKeyEntry('cert') or LStore.IsKeyEntry('CERT') then
    Fail('restore: cert identified as key entry');
  if LStore.IsEntryOfType('cert', TypeInfo(IAsymmetricKeyEntry)) then
    Fail('restore: cert identified as key entry via AsymmetricKeyEntry');
  if LStore.IsEntryOfType('CERT', TypeInfo(IAsymmetricKeyEntry)) then
    Fail('restore: cert identified as key entry via AsymmetricKeyEntry');
  if not LStore.IsEntryOfType('cert', TypeInfo(IX509CertificateEntry)) then
    Fail('restore: cert not identified as X509CertificateEntry');
end;

procedure TTestPkcs12Store.TestPkcs12Store_LoadEmptyPassword;
var
  LStore: IPkcs12Store;
  LEmptyPass: TCryptoLibCharArray;
begin
  LEmptyPass := nil;
  LStore := BuildPkcs12Store;
  LoadStoreFromBytes(LStore, FPkcs12NoPass, LEmptyPass);
end;

procedure TTestPkcs12Store.TestPkcs12Store_SentrixStores;
var
  LSentrixPass: TCryptoLibCharArray;
begin
  LSentrixPass := StringToCharArray('0000');
  LoadSentrixStoreAndCheck(FSentrixHard, LSentrixPass);
  LoadSentrixStoreAndCheck(FSentrixSoft, LSentrixPass);
  LoadSentrixStoreAndCheck(FSentrix1, LSentrixPass);
  LoadSentrixStoreAndCheck(FSentrix2, LSentrixPass);
  LoadSentrixStoreAndCheck(FSentrix3, LSentrixPass);
end;

procedure TTestPkcs12Store.TestLoadRepeatedLocalKeyID;
var
  LStore: IPkcs12Store;
  LChain: TCryptoLibGenericArray<IX509CertificateEntry>;
  LEmptyPass: TCryptoLibCharArray;
begin
  LStore := BuildPkcs12Store;
  LEmptyPass := nil;
  LoadStoreFromBytes(LStore, FRepeatedLocalKeyIdPfx, LEmptyPass);
  LChain := LStore.GetCertificateChain('d4be139f9db456d225a8dcd2969479d960d2514a');
  Check(LChain = nil, 'expected nil chain for d4be...');
  LChain := LStore.GetCertificateChain('45cbf1116fb3f38b2984b3c7224cae70a74f7789');
  Check((LChain <> nil) and (System.Length(LChain) = 1), 'expected chain length 1 for 45cb...');
end;

procedure TTestPkcs12Store.TestHmacSha384;
var
  LStore: IPkcs12Store;
  LChain: TCryptoLibGenericArray<IX509CertificateEntry>;
begin
  LStore := BuildPkcs12Store;
  LoadStoreFromBytes(LStore, FHmacSha384Test, FHmacSha384TestPassword);
  LChain := LStore.GetCertificateChain('test');
  Check((LChain <> nil) and (System.Length(LChain) = 1), 'expected chain length 1 for test');
end;

procedure TTestPkcs12Store.TestSupportedTypes;
var
  LPrivKey: IAsymmetricKeyEntry;
  LChain: TCryptoLibGenericArray<IX509CertificateEntry>;
begin
  CreateTestCertificateAndKey(LPrivKey, LChain);
  BasicStoreTest(LPrivKey, LChain, nil, nil,
    TBcObjectIdentifiers.BcPbeSha1Pkcs12Aes256Cbc, nil);
  BasicStoreTest(LPrivKey, LChain,
    TBcObjectIdentifiers.BcPbeSha1Pkcs12Aes256Cbc, nil,
    nil, nil);
  BasicStoreTest(LPrivKey, LChain,
    TBcObjectIdentifiers.BcPbeSha1Pkcs12Aes128Cbc, nil,
    TBcObjectIdentifiers.BcPbeSha1Pkcs12Aes256Cbc, nil);
  BasicStoreTest(LPrivKey, LChain,
    TBcObjectIdentifiers.BcPbeSha1Pkcs12Aes256Cbc, nil,
    TBcObjectIdentifiers.BcPbeSha1Pkcs12Aes256Cbc, nil);
  BasicStoreTest(LPrivKey, LChain, nil, nil,
    TNistObjectIdentifiers.IdAes128Cbc, TPkcsObjectIdentifiers.IdHmacWithSha256);
  BasicStoreTest(LPrivKey, LChain,
    TNistObjectIdentifiers.IdAes128Cbc, TPkcsObjectIdentifiers.IdHmacWithSha256,
    nil, nil);
  BasicStoreTest(LPrivKey, LChain,
    TBcObjectIdentifiers.BcPbeSha1Pkcs12Aes256Cbc, nil,
    TNistObjectIdentifiers.IdAes128Cbc, TPkcsObjectIdentifiers.IdHmacWithSha256);
  BasicStoreTest(LPrivKey, LChain,
    TNistObjectIdentifiers.IdAes128Cbc, TPkcsObjectIdentifiers.IdHmacWithSha256,
    TBcObjectIdentifiers.BcPbeSha1Pkcs12Aes256Cbc, nil);
  BasicStoreTest(LPrivKey, LChain,
    TNistObjectIdentifiers.IdAes256Cbc, TPkcsObjectIdentifiers.IdHmacWithSha512,
    TNistObjectIdentifiers.IdAes256Cbc, TPkcsObjectIdentifiers.IdHmacWithSha512);
end;

procedure TTestPkcs12Store.TestNoDuplicateOracleTrustedCertAttribute;
var
  LRandom: ISecureRandom;
  LCertificateAlias, LKeystorePassword: String;
  LKp1, LKp2: IAsymmetricCipherKeyPair;
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LRootCert, LOriginalCert: IX509Certificate;
  LV1Gen: IX509V1CertificateGenerator;
  LV3Gen: IX509V3CertificateGenerator;
  LRootName, LSubjectName: IX509Name;
  LFirstTrustStore, LFirstTrustStoreReadAgain, LSecondTrustStore: IPkcs12Store;
  LBytes: TBytes;
  LCertRead: IX509CertificateEntry;
  LPasswd: TCryptoLibCharArray;
begin
  LRandom := TSecureRandom.Create;
  LCertificateAlias := 'myAlias';
  LKeystorePassword := 'myPassword';
  LPasswd := StringToCharArray(LKeystorePassword);

  LKpg := TGeneratorUtilities.GetKeyPairGenerator('RSA');
  LKpg.Init(TRsaKeyGenerationParameters.Create(TBigInteger.ValueOf(Int64($10001)), LRandom, 1024, 25) as IRsaKeyGenerationParameters);
  LKp1 := LKpg.GenerateKeyPair;
  LKp2 := LKpg.GenerateKeyPair;

  LRootName := TX509Name.Create('CN=KP1 ROOT');
  LV1Gen := TX509V1CertificateGenerator.Create;
  LV1Gen.SetSerialNumber(TBigInteger.One);
  LV1Gen.SetIssuerDN(LRootName);
  LV1Gen.SetNotBeforeUtc(IncDay(TTimeZone.Local.ToUniversalTime(Now), -1));
  LV1Gen.SetNotAfterUtc(IncDay(TTimeZone.Local.ToUniversalTime(Now), 365));
  LV1Gen.SetSubjectDN(LRootName);
  LV1Gen.SetPublicKey(LKp1.Public as IAsymmetricKeyParameter);
  LRootCert := LV1Gen.Generate(TAsn1SignatureFactory.Create('SHA256withRSA', LKp1.Private as IAsymmetricKeyParameter, LRandom) as ISignatureFactory);

  LSubjectName := TX509Name.Create('CN=KP3 EE');
  LV3Gen := TX509V3CertificateGenerator.Create;
  LV3Gen.SetSerialNumber(TBigInteger.One);
  LV3Gen.SetIssuerDN(LRootName);
  LV3Gen.SetNotBeforeUtc(IncDay(TTimeZone.Local.ToUniversalTime(Now), -1));
  LV3Gen.SetNotAfterUtc(IncDay(TTimeZone.Local.ToUniversalTime(Now), 365));
  LV3Gen.SetSubjectDN(LSubjectName);
  LV3Gen.SetPublicKey(LKp2.Public as IAsymmetricKeyParameter);
  LOriginalCert := LV3Gen.Generate(TAsn1SignatureFactory.Create('SHA256withRSA', LKp1.Private as IAsymmetricKeyParameter, LRandom) as ISignatureFactory);

  LFirstTrustStore := BuildPkcs12Store;
  LFirstTrustStore.SetCertificateEntry(LCertificateAlias, TX509CertificateEntry.Create(LOriginalCert) as IX509CertificateEntry);
  LBytes := SaveStoreToBytes(LFirstTrustStore, LPasswd);

  LFirstTrustStoreReadAgain := BuildPkcs12Store;
  LoadStoreFromBytes(LFirstTrustStoreReadAgain, LBytes, LPasswd);
  LCertRead := LFirstTrustStoreReadAgain.GetCertificate(LCertificateAlias);
  if LCertRead = nil then
    Fail('certificate not found after read');

  LSecondTrustStore := BuildPkcs12Store;
  LSecondTrustStore.SetCertificateEntry(LCertificateAlias,
    TX509CertificateEntry.Create(LCertRead.Certificate) as IX509CertificateEntry);
  SaveStoreToBytes(LSecondTrustStore, LPasswd);
end;

procedure TTestPkcs12Store.TestFriendlyName_OverwriteFalse_KeepsNull;
var
  LStore1, LStore2: IPkcs12Store;
  LBytes: TBytes;
  LAlias2: String;
  LKeyEntry: IAsymmetricKeyEntry;
  LPkcs12Entry: IPkcs12Entry;
begin
  LStore1 := BuildPkcs12Store(False);
  LoadStoreFromBytes(LStore1, FFriendlyNameStore, FFriendlyNamePassword);
  LStore2 := BuildPkcs12Store;
  LBytes := SaveStoreToBytes(LStore1, FFriendlyNamePassword);
  LoadStoreFromBytes(LStore2, LBytes, FFriendlyNamePassword);
  LAlias2 := GetFirst(LStore2.Aliases);
  LKeyEntry := LStore2.GetKey(LAlias2);
  Check(LKeyEntry <> nil);
  if Supports(LKeyEntry, IPkcs12Entry, LPkcs12Entry) then
    Check(not LPkcs12Entry.HasFriendlyName,
      'with overwriteFriendlyName=false, default friendlyName should not be written to new store');
end;

procedure TTestPkcs12Store.TestFriendlyName_OverwriteTrue_WritesDefault;
var
  LStore1, LStore2: IPkcs12Store;
  LBytes: TBytes;
  LAlias2: String;
  LKeyEntry: IAsymmetricKeyEntry;
  LPkcs12Entry: IPkcs12Entry;
begin
  LStore1 := BuildPkcs12Store(True);
  LoadStoreFromBytes(LStore1, FFriendlyNameStore, FFriendlyNamePassword);
  LBytes := SaveStoreToBytes(LStore1, FFriendlyNamePassword);
  LStore2 := BuildPkcs12Store;
  LoadStoreFromBytes(LStore2, LBytes, FFriendlyNamePassword);
  LAlias2 := GetFirst(LStore2.Aliases);
  LKeyEntry := LStore2.GetKey(LAlias2);
  Check(LKeyEntry <> nil);
  if Supports(LKeyEntry, IPkcs12Entry, LPkcs12Entry) then
    Check(LPkcs12Entry.HasFriendlyName,
      'with overwriteFriendlyName=true, default friendlyName should be written to new store');
end;

procedure TTestPkcs12Store.TestFriendlyName_OverwriteTrue_CustomName_StillWritesDefault;
var
  LStore1, LStore2: IPkcs12Store;
  LBytes: TBytes;
  LAlias1, LAlias2: String;
begin
  LStore1 := BuildPkcs12Store(True);
  LoadStoreFromBytes(LStore1, FFriendlyNameStore, FFriendlyNamePassword);
  LAlias1 := GetFirst(LStore1.Aliases);
  LStore1.SetFriendlyName(LAlias1, 'my_custom_friendly_name');
  LStore2 := BuildPkcs12Store;
  LBytes := SaveStoreToBytes(LStore1, FFriendlyNamePassword);
  LoadStoreFromBytes(LStore2, LBytes, FFriendlyNamePassword);
  LAlias2 := GetFirst(LStore2.Aliases);
  Check(LAlias2 <> 'my_custom_friendly_name',
    'with overwriteFriendlyName=true, default friendlyName should be written to new store');
end;

procedure TTestPkcs12Store.TestFriendlyName_OverwriteFalse_AddedFriendlyName_Persisted;
var
  LStore1, LStore2: IPkcs12Store;
  LBytes: TBytes;
  LAlias1, LAlias2: String;
begin
  LStore1 := BuildPkcs12Store(False);
  LoadStoreFromBytes(LStore1, FFriendlyNameStore, FFriendlyNamePassword);
  LAlias1 := GetFirst(LStore1.Aliases);
  LStore1.SetFriendlyName(LAlias1, 'my_custom_friendly_name');
  LStore2 := BuildPkcs12Store;
  LBytes := SaveStoreToBytes(LStore1, FFriendlyNamePassword);
  LoadStoreFromBytes(LStore2, LBytes, FFriendlyNamePassword);
  LAlias2 := GetFirst(LStore2.Aliases);
  Check(LAlias2 = 'my_custom_friendly_name',
    'with overwriteFriendlyName=false, added friendlyName should be written to new store');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestPkcs12Store);
{$ELSE}
  RegisterTest(TTestPkcs12Store.Suite);
{$ENDIF FPC}

end.
