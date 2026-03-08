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
      ACertAlgorithm, ACertPrfAlgorithm, AKeyAlgorithm, AKeyPrfAlgorithm, AMacDigestAlgorithm: IDerObjectIdentifier);
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

  FFriendlyNameStore := DecodeBase64('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' +
    'lF431xs5rOtGUQtKE/3QkvsCAgQAAAA=');

  FPkcs12 := DecodeBase64('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' +
    'BBSCGvUUlsnp0FYUXFZFU/8M8LBEiAICBAAAAA==');

  FCertUTF := DecodeBase64('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');

  FPkcs12NoFriendly := DecodeBase64('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');

  FPkcs12StorageIssue := DecodeBase64('MIACAQMwgAYJKoZIhvcNAQcBoIAEghS1MIAwgAYJKoZIhvcNAQcBoIAEggQoMIIEJDCCBCAGCyqGSIb3DQEMCgECoIIC7TCCAukw' +
    'YwYJKoZIhvcNAQUNMFYwNQYJKoZIhvcNAQUMMCgEFAJglCKyu+0mIFh5Py+dvZH1hYWYAgIEADAMBggqhkiG9w0CCQUAMB0GCWCG' +
    'SAFlAwQBKgQQY2aANoV7EaSvlvIGz/5pcQSCAoBQqFeg51PS9soUHyuXLUCndbQ5xQAoqPCpx45D6jHC3PAzfX0o3XuBkEL5k47P' +
    'u5y9vPB8pXBH4395BZMasgeu0ETICSsye6Dw0AzyCe2aa4LHYLjzdLr1lxr3f9o70vk/Q6D6T39J8LYdM1LI4aDD05PHg3ro1miR' +
    'ai6ruftZ3+j0uWYKt4QsPNga6HjCyVvYYWum3MSg65E5BqZ5Ev+XBJC1rYwzFZZlD/QgXHnjc9hdt54Kai1BBwTp9aK2NHB3fsDh' +
    'fxjbFF2UmQk/pvvmkInak+bQ5Vv3Y1hzMeUUmEIdIduVLPmmV5trsClE7TWkqsnBvUCL43u9GD1kbE+HKHUw7oWSlZhiO/9mNfVx' +
    'cTH/EqmddeuFIHQeXTXTRfyJtNIJYWNpu+vQcbwb/urh76RwO5jUMgkQQHXaubrXYM7FZvp6/V4TQIaVavBfCjRjDYeiyUWjh9Et' +
    'rCV3ANmtTt/+UVWDBRLNa8JZIy3gnJ7pNf81+3loJ8OEPEn0tKXkOo742qBNdlWI2Y97xZrttI+YWcAJM72OtMqU54LlrNNo+37b' +
    'cFDaFWKKpjaWyPQAs0ZHqdk9cxlfinwisg4+auLXSlRWVPiGhxptHh8yBTjie6u37xc1w0GW+6ARSa9NcObIgS2+pr/a7Yzt4jYG' +
    'tKx/viSEMZfnfZf7RzH2EhTct5gAzrEI6r9JoxwWe5v/vK53v60nTR6S/KzcJ3sYTfpePHMqnDLKaOKUIzOHfGYDEUl7zEXCqTC6' +
    'hf0VaK7Z1Vkbbb37Ewn9ZhDOoOJlU9QgrbDkmtFykVaxt5/DE9d6pY0gqYehcfBJ0R7FfY8ju3qhXiDRH1DE3HeDyrneMYIBHjAT' +
    'BgkqhkiG9w0BCRUxBgQEAQAAADBpBgkrBgEEAYI3EQExXB5aAE0AaQBjAHIAbwBzAG8AZgB0ACAAUgBTAEEAIABTAEMAaABhAG4A' +
    'bgBlAGwAIABDAHIAeQBwAHQAbwBnAHIAYQBwAGgAaQBjACAAUAByAG8AdgBpAGQAZQByMIGbBgkqhkiG9w0BCRQxgY0egYoANwBk' +
    'AGUAZgA1AGIANAAzADYAYwBhAGIAZAAwADAAMgBkAGQAMgA5ADAAMwBiADEANgA4ADYAYwA3ADkANAA4AF8ANAA2AGYAMgA2AGYA' +
    'ZAA0AC0AOAAxADIAZAAtADQAZQBmAGIALQA4ADAAOAA4AC0ANAA1AGEAYgA5ADEAOQAxADAANwBjAGMAAAAAMIAGCSqGSIb3DQEH' +
    'BqCAMIACAQAwgAYJKoZIhvcNAQcBMGMGCSqGSIb3DQEFDTBWMDUGCSqGSIb3DQEFDDAoBBQ6ugG1vWe5gXq9bq7Fr12VuN+DsQIC' +
    'BAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEAuAoGMjAefi02oJnHM4Zs2Agg/gpSHsfEk21axiZdwJM4J3i81gPLthEfO2' +
    'rHNoB6i7B6pmTIpZozwLAZ6VaQORi+BqNidx5jwzd4yJKoaeYThO5ppnPeGUjv5H5yaSLJrwsm2KF6PneWeNqtngjjLlrwXEAUGT' +
    '5c89hK0CzXTVw1+ELKntdm9dqs8SzA/4HNP5UGKZgsh8931PASWDNZxhlDG0ylM+PiXdxCwF+us4ZCgjbN+xEifBp4o/63m2vLz2' +
    'yA5jLEGCP6rFYjxgD1QToYpB32k++9RoYDBV0TXaHw/mSXNHc8WSOOBQe/QqTHQMLKu+R+UanoFeT8alF1CPbCsSWC/bWTqHZTrz' +
    'G9oNhiTgRK3Mc+4NtLGhtm5WmS0MAxr4m8u7srOkXbcwxpIddfw0qvYg9zkjhUs+aTXBBrkmWXIzd+iuGcQW7YI9tZXOQXQZEMhg' +
    '6MjOJlY+dIDyTuxFbdsTIt+tCZlKqx/7Y9rITqKzDPxe+9U1x9VtAqFxEHE9uOok//nWmg2URpU8EnOEyT4JqQKntefcKi/FPid/' +
    'CVsEYpFFhI2Bjk1K/yev8C6pSvCwC8LKXBm5x/Y1+xfrnmaFl/2cFkge1wGyYresouScuv2O1t0b4lEY3Cy2erg2wW935QhAHkTN' +
    'H6fADELH+a7CSzjm6ru+x0lpFGFMQ9AmBeKLPWJ+BTP18ywOKmzO4CURTXY8SXyMwJAVKShLN9bU4i1JF+aObYgS7fEEhBG9LVEh' +
    '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');

  FPkcs12NoPass := DecodeBase64('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');

  FSentrixHard := DecodeBase64('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');

  FSentrixSoft := DecodeBase64('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');

  FSentrix1 := DecodeBase64('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');

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
    if TPkcsObjectIdentifiers.IdPbeS2.Equals(AEncAlgID.Algorithm) then
    begin
      // PBES2 — check the nested encryption scheme OID
      LPbeS2 := TPbeS2Parameters.GetInstance(AEncAlgID.Parameters);
      if not LPbeS2.EncryptionScheme.Algorithm.Equals(AExpectedEncAlgorithm) then
        Fail(AType + ' key encryption algorithm wrong');
    end
    else
    begin
      // Legacy — check top-level OID directly
      if not AExpectedEncAlgorithm.Equals(AEncAlgID.Algorithm) then
        Fail(AType + ' legacy key encryption algorithm wrong');
    end;
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
  ACertAlgorithm, ACertPrfAlgorithm, AKeyAlgorithm, AKeyPrfAlgorithm, AMacDigestAlgorithm: IDerObjectIdentifier);
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
  LBuilder.SetMacDigestAlgorithm(AMacDigestAlgorithm);
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
    TNistObjectIdentifiers.IdAes256Cbc, nil, nil);
  BasicStoreTest(LPrivKey, LChain,
    TNistObjectIdentifiers.IdAes256Cbc, nil,
    nil, nil, nil);
  BasicStoreTest(LPrivKey, LChain,
    TNistObjectIdentifiers.IdAes128Cbc, nil,
    TNistObjectIdentifiers.IdAes128Cbc, nil, nil);
  BasicStoreTest(LPrivKey, LChain,
    TNistObjectIdentifiers.IdAes256Cbc, nil,
    TNistObjectIdentifiers.IdAes256Cbc, nil, nil);
  BasicStoreTest(LPrivKey, LChain, nil, nil,
    TNistObjectIdentifiers.IdAes128Cbc, TPkcsObjectIdentifiers.IdHmacWithSha256, nil);
  BasicStoreTest(LPrivKey, LChain,
    TNistObjectIdentifiers.IdAes128Cbc, TPkcsObjectIdentifiers.IdHmacWithSha256,
    nil, nil, nil);
  BasicStoreTest(LPrivKey, LChain,
   TNistObjectIdentifiers.IdAes256Cbc, nil,
    TNistObjectIdentifiers.IdAes128Cbc, TPkcsObjectIdentifiers.IdHmacWithSha256, nil);
  BasicStoreTest(LPrivKey, LChain,
    TNistObjectIdentifiers.IdAes128Cbc, TPkcsObjectIdentifiers.IdHmacWithSha256,
    TNistObjectIdentifiers.IdAes256Cbc, nil, nil);
  BasicStoreTest(LPrivKey, LChain,
    TNistObjectIdentifiers.IdAes256Cbc, TPkcsObjectIdentifiers.IdHmacWithSha512,
    TNistObjectIdentifiers.IdAes256Cbc, TPkcsObjectIdentifiers.IdHmacWithSha512, TNistObjectIdentifiers.IdSha256);
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
