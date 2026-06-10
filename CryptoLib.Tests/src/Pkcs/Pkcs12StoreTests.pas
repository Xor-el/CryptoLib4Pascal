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
  ClpPrivateKeyInfoFactory,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpIX509Certificate,
  ClpPkcsAsn1Objects,
  ClpNistObjectIdentifiers,
  ClpAsn1Comparers,
  TypInfo,
  ClpDateTimeHelper,
  CertTestUtilities,
  CryptoTestKeys,
  ClpEncoders,
  CryptoLibTestBase,
  PkcsVectors;

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
    FRawKeyBagStore: TBytes;

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
    function CreateKeyBagPfx(const ASafeBag: ISafeBag): TBytes;
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
    procedure TestPkcs12Store_MissingContentInfoContent;
    procedure TestPkcs12Store_NegativeIterations;
    procedure TestRawKeyBagNoAttributes;
    procedure TestRawKeyBagStore;
    procedure TestWrongPassword;
  end;

implementation

{ TTestPkcs12Store }

procedure TTestPkcs12Store.SetUp;
begin
  inherited SetUp;
  FPasswd := StringToCharArray(TPkcs12StoreVectors.GetPassword('MainKeyAndChain'));
  FNoFriendlyPassword := StringToCharArray(TPkcs12StoreVectors.GetPassword('NoFriendly'));
  FStoragePassword := StringToCharArray(TPkcs12StoreVectors.GetPassword('StorageIssue'));
  FHmacSha384TestPassword := StringToCharArray(TPkcs12StoreVectors.GetPassword('HmacSha384'));
  FFriendlyNamePassword := StringToCharArray(TPkcs12StoreVectors.GetPassword('FriendlyName'));
  FRandom := TSecureRandom.Create();

  FCertsOnly := TPkcs12StoreVectors.LoadStoreBytes('CertsOnly');
  FRepeatedLocalKeyIdPfx := TPkcs12StoreVectors.LoadStoreBytes('RepeatedLocalKeyId');
  FHmacSha384Test := TPkcs12StoreVectors.LoadStoreBytes('HmacSha384');
  FFriendlyNameStore := TPkcs12StoreVectors.LoadStoreBytes('FriendlyName');
  FPkcs12 := TPkcs12StoreVectors.LoadStoreBytes('MainKeyAndChain');
  FCertUTF := TPkcs12StoreVectors.LoadStoreBytes('CertUtf');
  FPkcs12NoFriendly := TPkcs12StoreVectors.LoadStoreBytes('NoFriendly');
  FPkcs12StorageIssue := TPkcs12StoreVectors.LoadStoreBytes('StorageIssue');
  FPkcs12NoPass := TPkcs12StoreVectors.LoadStoreBytes('NoPass');
  FSentrixHard := TPkcs12StoreVectors.LoadStoreBytes('SentrixHard');
  FSentrixSoft := TPkcs12StoreVectors.LoadStoreBytes('SentrixSoft');
  FSentrix1 := TPkcs12StoreVectors.LoadStoreBytes('Sentrix1');
  FSentrix2 := TPkcs12StoreVectors.LoadStoreBytes('Sentrix2');
  FSentrix3 := TPkcs12StoreVectors.LoadStoreBytes('Sentrix3');
  FRawKeyBagStore := TPkcs12StoreVectors.LoadStoreBytes('RawKeyBagStore');
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

function TTestPkcs12Store.CreateKeyBagPfx(const ASafeBag: ISafeBag): TBytes;
var
  LDataInfo, LMainInfo: IPkcsContentInfo;
  LAuthSafe: IAuthenticatedSafe;
  LCInfos: TCryptoLibGenericArray<IPkcsContentInfo>;
begin
  LDataInfo := TPkcsContentInfo.Create(TPkcsObjectIdentifiers.Data,
    TDerOctetString.Create((TDerSequence.Create(ASafeBag) as IDerSequence).GetEncoded()) as IDerOctetString);
  SetLength(LCInfos, 1);
  LCInfos[0] := LDataInfo;
  LAuthSafe := TAuthenticatedSafe.Create(LCInfos);
  LMainInfo := TPkcsContentInfo.Create(TPkcsObjectIdentifiers.Data,
    TDerOctetString.Create(LAuthSafe.GetEncoded()) as IDerOctetString);
  Result := (TPfx.Create(LMainInfo, nil) as IPfx).GetEncoded();
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
    LUtc := Now.ToUniversalTime();
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
  LPrivKeyParams: IRsaPrivateCrtKeyParameters;
  LLocalKeyId: TBytes;
  LPrivKeyAttrs: TDictionary<IDerObjectIdentifier, IAsn1Encodable>;
begin
  LPrivKeyParams := TCryptoTestKeys.GetWriterRsaCrtPrivate;

  LLocalKeyId := TBytes.Create(4, 2, 4, 6, 13);
  LPrivKeyAttrs := TDictionary<IDerObjectIdentifier, IAsn1Encodable>.Create(TAsn1Comparers.OidEqualityComparer);
  LPrivKeyAttrs.Add(TPkcsObjectIdentifiers.Pkcs9AtLocalKeyID, TDerOctetString.Create(LLocalKeyId) as IDerOctetString);
  APrivKey := TAsymmetricKeyEntry.Create(LPrivKeyParams as IAsymmetricKeyParameter, LPrivKeyAttrs);

  SetLength(AChain, 1);
  AChain[0] := CreateCert(TCryptoTestKeys.GetWriterRsaCrtPublic as IAsymmetricKeyParameter,
    LPrivKeyParams as IAsymmetricKeyParameter,
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
  else if not LAttr.ToAsn1Object().Equals((TDerBmpString.Create('key') as IDerBmpString).ToAsn1Object()) then
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
  LCertificateAlias, LKeystorePassword: String;
  LKp1, LKp2: IAsymmetricCipherKeyPair;
  LRootCert, LOriginalCert: IX509Certificate;
  LFirstTrustStore, LFirstTrustStoreReadAgain, LSecondTrustStore: IPkcs12Store;
  LBytes: TBytes;
  LCertRead: IX509CertificateEntry;
  LPasswd: TCryptoLibCharArray;
begin
  LCertificateAlias := 'myAlias';
  LKeystorePassword := 'myPassword';
  LPasswd := StringToCharArray(LKeystorePassword);

  LKp1 := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LKp2 := TCertTestUtilities.GenerateRsaKeyPair(1024);

  LRootCert := TCertTestUtilities.GenerateRootCert(LKp1, TX509Name.Create('CN=KP1 ROOT') as IX509Name);
  LOriginalCert := TCertTestUtilities.GenerateEndEntityCert(LKp2.Public, TX509Name.Create('CN=KP3 EE') as IX509Name,
    TKeyPurposeId.IdKpCapwapAc, TKeyPurposeId.IdKpCapwapWtp, LKp1.Private, LRootCert);

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

procedure TTestPkcs12Store.TestPkcs12Store_NegativeIterations;
var
  LPayload: TBytes;
  LStore: IPkcs12Store;
  LStream: TMemoryStream;
  LEmptyPass: TCryptoLibCharArray;
begin
  LPayload := THexEncoder.Decode(
    '3049020103301106092a864879f70d010706a0040402300030313021300906052b0e03021a050004140000010000000000000000000000000000000000040800000000000000000202f300');
  LStore := BuildPkcs12Store;
  LEmptyPass := nil;
  LStream := TMemoryStream.Create;
  try
    if System.Length(LPayload) > 0 then
      LStream.WriteBuffer(LPayload[0], System.Length(LPayload));
    LStream.Position := 0;
    try
      LStore.Load(LStream, LEmptyPass);
      Fail('expected EInvalidOperationCryptoLibException');
    except
      on E: EInvalidOperationCryptoLibException do
        ;
    else
      raise;
    end;
  finally
    LStream.Free;
  end;
end;

procedure TTestPkcs12Store.TestPkcs12Store_MissingContentInfoContent;
var
  LPayload: TBytes;
  LStore: IPkcs12Store;
  LStream: TMemoryStream;
  LEmptyPass: TCryptoLibCharArray;
begin
  LPayload := THexEncoder.Decode(
    '30490201033011060f2a864886f70d010701a0040402300030313021300906052b0e03021a050004140000000003000000000000000000020000000000040c000000000000000002020800');
  LStore := BuildPkcs12Store;
  LEmptyPass := nil;
  LStream := TMemoryStream.Create;
  try
    if System.Length(LPayload) > 0 then
      LStream.WriteBuffer(LPayload[0], System.Length(LPayload));
    LStream.Position := 0;
    try
      LStore.Load(LStream, LEmptyPass);
      Fail('expected EAsn1ParsingCryptoLibException');
    except
      on E: EAsn1ParsingCryptoLibException do
        ;
    else
      raise;
    end;
  finally
    LStream.Free;
  end;
end;

procedure TTestPkcs12Store.TestRawKeyBagNoAttributes;
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKeyPair: IAsymmetricCipherKeyPair;
  LPrivateKeyInfo: IPrivateKeyInfo;
  LNoAttrBag, LFriendlyBag: ISafeBag;
  LKeyBagPfxA, LKeyBagPfxB: TBytes;
  LStoreA, LStoreB: IPkcs12Store;
  LEmptyPass: TCryptoLibCharArray;
  LAlias: String;
  LFriendlyName: IAsn1Encodable;
begin
  // RFC 7292 sec. 4.2.1 keyBag (unencrypted PrivateKeyInfo) may carry no bagAttributes, and the localKeyId
  // attribute is optional even when bagAttributes are present. Ensure correct handling.
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('RSA');
  LKpg.Init(TRsaKeyGenerationParameters.Create(TBigInteger.ValueOf(Int64($10001)), FRandom, 1024, 25) as IRsaKeyGenerationParameters);
  LKeyPair := LKpg.GenerateKeyPair;
  LPrivateKeyInfo := TPrivateKeyInfoFactory.CreatePrivateKeyInfo(LKeyPair.Private);

  // Case A: keyBag with no bagAttributes at all.
  LNoAttrBag := TSafeBag.Create(TPkcsObjectIdentifiers.KeyBag, LPrivateKeyInfo.ToAsn1Object());
  LKeyBagPfxA := CreateKeyBagPfx(LNoAttrBag);

  LStoreA := BuildPkcs12Store;
  LEmptyPass := nil;
  LoadStoreFromBytes(LStoreA, LKeyBagPfxA, LEmptyPass);

  LAlias := GetFirst(LStoreA.Aliases);
  Check(LStoreA.IsKeyEntry(LAlias), 'no-attributes keyBag entry not a key');
  Check(LStoreA.GetKey(LAlias) <> nil, 'no-attributes keyBag key not recoverable');

  // Case B: keyBag carrying a friendlyName but no localKeyId attribute.
  LFriendlyName := TDerSequence.Create(TPkcsObjectIdentifiers.Pkcs9AtFriendlyName,
    TDerSet.Create(TDerBmpString.Create('rawKeyBag') as IDerBmpString) as IDerSet);
  LFriendlyBag := TSafeBag.Create(TPkcsObjectIdentifiers.KeyBag, LPrivateKeyInfo.ToAsn1Object(),
    TDerSet.Create(LFriendlyName) as IDerSet);
  LKeyBagPfxB := CreateKeyBagPfx(LFriendlyBag);

  LStoreB := BuildPkcs12Store;
  LoadStoreFromBytes(LStoreB, LKeyBagPfxB, LEmptyPass);
  Check(LStoreB.IsKeyEntry('rawKeyBag'), 'friendlyName keyBag not stored under its alias');
  Check(LStoreB.GetKey('rawKeyBag') <> nil, 'friendlyName keyBag key not recoverable');
end;

procedure TTestPkcs12Store.TestRawKeyBagStore;
var
  LStore: IPkcs12Store;
  LEmptyPass: TCryptoLibCharArray;
begin
  LStore := BuildPkcs12Store;
  LEmptyPass := nil;
  LoadStoreFromBytes(LStore, FRawKeyBagStore, LEmptyPass);
  Check(LStore.IsKeyEntry('ONVIF_Test_Alias'), 'expected ONVIF_Test_Alias key entry');
end;

procedure TTestPkcs12Store.TestWrongPassword;
var
  LStore: IPkcs12Store;
begin
  LStore := BuildPkcs12Store;
  try
    LoadStoreFromBytes(LStore, FPkcs12, StringToCharArray('Goodbye World!'));
    Fail('expected EIOCryptoLibException');
  except
    on E: EIOCryptoLibException do
      ;
  else
    raise;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestPkcs12Store);
{$ELSE}
  RegisterTest(TTestPkcs12Store.Suite);
{$ENDIF FPC}

end.
