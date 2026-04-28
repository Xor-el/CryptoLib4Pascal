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

unit ClpPkcs12Store;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  Rtti,
  TypInfo,
  Generics.Collections,
  Generics.Defaults,
  ClpIMac,
  ClpPkcsRsaAsn1Objects,
  ClpDigestUtilities,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpIPkcsAsn1Objects,
  ClpPkcsAsn1Objects,
  ClpPkcsObjectIdentifiers,
  ClpOiwObjectIdentifiers,
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpX509ExtensionUtilities,
  ClpICipherParameters,
  ClpIAsymmetricKeyParameter,
  ClpX509Certificate,
  ClpIX509Certificate,
  ClpX509CertificateEntry,
  ClpIX509CertificateEntry,
  ClpAsymmetricKeyEntry,
  ClpIAsymmetricKeyEntry,
  ClpPrivateKeyFactory,
  ClpPrivateKeyInfoFactory,
  ClpEncryptedPrivateKeyInfoFactory,
  ClpIPkcs12Entry,
  ClpAsn1Comparers,
  ClpCryptoLibComparers,
  ClpCollectionUtilities,
  ClpArrayUtilities,
  ClpCryptoLibTypes,
  ClpEncoders,
  ClpPbeUtilities,
  ClpValueHelper,
  ClpMacUtilities,
  ClpCipherUtilities,
  ClpIBufferedCipher,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpDefaultDigestAlgorithmFinder,
  ClpIDigestAlgorithmFinder,
  ClpMiscObjectIdentifiers,
  ClpIPkcs12Store;

resourcestring
  SInputNil = 'input';
  SMacInvalid = 'PKCS12 key store MAC invalid - wrong password or corrupted file.';
  SPasswordNotNeeded = 'password supplied for keystore that does not require one';
  SUnsupportedCertType = 'Unsupported certificate type: %s';
  SAliasNil = 'alias';
  SCertEntryNil = 'certEntry';
  SKeyEntryNil = 'keyEntry';
  SKeyEntryWithName = 'There is a key entry with the name %s.';
  SNoChainForPrivateKey = 'No certificate chain for private key';
  SUnknownEncryption = 'Unknown encryption algorithm: %s';
  SAttemptAddExistingAttr = 'attempt to add existing attribute with different value';
  SStreamNil = 'stream';
  SRandomNil = 'random';

type
  /// <summary>
  /// PKCS#12 store for keys and certificates. Load/Save PFX (PKCS#12) and manage aliases.
  /// </summary>
  TPkcs12Store = class sealed(TInterfacedObject, IPkcs12Store)
  private
    type
      /// <summary>
      /// PKCS#12 CertID value type: identifies a certificate by its LocalKeyID (octet string) value.
      /// Used as key in chain cert storage. Equals and GetHashCode are value-based (byte array content).
      /// </summary>
      TCertID = record
      private
        FId: TCryptoLibByteArray;
        function GetOctets(const AOctetString: IAsn1OctetString): TCryptoLibByteArray;
      public
        constructor Create(const AId: TCryptoLibByteArray); overload;
        constructor Create(const AOctetString: IAsn1OctetString); overload;
        constructor Create(const ACertEntry: IX509CertificateEntry); overload;
        constructor Create(const ACert: IX509Certificate); overload;
        function Equals(const AOther: TCertID): Boolean;
        function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF}
        property Id: TCryptoLibByteArray read FId;
      end;
  strict private
    class var
      FIgnoreUselessPassword: Boolean;
      FCertIDEqualityComparer: IEqualityComparer<TCertID>;
      FCertIDComparer: IComparer<TCertID>;
    class constructor Create;
  var
    FKeys: TDictionary<String, IAsymmetricKeyEntry>;
    FKeysOrder: TList<String>;
    FLocalIDs: TDictionary<String, String>;
    FCerts: TDictionary<String, IX509CertificateEntry>;
    FCertsOrder: TList<String>;
    FChainCerts: TDictionary<TCertID, IX509CertificateEntry>;
    FChainCertsOrder: TList<TCertID>;
    FKeyCerts: TDictionary<String, IX509CertificateEntry>;
    FCertAlgorithm: IDerObjectIdentifier;
    FCertPrfAlgorithm: IDerObjectIdentifier;
    FKeyAlgorithm: IDerObjectIdentifier;
    FKeyPrfAlgorithm: IDerObjectIdentifier;
    FMacDigestAlgorithm: IDerObjectIdentifier;
    FUseDerEncoding: Boolean;
    FReverseCertificates: Boolean;
    FOverwriteFriendlyName: Boolean;
    FEnableOracleTrustedKeyUsage: Boolean;
    FKeyIterations: Int32;
    FCertIterations: Int32;
    FMacIterations: Int32;
    FKeySaltSize: Int32;
    FCertSaltSize: Int32;
    FMacSaltSize: Int32;
    FUnmarkedKeyEntry: IAsymmetricKeyEntry;
  strict private
    procedure ClearKeys;
    procedure ClearCerts;
    procedure MapEntry<TKey, TValue>(const ADict: TDictionary<TKey, TValue>; const AOrder: TList<TKey>;
      const AKey: TKey; const AEntry: TValue; const AComparer: IEqualityComparer<TKey>);
    function RemoveEntry<TKey, TValue>(const ADict: TDictionary<TKey, TValue>; const AOrder: TList<TKey>;
      const AKey: TKey; const AComparer: IEqualityComparer<TKey>): Boolean; overload;
    function RemoveEntry<TKey, TValue>(const ADict: TDictionary<TKey, TValue>; const AOrder: TList<TKey>;
      const AKey: TKey; out AEntry: TValue; const AComparer: IEqualityComparer<TKey>): Boolean; overload;
    procedure MapKey(const AKey: String; const AEntry: IAsymmetricKeyEntry);
    procedure MapCert(const AKey: String; const AEntry: IX509CertificateEntry);
    procedure MapChainCert(const AKey: TCertID; const AEntry: IX509CertificateEntry);
    function RemoveKey(const AKey: String): Boolean;
    function RemoveCert(const AKey: String; out AEntry: IX509CertificateEntry): Boolean;
    function RemoveChainCert(const AKey: TCertID): Boolean;
    procedure RemoveOrdering<T>(const AOrder: TList<T>; const AKey: T; const AComparer: IEqualityComparer<T>);
    procedure ReplaceOrdering<T>(const AOrder: TList<T>; const AOldKey, ANewKey: T; const AComparer: IEqualityComparer<T>);
    class function CreateLocalKeyID(const ACertificate: IX509Certificate): IAsn1OctetString; static;
    class function CryptPbeData(AForEncryption: Boolean; const AAlgID: IAlgorithmIdentifier;
      const APassword: TCryptoLibCharArray; AWrongPkcs12Zero: Boolean;
      const AData: TCryptoLibByteArray): TCryptoLibByteArray; static;
    class function VerifyPbeMac(const AMacData: IMacData; const APassword: TCryptoLibCharArray;
      AWrongPkcs12Zero: Boolean; const AData: TCryptoLibByteArray): Boolean; static;
    procedure DeleteCertsEntry(const AAlias: String);
    procedure DeleteKeysEntry(const AAlias: String);
    function CreateEntryFriendlyName(const AAlias: String; const AEntry: IPkcs12Entry): IAsn1Sequence;
    procedure AddLocalKeyID(const V: IAsn1EncodableVector; const ACertEntry: IX509CertificateEntry); overload;
    procedure AddLocalKeyID(const V: IAsn1EncodableVector; const AC: IX509Certificate); overload;
    function CreateCertBag(const AC: IX509Certificate): ICertBag;
  strict protected
    function GetCount: Int32;
    function GetAliases: TCryptoLibStringArray;

    procedure LoadKeyBag(const APrivKeyInfo: IPrivateKeyInfo; const ABagAttributes: IAsn1Set); virtual;
    procedure LoadPkcs8ShroudedKeyBag(const AEncPrivKeyInfo: IEncryptedPrivateKeyInfo;
      const ABagAttributes: IAsn1Set; const APassword: TCryptoLibCharArray; AWrongPkcs12Zero: Boolean); virtual;
  public
    const
      DefaultIterations = 1024;
      DefaultSaltSize = 20;
    /// <summary>When True, ignore useless password.</summary>
    class property IgnoreUselessPassword: Boolean read FIgnoreUselessPassword write FIgnoreUselessPassword;
    /// <summary>Calculate PBE MAC for PKCS#12 (exposed for Pkcs12Utilities).</summary>
    class function CalculatePbeMac(const AMacDigestAlgorithm: IAlgorithmIdentifier;
      const ASalt: TCryptoLibByteArray; AIterations: Int32;
      const APassword: TCryptoLibCharArray; AWrongPkcs12Zero: Boolean;
      const AData: TCryptoLibByteArray): TCryptoLibByteArray; static;
    /// <summary>
    /// Create store with algorithm and behaviour flags only; iterations and salt sizes use defaults.
    /// </summary>
    constructor Create(const ACertAlgorithm, ACertPrfAlgorithm, AKeyAlgorithm, AKeyPrfAlgorithm, AMacDigestAlgorithm: IDerObjectIdentifier;
      AUseDerEncoding: Boolean; AReverseCertificates: Boolean; AOverwriteFriendlyName: Boolean;
      AEnableOracleTrustedKeyUsage: Boolean); overload;
    /// <summary>
    /// Create store with all parameters; iteration and salt params default when omitted.
    /// </summary>
    constructor Create(const ACertAlgorithm, ACertPrfAlgorithm, AKeyAlgorithm, AKeyPrfAlgorithm, AMacDigestAlgorithm: IDerObjectIdentifier;
      AUseDerEncoding: Boolean; AReverseCertificates: Boolean; AOverwriteFriendlyName: Boolean;
      AEnableOracleTrustedKeyUsage: Boolean;
      AKeyIterations: Int32; ACertIterations: Int32;
      AMacIterations: Int32; AKeySaltSize: Int32;
      ACertSaltSize: Int32; AMacSaltSize: Int32); overload;
    destructor Destroy; override;
    procedure Load(const AInput: TStream; const APassword: TCryptoLibCharArray);
    function GetKey(const AAlias: String): IAsymmetricKeyEntry;
    function IsCertificateEntry(const AAlias: String): Boolean;
    function IsKeyEntry(const AAlias: String): Boolean;
    function ContainsAlias(const AAlias: String): Boolean;
    function GetCertificate(const AAlias: String): IX509CertificateEntry;
    function GetCertificateAlias(const ACert: IX509Certificate): String;
    function GetCertificateChain(const AAlias: String): TCryptoLibGenericArray<IX509CertificateEntry>;
    procedure SetCertificateEntry(const AAlias: String; const ACertEntry: IX509CertificateEntry);
    procedure SetFriendlyName(const AAlias: String; const ANewFriendlyName: String);
    procedure SetKeyEntry(const AAlias: String; const AKeyEntry: IAsymmetricKeyEntry;
      const AChain: TCryptoLibGenericArray<IX509CertificateEntry>);
    procedure DeleteEntry(const AAlias: String);
    function IsEntryOfType(const AAlias: String; AEntryType: PTypeInfo): Boolean;
    procedure Save(const AStream: TStream; const APassword: TCryptoLibCharArray; const ARandom: ISecureRandom);
    property Count: Int32 read GetCount;
    property Aliases: TCryptoLibStringArray read GetAliases;
  end;

implementation

type
  TCertIDEqualityComparer = class(TInterfacedObject, IEqualityComparer<TPkcs12Store.TCertID>)
  public
{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
    function Equals(constref ALeft, ARight: TPkcs12Store.TCertID): Boolean; reintroduce;
    function GetHashCode(constref AValue: TPkcs12Store.TCertID): UInt32; reintroduce;
{$ELSE}
    function Equals(const ALeft, ARight: TPkcs12Store.TCertID): Boolean; reintroduce;
    function GetHashCode(const AValue: TPkcs12Store.TCertID): {$IFDEF DELPHI}Int32; {$ELSE}UInt32; {$ENDIF} reintroduce;
{$ENDIF}
  end;

  TCertIDComparer = class(TInterfacedObject, IComparer<TPkcs12Store.TCertID>)
  public
{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
    function Compare(constref ALeft, ARight: TPkcs12Store.TCertID): Integer;
{$ELSE}
    function Compare(const ALeft, ARight: TPkcs12Store.TCertID): Integer;
{$ENDIF}
  end;

{ TPkcs12Store.TCertID }

constructor TPkcs12Store.TCertID.Create(const AId: TCryptoLibByteArray);
begin
  FId := AId;
end;

function TPkcs12Store.TCertID.GetOctets(const AOctetString: IAsn1OctetString): TCryptoLibByteArray;
begin
  if AOctetString = nil then
    Result := nil
  else
    Result := AOctetString.GetOctets();
end;

constructor TPkcs12Store.TCertID.Create(const AOctetString: IAsn1OctetString);
begin
  FId := GetOctets(AOctetString);
end;

constructor TPkcs12Store.TCertID.Create(const ACertEntry: IX509CertificateEntry);
begin
  FId := GetOctets(TPkcs12Store.CreateLocalKeyID(ACertEntry.Certificate));
end;

constructor TPkcs12Store.TCertID.Create(const ACert: IX509Certificate);
begin
  FId := GetOctets(TPkcs12Store.CreateLocalKeyID(ACert));
end;

function TPkcs12Store.TCertID.Equals(const AOther: TCertID): Boolean;
begin
  Result := TArrayUtilities.AreEqual(FId, AOther.Id);
end;

function TPkcs12Store.TCertID.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF}
begin
  Result := TArrayUtilities.GetArrayHashCode(FId);
end;

{ TCertIDEqualityComparer }

{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
function TCertIDEqualityComparer.Equals(constref ALeft, ARight: TPkcs12Store.TCertID): Boolean;
{$ELSE}
function TCertIDEqualityComparer.Equals(const ALeft, ARight: TPkcs12Store.TCertID): Boolean;
{$ENDIF}
begin
  Result := ALeft.Equals(ARight);
end;

{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
function TCertIDEqualityComparer.GetHashCode(constref AValue: TPkcs12Store.TCertID): UInt32;
{$ELSE}
function TCertIDEqualityComparer.GetHashCode(const AValue: TPkcs12Store.TCertID): {$IFDEF DELPHI}Int32; {$ELSE}UInt32; {$ENDIF}
{$ENDIF}
begin
  Result := AValue.GetHashCode;
end;

{ TCertIDComparer }

{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
function TCertIDComparer.Compare(constref ALeft, ARight: TPkcs12Store.TCertID): Integer;
{$ELSE}
function TCertIDComparer.Compare(const ALeft, ARight: TPkcs12Store.TCertID): Integer;
{$ENDIF}
var
  LIdL, LIdR: TCryptoLibByteArray;
  LLen, LI: Int32;
begin
  LIdL := ALeft.Id;
  LIdR := ARight.Id;
  if LIdL = LIdR then
  begin
    Result := 0;
    Exit;
  end;
  if LIdL = nil then
  begin
    Result := -1;
    Exit;
  end;
  if LIdR = nil then
  begin
    Result := 1;
    Exit;
  end;
  LLen := System.Length(LIdL);
  if LLen <> System.Length(LIdR) then
  begin
    if LLen < System.Length(LIdR) then
      Result := -1
    else
      Result := 1;
    Exit;
  end;
  for LI := 0 to LLen - 1 do
  begin
    if LIdL[LI] <> LIdR[LI] then
    begin
      if LIdL[LI] < LIdR[LI] then
        Result := -1
      else
        Result := 1;
      Exit;
    end;
  end;
  Result := 0;
end;

{ TPkcs12Store }

class constructor TPkcs12Store.Create;
begin
  FIgnoreUselessPassword := False;
  FCertIDEqualityComparer := TCertIDEqualityComparer.Create;
  FCertIDComparer := TCertIDComparer.Create;
end;

constructor TPkcs12Store.Create(const ACertAlgorithm, ACertPrfAlgorithm, AKeyAlgorithm, AKeyPrfAlgorithm, AMacDigestAlgorithm: IDerObjectIdentifier;
  AUseDerEncoding: Boolean; AReverseCertificates: Boolean; AOverwriteFriendlyName: Boolean;
  AEnableOracleTrustedKeyUsage: Boolean);
begin
  Create(ACertAlgorithm, ACertPrfAlgorithm, AKeyAlgorithm, AKeyPrfAlgorithm, AMacDigestAlgorithm,
    AUseDerEncoding, AReverseCertificates, AOverwriteFriendlyName, AEnableOracleTrustedKeyUsage,
    DefaultIterations, DefaultIterations, DefaultIterations, DefaultSaltSize, DefaultSaltSize, DefaultSaltSize);
end;

constructor TPkcs12Store.Create(const ACertAlgorithm, ACertPrfAlgorithm, AKeyAlgorithm, AKeyPrfAlgorithm, AMacDigestAlgorithm: IDerObjectIdentifier;
  AUseDerEncoding: Boolean; AReverseCertificates: Boolean; AOverwriteFriendlyName: Boolean;
  AEnableOracleTrustedKeyUsage: Boolean;
  AKeyIterations: Int32; ACertIterations: Int32;
  AMacIterations: Int32; AKeySaltSize: Int32;
  ACertSaltSize: Int32; AMacSaltSize: Int32);
begin
  inherited Create;
  FKeys := TDictionary<String, IAsymmetricKeyEntry>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FKeysOrder := TList<String>.Create;
  FLocalIDs := TDictionary<String, String>.Create;
  FCerts := TDictionary<String, IX509CertificateEntry>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FCertsOrder := TList<String>.Create;
  FChainCerts := TDictionary<TCertID, IX509CertificateEntry>.Create(FCertIDEqualityComparer);
  FChainCertsOrder := TList<TCertID>.Create(FCertIDComparer);
  FKeyCerts := TDictionary<String, IX509CertificateEntry>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FCertAlgorithm := ACertAlgorithm;
  FCertPrfAlgorithm := ACertPrfAlgorithm;
  FKeyAlgorithm := AKeyAlgorithm;
  FKeyPrfAlgorithm := AKeyPrfAlgorithm;
  FMacDigestAlgorithm := AMacDigestAlgorithm;
  FUseDerEncoding := AUseDerEncoding;
  FReverseCertificates := AReverseCertificates;
  FOverwriteFriendlyName := AOverwriteFriendlyName;
  FEnableOracleTrustedKeyUsage := AEnableOracleTrustedKeyUsage;
  FKeyIterations := AKeyIterations;
  FCertIterations := ACertIterations;
  FMacIterations := AMacIterations;
  FKeySaltSize := AKeySaltSize;
  FCertSaltSize := ACertSaltSize;
  FMacSaltSize := AMacSaltSize;
end;

destructor TPkcs12Store.Destroy;
begin
  FKeys.Free;
  FKeysOrder.Free;
  FLocalIDs.Free;
  FCerts.Free;
  FCertsOrder.Free;
  FChainCerts.Free;
  FChainCertsOrder.Free;
  FKeyCerts.Free;
  inherited Destroy;
end;

procedure TPkcs12Store.ClearKeys;
begin
  FKeys.Clear;
  FKeysOrder.Clear;
end;

procedure TPkcs12Store.ClearCerts;
begin
  FCerts.Clear;
  FCertsOrder.Clear;
  FChainCerts.Clear;
  FChainCertsOrder.Clear;
  FKeyCerts.Clear;
end;

procedure TPkcs12Store.RemoveOrdering<T>(const AOrder: TList<T>; const AKey: T; const AComparer: IEqualityComparer<T>);
var
  LI: Int32;
begin
  for LI := AOrder.Count - 1 downto 0 do
    if AComparer.Equals(AOrder[LI], AKey) then
    begin
      AOrder.Delete(LI);
      Exit;
    end;
end;

procedure TPkcs12Store.ReplaceOrdering<T>(const AOrder: TList<T>; const AOldKey, ANewKey: T; const AComparer: IEqualityComparer<T>);
var
  LI: Int32;
begin
  for LI := 0 to AOrder.Count - 1 do
    if AComparer.Equals(AOrder[LI], AOldKey) then
    begin
      AOrder[LI] := ANewKey;
      Exit;
    end;
end;

procedure TPkcs12Store.MapEntry<TKey, TValue>(const ADict: TDictionary<TKey, TValue>; const AOrder: TList<TKey>;
  const AKey: TKey; const AEntry: TValue; const AComparer: IEqualityComparer<TKey>);
begin
  if ADict.ContainsKey(AKey) then
    RemoveOrdering<TKey>(AOrder, AKey, AComparer);
  AOrder.Add(AKey);
  ADict.AddOrSetValue(AKey, AEntry);
end;

function TPkcs12Store.RemoveEntry<TKey, TValue>(const ADict: TDictionary<TKey, TValue>; const AOrder: TList<TKey>;
  const AKey: TKey; const AComparer: IEqualityComparer<TKey>): Boolean;
begin
  Result := TCollectionUtilities.Remove<TKey, TValue>(ADict, AKey);
  if Result then
    RemoveOrdering<TKey>(AOrder, AKey, AComparer);
end;

function TPkcs12Store.RemoveEntry<TKey, TValue>(const ADict: TDictionary<TKey, TValue>; const AOrder: TList<TKey>;
  const AKey: TKey; out AEntry: TValue; const AComparer: IEqualityComparer<TKey>): Boolean;
begin
  Result := TCollectionUtilities.Remove<TKey, TValue>(ADict, AKey, AEntry);
  if Result then
    RemoveOrdering<TKey>(AOrder, AKey, AComparer);
end;

procedure TPkcs12Store.MapKey(const AKey: String; const AEntry: IAsymmetricKeyEntry);
begin
  MapEntry<String, IAsymmetricKeyEntry>(FKeys, FKeysOrder, AKey, AEntry, TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
end;

procedure TPkcs12Store.MapCert(const AKey: String; const AEntry: IX509CertificateEntry);
begin
  MapEntry<String, IX509CertificateEntry>(FCerts, FCertsOrder, AKey, AEntry, TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
end;

procedure TPkcs12Store.MapChainCert(const AKey: TCertID; const AEntry: IX509CertificateEntry);
begin
  MapEntry<TCertID, IX509CertificateEntry>(FChainCerts, FChainCertsOrder, AKey, AEntry, FCertIDEqualityComparer);
end;

function TPkcs12Store.RemoveKey(const AKey: String): Boolean;
begin
  Result := RemoveEntry<String, IAsymmetricKeyEntry>(FKeys, FKeysOrder, AKey, TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
end;

function TPkcs12Store.RemoveCert(const AKey: String; out AEntry: IX509CertificateEntry): Boolean;
begin
  Result := RemoveEntry<String, IX509CertificateEntry>(FCerts, FCertsOrder, AKey, AEntry, TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
end;

function TPkcs12Store.RemoveChainCert(const AKey: TCertID): Boolean;
begin
  Result := RemoveEntry<TCertID, IX509CertificateEntry>(FChainCerts, FChainCertsOrder, AKey, FCertIDEqualityComparer);
end;

class function TPkcs12Store.CreateLocalKeyID(const ACertificate: IX509Certificate): IAsn1OctetString;
begin
  Result := TX509ExtensionUtilities.CalculateKeyIdentifier(ACertificate);
end;

class function TPkcs12Store.CalculatePbeMac(const AMacDigestAlgorithm: IAlgorithmIdentifier;
  const ASalt: TCryptoLibByteArray; AIterations: Int32;
  const APassword: TCryptoLibCharArray; AWrongPkcs12Zero: Boolean;
  const AData: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LHmacDigestOid: IDerObjectIdentifier;
  LPbeParameters: IAsn1Encodable;
  LCipherParameters: ICipherParameters;
  LMac: IMac;
  LEngine: TValue;
begin
  LHmacDigestOid := AMacDigestAlgorithm.Algorithm;
  LPbeParameters := TPbeUtilities.GenerateAlgorithmParameters(LHmacDigestOid, ASalt, AIterations);
  LCipherParameters := TPbeUtilities.GenerateCipherParameters(LHmacDigestOid, APassword, AWrongPkcs12Zero, LPbeParameters);
  LEngine := TPbeUtilities.CreateEngine(LHmacDigestOid);
  if not (LEngine.TryGetAsType<IMac>(LMac)) or (LMac = nil) then
    raise ECryptoLibException.Create('PBE engine for MAC not found for ' + LHmacDigestOid.Id);
  LMac.Init(LCipherParameters);
  Result := TMacUtilities.DoFinal(LMac, AData);
end;

class function TPkcs12Store.VerifyPbeMac(const AMacData: IMacData; const APassword: TCryptoLibCharArray;
  AWrongPkcs12Zero: Boolean; const AData: TCryptoLibByteArray): Boolean;
var
  LMac: IDigestInfo;
  LMacResult: TCryptoLibByteArray;
begin
  LMac := AMacData.Mac;
  LMacResult := CalculatePbeMac(LMac.DigestAlgorithm, AMacData.MacSalt.GetOctets(),
    AMacData.Iterations.IntValueExact, APassword, AWrongPkcs12Zero, AData);
  Result := TArrayUtilities.FixedTimeEquals(LMacResult, LMac.Digest.GetOctets());
end;

class function TPkcs12Store.CryptPbeData(AForEncryption: Boolean; const AAlgID: IAlgorithmIdentifier;
  const APassword: TCryptoLibCharArray; AWrongPkcs12Zero: Boolean;
  const AData: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LEngine: TValue;
  LCipher: IBufferedCipher;
  LPbeParameters: IAsn1Encodable;
  LCipherParameters: ICipherParameters;
begin
  LEngine := TPbeUtilities.CreateEngine(AAlgID);
  if not (LEngine.TryGetAsType<IBufferedCipher>(LCipher)) or (LCipher = nil) then
    raise ECryptoLibException.Create(Format(SUnknownEncryption, [AAlgID.Algorithm.Id]));
  if TPkcsObjectIdentifiers.IdPbeS2.Equals(AAlgID.Algorithm) then
  begin
    AWrongPkcs12Zero := False;
    LPbeParameters := TPbeS2Parameters.GetInstance(AAlgID.Parameters);
  end
  else
    LPbeParameters := TPkcs12PbeParams.GetInstance(AAlgID.Parameters);
  LCipherParameters := TPbeUtilities.GenerateCipherParameters(AAlgID.Algorithm, APassword, AWrongPkcs12Zero, LPbeParameters);
  LCipher.Init(AForEncryption, LCipherParameters);
  Result := LCipher.DoFinal(AData);
end;

procedure TPkcs12Store.LoadKeyBag(const APrivKeyInfo: IPrivateKeyInfo; const ABagAttributes: IAsn1Set);
var
  LKey: IAsymmetricKeyParameter;
  LAttributes: TDictionary<IDerObjectIdentifier, IAsn1Encodable>;
  LKeyEntry: IAsymmetricKeyEntry;
  LAlias: String;
  LLocalID: IAsn1OctetString;
  LI: Int32;
  LSq: IAsn1Sequence;
  LAOid: IDerObjectIdentifier;
  LAttrSet: IAsn1Set;
  LAttr: IAsn1Encodable;
  LExisting: IAsn1Encodable;
  LName: String;
begin
  LKey := TPrivateKeyFactory.CreateKey(APrivKeyInfo);
  LAttributes := TDictionary<IDerObjectIdentifier, IAsn1Encodable>.Create(TAsn1Comparers.OidEqualityComparer);
  LKeyEntry := TAsymmetricKeyEntry.Create(LKey, LAttributes);
  LAlias := '';
  LLocalID := nil;
  if ABagAttributes <> nil then
  begin
    for LI := 0 to ABagAttributes.Count - 1 do
    begin
      LSq := TAsn1Sequence.GetInstance(ABagAttributes[LI]);
      LAOid := TDerObjectIdentifier.GetInstance(LSq[0]);
      LAttrSet := TAsn1Set.GetInstance(LSq[1]);
      if LAttrSet.Count < 1 then
        Continue;
      LAttr := LAttrSet[0];
      if LAttributes.TryGetValue(LAOid, LExisting) then
      begin
        if not LExisting.Equals(LAttr) then
          raise EIOCryptoLibException.Create(SAttemptAddExistingAttr);
      end
      else
        LAttributes.Add(LAOid, LAttr);
      if TPkcsObjectIdentifiers.Pkcs9AtFriendlyName.Equals(LAOid) then
      begin
        LAlias := TDerBmpString.GetInstance(LAttr).GetString();
        MapKey(LAlias, LKeyEntry);
      end
      else if TPkcsObjectIdentifiers.Pkcs9AtLocalKeyID.Equals(LAOid) then
        LLocalID := TDerOctetString.GetInstance(LAttr);
    end;
  end;
  if LLocalID <> nil then
  begin
    LName := THexEncoder.Encode(LLocalID.GetOctets());
    if LAlias = '' then
      MapKey(LName, LKeyEntry)
    else
      FLocalIDs.AddOrSetValue(LAlias, LName);
  end
  else
    FUnmarkedKeyEntry := LKeyEntry;
end;

procedure TPkcs12Store.LoadPkcs8ShroudedKeyBag(const AEncPrivKeyInfo: IEncryptedPrivateKeyInfo;
  const ABagAttributes: IAsn1Set; const APassword: TCryptoLibCharArray; AWrongPkcs12Zero: Boolean);
var
  LPrivateKeyInfo: IPrivateKeyInfo;
begin
  LPrivateKeyInfo := TPrivateKeyInfoFactory.CreatePrivateKeyInfo(APassword, AWrongPkcs12Zero, AEncPrivKeyInfo);
  LoadKeyBag(LPrivateKeyInfo, ABagAttributes);
end;

procedure TPkcs12Store.Load(const AInput: TStream; const APassword: TCryptoLibCharArray);
var
  LPfx: IPfx;
  LInfo: IPkcsContentInfo;
  LWrongPkcs12Zero: Boolean;
  LPasswordNeeded: Boolean;
  LMacData: IMacData;
  LBytes: TCryptoLibByteArray;
  LData: TCryptoLibByteArray;
  LCertBags: TList<ISafeBag>;
  LContent: IAsn1Encodable;
  LOctets: TCryptoLibByteArray;
  LAuthSafe: IAuthenticatedSafe;
  LCis: TCryptoLibGenericArray<IPkcsContentInfo>;
  LCi: IPkcsContentInfo;
  LOid: IDerObjectIdentifier;
  LEncryptedData: IPkcsEncryptedData;
  LSeq: IAsn1Sequence;
  LJ: Int32;
  LSafeBag: ISafeBag;
  LSafeBagID: IDerObjectIdentifier;
  LCertBag: ICertBag;
  LCertValue: IAsn1OctetString;
  LCert: IX509Certificate;
  LAttributes: TDictionary<IDerObjectIdentifier, IAsn1Encodable>;
  LLocalID: IAsn1OctetString;
  LAlias: String;
  LI: Int32;
  LSq: IAsn1Sequence;
  LAOid: IDerObjectIdentifier;
  LAttrSet: IAsn1Set;
  LAttr: IAsn1Encodable;
  LExisting: IAsn1Encodable;
  LId: String;
  LCertID: TCertID;
  LCertEntry: IX509CertificateEntry;
  LName: String;
  LIgnore: Boolean;
begin
  if AInput = nil then
    raise EArgumentNilCryptoLibException.Create(SInputNil);
  AInput.Position := 0;
  SetLength(LBytes, AInput.Size);
  if AInput.Size > 0 then
    AInput.ReadBuffer(LBytes[0], AInput.Size);
  LPfx := TPfx.GetInstance(LBytes);
  LInfo := LPfx.AuthSafe;
  LWrongPkcs12Zero := False;
  LPasswordNeeded := False;
  LMacData := LPfx.MacData;
  if LMacData <> nil then
  begin
    LPasswordNeeded := True;

    LContent := LInfo.Content;
    LData := TAsn1OctetString.GetInstance(LContent).GetOctets();
    if not VerifyPbeMac(LMacData, APassword, False, LData) then
    begin
      if (System.Length(APassword) = 0) and VerifyPbeMac(LMacData, APassword, True, LData) then
        LWrongPkcs12Zero := True
      else
        raise EIOCryptoLibException.Create(SMacInvalid);
    end;
  end;
  ClearKeys;
  FLocalIDs.Clear;
  FUnmarkedKeyEntry := nil;
  LCertBags := TList<ISafeBag>.Create;
  try
    if TPkcsObjectIdentifiers.Data.Equals(LInfo.ContentType) then
    begin
      LContent := LInfo.Content;
      LOctets := TAsn1OctetString.GetInstance(LContent).GetOctets();
      LAuthSafe := TAuthenticatedSafe.GetInstance(LOctets);
      LCis := LAuthSafe.GetContentInfo();
      for LJ := 0 to System.Length(LCis) - 1 do
      begin
        LCi := LCis[LJ];
        LOid := LCi.ContentType;
        LOctets := nil;
        if TPkcsObjectIdentifiers.Data.Equals(LOid) then
          LOctets := TAsn1OctetString.GetInstance(LCi.Content).GetOctets()
        else if TPkcsObjectIdentifiers.EncryptedData.Equals(LOid) then
        begin
          LPasswordNeeded := True;
          LEncryptedData := TPkcsEncryptedData.GetInstance(LCi.Content);
          LOctets := CryptPbeData(False, LEncryptedData.EncryptionAlgorithm, APassword, LWrongPkcs12Zero,
            LEncryptedData.Content.GetOctets());
        end;
        if LOctets = nil then
          Continue;
        LSeq := TAsn1Sequence.GetInstance(LOctets);
        for LI := 0 to LSeq.Count - 1 do
        begin
          LSafeBag := TSafeBag.GetInstance(LSeq[LI]);
          LSafeBagID := LSafeBag.BagID;
          if TPkcsObjectIdentifiers.CertBag.Equals(LSafeBagID) then
            LCertBags.Add(LSafeBag)
          else if TPkcsObjectIdentifiers.KeyBag.Equals(LSafeBagID) then
            LoadKeyBag(TPrivateKeyInfo.GetInstance(LSafeBag.BagValueEncodable), LSafeBag.BagAttributes)
          else if TPkcsObjectIdentifiers.Pkcs8ShroudedKeyBag.Equals(LSafeBagID) then
          begin
            LPasswordNeeded := True;
            LoadPkcs8ShroudedKeyBag(TEncryptedPrivateKeyInfo.GetInstance(LSafeBag.BagValueEncodable),
              LSafeBag.BagAttributes, APassword, LWrongPkcs12Zero);
          end;
        end;
      end;
    end;
    ClearCerts;
    for LI := 0 to LCertBags.Count - 1 do
    begin
      LSafeBag := LCertBags[LI];
      LCertBag := TCertBag.GetInstance(LSafeBag.BagValueEncodable);
      if not TPkcsObjectIdentifiers.X509Certificate.Equals(LCertBag.CertID) then
        raise ECryptoLibException.Create(Format(SUnsupportedCertType, [LCertBag.CertID.Id]));
      LCertValue := TAsn1OctetString.GetInstance(LCertBag.CertValueEncodable);
      LCert := TX509Certificate.Create(LCertValue.GetOctets());
      LAttributes := TDictionary<IDerObjectIdentifier, IAsn1Encodable>.Create(TAsn1Comparers.OidEqualityComparer);
      LLocalID := nil;
      LAlias := '';
      if LSafeBag.BagAttributes <> nil then
      begin
        for LJ := 0 to LSafeBag.BagAttributes.Count - 1 do
        begin
          LSq := TAsn1Sequence.GetInstance(LSafeBag.BagAttributes[LJ]);
          LAOid := TDerObjectIdentifier.GetInstance(LSq[0]);
          LAttrSet := TAsn1Set.GetInstance(LSq[1]);
          if LAttrSet.Count < 1 then
            Continue;
          LAttr := LAttrSet[0];
          if LAttributes.TryGetValue(LAOid, LExisting) then
          begin
            if TPkcsObjectIdentifiers.Pkcs9AtLocalKeyID.Equals(LAOid) then
            begin
              LId := THexEncoder.Encode(TAsn1OctetString.GetInstance(LAttr).GetOctets());
              if not FKeys.ContainsKey(LId) and not FLocalIDs.ContainsKey(LId) then
                Continue;
            end;
            if not LExisting.Equals(LAttr) then
              raise EIOCryptoLibException.Create(SAttemptAddExistingAttr);
          end
          else
            LAttributes.Add(LAOid, LAttr);
          if TPkcsObjectIdentifiers.Pkcs9AtFriendlyName.Equals(LAOid) then
            LAlias := TDerBmpString.GetInstance(LAttr).GetString()
          else if TPkcsObjectIdentifiers.Pkcs9AtLocalKeyID.Equals(LAOid) then
            LLocalID := TDerOctetString.GetInstance(LAttr);
        end;
      end;
      LCertID := TCertID.Create(LCert);
      LCertEntry := TX509CertificateEntry.Create(LCert, LAttributes);
      MapChainCert(LCertID, LCertEntry);
      if FUnmarkedKeyEntry <> nil then
      begin
        if FKeyCerts.Count = 0 then
        begin
          LName := THexEncoder.Encode(LCertID.Id);
          FKeyCerts.Add(LName, LCertEntry);
          MapKey(LName, FUnmarkedKeyEntry);
        end
        else
          MapKey('unmarked', FUnmarkedKeyEntry);
      end
      else
      begin
        if LLocalID <> nil then
        begin
          LName := THexEncoder.Encode(LLocalID.GetOctets());
          FKeyCerts.Add(LName, LCertEntry);
        end;
        if LAlias <> '' then
          MapCert(LAlias, LCertEntry);
      end;
    end;
    if not LPasswordNeeded and (APassword <> nil) then
    begin
      LIgnore := FIgnoreUselessPassword;
      if not LIgnore then
        raise EIOCryptoLibException.Create(SPasswordNotNeeded);
    end;
  finally
    LCertBags.Free;
  end;
end;

function TPkcs12Store.GetKey(const AAlias: String): IAsymmetricKeyEntry;
begin
  if AAlias = '' then
    raise EArgumentNilCryptoLibException.Create(SAliasNil);
  Result := TCollectionUtilities.GetValueOrNull<String, IAsymmetricKeyEntry>(FKeys, AAlias);
end;

function TPkcs12Store.IsCertificateEntry(const AAlias: String): Boolean;
begin
  if AAlias = '' then
    raise EArgumentNilCryptoLibException.Create(SAliasNil);
  Result := FCerts.ContainsKey(AAlias) and not FKeys.ContainsKey(AAlias);
end;

function TPkcs12Store.IsKeyEntry(const AAlias: String): Boolean;
begin
  if AAlias = '' then
    raise EArgumentNilCryptoLibException.Create(SAliasNil);
  Result := FKeys.ContainsKey(AAlias);
end;

function TPkcs12Store.GetAliases: TCryptoLibStringArray;
var
  LSet: TDictionary<String, Byte>;
  LKey: String;
begin
  LSet := TDictionary<String, Byte>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  try
    for LKey in FCerts.Keys do
      LSet.AddOrSetValue(LKey, 0);
    for LKey in FKeys.Keys do
      LSet.AddOrSetValue(LKey, 0);
    Result := TCollectionUtilities.Keys<String, Byte>(LSet);
  finally
    LSet.Free;
  end;
end;

function TPkcs12Store.ContainsAlias(const AAlias: String): Boolean;
begin
  if AAlias = '' then
    raise EArgumentNilCryptoLibException.Create(SAliasNil);
  Result := FCerts.ContainsKey(AAlias) or FKeys.ContainsKey(AAlias);
end;

function TPkcs12Store.GetCertificate(const AAlias: String): IX509CertificateEntry;
var
  LKeyCertsKey: String;
  LLocalID: String;
begin
  if AAlias = '' then
    raise EArgumentNilCryptoLibException.Create(SAliasNil);
  if FCerts.TryGetValue(AAlias, Result) then
    Exit;
  LKeyCertsKey := AAlias;
  if FLocalIDs.TryGetValue(AAlias, LLocalID) then
    LKeyCertsKey := LLocalID;
  Result := TCollectionUtilities.GetValueOrNull<String, IX509CertificateEntry>(FKeyCerts, LKeyCertsKey);
end;

function TPkcs12Store.GetCertificateAlias(const ACert: IX509Certificate): String;
var
  LEntry: TPair<String, IX509CertificateEntry>;
begin
  if ACert = nil then
    raise EArgumentNilCryptoLibException.Create('cert');
  for LEntry in FCerts do
    if LEntry.Value.Certificate.Equals(ACert) then
    begin
      Result := LEntry.Key;
      Exit;
    end;
  for LEntry in FKeyCerts do
    if LEntry.Value.Certificate.Equals(ACert) then
    begin
      Result := LEntry.Key;
      Exit;
    end;
  Result := '';
end;

function TPkcs12Store.GetCertificateChain(const AAlias: String): TCryptoLibGenericArray<IX509CertificateEntry>;
var
  LC: IX509CertificateEntry;
  LX509c: IX509Certificate;
  LAki: IAuthorityKeyIdentifier;
  LKeyIdOid: IAsn1OctetString;
  LNextC: IX509CertificateEntry;
  LCs: TList<IX509CertificateEntry>;
  LNextCertID: TCertID;
  LEntry: TPair<TCertID, IX509CertificateEntry>;
  LI: IX509Name;
  LS: IX509Name;
  LCert: IX509Certificate;
begin
  if AAlias = '' then
    raise EArgumentNilCryptoLibException.Create(SAliasNil);
  if not IsKeyEntry(AAlias) then
  begin
    Result := nil;
    Exit;
  end;
  LC := GetCertificate(AAlias);
  if LC = nil then
  begin
    Result := nil;
    Exit;
  end;
  LCs := TList<IX509CertificateEntry>.Create;
  try
    while LC <> nil do
    begin
      LX509c := LC.Certificate;
      LNextC := nil;
      if LX509c.TbsCertificate <> nil then
        LAki := TX509ExtensionUtilities.GetAuthorityKeyIdentifier(LX509c.TbsCertificate.Extensions)
      else
        LAki := nil;
      if LAki <> nil then
      begin
        LKeyIdOid := LAki.KeyIdentifier;
        if (LKeyIdOid <> nil) and (LKeyIdOid.GetOctets() <> nil) then
        begin
          LNextCertID := TCertID.Create(LKeyIdOid);
          LNextC := TCollectionUtilities.GetValueOrNull<TCertID, IX509CertificateEntry>(FChainCerts, LNextCertID);
        end;
      end;
      if LNextC = nil then
      begin
        LI := LX509c.IssuerDN;
        LS := LX509c.SubjectDN;
        if not LI.Equivalent(LS) then
        begin
          for LEntry in FChainCerts do
          begin
            LCert := LEntry.Value.Certificate;
            if LCert.SubjectDN.Equivalent(LI) then
            begin
              try
                LX509c.Verify(LCert.GetPublicKey());
                LNextC := LEntry.Value;
                Break;
              except
                on EInvalidKeyCryptoLibException do
                  ;
              end;
            end;
          end;
        end;
      end;
      LCs.Add(LC);
      if (LNextC = nil) or (LNextC = LC) then
        LC := nil
      else
        LC := LNextC;
    end;
    Result := TCollectionUtilities.ToArray<IX509CertificateEntry>(LCs);
  finally
    LCs.Free;
  end;
end;

procedure TPkcs12Store.SetCertificateEntry(const AAlias: String; const ACertEntry: IX509CertificateEntry);
var
  LCertID: TCertID;
begin
  if AAlias = '' then
    raise EArgumentNilCryptoLibException.Create(SAliasNil);
  if ACertEntry = nil then
    raise EArgumentNilCryptoLibException.Create(SCertEntryNil);
  if FKeys.ContainsKey(AAlias) then
    raise EArgumentCryptoLibException.Create(Format(SKeyEntryWithName, [AAlias]));
  MapCert(AAlias, ACertEntry);
  LCertID := TCertID.Create(ACertEntry);
  MapChainCert(LCertID, ACertEntry);
end;

procedure TPkcs12Store.SetFriendlyName(const AAlias: String; const ANewFriendlyName: String);
var
  LCertEntry: IX509CertificateEntry;
  LKeyEntry: IAsymmetricKeyEntry;
  LLocalID: String;
  LKeyCertsKey: String;
  LKeyCertEntry: IX509CertificateEntry;
begin
  if AAlias = '' then
    raise EArgumentNilCryptoLibException.Create(SAliasNil);
  if ANewFriendlyName = '' then
    raise EArgumentNilCryptoLibException.Create('newFriendlyName');
  if SameText(AAlias, ANewFriendlyName) or FOverwriteFriendlyName then
    Exit;
  if TCollectionUtilities.Remove<String, IX509CertificateEntry>(FCerts, AAlias, LCertEntry) then
  begin
    DeleteCertsEntry(ANewFriendlyName);
    LCertEntry.SetFriendlyName(ANewFriendlyName);
    FCerts.Add(ANewFriendlyName, LCertEntry);
    ReplaceOrdering<String>(FCertsOrder, AAlias, ANewFriendlyName, TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  end;
  if TCollectionUtilities.Remove<String, IAsymmetricKeyEntry>(FKeys, AAlias, LKeyEntry) then
  begin
    DeleteKeysEntry(ANewFriendlyName);
    LKeyEntry.SetFriendlyName(ANewFriendlyName);
    FKeys.Add(ANewFriendlyName, LKeyEntry);
    ReplaceOrdering<String>(FKeysOrder, AAlias, ANewFriendlyName, TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
    LKeyCertsKey := AAlias;
    if TCollectionUtilities.Remove<String, String>(FLocalIDs, AAlias, LLocalID) then
    begin
      FLocalIDs.Add(ANewFriendlyName, LLocalID);
      LKeyCertsKey := LLocalID;
    end;
    if TCollectionUtilities.Remove<String, IX509CertificateEntry>(FKeyCerts, LKeyCertsKey, LKeyCertEntry) then
    begin
      LKeyCertEntry.SetFriendlyName(ANewFriendlyName);
      FKeyCerts.Add(ANewFriendlyName, LKeyCertEntry);
    end;
  end;
end;

procedure TPkcs12Store.SetKeyEntry(const AAlias: String; const AKeyEntry: IAsymmetricKeyEntry;
  const AChain: TCryptoLibGenericArray<IX509CertificateEntry>);
var
  LChainProvided: Boolean;
  LI: Int32;
  LCertID: TCertID;
begin
  if AAlias = '' then
    raise EArgumentNilCryptoLibException.Create(SAliasNil);
  if AKeyEntry = nil then
    raise EArgumentNilCryptoLibException.Create(SKeyEntryNil);
  LChainProvided := (AChain <> nil) and (System.Length(AChain) > 0);
  if AKeyEntry.Key.IsPrivate and not LChainProvided then
    raise EArgumentCryptoLibException.Create(SNoChainForPrivateKey);
  if FKeys.ContainsKey(AAlias) then
    DeleteEntry(AAlias);
  MapKey(AAlias, AKeyEntry);
  if LChainProvided then
  begin
    MapCert(AAlias, AChain[0]);
    for LI := 0 to System.Length(AChain) - 1 do
    begin
      LCertID := TCertID.Create(AChain[LI]);
      MapChainCert(LCertID, AChain[LI]);
    end;
  end;
end;

procedure TPkcs12Store.DeleteCertsEntry(const AAlias: String);
var
  LCertEntry: IX509CertificateEntry;
  LCertID: TCertID;
begin
  if RemoveCert(AAlias, LCertEntry) then
  begin
    LCertID := TCertID.Create(LCertEntry);
    RemoveChainCert(LCertID);
  end;
end;

procedure TPkcs12Store.DeleteKeysEntry(const AAlias: String);
var
  LKeyCertsKey: String;
  LLocalID: String;
  LKeyCertEntry: IX509CertificateEntry;
  LCertID: TCertID;
begin
  if RemoveKey(AAlias) then
  begin
    LKeyCertsKey := AAlias;
    if TCollectionUtilities.Remove<String, String>(FLocalIDs, AAlias, LLocalID) then
      LKeyCertsKey := LLocalID;
    if TCollectionUtilities.Remove<String, IX509CertificateEntry>(FKeyCerts, LKeyCertsKey, LKeyCertEntry) then
    begin
      LCertID := TCertID.Create(LKeyCertEntry);
      RemoveChainCert(LCertID);
    end;
  end;
end;

procedure TPkcs12Store.DeleteEntry(const AAlias: String);
begin
  if AAlias = '' then
    raise EArgumentNilCryptoLibException.Create(SAliasNil);
  DeleteCertsEntry(AAlias);
  DeleteKeysEntry(AAlias);
end;

function TPkcs12Store.IsEntryOfType(const AAlias: String; AEntryType: PTypeInfo): Boolean;
begin
  if AAlias = '' then
    raise EArgumentNilCryptoLibException.Create(SAliasNil);
  if AEntryType = nil then
    Result := False
  else if AEntryType = TypeInfo(IX509CertificateEntry) then
    Result := IsCertificateEntry(AAlias)
  else if AEntryType = TypeInfo(IAsymmetricKeyEntry) then
    Result := IsKeyEntry(AAlias) and (GetCertificate(AAlias) <> nil)
  else
    Result := False;
end;

function TPkcs12Store.GetCount: Int32;
var
  LKey: String;
begin
  Result := FCerts.Count;
  for LKey in FKeys.Keys do
    if not FCerts.ContainsKey(LKey) then
      Inc(Result);
end;

function TPkcs12Store.CreateEntryFriendlyName(const AAlias: String; const AEntry: IPkcs12Entry): IAsn1Sequence;
var
  LFriendlyName: IAsn1Set;
  LAttr: IAsn1Encodable;
begin
  LFriendlyName := TDerSet.Empty;
  if FOverwriteFriendlyName then
    LFriendlyName := TDerSet.Create(TDerBmpString.Create(AAlias) as IDerBmpString) as IDerSet
  else if AEntry.TryGetAttribute(TPkcsObjectIdentifiers.Pkcs9AtFriendlyName, LAttr) then
    LFriendlyName := TDerSet.Create(LAttr) as IDerSet;
  Result := TDerSequence.Create(TPkcsObjectIdentifiers.Pkcs9AtFriendlyName, LFriendlyName) as IDerSequence;
end;

procedure TPkcs12Store.AddLocalKeyID(const V: IAsn1EncodableVector; const ACertEntry: IX509CertificateEntry);
begin
  AddLocalKeyID(V, ACertEntry.Certificate);
end;

procedure TPkcs12Store.AddLocalKeyID(const V: IAsn1EncodableVector; const AC: IX509Certificate);
begin
  V.Add(TDerSequence.Create(TPkcsObjectIdentifiers.Pkcs9AtLocalKeyID, TDerSet.Create(CreateLocalKeyID(AC)) as IDerSet) as IDerSequence);
end;

function TPkcs12Store.CreateCertBag(const AC: IX509Certificate): ICertBag;
begin
  Result := TCertBag.Create(TPkcsObjectIdentifiers.X509Certificate, TDerOctetString.Create(AC.GetEncoded()) as IDerOctetString);
end;

procedure TPkcs12Store.Save(const AStream: TStream; const APassword: TCryptoLibCharArray; const ARandom: ISecureRandom);
var
  LKeyBags, LKeyNames: IAsn1EncodableVector;
  LCertBags: IAsn1EncodableVector;
  LBagAttrs, LFName: IAsn1EncodableVector;
  LName: String;
  LPrivKey: IAsymmetricKeyEntry;
  LKSalt: TCryptoLibByteArray;
  LBagOid: IDerObjectIdentifier;
  LBagData: IAsn1Encodable;
  LOid: IDerObjectIdentifier;
  LKeyBagsEncoding, LCertBagsEncoding, LData: TCryptoLibByteArray;
  LKeysInfo, LCertsInfo: IPkcsContentInfo;
  LInfo: TCryptoLibGenericArray<IPkcsContentInfo>;
  LAuthSafe: IAuthenticatedSafe;
  LMainInfo: IPkcsContentInfo;
  LMacData: IMacData;
  LPfx: IPfx;
  LEncoding: String;
  LI, LJ: Int32;
  LReverseCertificates: Boolean;
  LCertEntry: IX509CertificateEntry;
  LCertBag: ICertBag;
  LDoneCerts: TList<IX509Certificate>;
  LCert: IX509Certificate;
  LCertID: TCertID;
  LCertBagsSeq: IAsn1Sequence;
  LEncAlgID: IAlgorithmIdentifier;
  LEncParams: IAsn1Encodable;
  LCertBytes: TCryptoLibByteArray;
  LCSalt: TCryptoLibByteArray;
  LCIterations: Int32;
  LMacDigestAlgorithm: IAlgorithmIdentifier;
  LSalt: TCryptoLibByteArray;
  LItCount: Int32;
  LMacResult: TCryptoLibByteArray;
  LMac: IDigestInfo;
  LExts: IX509Extensions;
  LObj: IAsn1Object;
  LEku: IExtendedKeyUsage;
  LUsages: TCryptoLibGenericArray<IDerObjectIdentifier>;
  LEncodables: TCryptoLibGenericArray<IAsn1Encodable>;
  LAttrValue: IAsn1Set;
  LIdx: Int32;
  LCertEnc: TCryptoLibByteArray;
  LEffectiveKeyPrfAlgorithm, LEffectiveCertPrfAlgorithm, LEffectiveMacDigestAlgorithm: IDerObjectIdentifier;
begin
  if AStream = nil then
    raise EArgumentNilCryptoLibException.Create(SStreamNil);
  if ARandom = nil then
    raise EArgumentNilCryptoLibException.Create(SRandomNil);

  LEffectiveKeyPrfAlgorithm := FKeyPrfAlgorithm;
  LEffectiveCertPrfAlgorithm := FCertPrfAlgorithm;

  if (LEffectiveKeyPrfAlgorithm = nil) and (FKeyAlgorithm <> nil) and
    TPbeUtilities.IsPbes2Cipher(FKeyAlgorithm.ID) then
  begin
    // Default PRF for PBES2 ciphers per RFC 8018 Section A.2
    LEffectiveKeyPrfAlgorithm := TPkcsObjectIdentifiers.IdHmacWithSha1;
  end;

  if (LEffectiveCertPrfAlgorithm = nil) and (FCertAlgorithm <> nil) and
    TPbeUtilities.IsPbes2Cipher(FCertAlgorithm.ID) then
  begin
    // Default PRF for PBES2 ciphers per RFC 8018 Section A.2
    LEffectiveCertPrfAlgorithm := TPkcsObjectIdentifiers.IdHmacWithSha1;
  end;

  LReverseCertificates := FReverseCertificates;
  if FUseDerEncoding then
    LEncoding := TAsn1Encodable.Der
  else
    LEncoding := TAsn1Encodable.Ber;

  // Key bags
  LKeyBags := TAsn1EncodableVector.Create();
  LI := 0;
  if LReverseCertificates then
    LI := FKeysOrder.Count - 1;
  while (LReverseCertificates and (LI >= 0)) or (not LReverseCertificates and (LI < FKeysOrder.Count)) do
  begin
    LName := FKeysOrder[LI];
    LPrivKey := FKeys[LName];
    LKSalt := TSecureRandom.GetNextBytes(ARandom, FKeySaltSize);

    if (APassword = nil) or (FKeyAlgorithm = nil) then
    begin
      LBagOid := TPkcsObjectIdentifiers.KeyBag;
      LBagData := TPrivateKeyInfoFactory.CreatePrivateKeyInfo(LPrivKey.Key);
    end
    else
    begin
      LBagOid := TPkcsObjectIdentifiers.Pkcs8ShroudedKeyBag;
      if LEffectiveKeyPrfAlgorithm <> nil then
        LBagData := TEncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
          FKeyAlgorithm, LEffectiveKeyPrfAlgorithm, APassword, LKSalt, FKeyIterations, ARandom, LPrivKey.Key)
      else
        LBagData := TEncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
          FKeyAlgorithm, APassword, LKSalt, FKeyIterations, LPrivKey.Key);
    end;

    LKeyNames := TAsn1EncodableVector.Create();
    for LOid in LPrivKey.BagAttributeKeys do
    begin
      if TPkcsObjectIdentifiers.Pkcs9AtFriendlyName.Equals(LOid) then
        Continue;
      LKeyNames.Add(TDerSequence.Create([LOid, TDerSet.Create(LPrivKey[LOid]) as IDerSet]) as IDerSequence);
    end;
    LKeyNames.Add(CreateEntryFriendlyName(LName, LPrivKey));
    if LPrivKey[TPkcsObjectIdentifiers.Pkcs9AtLocalKeyID] = nil then
      AddLocalKeyID(LKeyNames, GetCertificate(LName));
    LKeyBags.Add(TSafeBag.Create(LBagOid, LBagData, TDerSet.FromVector(LKeyNames)) as ISafeBag);
    if LReverseCertificates then
      Dec(LI)
    else
      Inc(LI);
  end;

  LKeyBagsEncoding := TDerSequence.FromVector(LKeyBags).GetEncoded(TAsn1Encodable.Der);
  LKeysInfo := TPkcsContentInfo.Create(TPkcsObjectIdentifiers.Data, TBerOctetString.FromContents(LKeyBagsEncoding));

  // Certificate bags
  LCertBags := TAsn1EncodableVector.Create();
  LDoneCerts := TList<IX509Certificate>.Create();
  try
    // Certs for key entries
    LI := 0;
    if LReverseCertificates then
      LI := FKeysOrder.Count - 1;
    while (LReverseCertificates and (LI >= 0)) or (not LReverseCertificates and (LI < FKeysOrder.Count)) do
    begin
      LName := FKeysOrder[LI];
      LCertEntry := GetCertificate(LName);
      LCertBag := CreateCertBag(LCertEntry.Certificate);
      LBagAttrs := TAsn1EncodableVector.Create();
      for LOid in LCertEntry.BagAttributeKeys do
      begin
        if TPkcsObjectIdentifiers.Pkcs9AtFriendlyName.Equals(LOid) then
          Continue;
        LBagAttrs.Add(TDerSequence.Create([LOid, TDerSet.Create(LCertEntry[LOid]) as IDerSet]) as IDerSequence);
      end;
      LBagAttrs.Add(CreateEntryFriendlyName(LName, LCertEntry));
      if LCertEntry[TPkcsObjectIdentifiers.Pkcs9AtLocalKeyID] = nil then
        AddLocalKeyID(LBagAttrs, LCertEntry);
      LCertBags.Add(TSafeBag.Create(TPkcsObjectIdentifiers.CertBag, LCertBag, TDerSet.FromVector(LBagAttrs)) as ISafeBag);
      LDoneCerts.Add(LCertEntry.Certificate);
      if LReverseCertificates then
        Dec(LI)
      else
        Inc(LI);
    end;

    // Certs-only entries
    LJ := 0;
    if LReverseCertificates then
      LJ := FCertsOrder.Count - 1;
    while (LReverseCertificates and (LJ >= 0)) or (not LReverseCertificates and (LJ < FCertsOrder.Count)) do
    begin
      LName := FCertsOrder[LJ];
      if FKeys.ContainsKey(LName) then
      begin
        if LReverseCertificates then
          Dec(LJ)
        else
          Inc(LJ);
        Continue;
      end;
      LCertEntry := FCerts[LName];
      LCertBag := CreateCertBag(LCertEntry.Certificate);
      LBagAttrs := TAsn1EncodableVector.Create();
      for LOid in LCertEntry.BagAttributeKeys do
      begin
        if TPkcsObjectIdentifiers.Pkcs9AtLocalKeyID.Equals(LOid) then
          Continue;
        if TPkcsObjectIdentifiers.Pkcs9AtFriendlyName.Equals(LOid) then
          Continue;
        if TMiscObjectIdentifiers.IdOraclePkcs12TrustedKeyUsage.Equals(LOid) then
          Continue;
        LBagAttrs.Add(TDerSequence.Create(LOid, TDerSet.Create(LCertEntry[LOid]) as IDerSet) as IDerSequence);
      end;
      LBagAttrs.Add(CreateEntryFriendlyName(LName, LCertEntry));
      if FEnableOracleTrustedKeyUsage then
      begin
        LExts := LCertEntry.Certificate.CertificateStructure.Extensions;
        if LExts <> nil then
          LObj := TX509Extensions.GetExtensionParsedValue(LExts, TX509Extensions.ExtendedKeyUsage)
        else
          LObj := nil;
        if LObj <> nil then
        begin
          LEku := TExtendedKeyUsage.GetInstance(LObj);
          LUsages := LEku.GetAllUsages;
          SetLength(LEncodables, System.Length(LUsages));
          for LIdx := 0 to System.Length(LUsages) - 1 do
            LEncodables[LIdx] := LUsages[LIdx];
          LAttrValue := TDerSet.Create(LEncodables) as IDerSet;
        end
        else
          LAttrValue := TDerSet.Create([TKeyPurposeId.AnyExtendedKeyUsage]) as IDerSet;
        LBagAttrs.Add(TDerSequence.Create([TMiscObjectIdentifiers.IdOraclePkcs12TrustedKeyUsage, LAttrValue]) as IDerSequence);
      end;
      LCertBags.Add(TSafeBag.Create(TPkcsObjectIdentifiers.CertBag, LCertBag, TDerSet.FromVector(LBagAttrs)) as ISafeBag);
      LDoneCerts.Add(LCertEntry.Certificate);
      if LReverseCertificates then
        Dec(LJ)
      else
        Inc(LJ);
    end;

    // Chain certs
    LI := 0;
    if LReverseCertificates then
      LI := FChainCertsOrder.Count - 1;
    while (LReverseCertificates and (LI >= 0)) or (not LReverseCertificates and (LI < FChainCertsOrder.Count)) do
    begin
      LCertID := FChainCertsOrder[LI];
      LCertEntry := FChainCerts[LCertID];
      LCert := LCertEntry.Certificate;
      LCertEnc := LCert.GetEncoded();
      LIdx := 0;
      while LIdx < LDoneCerts.Count do
      begin
        if TArrayUtilities.AreEqual(LCertEnc, LDoneCerts[LIdx].GetEncoded()) then
          Break;
        Inc(LIdx);
      end;
      if LIdx < LDoneCerts.Count then
      begin
        if LReverseCertificates then
          Dec(LI)
        else
          Inc(LI);
        Continue;
      end;
      LCertBag := CreateCertBag(LCert);
      LFName := TAsn1EncodableVector.Create();
      for LOid in LCertEntry.BagAttributeKeys do
      begin
        if TPkcsObjectIdentifiers.Pkcs9AtLocalKeyID.Equals(LOid) then
          Continue;
        LFName.Add(TDerSequence.Create([LOid, TDerSet.Create(LCertEntry[LOid]) as IDerSet]) as IDerSequence);
      end;
      LCertBags.Add(TSafeBag.Create(TPkcsObjectIdentifiers.CertBag, LCertBag, TDerSet.FromVector(LFName)) as ISafeBag);
      if LReverseCertificates then
        Dec(LI)
      else
        Inc(LI);
    end;

    LCertBagsSeq := TDerSequence.FromVector(LCertBags);
    LCertBagsEncoding := LCertBagsSeq.GetEncoded(TAsn1Encodable.Der);

    if (APassword = nil) or (FCertAlgorithm = nil) then
      LCertsInfo := TPkcsContentInfo.Create(TPkcsObjectIdentifiers.Data, TBerOctetString.FromContents(LCertBagsEncoding))
    else
    begin
      LCSalt := TSecureRandom.GetNextBytes(ARandom, FCertSaltSize);
      LCIterations := FCertIterations;
      if LEffectiveCertPrfAlgorithm <> nil then
      begin
        LEncParams := TPbeUtilities.GenerateAlgorithmParameters(FCertAlgorithm, LEffectiveCertPrfAlgorithm, LCSalt, LCIterations, ARandom);
        LEncAlgID := TAlgorithmIdentifier.Create(TPkcsObjectIdentifiers.IdPbeS2, LEncParams);
      end
      else
      begin
        LEncParams := TPkcs12PbeParams.Create(LCSalt, LCIterations);
        LEncAlgID := TAlgorithmIdentifier.Create(FCertAlgorithm, LEncParams);
      end;
      LCertBytes := CryptPbeData(True, LEncAlgID, APassword, False, LCertBagsEncoding);
      LCertsInfo := TPkcsContentInfo.Create(TPkcsObjectIdentifiers.EncryptedData,
        TPkcsEncryptedData.Create(TPkcsObjectIdentifiers.Data, LEncAlgID, TBerOctetString.FromContents(LCertBytes)) as IPkcsEncryptedData);
    end;

    SetLength(LInfo, 2);
    LInfo[0] := LKeysInfo;
    LInfo[1] := LCertsInfo;
    LAuthSafe := TAuthenticatedSafe.Create(LInfo);
    LData := LAuthSafe.GetEncoded(LEncoding);
    LMainInfo := TPkcsContentInfo.Create(TPkcsObjectIdentifiers.Data, TBerOctetString.FromContents(LData));

    if APassword <> nil then
    begin
      LEffectiveMacDigestAlgorithm := FMacDigestAlgorithm;
      if LEffectiveMacDigestAlgorithm = nil then
       LEffectiveMacDigestAlgorithm := TOiwObjectIdentifiers.IdSha1;

      LMacDigestAlgorithm := TDefaultDigestAlgorithmFinder.Instance.Find(LEffectiveMacDigestAlgorithm);
      LSalt := TSecureRandom.GetNextBytes(ARandom, FMacSaltSize);
      LItCount := FMacIterations;
      LMacResult := CalculatePbeMac(LMacDigestAlgorithm, LSalt, LItCount, APassword, False, LData);
      LMac := TDigestInfo.Create(LMacDigestAlgorithm, TDerOctetString.Create(LMacResult) as IDerOctetString);
      LMacData := TMacData.Create(LMac, LSalt, LItCount);
    end
    else
      LMacData := nil;

    LPfx := TPfx.Create(LMainInfo, LMacData);
    LPfx.EncodeTo(AStream, LEncoding);
  finally
    LDoneCerts.Free;
  end;
end;

end.
