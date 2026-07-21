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

unit ClpIPkixTypes;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Generics.Collections,
  ClpIStore,
  ClpIAsn1Objects,
  ClpIX500Asn1Objects,
  ClpIX509Asn1Objects,
  ClpIX509Certificate,
  ClpIX509Crl,
  ClpIX509V2AttributeCertificate,
  ClpIAsymmetricKeyParameter,
  ClpNullable,
  ClpCryptoLibTypes;

type
  IPkixCertPath = interface;
  IPkixParameters = interface;
  IPkixBuilderParameters = interface;

  /// <summary>
  /// A most-trusted CA used as the anchor of a certification path: its public key, its name,
  /// and any name constraints that further restrict paths validated with it.
  /// </summary>
  ITrustAnchor = interface(IInterface)
    ['{A1F03C57-6B48-4E92-9D3A-0C7E15B482D6}']

    function GetTrustedCert: IX509Certificate;
    function GetCA: IX509Name;
    function GetCAName: String;
    function GetCAPublicKey: IAsymmetricKeyParameter;
    /// <summary>The DER encoding of a NameConstraints extension value, or nil.</summary>
    function GetNameConstraints: TCryptoLibByteArray;
    function GetNameConstraintsObject: INameConstraints;
    function ToString: String;

    property TrustedCert: IX509Certificate read GetTrustedCert;
    property CA: IX509Name read GetCA;
    property CAName: String read GetCAName;
    property CAPublicKey: IAsymmetricKeyParameter read GetCAPublicKey;
  end;

  /// <summary>
  /// A directoryName (tested name or constraint) parsed into its RDNs. Equality and display are those
  /// of the underlying sequence; MATCHING uses the normalized RDN comparison of RFC 5280 7.1.
  /// </summary>
  INameConstraintDN = interface(IInterface)
    ['{5D0E6B21-A73F-4C8D-96E4-B10A82F5D3C6}']

    function GetSequence: IAsn1Sequence;
    function GetRdns: TCryptoLibGenericArray<IRdn>;
    function Equals(const AOther: INameConstraintDN): Boolean;
    function ToString: String;

    property Sequence: IAsn1Sequence read GetSequence;
    property Rdns: TCryptoLibGenericArray<IRdn> read GetRdns;
  end;

  /// <summary>
  /// The set of CRL revocation reasons a distribution point covers, accumulated across CRLs.
  /// </summary>
  /// <remarks>
  /// Reference semantics are load-bearing: RFC 5280 6.3.3 creates one mask in the caller and has the
  /// per-CRL processing add to it, terminating once every reason is covered.
  /// </remarks>
  IReasonsMask = interface(IInterface)
    ['{3C9AD4E0-F5C1-472A-B6C3-956704CE1B7F}']

    /// <summary>Add every reason of AMask to this mask.</summary>
    procedure AddReasons(const AMask: IReasonsMask);
    /// <summary>True when this mask already covers every possible reason.</summary>
    function IsAllReasons: Boolean;
    /// <summary>True when AMask carries at least one reason this mask does not have.</summary>
    function HasNewReasons(const AMask: IReasonsMask): Boolean;
    function GetReasons: Int32;

    property Reasons: Int32 read GetReasons;
  end;

  /// <summary>
  /// A node of the RFC 5280 6.1 valid policy tree.
  /// </summary>
  /// <remarks>
  /// The tree is mutated in place as the path is processed, so nodes are reference types. A node's
  /// parent link is weak - children are owned by their parent, and a strong link both ways would leak
  /// the whole tree.
  /// </remarks>
  IPkixPolicyNode = interface(IInterface)
    ['{8F41C7B2-06DE-4A93-B85F-C3092D6E41A7}']

    function GetDepth: Int32;
    function GetChildren: TCryptoLibGenericArray<IPkixPolicyNode>;
    function GetHasChildren: Boolean;
    function GetIsCritical: Boolean;
    procedure SetIsCritical(AValue: Boolean);
    function GetPolicyQualifiers: TCryptoLibGenericArray<IPolicyQualifierInfo>;
    function GetValidPolicy: String;
    function GetExpectedPolicies: TCryptoLibStringArray;
    procedure SetExpectedPolicies(const AValue: TCryptoLibStringArray);
    function GetParent: IPkixPolicyNode;
    procedure SetParent(const AValue: IPkixPolicyNode);

    procedure AddChild(const AChild: IPkixPolicyNode);
    procedure RemoveChild(const AChild: IPkixPolicyNode);
    function HasExpectedPolicy(const APolicy: String): Boolean;
    /// <summary>A deep copy of this node and its subtree, detached from any parent.</summary>
    function Copy: IPkixPolicyNode;
    function ToString: String; overload;
    function ToString(const AIndent: String): String; overload;

    property Depth: Int32 read GetDepth;
    property Children: TCryptoLibGenericArray<IPkixPolicyNode> read GetChildren;
    property HasChildren: Boolean read GetHasChildren;
    property IsCritical: Boolean read GetIsCritical write SetIsCritical;
    property PolicyQualifiers: TCryptoLibGenericArray<IPolicyQualifierInfo> read GetPolicyQualifiers;
    property ValidPolicy: String read GetValidPolicy;
    property ExpectedPolicies: TCryptoLibStringArray read GetExpectedPolicies write SetExpectedPolicies;
    property Parent: IPkixPolicyNode read GetParent write SetParent;
  end;

  /// <summary>
  /// Mutable revocation status carried through path validation.
  /// </summary>
  ICertStatus = interface(IInterface)
    ['{B2016D68-7C59-4FA3-8E4B-1D8F26C593E7}']

    function GetStatus: Int32;
    procedure SetStatus(AValue: Int32);
    function GetRevocationDate: TNullable<TDateTime>;
    procedure SetRevocationDate(const AValue: TNullable<TDateTime>);

    property Status: Int32 read GetStatus write SetStatus;
    property RevocationDate: TNullable<TDateTime> read GetRevocationDate write SetRevocationDate;
  end;

  /// <summary>
  /// Additional per-certificate check run by a path validator or builder.
  /// </summary>
  IPkixCertPathChecker = interface(IInterface)
    ['{C3127E79-8D6A-40B4-9F5C-2E9037D6A4F8}']

    /// <summary>Reset the internal state. AForward is True when certificates arrive target-first.</summary>
    procedure Init(AForward: Boolean);
    function IsForwardCheckingSupported: Boolean;
    /// <summary>The critical extension OIDs this checker recognizes, or nil when none.</summary>
    function GetSupportedExtensions: TCryptoLibStringArray;
    /// <summary>Check ACert, removing every critical extension OID it processes from AUnresolvedCritExts.</summary>
    procedure Check(const ACert: IX509Certificate; const AUnresolvedCritExts: TList<String>);
    function Clone: IPkixCertPathChecker;
  end;

  /// <summary>
  /// Additional per-attribute-certificate check run by an attribute certificate path validator.
  /// </summary>
  IPkixAttrCertChecker = interface(IInterface)
    ['{D4238F8A-9E7B-41C5-A06D-3F0148E7B509}']

    function GetSupportedExtensions: TCryptoLibStringArray;
    procedure Check(const AAttrCert: IX509V2AttributeCertificate; const ACertPath: IPkixCertPath;
      const AHolderCertPath: IPkixCertPath; const AUnresolvedCritExts: TList<String>);
    function Clone: IPkixAttrCertChecker;
  end;

  /// <summary>
  /// Everything a revocation checker needs about the one certificate of the path it is asked
  /// about: the validation parameters, the time the path is validated at, the path itself and the
  /// position in it, and the issuing certificate and its public key.
  /// </summary>
  IPkixCertRevocationCheckerParameters = interface(IInterface)
    ['{01B53FF3-EC15-461F-B873-ED17CFD76E29}']

    function GetPkixParameters: IPkixParameters;
    function GetValidDate: TDateTime;
    function GetCertPath: IPkixCertPath;
    function GetIndex: Int32;
    function GetSigningCert: IX509Certificate;
    function GetWorkingPublicKey: IAsymmetricKeyParameter;

    property PkixParameters: IPkixParameters read GetPkixParameters;
    property ValidDate: TDateTime read GetValidDate;
    property CertPath: IPkixCertPath read GetCertPath;
    /// <summary>The position of the certificate in the path, counted from the end entity.</summary>
    property Index: Int32 read GetIndex;
    property SigningCert: IX509Certificate read GetSigningCert;
    property WorkingPublicKey: IAsymmetricKeyParameter read GetWorkingPublicKey;
  end;

  /// <summary>
  /// The revocation status check of RFC 5280 6.1.3 (a)(3), whatever mechanism settles it.
  /// </summary>
  /// <remarks>
  /// The path processing calls <c>Initialize</c> once per certificate and then <c>Check</c>. A
  /// checker that cannot settle the status raises a recoverable failure so a peer mechanism may
  /// still answer; anything else it raises ends the path.
  /// </remarks>
  IPkixCertRevocationChecker = interface(IInterface)
    ['{FAB354CC-FCAC-42CA-BB36-F56D41593D9F}']

    procedure Initialize(const AParameters: IPkixCertRevocationCheckerParameters);
    procedure Check(const ACert: IX509Certificate); overload;
  end;

  /// <summary>
  /// An immutable certification path, ordered from the target certificate towards the trust anchor.
  /// The trust anchor's own certificate is not part of the path.
  /// </summary>
  IPkixCertPath = interface(IInterface)
    ['{E534909B-AF8C-42D6-B17E-40125968C61A}']

    function GetCertificates: TCryptoLibGenericArray<IX509Certificate>;
    /// <summary>The supported encoding names, default encoding first.</summary>
    function GetEncodings: TCryptoLibStringArray;
    function GetEncoded: TCryptoLibByteArray; overload;
    function GetEncoded(const AEncoding: String): TCryptoLibByteArray; overload;
    function Equals(const AOther: IPkixCertPath): Boolean;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}

    property Certificates: TCryptoLibGenericArray<IX509Certificate> read GetCertificates;
  end;

  /// <summary>
  /// Accumulates the permitted and excluded name subtrees of a certification path and tests names
  /// against them (RFC 5280 4.2.1.10, 6.1.4).
  /// </summary>
  IPkixNameConstraintValidator = interface(IInterface)
    ['{1A78B2CE-D3AF-4508-E4A1-734582ACF95D}']

    /// <summary>Check AName against the permitted subtrees, then the excluded ones.</summary>
    procedure CheckName(const AName: IGeneralName);
    procedure CheckPermittedName(const AName: IGeneralName);
    procedure CheckExcludedName(const AName: IGeneralName);

    procedure CheckDN(const ADn: IX509Name); overload;
    procedure CheckDN(const ADn: IAsn1Sequence); overload;
    /// <summary>
    /// Check ADn with the relaxed GSMA SGP.22 directoryName matching for this call only, whatever the
    /// process wide switch says.
    /// </summary>
    procedure CheckDNSgp22(const ADn: IX509Name);
    procedure CheckPermittedDN(const ADn: IAsn1Sequence);
    procedure CheckExcludedDN(const ADn: IAsn1Sequence);

    procedure CheckEmail(const AEmail: String);
    procedure CheckPermittedEmail(const AEmail: String);
    procedure CheckExcludedEmail(const AEmail: String);

    /// <summary>Narrow the permitted subtrees by intersecting them with APermitted.</summary>
    procedure IntersectPermittedSubtree(const APermitted: IGeneralSubtree); overload;
    procedure IntersectPermittedSubtree(const APermitted: IAsn1Sequence); overload;
    /// <summary>Permit nothing at all of ANameType (a GeneralName tag number).</summary>
    procedure IntersectEmptyPermittedSubtree(ANameType: Int32);
    procedure AddExcludedSubtree(const ASubtree: IGeneralSubtree);

    function ToString: String;
  end;

  /// <summary>
  /// The outcome of a successful certification path validation (RFC 5280 6.1.6).
  /// </summary>
  IPkixCertPathValidatorResult = interface(IInterface)
    ['{6E3B08C4-91DA-4F27-B5A8-D0714C29E6F3}']

    function GetTrustAnchor: ITrustAnchor;
    function GetPolicyTree: IPkixPolicyNode;
    function GetSubjectPublicKey: IAsymmetricKeyParameter;
    function ToString: String;

    property TrustAnchor: ITrustAnchor read GetTrustAnchor;
    /// <summary>The valid policy tree, or nil when no policy was required.</summary>
    property PolicyTree: IPkixPolicyNode read GetPolicyTree;
    property SubjectPublicKey: IAsymmetricKeyParameter read GetSubjectPublicKey;
  end;

  /// <summary>
  /// Validator of an X.509 certification path (RFC 5280 6.1).
  /// </summary>
  IPkixCertPathValidator = interface(IInterface)
    ['{2B5D74E1-9C36-48AF-A7D0-64E9183BC5A2}']

    /// <summary>Validate ACertPath against AParams (RFC 5280 6.1).</summary>
    function Validate(const ACertPath: IPkixCertPath;
      const AParams: IPkixParameters): IPkixCertPathValidatorResult;
  end;

  /// <summary>
  /// A validation result plus the path that was built to reach it.
  /// </summary>
  IPkixCertPathBuilderResult = interface(IPkixCertPathValidatorResult)
    ['{7F4C19D5-A2EB-4038-C6B9-E1825D3AF704}']

    function GetCertPath: IPkixCertPath;

    property CertPath: IPkixCertPath read GetCertPath;
  end;

  /// <summary>
  /// Builder of an X.509 certification path (RFC 5280 6.1).
  /// </summary>
  IPkixCertPathBuilder = interface(IInterface)
    ['{3AD8F206-1C74-4E59-B8F1-90D6C2E4A7B3}']

    /// <summary>Build and validate a certification path from AParams (RFC 5280 6.1).</summary>
    function Build(const AParams: IPkixBuilderParameters): IPkixCertPathBuilderResult;
  end;

  /// <summary>
  /// Validator of an X.509 attribute certificate path (RFC 3281 5).
  /// </summary>
  IPkixAttrCertPathValidator = interface(IInterface)
    ['{4C1E7A93-2D68-4B0F-9E3C-5A71D8F62B04}']

    /// <summary>
    /// Validate the attribute certificate against ACertPath, the certification path of its issuer
    /// public key certificate (RFC 3281 5).
    /// </summary>
    function Validate(const ACertPath: IPkixCertPath;
      const AParams: IPkixParameters): IPkixCertPathValidatorResult;
  end;

  /// <summary>
  /// Builder of an X.509 attribute certificate path (RFC 3281 5).
  /// </summary>
  IPkixAttrCertPathBuilder = interface(IInterface)
    ['{9B62F04D-1A57-4E3C-8D6B-72C0A9E145F8}']

    /// <summary>Build and validate an attribute certificate path from AParams (RFC 3281 5).</summary>
    function Build(const AParams: IPkixBuilderParameters): IPkixCertPathBuilderResult;
  end;

  /// <summary>
  /// Input parameters for PKIX certification path validation.
  /// </summary>
  IPkixParameters = interface(IInterface)
    ['{F645A1AC-B09D-43E7-C28F-5123608AD72B}']

    function GetIsRevocationEnabled: Boolean;
    procedure SetIsRevocationEnabled(AValue: Boolean);
    function GetIsExplicitPolicyRequired: Boolean;
    procedure SetIsExplicitPolicyRequired(AValue: Boolean);
    function GetIsAnyPolicyInhibited: Boolean;
    procedure SetIsAnyPolicyInhibited(AValue: Boolean);
    function GetIsPolicyMappingInhibited: Boolean;
    procedure SetIsPolicyMappingInhibited(AValue: Boolean);
    function GetIsPolicyQualifiersRejected: Boolean;
    procedure SetIsPolicyQualifiersRejected(AValue: Boolean);
    /// <summary>Whether delta CRLs are used when checking revocation status.</summary>
    function GetIsUseDeltasEnabled: Boolean;
    procedure SetIsUseDeltasEnabled(AValue: Boolean);
    /// <summary>Whether stores advertised in certificates or CRLs may also be consulted.</summary>
    function GetIsAdditionalLocationsEnabled: Boolean;
    procedure SetAdditionalLocationsEnabled(AValue: Boolean);
    function GetValidityModel: Int32;
    procedure SetValidityModel(AValue: Int32);
    /// <summary>The time all certificates must be valid at; unset means the current time.</summary>
    function GetDate: TNullable<TDateTime>;
    procedure SetDate(const AValue: TNullable<TDateTime>);

    function GetTrustAnchors: TCryptoLibGenericArray<ITrustAnchor>;
    procedure SetTrustAnchors(const AValue: TCryptoLibGenericArray<ITrustAnchor>);

    function GetTargetConstraintsCert: ISelector<IX509Certificate>;
    procedure SetTargetConstraintsCert(const AValue: ISelector<IX509Certificate>);
    function GetTargetConstraintsAttrCert: ISelector<IX509V2AttributeCertificate>;
    procedure SetTargetConstraintsAttrCert(const AValue: ISelector<IX509V2AttributeCertificate>);

    /// <summary>Acceptable initial policy OIDs; empty means any policy is acceptable.</summary>
    function GetInitialPolicies: TCryptoLibStringArray;
    procedure SetInitialPolicies(const AValue: TCryptoLibStringArray);

    function GetCertPathCheckers: TCryptoLibGenericArray<IPkixCertPathChecker>;
    procedure SetCertPathCheckers(const AValue: TCryptoLibGenericArray<IPkixCertPathChecker>);
    procedure AddCertPathChecker(const AChecker: IPkixCertPathChecker);

    function GetStoresCert: TCryptoLibGenericArray<IStore<IX509Certificate>>;
    procedure SetStoresCert(const AValue: TCryptoLibGenericArray<IStore<IX509Certificate>>);
    procedure AddStoreCert(const AStore: IStore<IX509Certificate>);
    function GetStoresCrl: TCryptoLibGenericArray<IStore<IX509Crl>>;
    procedure SetStoresCrl(const AValue: TCryptoLibGenericArray<IStore<IX509Crl>>);
    procedure AddStoreCrl(const AStore: IStore<IX509Crl>);
    function GetStoresAttrCert: TCryptoLibGenericArray<IStore<IX509V2AttributeCertificate>>;
    procedure SetStoresAttrCert(const AValue: TCryptoLibGenericArray<IStore<IX509V2AttributeCertificate>>);
    procedure AddStoreAttrCert(const AStore: IStore<IX509V2AttributeCertificate>);

    /// <summary>Trust anchors accepted as attribute certificate issuers.</summary>
    function GetTrustedACIssuers: TCryptoLibGenericArray<ITrustAnchor>;
    procedure SetTrustedACIssuers(const AValue: TCryptoLibGenericArray<ITrustAnchor>);
    /// <summary>OIDs of attributes an attribute certificate must carry.</summary>
    function GetNecessaryACAttributes: TCryptoLibStringArray;
    procedure SetNecessaryACAttributes(const AValue: TCryptoLibStringArray);
    /// <summary>OIDs of attributes an attribute certificate must not carry.</summary>
    function GetProhibitedACAttributes: TCryptoLibStringArray;
    procedure SetProhibitedACAttributes(const AValue: TCryptoLibStringArray);
    function GetAttrCertCheckers: TCryptoLibGenericArray<IPkixAttrCertChecker>;
    procedure SetAttrCertCheckers(const AValue: TCryptoLibGenericArray<IPkixAttrCertChecker>);

    function Clone: IPkixParameters;
    function ToString: String;

    property IsRevocationEnabled: Boolean read GetIsRevocationEnabled write SetIsRevocationEnabled;
    property IsExplicitPolicyRequired: Boolean read GetIsExplicitPolicyRequired write SetIsExplicitPolicyRequired;
    property IsAnyPolicyInhibited: Boolean read GetIsAnyPolicyInhibited write SetIsAnyPolicyInhibited;
    property IsPolicyMappingInhibited: Boolean read GetIsPolicyMappingInhibited write SetIsPolicyMappingInhibited;
    property IsPolicyQualifiersRejected: Boolean read GetIsPolicyQualifiersRejected
      write SetIsPolicyQualifiersRejected;
    property IsUseDeltasEnabled: Boolean read GetIsUseDeltasEnabled write SetIsUseDeltasEnabled;
    property IsAdditionalLocationsEnabled: Boolean read GetIsAdditionalLocationsEnabled;
    property ValidityModel: Int32 read GetValidityModel write SetValidityModel;
    property Date: TNullable<TDateTime> read GetDate write SetDate;
  end;

  /// <summary>
  /// Input parameters for PKIX certification path building.
  /// </summary>
  IPkixBuilderParameters = interface(IPkixParameters)
    ['{07569BBD-C1AE-44F8-D390-6234719BE83C}']

    /// <summary>Maximum number of intermediate certificates; -1 means unlimited.</summary>
    function GetMaxPathLength: Int32;
    procedure SetMaxPathLength(AValue: Int32);
    /// <summary>Certificates that must not be used while building a path.</summary>
    function GetExcludedCerts: TCryptoLibGenericArray<IX509Certificate>;
    procedure SetExcludedCerts(const AValue: TCryptoLibGenericArray<IX509Certificate>);

    property MaxPathLength: Int32 read GetMaxPathLength write SetMaxPathLength;
  end;

implementation

end.
