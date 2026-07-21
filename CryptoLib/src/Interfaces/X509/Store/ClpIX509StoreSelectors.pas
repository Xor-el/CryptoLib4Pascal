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

unit ClpIX509StoreSelectors;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIStore,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpIX509Certificate,
  ClpIX509CertificatePair,
  ClpIX509Crl,
  ClpIX509V2AttributeCertificate,
  ClpIAttributeCertificateHolder,
  ClpIAttributeCertificateIssuer,
  ClpNullable,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Selects X.509 certificates from configurable criteria. An unset criterion matches anything.
  /// </summary>
  IX509CertStoreSelector = interface(ISelector<IX509Certificate>)
    ['{6B1D2A4C-9E0F-4C3B-8D71-2F5A6E90C481}']

    /// <summary>The DER encoding of an AuthorityKeyIdentifier extension value.</summary>
    function GetAuthorityKeyIdentifier: TCryptoLibByteArray;
    procedure SetAuthorityKeyIdentifier(const AValue: TCryptoLibByteArray);
    /// <summary>Minimum required path length; -2 selects only end-entity certificates.</summary>
    function GetBasicConstraints: Int32;
    procedure SetBasicConstraints(AValue: Int32);
    function GetCertificate: IX509Certificate;
    procedure SetCertificate(const AValue: IX509Certificate);
    function GetCertificateValid: TNullable<TDateTime>;
    procedure SetCertificateValid(const AValue: TNullable<TDateTime>);
    function GetExtendedKeyUsage: TCryptoLibGenericArray<IDerObjectIdentifier>;
    procedure SetExtendedKeyUsage(const AValue: TCryptoLibGenericArray<IDerObjectIdentifier>);
    function GetIgnoreX509NameOrdering: Boolean;
    procedure SetIgnoreX509NameOrdering(AValue: Boolean);
    function GetIssuer: IX509Name;
    procedure SetIssuer(const AValue: IX509Name);
    function GetKeyUsage: TCryptoLibBooleanArray;
    procedure SetKeyUsage(const AValue: TCryptoLibBooleanArray);
    function GetMatchAllSubjectAltNames: Boolean;
    procedure SetMatchAllSubjectAltNames(AValue: Boolean);
    /// <summary>True once a policy criterion has been set; an empty policy set still requires the extension.</summary>
    function GetHasPolicy: Boolean;
    function GetPolicy: TCryptoLibGenericArray<IDerObjectIdentifier>;
    procedure SetPolicy(const AValue: TCryptoLibGenericArray<IDerObjectIdentifier>);
    procedure ClearPolicy;
    function GetPrivateKeyValid: TNullable<TDateTime>;
    procedure SetPrivateKeyValid(const AValue: TNullable<TDateTime>);
    function GetSerialNumber: TBigInteger;
    procedure SetSerialNumber(const AValue: TBigInteger);
    function GetSubject: IX509Name;
    procedure SetSubject(const AValue: IX509Name);
    function GetSubjectAlternativeNames: TCryptoLibGenericArray<IGeneralName>;
    procedure SetSubjectAlternativeNames(const AValue: TCryptoLibGenericArray<IGeneralName>);
    /// <summary>The DER encoding of a SubjectKeyIdentifier (OCTET STRING) extension value.</summary>
    function GetSubjectKeyIdentifier: TCryptoLibByteArray;
    procedure SetSubjectKeyIdentifier(const AValue: TCryptoLibByteArray);
    function GetSubjectPublicKey: ISubjectPublicKeyInfo;
    procedure SetSubjectPublicKey(const AValue: ISubjectPublicKeyInfo);
    function GetSubjectPublicKeyAlgID: IDerObjectIdentifier;
    procedure SetSubjectPublicKeyAlgID(const AValue: IDerObjectIdentifier);

    function GetHashCodeOfSubjectKeyIdentifier: Int32;
    function MatchesIssuer(const AOther: IX509CertStoreSelector): Boolean;
    function MatchesSerialNumber(const AOther: IX509CertStoreSelector): Boolean;
    function MatchesSubjectKeyIdentifier(const AOther: IX509CertStoreSelector): Boolean;

    property AuthorityKeyIdentifier: TCryptoLibByteArray read GetAuthorityKeyIdentifier
      write SetAuthorityKeyIdentifier;
    property BasicConstraints: Int32 read GetBasicConstraints write SetBasicConstraints;
    property Certificate: IX509Certificate read GetCertificate write SetCertificate;
    property CertificateValid: TNullable<TDateTime> read GetCertificateValid write SetCertificateValid;
    property ExtendedKeyUsage: TCryptoLibGenericArray<IDerObjectIdentifier> read GetExtendedKeyUsage
      write SetExtendedKeyUsage;
    property IgnoreX509NameOrdering: Boolean read GetIgnoreX509NameOrdering write SetIgnoreX509NameOrdering;
    property Issuer: IX509Name read GetIssuer write SetIssuer;
    property KeyUsage: TCryptoLibBooleanArray read GetKeyUsage write SetKeyUsage;
    property MatchAllSubjectAltNames: Boolean read GetMatchAllSubjectAltNames write SetMatchAllSubjectAltNames;
    property HasPolicy: Boolean read GetHasPolicy;
    property Policy: TCryptoLibGenericArray<IDerObjectIdentifier> read GetPolicy write SetPolicy;
    property PrivateKeyValid: TNullable<TDateTime> read GetPrivateKeyValid write SetPrivateKeyValid;
    property SerialNumber: TBigInteger read GetSerialNumber write SetSerialNumber;
    property Subject: IX509Name read GetSubject write SetSubject;
    property SubjectAlternativeNames: TCryptoLibGenericArray<IGeneralName> read GetSubjectAlternativeNames
      write SetSubjectAlternativeNames;
    property SubjectKeyIdentifier: TCryptoLibByteArray read GetSubjectKeyIdentifier write SetSubjectKeyIdentifier;
    property SubjectPublicKey: ISubjectPublicKeyInfo read GetSubjectPublicKey write SetSubjectPublicKey;
    property SubjectPublicKeyAlgID: IDerObjectIdentifier read GetSubjectPublicKeyAlgID
      write SetSubjectPublicKeyAlgID;
  end;

  /// <summary>
  /// Selects X.509 CRLs from configurable criteria. An unset criterion matches anything.
  /// </summary>
  IX509CrlStoreSelector = interface(ISelector<IX509Crl>)
    ['{7C2E3B5D-A01F-4D4C-9E82-3A6B7F01D592}']

    /// <summary>The certificate being checked. Not a criterion, only a hint for locating relevant CRLs.</summary>
    function GetCertificateChecking: IX509Certificate;
    procedure SetCertificateChecking(const AValue: IX509Certificate);
    function GetDateAndTime: TNullable<TDateTime>;
    procedure SetDateAndTime(const AValue: TNullable<TDateTime>);
    function GetIssuers: TCryptoLibGenericArray<IX509Name>;
    procedure SetIssuers(const AValue: TCryptoLibGenericArray<IX509Name>);
    function GetMaxCrlNumber: TBigInteger;
    procedure SetMaxCrlNumber(const AValue: TBigInteger);
    function GetMinCrlNumber: TBigInteger;
    procedure SetMinCrlNumber(const AValue: TBigInteger);
    /// <summary>The attribute certificate being checked. Not a criterion, only a hint.</summary>
    function GetAttrCertChecking: IX509V2AttributeCertificate;
    procedure SetAttrCertChecking(const AValue: IX509V2AttributeCertificate);
    /// <summary>If True only complete CRLs are selected.</summary>
    function GetCompleteCrlEnabled: Boolean;
    procedure SetCompleteCrlEnabled(AValue: Boolean);
    /// <summary>If True only CRLs carrying a delta CRL indicator are selected.</summary>
    function GetDeltaCrlIndicatorEnabled: Boolean;
    procedure SetDeltaCrlIndicatorEnabled(AValue: Boolean);
    /// <summary>The DER encoding of an IssuingDistributionPoint extension value.</summary>
    function GetIssuingDistributionPoint: TCryptoLibByteArray;
    procedure SetIssuingDistributionPoint(const AValue: TCryptoLibByteArray);
    function GetIssuingDistributionPointEnabled: Boolean;
    procedure SetIssuingDistributionPointEnabled(AValue: Boolean);
    function GetMaxBaseCrlNumber: TBigInteger;
    procedure SetMaxBaseCrlNumber(const AValue: TBigInteger);

    property CertificateChecking: IX509Certificate read GetCertificateChecking write SetCertificateChecking;
    property DateAndTime: TNullable<TDateTime> read GetDateAndTime write SetDateAndTime;
    property Issuers: TCryptoLibGenericArray<IX509Name> read GetIssuers write SetIssuers;
    property MaxCrlNumber: TBigInteger read GetMaxCrlNumber write SetMaxCrlNumber;
    property MinCrlNumber: TBigInteger read GetMinCrlNumber write SetMinCrlNumber;
    property AttrCertChecking: IX509V2AttributeCertificate read GetAttrCertChecking write SetAttrCertChecking;
    property CompleteCrlEnabled: Boolean read GetCompleteCrlEnabled write SetCompleteCrlEnabled;
    property DeltaCrlIndicatorEnabled: Boolean read GetDeltaCrlIndicatorEnabled write SetDeltaCrlIndicatorEnabled;
    property IssuingDistributionPoint: TCryptoLibByteArray read GetIssuingDistributionPoint
      write SetIssuingDistributionPoint;
    property IssuingDistributionPointEnabled: Boolean read GetIssuingDistributionPointEnabled
      write SetIssuingDistributionPointEnabled;
    property MaxBaseCrlNumber: TBigInteger read GetMaxBaseCrlNumber write SetMaxBaseCrlNumber;
  end;

  /// <summary>
  /// Selects X.509 attribute certificates from configurable criteria (RFC 3281).
  /// </summary>
  IX509AttrCertStoreSelector = interface(ISelector<IX509V2AttributeCertificate>)
    ['{8D3F4C6E-B120-4E5D-AF93-4B7C8012E6A3}']

    function GetAttributeCert: IX509V2AttributeCertificate;
    procedure SetAttributeCert(const AValue: IX509V2AttributeCertificate);
    function GetAttributeCertificateValid: TNullable<TDateTime>;
    procedure SetAttributeCertificateValid(const AValue: TNullable<TDateTime>);
    function GetHolder: IAttributeCertificateHolder;
    procedure SetHolder(const AValue: IAttributeCertificateHolder);
    function GetIssuer: IAttributeCertificateIssuer;
    procedure SetIssuer(const AValue: IAttributeCertificateIssuer);
    function GetSerialNumber: TBigInteger;
    procedure SetSerialNumber(const AValue: TBigInteger);

    /// <summary>Require the target information extension to name at least one of the added target names.</summary>
    procedure AddTargetName(const AName: IGeneralName); overload;
    procedure AddTargetName(const AEncodedName: TCryptoLibByteArray); overload;
    procedure SetTargetNames(const ANames: TCryptoLibGenericArray<IGeneralName>);
    function GetTargetNames: TCryptoLibGenericArray<IGeneralName>;
    /// <summary>Require the target information extension to name at least one of the added target groups.</summary>
    procedure AddTargetGroup(const AGroup: IGeneralName); overload;
    procedure AddTargetGroup(const AEncodedGroup: TCryptoLibByteArray); overload;
    procedure SetTargetGroups(const AGroups: TCryptoLibGenericArray<IGeneralName>);
    function GetTargetGroups: TCryptoLibGenericArray<IGeneralName>;

    property AttributeCert: IX509V2AttributeCertificate read GetAttributeCert write SetAttributeCert;
    property AttributeCertificateValid: TNullable<TDateTime> read GetAttributeCertificateValid
      write SetAttributeCertificateValid;
    property Holder: IAttributeCertificateHolder read GetHolder write SetHolder;
    property Issuer: IAttributeCertificateIssuer read GetIssuer write SetIssuer;
    property SerialNumber: TBigInteger read GetSerialNumber write SetSerialNumber;
  end;

  /// <summary>
  /// Selects cross-certificate pairs; each present component selector must match its side of the pair.
  /// </summary>
  IX509CertPairStoreSelector = interface(ISelector<IX509CertificatePair>)
    ['{9E405D7F-C231-4F6E-B0A4-5C8D9123F7B4}']

    function GetCertPair: IX509CertificatePair;
    procedure SetCertPair(const AValue: IX509CertificatePair);
    function GetForwardSelector: IX509CertStoreSelector;
    procedure SetForwardSelector(const AValue: IX509CertStoreSelector);
    function GetReverseSelector: IX509CertStoreSelector;
    procedure SetReverseSelector(const AValue: IX509CertStoreSelector);

    property CertPair: IX509CertificatePair read GetCertPair write SetCertPair;
    property ForwardSelector: IX509CertStoreSelector read GetForwardSelector write SetForwardSelector;
    property ReverseSelector: IX509CertStoreSelector read GetReverseSelector write SetReverseSelector;
  end;

implementation

end.
