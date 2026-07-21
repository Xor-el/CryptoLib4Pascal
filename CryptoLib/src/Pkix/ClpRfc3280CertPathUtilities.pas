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

unit ClpRfc3280CertPathUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpCryptoLibHashSet,
  ClpIStore,
  ClpIAsn1Core,
  ClpAsn1Core,
  ClpIAsn1Objects,
  ClpAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIX509Certificate,
  ClpIX509Crl,
  ClpIX509V2AttributeCertificate,
  ClpIX509StoreSelectors,
  ClpX509StoreSelectors,
  ClpX509ExtensionUtilities,
  ClpX509Comparers,
  ClpGsmaObjectIdentifiers,
  ClpIAsymmetricKeyParameter,
  ClpIPkixTypes,
  ClpPkixPolicyNode,
  ClpPkixParameters,
  ClpPkixBuilderParameters,
  ClpPkixCertPathValidatorUtilities,
  ClpPkixCertRevocationCheckerParameters,
  ClpCertStatus,
  ClpReasonsMask,
  ClpArrayUtilities,
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SExtensionDecodeFailed = '%s extension could not be decoded: %s';
  SExtensionContentsDecodeFailed = '%s extension contents could not be decoded: %s';
  SCrlIssuerReadFailed = 'could not read the CRL issuer: %s';
  SCertIssuerReadFailed = 'could not read the certificate issuer: %s';
  SNoIdpNameMatch = 'no match for the certificate CRL distribution point name to the CRL issuing ' +
    'distribution point name; certificate names: [%s]; CRL IDP names: [%s]';
  SDistributionPointFieldsOmitted = 'either the cRLIssuer or the distributionPoint field must be ' +
    'contained in a DistributionPoint';
  SCrlOnlyContainsUserCerts = 'CA certificate checked against a CRL that only contains user certificates';
  SCrlOnlyContainsCACerts = 'end-entity certificate checked against a CRL that only contains CA certificates';
  SCrlOnlyContainsAttributeCerts = 'the onlyContainsAttributeCerts boolean is asserted';
  SSubtreeCheckFailed = 'subtree check for the certificate %s failed: %s';
  SIssuerDomainPolicyIsAnyPolicy = 'issuerDomainPolicy is anyPolicy';
  SSubjectDomainPolicyIsAnyPolicy = 'subjectDomainPolicy is anyPolicy';
  SPolicyQualifierSetFailed = 'policy qualifier info set could not be built: %s';
  SCrlIssuerNotIndirect = 'the distribution point contains a cRLIssuer field but the CRL is not indirect';
  SCrlIssuerMismatch = 'the CRL issuer does not match the CRL issuer of the distribution point';
  SNoMatchingCrlIssuer = 'cannot find a matching CRL issuer for the certificate';
  SCrlSignerCriteriaFailed = 'subject criteria to find the issuer certificate for the CRL could not be set: %s';
  SCrlSignerSearchFailed = 'the issuer certificate for the CRL cannot be searched: %s';
  SCrlSignerPathFailed = 'the certification path for the CRL signer failed to validate: %s';
  SCrlCheckFailed = 'the certificate revocation status could not be checked: %s';
  SCrlSignerKeyUsage = 'the issuer certificate key usage extension does not permit CRL signing';
  SNoValidCrlIssuer = 'cannot find a valid CRL issuer certificate';
  SCannotVerifyCrl = 'cannot verify the CRL: %s';
  SCannotVerifyDeltaCrl = 'cannot verify the delta CRL: %s';
  SValidationTimeInFuture = 'the validation time is in the future';
  SNoValidCrlForCurrentTime = 'no valid CRL for the current time found';
  SNoValidCrlFound = 'no valid CRL found for the certificate';
  SAdditionalCrlLocationsFailed = 'no additional CRL locations could be decoded from the CRL ' +
    'distribution point extension: %s';
  SDistributionPointsReadFailed = 'the distribution points could not be read: %s';
  SCertificateRevoked = 'certificate revocation after %s, reason: %s';
  SCertStatusUndetermined = 'the certificate status could not be determined';
  SNoValidPolicyTree = 'no valid policy tree found when one expected';
  SSignatureValidationFailed = 'could not validate the certificate signature: %s';
  SValidityTimeFailed = 'could not validate the time of the certificate: %s';
  SCertificateValidityFailed = 'could not validate the certificate: %s';
  SNameChainingFailed = 'IssuerName(%s) does not match SubjectName(%s) of the signing certificate';
  SPermittedSubtreesFailed = 'permitted subtrees could not be built from the name constraints extension: %s';
  SExcludedSubtreesFailed = 'excluded subtrees could not be built from the name constraints extension: %s';
  SIntermediateLacksBasicConstraints = 'the intermediate certificate at index %d lacks basic constraints';
  SNotACACertificate = 'the certificate at index %d is not a CA certificate';
  SMaxPathLengthExhausted = 'the maximum path length is not greater than zero';
  SInvalidPathLengthConstraint = 'basic constraints violated: invalid path length constraint';
  SKeyUsageNoKeyCertSign = 'the issuer certificate key usage extension does not permit certificate signing';
  SUnsupportedCriticalExtensions = 'the certificate at index %d has unsupported critical extensions: [%s]';
  SCertPathCheckerFailed = 'an additional certificate path checker failed: %s';
  SExplicitPolicyUnavailable = 'explicit policy requested but none available';
  SDeltaCrlIssuerMismatch = 'the complete CRL issuer does not match the delta CRL issuer';
  SDeltaCrlIdpMismatch = 'the issuing distribution point extensions of the delta CRL and the ' +
    'complete CRL do not match';
  SAuthorityKeyIdentifierMissing = 'the %s authority key identifier is nil';
  SAuthorityKeyIdentifierFailed = 'the authority key identifier extension could not be extracted from the %s: %s';
  SDeltaCrlAuthorityKeyIdentifierMismatch = 'the delta CRL authority key identifier does not match the ' +
    'complete CRL authority key identifier';

type
  /// <summary>
  /// The certification path processing steps of RFC 5280 6.1 (basic path validation), 6.2 (policy
  /// tree wrap-up) and 6.3 (CRL processing).
  /// </summary>
  TRfc3280CertPathUtilities = class sealed(TObject)

  strict private
    /// <summary>
    /// Certificates whose CRL signer path is being built further up this thread's stack. Thread
    /// local: it is per-call-stack scratch, and sharing it would let one thread's recursion guard
    /// change another thread's validation outcome.
    /// </summary>
    class threadvar
      FCrlSignersInProgress: TCryptoLibHashSet<IX509Certificate>;

    class function ParseExtension(const AExtensionValue: IAsn1OctetString): IAsn1Object; static;
    class function GetCertExtension(const ACert: IX509Certificate;
      const AOid: IDerObjectIdentifier; const AName: String): IAsn1Object; static;
    class function GetCrlExtension(const ACrl: IX509Crl;
      const AOid: IDerObjectIdentifier; const AName: String): IAsn1Object; static;
    /// <summary>Whether ACert asserts APolicyOid in its certificatePolicies extension.</summary>
    class function HasCertificatePolicy(const ACert: IX509Certificate;
      const APolicyOid: IDerObjectIdentifier): Boolean; static;
    class function GetIssuingDistributionPoint(const ACrl: IX509Crl): IIssuingDistributionPoint; static;
    class function GetCrlAuthorityKeyIdentifier(const ACrl: IX509Crl;
      const AName: String): IAuthorityKeyIdentifier; static;
    /// <summary>The reason flags as an Int32, or ADefault when the flags are absent.</summary>
    class function ReasonFlagsValue(const AFlags: IReasonFlags; ADefault: Int32): Int32; static;
    class function GeneralNamesToString(const ANames: TCryptoLibGenericArray<IGeneralName>): String; static;
    class function ContainsGeneralName(const ANames: TCryptoLibGenericArray<IGeneralName>;
      const AName: IGeneralName): Boolean; static;
    class function ContainsString(const AValues: TCryptoLibStringArray; const AValue: String): Boolean; static;
    class procedure AppendString(var AValues: TCryptoLibStringArray; const AValue: String); static;
    /// <summary>The node of ANodes whose valid policy is APolicy, or nil when there is none.</summary>
    class function FindValidPolicy(const ANodes: TCryptoLibGenericArray<IPkixPolicyNode>;
      const APolicy: String): IPkixPolicyNode; static;
    /// <summary>ADn with the relative name of ADpName appended, as a directoryName.</summary>
    class function AppendRelativeName(const ADn: IAsn1Sequence;
      const ARelativeName: IAsn1Encodable): IGeneralName; static;

    class procedure DoProcessCrlB1(const ADistributionPoint: IDistributionPoint;
      const AIssuer: IX509Name; const ACrl: IX509Crl); static;
    class procedure DoProcessCrlB2(const ADistributionPoint: IDistributionPoint;
      const AIssuer: IX509Name; const ABasicConstraintsValue: IAsn1OctetString;
      AIsCertificate: Boolean; const ACrl: IX509Crl); static;

    /// <summary>RFC 5280 6.3.3: check ACert against one distribution point.</summary>
    class procedure CheckCrl(const ADistributionPoint: IDistributionPoint;
      const APkixParams: IPkixParameters; ACurrentDate, AValidityDate: TDateTime;
      const ACert, ADefaultCrlSignCert: IX509Certificate;
      const ADefaultCrlSignKey: IAsymmetricKeyParameter; const ACertStatus: ICertStatus;
      const AReasonsMask: IReasonsMask;
      const ACertPathCerts: TCryptoLibGenericArray<IX509Certificate>); static;

    /// <summary>Guard against re-entering the CRL signer path build for the same certificate.</summary>
    class function CrlSignerEnter(const ACert: IX509Certificate): Boolean; static;
    class procedure CrlSignerExit(const ACert: IX509Certificate); static;

    class function ContainsCertificate(const ACerts: TCryptoLibGenericArray<IX509Certificate>;
      const ACert: IX509Certificate): Boolean; static;
    class procedure AppendCertificate(var ACerts: TCryptoLibGenericArray<IX509Certificate>;
      const ACert: IX509Certificate); static;
    class procedure AppendKey(var AKeys: TCryptoLibGenericArray<IAsymmetricKeyParameter>;
      const AKey: IAsymmetricKeyParameter); static;
    class function JoinCriticalExtensions(const ACriticalExtensions: TList<String>): String; static;

  public
    /// <summary>The anyPolicy policy identifier of RFC 5280 4.2.1.4.</summary>
    const AnyPolicy = TPkixCertPathValidatorUtilities.AnyPolicy;

    /// <summary>
    /// The RFC 5280 5.3.1 CRL reason code as its ASN.1 identifier, or 'unknown' when the code is
    /// outside that enumeration. Public so the attribute certificate path (RFC 3281) reports
    /// revocation with the same wording rather than carrying a second copy of the table.
    /// </summary>
    class function CrlReasonName(AReason: Int32): String; static;

    /// <summary>
    /// RFC 5280 6.3.3 (b)(1): the CRL issuer must match the cRLIssuer field of the distribution
    /// point, and the CRL must then be an indirect CRL; otherwise it must match the certificate issuer.
    /// </summary>
    class procedure ProcessCrlB1(const ADistributionPoint: IDistributionPoint;
      const ACert: IX509Certificate; const ACrl: IX509Crl); overload; static;
    /// <summary>RFC 3281: the attribute certificate variant of the above.</summary>
    class procedure ProcessCrlB1(const ADistributionPoint: IDistributionPoint;
      const AAttrCert: IX509V2AttributeCertificate; const ACrl: IX509Crl); overload; static;

    /// <summary>
    /// RFC 5280 6.3.3 (b)(2): match the issuing distribution point of the CRL against the
    /// distribution point of the certificate, and check the scope booleans of the IDP.
    /// </summary>
    class procedure ProcessCrlB2(const ADistributionPoint: IDistributionPoint;
      const ACert: IX509Certificate; const ACrl: IX509Crl); overload; static;
    /// <summary>RFC 3281: the attribute certificate variant of the above.</summary>
    class procedure ProcessCrlB2(const ADistributionPoint: IDistributionPoint;
      const AAttrCert: IX509V2AttributeCertificate; const ACrl: IX509Crl); overload; static;

    /// <summary>RFC 5280 5.2.4/6.3.3 (c): verify the issuer and the scope of a delta CRL.</summary>
    class procedure ProcessCrlC(const ADeltaCrl, ACompleteCrl: IX509Crl); static;

    /// <summary>
    /// RFC 5280 6.3.3 (d): the reasons covered by this CRL, the intersection of the IDP reasons and
    /// the distribution point reasons. An absent reasons field means all reasons.
    /// </summary>
    class function ProcessCrlD(const ACrl: IX509Crl;
      const ADistributionPoint: IDistributionPoint): IReasonsMask; static;

    /// <summary>
    /// RFC 5280 6.3.3 (f): the public keys of every certificate that may have signed ACrl, each with
    /// a validated certification path and the cRLSign key usage bit.
    /// </summary>
    class function ProcessCrlF(const ACrl: IX509Crl; const ADefaultCrlSignCert: IX509Certificate;
      const ADefaultCrlSignKey: IAsymmetricKeyParameter; const APkixParams: IPkixParameters;
      const ACertPathCerts: TCryptoLibGenericArray<IX509Certificate>)
      : TCryptoLibGenericArray<IAsymmetricKeyParameter>; static;

    /// <summary>RFC 5280 6.3.3 (g): the key of AKeys that verifies ACrl.</summary>
    class function ProcessCrlG(const ACrl: IX509Crl;
      const AKeys: TCryptoLibGenericArray<IAsymmetricKeyParameter>): IAsymmetricKeyParameter; static;

    /// <summary>RFC 5280 6.3.3 (h): the first delta CRL that AKey verifies, or nil when none.</summary>
    class function ProcessCrlH(const ADeltaCrls: TCryptoLibGenericArray<IX509Crl>;
      const AKey: IAsymmetricKeyParameter): IX509Crl; static;

    /// <summary>RFC 5280 6.3.3 (i): set the status from the delta CRL.</summary>
    class procedure ProcessCrlI(AValidDate: TDateTime; const ADeltaCrl: IX509Crl;
      const ACert: IX509Certificate; const ACertStatus: ICertStatus); overload; static;
    /// <summary>RFC 3281: the attribute certificate variant of the above.</summary>
    class procedure ProcessCrlI(AValidDate: TDateTime; const ADeltaCrl: IX509Crl;
      const AAttrCert: IX509V2AttributeCertificate; const ACertStatus: ICertStatus); overload; static;

    /// <summary>RFC 5280 6.3.3 (j): set the status from the complete CRL.</summary>
    class procedure ProcessCrlJ(AValidDate: TDateTime; const ACompleteCrl: IX509Crl;
      const ACert: IX509Certificate; const ACertStatus: ICertStatus); overload; static;
    /// <summary>RFC 3281: the attribute certificate variant of the above.</summary>
    class procedure ProcessCrlJ(AValidDate: TDateTime; const ACompleteCrl: IX509Crl;
      const AAttrCert: IX509V2AttributeCertificate; const ACertStatus: ICertStatus); overload; static;

    /// <summary>
    /// RFC 5280 6.3.3: check ACert against every distribution point it names, and against any CRL
    /// issued by its issuer that no distribution point names.
    /// </summary>
    class procedure CheckCrls(const APkixParams: IPkixParameters; const ACert: IX509Certificate;
      ACurrentDate, AValidityDate: TDateTime; const ASign: IX509Certificate;
      const AWorkingPublicKey: IAsymmetricKeyParameter;
      const ACertPathCerts: TCryptoLibGenericArray<IX509Certificate>); static;

    /// <summary>RFC 5280 6.1.3 (a): signature, validity, revocation status and name chaining.</summary>
    class procedure ProcessCertA(const ACertPath: IPkixCertPath; const APkixParams: IPkixParameters;
      AValidityDate: TDateTime; const ARevocationChecker: IPkixCertRevocationChecker; AIndex: Int32;
      const AWorkingPublicKey: IAsymmetricKeyParameter; AVerificationAlreadyPerformed: Boolean;
      const AWorkingIssuerName: IX509Name; const ASign: IX509Certificate); static;

    /// <summary>RFC 5280 6.1.3 (b)(c): permitted and excluded name subtree checking.</summary>
    class procedure ProcessCertBC(const ACertPath: IPkixCertPath; AIndex: Int32;
      const ANameConstraintValidator: IPkixNameConstraintValidator; AIsForCrlCheck: Boolean); static;

    /// <summary>RFC 5280 6.1.3 (d): grow the valid policy tree from the certificate policies.</summary>
    class function ProcessCertD(const ACertPath: IPkixCertPath; AIndex: Int32;
      const AAcceptablePolicies: TList<String>; const AValidPolicyTree: IPkixPolicyNode;
      const APolicyNodes: TPkixPolicyNodeLevels; AInhibitAnyPolicy: Int32;
      AIsForCrlCheck: Boolean): IPkixPolicyNode; static;

    /// <summary>RFC 5280 6.1.3 (e): a certificate without policies clears the policy tree.</summary>
    class function ProcessCertE(const ACertPath: IPkixCertPath; AIndex: Int32;
      const AValidPolicyTree: IPkixPolicyNode): IPkixPolicyNode; static;

    /// <summary>RFC 5280 6.1.3 (f): an empty policy tree is only allowed without explicit policy.</summary>
    class procedure ProcessCertF(AIndex: Int32; const AValidPolicyTree: IPkixPolicyNode;
      AExplicitPolicy: Int32); static;

    /// <summary>RFC 5280 6.1.4 (a): neither side of a policy mapping may be anyPolicy.</summary>
    class procedure PrepareNextCertA(const ACertPath: IPkixCertPath; AIndex: Int32); static;

    /// <summary>RFC 5280 6.1.4 (b): apply the policy mappings to the valid policy tree.</summary>
    class function PrepareCertB(const ACertPath: IPkixCertPath; AIndex: Int32;
      const APolicyNodes: TPkixPolicyNodeLevels; const AValidPolicyTree: IPkixPolicyNode;
      APolicyMapping: Int32): IPkixPolicyNode; static;

    /// <summary>RFC 5280 6.1.4 (g): intersect the name constraints of the certificate.</summary>
    class procedure PrepareNextCertG(const ACertPath: IPkixCertPath; AIndex: Int32;
      const ANameConstraintValidator: IPkixNameConstraintValidator); static;

    /// <summary>RFC 5280 6.1.4 (h)(1): decrement explicitPolicy.</summary>
    class function PrepareNextCertH1(const ACertPath: IPkixCertPath; AIndex: Int32;
      AExplicitPolicy: Int32): Int32; static;
    /// <summary>RFC 5280 6.1.4 (h)(2): decrement policyMapping.</summary>
    class function PrepareNextCertH2(const ACertPath: IPkixCertPath; AIndex: Int32;
      APolicyMapping: Int32): Int32; static;
    /// <summary>RFC 5280 6.1.4 (h)(3): decrement inhibitAnyPolicy.</summary>
    class function PrepareNextCertH3(const ACertPath: IPkixCertPath; AIndex: Int32;
      AInhibitAnyPolicy: Int32): Int32; static;

    /// <summary>RFC 5280 6.1.4 (i)(1): apply requireExplicitPolicy.</summary>
    class function PrepareNextCertI1(const ACertPath: IPkixCertPath; AIndex: Int32;
      AExplicitPolicy: Int32): Int32; static;
    /// <summary>RFC 5280 6.1.4 (i)(2): apply inhibitPolicyMapping.</summary>
    class function PrepareNextCertI2(const ACertPath: IPkixCertPath; AIndex: Int32;
      APolicyMapping: Int32): Int32; static;

    /// <summary>RFC 5280 6.1.4 (j): apply the inhibit anyPolicy extension.</summary>
    class function PrepareNextCertJ(const ACertPath: IPkixCertPath; AIndex: Int32;
      AInhibitAnyPolicy: Int32): Int32; static;

    /// <summary>RFC 5280 6.1.4 (k): the certificate must be a CA certificate.</summary>
    class function PrepareNextCertK(const ACertPath: IPkixCertPath; AIndex: Int32): IBasicConstraints; static;

    /// <summary>RFC 5280 6.1.4 (l): consume one of the remaining path length.</summary>
    class function PrepareNextCertL(const ACertPath: IPkixCertPath; AIndex: Int32;
      AMaxPathLength: Int32): Int32; static;

    /// <summary>RFC 5280 6.1.4 (m): apply the path length constraint.</summary>
    class function PrepareNextCertM(const ACertPath: IPkixCertPath; AIndex: Int32;
      AMaxPathLength: Int32; const ACaBasicConstraints: IBasicConstraints): Int32; static;

    /// <summary>RFC 5280 6.1.4 (n): the certificate must be permitted to sign certificates.</summary>
    class procedure PrepareNextCertN(const ACertPath: IPkixCertPath; AIndex: Int32); static;

    /// <summary>RFC 5280 6.1.4 (o): run the extra checkers and reject unresolved critical extensions.</summary>
    class procedure PrepareNextCertO(const ACertPath: IPkixCertPath; AIndex: Int32;
      const ACriticalExtensions: TList<String>;
      const ACheckers: TCryptoLibGenericArray<IPkixCertPathChecker>); static;

    /// <summary>RFC 5280 6.1.5 (a): decrement explicitPolicy for the final certificate.</summary>
    class function WrapupCertA(AExplicitPolicy: Int32; const ACert: IX509Certificate): Int32; static;

    /// <summary>RFC 5280 6.1.5 (b): requireExplicitPolicy of 0 forces an explicit policy.</summary>
    class function WrapupCertB(const ACertPath: IPkixCertPath; AIndex: Int32;
      AExplicitPolicy: Int32): Int32; static;

    /// <summary>RFC 5280 6.1.5 (f): run the extra checkers on the final certificate.</summary>
    class procedure WrapupCertF(const ACertPath: IPkixCertPath; AIndex: Int32;
      const ACheckers: TCryptoLibGenericArray<IPkixCertPathChecker>;
      const ACriticalExtensions: TList<String>); static;

    /// <summary>
    /// RFC 5280 6.1.5 (g): intersect the valid policy tree with the user initial policy set.
    /// </summary>
    class function WrapupCertG(const ACertPath: IPkixCertPath; const APkixParams: IPkixParameters;
      const AUserInitialPolicySet: TCryptoLibStringArray; AIndex: Int32;
      const APolicyNodes: TPkixPolicyNodeLevels; const AValidPolicyTree: IPkixPolicyNode;
      const AAcceptablePolicies: TList<String>): IPkixPolicyNode; static;
  end;

implementation

uses
  ClpPkixCertPathBuilder;

const
  CrlReasonNames: array [0 .. 10] of String = ('unspecified', 'keyCompromise', 'cACompromise',
    'affiliationChanged', 'superseded', 'cessationOfOperation', 'certificateHold', 'unknown',
    'removeFromCRL', 'privilegeWithdrawn', 'aACompromise');

{ TRfc3280CertPathUtilities }

class function TRfc3280CertPathUtilities.CrlReasonName(AReason: Int32): String;
begin
  if (AReason >= 0) and (AReason <= System.High(CrlReasonNames)) then
    Result := CrlReasonNames[AReason]
  else
    Result := 'unknown';
end;

class function TRfc3280CertPathUtilities.ParseExtension(const AExtensionValue: IAsn1OctetString): IAsn1Object;
begin
  if AExtensionValue = nil then
    Result := nil
  else
    Result := TX509ExtensionUtilities.FromExtensionValue(AExtensionValue);
end;

class function TRfc3280CertPathUtilities.GetCertExtension(const ACert: IX509Certificate;
  const AOid: IDerObjectIdentifier; const AName: String): IAsn1Object;
begin
  try
    Result := ParseExtension(ACert.GetExtensionValue(AOid));
  except
    on E: Exception do
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SExtensionDecodeFailed, [AName, E.Message]);
  end;
end;

class function TRfc3280CertPathUtilities.GetCrlExtension(const ACrl: IX509Crl;
  const AOid: IDerObjectIdentifier; const AName: String): IAsn1Object;
begin
  try
    Result := ParseExtension(ACrl.GetExtensionValue(AOid));
  except
    on E: Exception do
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SExtensionDecodeFailed, [AName, E.Message]);
  end;
end;

class function TRfc3280CertPathUtilities.HasCertificatePolicy(const ACert: IX509Certificate;
  const APolicyOid: IDerObjectIdentifier): Boolean;
var
  LParsed: IAsn1Object;
  LPolicies: IAsn1Sequence;
  LIdx: Int32;
begin
  Result := False;

  LParsed := GetCertExtension(ACert, TX509Extensions.CertificatePolicies, 'certificate policies');
  if LParsed = nil then
    Exit;

  LPolicies := TAsn1Sequence.GetInstance(LParsed);
  for LIdx := 0 to LPolicies.Count - 1 do
  begin
    if TPolicyInformation.GetInstance(LPolicies[LIdx]).PolicyIdentifier.GetID() = APolicyOid.GetID() then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

class function TRfc3280CertPathUtilities.GetIssuingDistributionPoint(const ACrl: IX509Crl)
  : IIssuingDistributionPoint;
var
  LParsed: IAsn1Object;
begin
  LParsed := GetCrlExtension(ACrl, TX509Extensions.IssuingDistributionPoint, 'issuing distribution point');
  if LParsed = nil then
  begin
    Result := nil;
    Exit;
  end;

  try
    Result := TIssuingDistributionPoint.GetInstance(LParsed);
  except
    on E: Exception do
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SExtensionDecodeFailed,
        ['issuing distribution point', E.Message]);
  end;
end;

class function TRfc3280CertPathUtilities.GetCrlAuthorityKeyIdentifier(const ACrl: IX509Crl;
  const AName: String): IAuthorityKeyIdentifier;
begin
  try
    Result := TX509ExtensionUtilities.GetAuthorityKeyIdentifier(ACrl.CertificateList.TbsCertList.Extensions);
  except
    on E: Exception do
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SAuthorityKeyIdentifierFailed,
        [AName, E.Message]);
  end;
end;

class function TRfc3280CertPathUtilities.ReasonFlagsValue(const AFlags: IReasonFlags; ADefault: Int32): Int32;
var
  LBits: IDerBitString;
begin
  // ReasonFlags is a BIT STRING, so the flag word is reached through the bit string behaviour
  if (AFlags <> nil) and Supports(AFlags, IDerBitString, LBits) then
    Result := LBits.Int32Value
  else
    Result := ADefault;
end;

class function TRfc3280CertPathUtilities.GeneralNamesToString(const ANames
  : TCryptoLibGenericArray<IGeneralName>): String;
var
  LIdx: Int32;
begin
  Result := '';
  for LIdx := 0 to System.High(ANames) do
  begin
    if LIdx > 0 then
      Result := Result + ', ';
    if ANames[LIdx] <> nil then
      Result := Result + ANames[LIdx].ToString();
  end;
end;

class function TRfc3280CertPathUtilities.ContainsGeneralName(const ANames
  : TCryptoLibGenericArray<IGeneralName>; const AName: IGeneralName): Boolean;
var
  LIdx: Int32;
begin
  for LIdx := 0 to System.High(ANames) do
  begin
    if (ANames[LIdx] <> nil) and (AName <> nil) and ANames[LIdx].Equals(AName as IAsn1Convertible) then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := False;
end;

class function TRfc3280CertPathUtilities.ContainsString(const AValues: TCryptoLibStringArray;
  const AValue: String): Boolean;
var
  LIdx: Int32;
begin
  for LIdx := 0 to System.High(AValues) do
  begin
    if AValues[LIdx] = AValue then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := False;
end;

class procedure TRfc3280CertPathUtilities.AppendString(var AValues: TCryptoLibStringArray;
  const AValue: String);
begin
  System.SetLength(AValues, System.Length(AValues) + 1);
  AValues[System.High(AValues)] := AValue;
end;

class function TRfc3280CertPathUtilities.FindValidPolicy(const ANodes
  : TCryptoLibGenericArray<IPkixPolicyNode>; const APolicy: String): IPkixPolicyNode;
var
  LIdx: Int32;
begin
  for LIdx := 0 to System.High(ANodes) do
  begin
    if ANodes[LIdx].ValidPolicy = APolicy then
    begin
      Result := ANodes[LIdx];
      Exit;
    end;
  end;
  Result := nil;
end;

class function TRfc3280CertPathUtilities.AppendRelativeName(const ADn: IAsn1Sequence;
  const ARelativeName: IAsn1Encodable): IGeneralName;
var
  LElements: TCryptoLibGenericArray<IAsn1Encodable>;
  LIdx: Int32;
begin
  System.SetLength(LElements, ADn.Count + 1);
  for LIdx := 0 to ADn.Count - 1 do
  begin
    LElements[LIdx] := ADn[LIdx];
  end;
  LElements[ADn.Count] := ARelativeName;

  Result := TGeneralName.Create(TX509Name.GetInstance(TDerSequence.FromCollection(LElements)
    as IAsn1Convertible)) as IGeneralName;
end;

class procedure TRfc3280CertPathUtilities.DoProcessCrlB1(const ADistributionPoint: IDistributionPoint;
  const AIssuer: IX509Name; const ACrl: IX509Crl);
var
  LIdp: IIssuingDistributionPoint;
  LIsIndirect, LMatchIssuer: Boolean;
  LIssuerBytes: TCryptoLibByteArray;
  LGenNames: TCryptoLibGenericArray<IGeneralName>;
  LIdx: Int32;
begin
  LIdp := GetIssuingDistributionPoint(ACrl);
  LIsIndirect := (LIdp <> nil) and LIdp.IsIndirectCrl;

  LIssuerBytes := ACrl.IssuerDN.GetEncoded();
  LMatchIssuer := False;

  if ADistributionPoint.CrlIssuer <> nil then
  begin
    LGenNames := ADistributionPoint.CrlIssuer.GetNames();
    for LIdx := 0 to System.High(LGenNames) do
    begin
      if LGenNames[LIdx].TagNo <> TGeneralName.DirectoryName then
        Continue;

      try
        if TArrayUtilities.AreEqual(LGenNames[LIdx].Name.GetEncoded(), LIssuerBytes) then
          LMatchIssuer := True;
      except
        on E: Exception do
          raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SCrlIssuerReadFailed, [E.Message]);
      end;
    end;

    if LMatchIssuer and (not LIsIndirect) then
      raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SCrlIssuerNotIndirect);

    if not LMatchIssuer then
      raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SCrlIssuerMismatch);
  end
  else
  begin
    if ACrl.IssuerDN.Equivalent(AIssuer, True) then
      LMatchIssuer := True;
  end;

  if not LMatchIssuer then
    raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SNoMatchingCrlIssuer);
end;

class procedure TRfc3280CertPathUtilities.ProcessCrlB1(const ADistributionPoint: IDistributionPoint;
  const ACert: IX509Certificate; const ACrl: IX509Crl);
begin
  DoProcessCrlB1(ADistributionPoint, TPkixCertPathValidatorUtilities.GetIssuerPrincipal(ACert), ACrl);
end;

class procedure TRfc3280CertPathUtilities.ProcessCrlB1(const ADistributionPoint: IDistributionPoint;
  const AAttrCert: IX509V2AttributeCertificate; const ACrl: IX509Crl);
begin
  DoProcessCrlB1(ADistributionPoint, TPkixCertPathValidatorUtilities.GetIssuerPrincipal(AAttrCert), ACrl);
end;

class procedure TRfc3280CertPathUtilities.DoProcessCrlB2(const ADistributionPoint: IDistributionPoint;
  const AIssuer: IX509Name; const ABasicConstraintsValue: IAsn1OctetString; AIsCertificate: Boolean;
  const ACrl: IX509Crl);
var
  LIdp: IIssuingDistributionPoint;
  LIdpName, LDpName: IDistributionPointName;
  LIdpNames, LGenNames: TCryptoLibGenericArray<IGeneralName>;
  LIdx: Int32;
  LCrlIssuerDn: IAsn1Sequence;
  LMatches: Boolean;
  LBasicConstraints: IBasicConstraints;
  LParsed: IAsn1Object;
begin
  LIdp := GetIssuingDistributionPoint(ACrl);

  // (b)(2)(i) only applies when the IDP carries a distribution point name
  if LIdp = nil then
    Exit;

  LIdpName := LIdp.DistributionPoint;
  if LIdpName <> nil then
  begin
    LIdpNames := nil;

    if LIdpName.GetType() = TDistributionPointName.FullName then
      LIdpNames := TGeneralNames.GetInstance(LIdpName.GetName()).GetNames();

    if LIdpName.GetType() = TDistributionPointName.NameRelativeToCrlIssuer then
    begin
      try
        LCrlIssuerDn := TAsn1Sequence.GetInstance(ACrl.IssuerDN as IAsn1Convertible);
      except
        on E: Exception do
          raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SCrlIssuerReadFailed, [E.Message]);
      end;

      System.SetLength(LIdpNames, 1);
      LIdpNames[0] := AppendRelativeName(LCrlIssuerDn, LIdpName.GetName());
    end;

    LMatches := False;
    LDpName := ADistributionPoint.DistributionPointName;

    if LDpName <> nil then
    begin
      LGenNames := nil;

      if LDpName.GetType() = TDistributionPointName.FullName then
        LGenNames := TGeneralNames.GetInstance(LDpName.GetName()).GetNames();

      if LDpName.GetType() = TDistributionPointName.NameRelativeToCrlIssuer then
      begin
        if ADistributionPoint.CrlIssuer <> nil then
        begin
          LGenNames := ADistributionPoint.CrlIssuer.GetNames();
        end
        else
        begin
          System.SetLength(LGenNames, 1);
          try
            LGenNames[0] := TGeneralName.Create(AIssuer) as IGeneralName;
          except
            on E: Exception do
              raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SCertIssuerReadFailed, [E.Message]);
          end;
        end;

        // the relative name of the DP completes each of the cRLIssuer names
        for LIdx := 0 to System.High(LGenNames) do
        begin
          LGenNames[LIdx] := AppendRelativeName(TAsn1Sequence.GetInstance(LGenNames[LIdx]
            .Name.ToAsn1Object()), LDpName.GetName());
        end;
      end;

      for LIdx := 0 to System.High(LGenNames) do
      begin
        if ContainsGeneralName(LIdpNames, LGenNames[LIdx]) then
        begin
          LMatches := True;
          Break;
        end;
      end;

      if not LMatches then
        raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SNoIdpNameMatch,
          [GeneralNamesToString(LGenNames), GeneralNamesToString(LIdpNames)]);
    end
    else
    begin
      // with no distributionPoint field the IDP must match the cRLIssuer field instead
      if ADistributionPoint.CrlIssuer = nil then
        raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SDistributionPointFieldsOmitted);

      LGenNames := ADistributionPoint.CrlIssuer.GetNames();
      for LIdx := 0 to System.High(LGenNames) do
      begin
        if ContainsGeneralName(LIdpNames, LGenNames[LIdx]) then
        begin
          LMatches := True;
          Break;
        end;
      end;

      if not LMatches then
        raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SNoIdpNameMatch,
          [GeneralNamesToString(LGenNames), GeneralNamesToString(LIdpNames)]);
    end;
  end;

  LBasicConstraints := nil;
  try
    LParsed := ParseExtension(ABasicConstraintsValue);
    if LParsed <> nil then
      LBasicConstraints := TBasicConstraints.GetInstance(LParsed);
  except
    on E: Exception do
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SExtensionDecodeFailed,
        ['basic constraints', E.Message]);
  end;

  if AIsCertificate then
  begin
    if (LBasicConstraints <> nil) and LBasicConstraints.IsCA() then
    begin
      // (b)(2)(ii)
      if LIdp.OnlyContainsUserCerts then
        raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SCrlOnlyContainsUserCerts);
    end
    else
    begin
      // (b)(2)(iii)
      if LIdp.OnlyContainsCACerts then
        raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SCrlOnlyContainsCACerts);
    end;
  end;

  // (b)(2)(iv)
  if LIdp.OnlyContainsAttributeCerts then
    raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SCrlOnlyContainsAttributeCerts);
end;

class procedure TRfc3280CertPathUtilities.ProcessCrlB2(const ADistributionPoint: IDistributionPoint;
  const ACert: IX509Certificate; const ACrl: IX509Crl);
begin
  DoProcessCrlB2(ADistributionPoint, TPkixCertPathValidatorUtilities.GetIssuerPrincipal(ACert),
    ACert.GetExtensionValue(TX509Extensions.BasicConstraints), True, ACrl);
end;

class procedure TRfc3280CertPathUtilities.ProcessCrlB2(const ADistributionPoint: IDistributionPoint;
  const AAttrCert: IX509V2AttributeCertificate; const ACrl: IX509Crl);
begin
  DoProcessCrlB2(ADistributionPoint, TPkixCertPathValidatorUtilities.GetIssuerPrincipal(AAttrCert),
    AAttrCert.GetExtensionValue(TX509Extensions.BasicConstraints), False, ACrl);
end;

class procedure TRfc3280CertPathUtilities.ProcessCrlC(const ADeltaCrl, ACompleteCrl: IX509Crl);
var
  LCompleteIdp, LDeltaIdp: IIssuingDistributionPoint;
  LCompleteKeyId, LDeltaKeyId: IAuthorityKeyIdentifier;
  LIdpEqual: Boolean;
begin
  LCompleteIdp := GetIssuingDistributionPoint(ACompleteCrl);

  // (c)(1)
  if not ADeltaCrl.IssuerDN.Equivalent(ACompleteCrl.IssuerDN, True) then
    raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SDeltaCrlIssuerMismatch);

  // (c)(2)
  LDeltaIdp := GetIssuingDistributionPoint(ADeltaCrl);

  if (LCompleteIdp = nil) or (LDeltaIdp = nil) then
    LIdpEqual := (LCompleteIdp = nil) and (LDeltaIdp = nil)
  else
    LIdpEqual := LCompleteIdp.Equals(LDeltaIdp as IAsn1Convertible);

  if not LIdpEqual then
    raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SDeltaCrlIdpMismatch);

  // (c)(3)
  LCompleteKeyId := GetCrlAuthorityKeyIdentifier(ACompleteCrl, 'complete CRL');
  LDeltaKeyId := GetCrlAuthorityKeyIdentifier(ADeltaCrl, 'delta CRL');

  if LCompleteKeyId = nil then
    raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SAuthorityKeyIdentifierMissing, ['CRL']);

  if LDeltaKeyId = nil then
    raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SAuthorityKeyIdentifierMissing, ['delta CRL']);

  if not LCompleteKeyId.Equals(LDeltaKeyId as IAsn1Convertible) then
    raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SDeltaCrlAuthorityKeyIdentifierMismatch);
end;

class function TRfc3280CertPathUtilities.ProcessCrlD(const ACrl: IX509Crl;
  const ADistributionPoint: IDistributionPoint): IReasonsMask;
var
  LIdp: IIssuingDistributionPoint;
  LIdpFlags, LDpFlags: Int32;
begin
  LIdp := GetIssuingDistributionPoint(ACrl);

  // (d)(1..4) intersect the IDP and DP reasons; absent reasons mean all reasons
  if LIdp = nil then
    LIdpFlags := TReasonsMask.AllReasons
  else
    LIdpFlags := ReasonFlagsValue(LIdp.OnlySomeReasons, TReasonsMask.AllReasons);

  LDpFlags := ReasonFlagsValue(ADistributionPoint.Reasons, TReasonsMask.AllReasons);

  Result := TReasonsMask.Create(LIdpFlags and LDpFlags) as IReasonsMask;
end;

class function TRfc3280CertPathUtilities.CrlSignerEnter(const ACert: IX509Certificate): Boolean;
begin
  if FCrlSignersInProgress = nil then
    FCrlSignersInProgress := TCryptoLibHashSet<IX509Certificate>.Create
      (TX509Comparers.CertificateEqualityComparer);

  // False when the certificate is already in progress further up this stack
  Result := FCrlSignersInProgress.Add(ACert);
end;

class procedure TRfc3280CertPathUtilities.CrlSignerExit(const ACert: IX509Certificate);
begin
  if FCrlSignersInProgress = nil then
    Exit;

  FCrlSignersInProgress.Remove(ACert);

  if FCrlSignersInProgress.Count < 1 then
  begin
    FCrlSignersInProgress.Free;
    FCrlSignersInProgress := nil;
  end;
end;

class function TRfc3280CertPathUtilities.ContainsCertificate(const ACerts
  : TCryptoLibGenericArray<IX509Certificate>; const ACert: IX509Certificate): Boolean;
var
  LIdx: Int32;
begin
  for LIdx := 0 to System.High(ACerts) do
  begin
    if ACerts[LIdx].Equals(ACert) then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := False;
end;

class procedure TRfc3280CertPathUtilities.AppendCertificate(var ACerts
  : TCryptoLibGenericArray<IX509Certificate>; const ACert: IX509Certificate);
begin
  System.SetLength(ACerts, System.Length(ACerts) + 1);
  ACerts[System.High(ACerts)] := ACert;
end;

class procedure TRfc3280CertPathUtilities.AppendKey(var AKeys
  : TCryptoLibGenericArray<IAsymmetricKeyParameter>; const AKey: IAsymmetricKeyParameter);
begin
  System.SetLength(AKeys, System.Length(AKeys) + 1);
  AKeys[System.High(AKeys)] := AKey;
end;

class function TRfc3280CertPathUtilities.ProcessCrlF(const ACrl: IX509Crl;
  const ADefaultCrlSignCert: IX509Certificate; const ADefaultCrlSignKey: IAsymmetricKeyParameter;
  const APkixParams: IPkixParameters; const ACertPathCerts: TCryptoLibGenericArray<IX509Certificate>)
  : TCryptoLibGenericArray<IAsymmetricKeyParameter>;
var
  LSelector: IX509CertStoreSelector;
  LCrlAki: IAuthorityKeyIdentifier;
  LStores: TCryptoLibGenericArray<IStore<IX509Certificate>>;
  LMatches, LSigningCerts, LValidCerts, LBuiltCerts: TCryptoLibGenericArray<IX509Certificate>;
  LValidKeys: TCryptoLibGenericArray<IAsymmetricKeyParameter>;
  LOuter, LInner: Int32;
  LSigningCert: IX509Certificate;
  LParameters: IPkixBuilderParameters;
  LKeyUsage: TCryptoLibBooleanArray;
  LSignerLastMessage: String;
  LKeyUsageRejected, LSeen: Boolean;
begin
  // (f) narrow the candidate signers to the certificates that could have issued the CRL
  LSelector := TX509CertStoreSelector.Create() as IX509CertStoreSelector;
  try
    LSelector.Subject := ACrl.IssuerDN;

    // RFC 5280 5.2.1: an authority key identifier with a keyIdentifier narrows the candidate set,
    // which keeps trust anchors that share an issuer name from fanning out combinatorially
    LCrlAki := GetCrlAuthorityKeyIdentifier(ACrl, 'CRL');
    if (LCrlAki <> nil) and (LCrlAki.KeyIdentifier <> nil) then
      LSelector.SubjectKeyIdentifier := LCrlAki.KeyIdentifier.GetEncoded(TAsn1Encodable.Der);
  except
    on E: Exception do
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SCrlSignerCriteriaFailed, [E.Message]);
  end;

  LSigningCerts := nil;
  LStores := APkixParams.GetStoresCert();
  for LOuter := 0 to System.High(LStores) do
  begin
    try
      LMatches := LStores[LOuter].EnumerateMatches(LSelector);
    except
      on E: Exception do
        raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SCrlSignerSearchFailed, [E.Message]);
    end;

    for LInner := 0 to System.High(LMatches) do
    begin
      if not ContainsCertificate(LSigningCerts, LMatches[LInner]) then
        AppendCertificate(LSigningCerts, LMatches[LInner]);
    end;
  end;

  if not ContainsCertificate(LSigningCerts, ADefaultCrlSignCert) then
    AppendCertificate(LSigningCerts, ADefaultCrlSignCert);

  LValidCerts := nil;
  LValidKeys := nil;
  LSignerLastMessage := '';

  for LOuter := 0 to System.High(LSigningCerts) do
  begin
    LSigningCert := LSigningCerts[LOuter];

    // the issuer of the checked certificate has already been validated as part of the path
    if LSigningCert.Equals(ADefaultCrlSignCert) then
    begin
      AppendCertificate(LValidCerts, LSigningCert);
      AppendKey(LValidKeys, ADefaultCrlSignKey);
      Continue;
    end;

    // a candidate already being validated further up the stack is treated as a self-signed root,
    // otherwise candidates that share a subject name would recurse forever
    if not CrlSignerEnter(LSigningCert) then
    begin
      AppendCertificate(LValidCerts, LSigningCert);
      AppendKey(LValidKeys, LSigningCert.GetPublicKey());
      Continue;
    end;

    try
      try
        LSelector := TX509CertStoreSelector.Create() as IX509CertStoreSelector;
        LSelector.Certificate := LSigningCert;

        LParameters := TPkixBuilderParameters.GetInstance(APkixParams);
        LParameters.SetTargetConstraintsCert(LSelector);

        // the CRL of a signer already on the path can only be checked with revocation disabled,
        // otherwise checking it would depend on itself; forgery is still caught by the outer loop
        LParameters.IsRevocationEnabled := not ContainsCertificate(ACertPathCerts, LSigningCert);

        LBuiltCerts := (TPkixCertPathBuilder.Create(True) as IPkixCertPathBuilder)
          .Build(LParameters).CertPath.Certificates;
        AppendCertificate(LValidCerts, LSigningCert);
        AppendKey(LValidKeys, TPkixCertPathValidatorUtilities.GetNextWorkingKey(LBuiltCerts, 0));
      except
        on E: Exception do
          // this candidate is skipped; the post-loop check reports when no signer validated at all
          LSignerLastMessage := E.Message;
      end;
    finally
      CrlSignerExit(LSigningCert);
    end;
  end;

  if (System.Length(LValidCerts) < 1) and (LSignerLastMessage <> '') then
    raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SCrlSignerPathFailed,
      [LSignerLastMessage]);

  Result := nil;
  LKeyUsageRejected := False;

  for LOuter := 0 to System.High(LValidCerts) do
  begin
    LKeyUsage := LValidCerts[LOuter].GetKeyUsage();

    if (LKeyUsage <> nil) and ((System.Length(LKeyUsage) <= TPkixCertPathValidatorUtilities.CrlSign) or
      (not LKeyUsage[TPkixCertPathValidatorUtilities.CrlSign])) then
    begin
      LKeyUsageRejected := True;
      Continue;
    end;

    LSeen := False;
    for LInner := 0 to System.High(Result) do
    begin
      if Result[LInner] = LValidKeys[LOuter] then
      begin
        LSeen := True;
        Break;
      end;
    end;

    if not LSeen then
      AppendKey(Result, LValidKeys[LOuter]);
  end;

  if System.Length(Result) < 1 then
  begin
    if LKeyUsageRejected then
      raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SCrlSignerKeyUsage);
    raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SNoValidCrlIssuer);
  end;
end;

class function TRfc3280CertPathUtilities.ProcessCrlG(const ACrl: IX509Crl;
  const AKeys: TCryptoLibGenericArray<IAsymmetricKeyParameter>): IAsymmetricKeyParameter;
var
  LIdx: Int32;
  LLastMessage: String;
begin
  LLastMessage := '';
  for LIdx := 0 to System.High(AKeys) do
  begin
    try
      ACrl.Verify(AKeys[LIdx]);
      Result := AKeys[LIdx];
      Exit;
    except
      on E: Exception do
        LLastMessage := E.Message;
    end;
  end;

  raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SCannotVerifyCrl, [LLastMessage]);
end;

class function TRfc3280CertPathUtilities.ProcessCrlH(const ADeltaCrls: TCryptoLibGenericArray<IX509Crl>;
  const AKey: IAsymmetricKeyParameter): IX509Crl;
var
  LIdx: Int32;
  LLastMessage: String;
begin
  LLastMessage := '';
  for LIdx := 0 to System.High(ADeltaCrls) do
  begin
    try
      ADeltaCrls[LIdx].Verify(AKey);
      Result := ADeltaCrls[LIdx];
      Exit;
    except
      on E: Exception do
        LLastMessage := E.Message;
    end;
  end;

  if LLastMessage <> '' then
    raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SCannotVerifyDeltaCrl, [LLastMessage]);

  Result := nil;
end;

class procedure TRfc3280CertPathUtilities.ProcessCrlI(AValidDate: TDateTime; const ADeltaCrl: IX509Crl;
  const ACert: IX509Certificate; const ACertStatus: ICertStatus);
begin
  TPkixCertPathValidatorUtilities.GetCertStatus(AValidDate, ADeltaCrl, ACert, ACertStatus);
end;

class procedure TRfc3280CertPathUtilities.ProcessCrlI(AValidDate: TDateTime; const ADeltaCrl: IX509Crl;
  const AAttrCert: IX509V2AttributeCertificate; const ACertStatus: ICertStatus);
begin
  TPkixCertPathValidatorUtilities.GetCertStatus(AValidDate, ADeltaCrl, AAttrCert, ACertStatus);
end;

class procedure TRfc3280CertPathUtilities.ProcessCrlJ(AValidDate: TDateTime; const ACompleteCrl: IX509Crl;
  const ACert: IX509Certificate; const ACertStatus: ICertStatus);
begin
  if ACertStatus.Status = TCertStatus.Unrevoked then
    TPkixCertPathValidatorUtilities.GetCertStatus(AValidDate, ACompleteCrl, ACert, ACertStatus);
end;

class procedure TRfc3280CertPathUtilities.ProcessCrlJ(AValidDate: TDateTime; const ACompleteCrl: IX509Crl;
  const AAttrCert: IX509V2AttributeCertificate; const ACertStatus: ICertStatus);
begin
  if ACertStatus.Status = TCertStatus.Unrevoked then
    TPkixCertPathValidatorUtilities.GetCertStatus(AValidDate, ACompleteCrl, AAttrCert, ACertStatus);
end;

class procedure TRfc3280CertPathUtilities.CheckCrl(const ADistributionPoint: IDistributionPoint;
  const APkixParams: IPkixParameters; ACurrentDate, AValidityDate: TDateTime;
  const ACert, ADefaultCrlSignCert: IX509Certificate; const ADefaultCrlSignKey: IAsymmetricKeyParameter;
  const ACertStatus: ICertStatus; const AReasonsMask: IReasonsMask;
  const ACertPathCerts: TCryptoLibGenericArray<IX509Certificate>);
var
  LCrls, LDeltaCrls: TCryptoLibGenericArray<IX509Crl>;
  LIdx: Int32;
  LCrl, LDeltaCrl: IX509Crl;
  LInterimReasonsMask: IReasonsMask;
  LKeys: TCryptoLibGenericArray<IAsymmetricKeyParameter>;
  LKey: IAsymmetricKeyParameter;
  LValidCrlFound: Boolean;
  LLastMessage: String;
begin
  if AValidityDate > ACurrentDate then
    raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SValidationTimeInFuture);

  // (a) timely valid CRLs are always used, so there is no step (a)(1) here: locally cached CRLs are
  // assumed to be in the configured CRL stores
  LCrls := TPkixCertPathValidatorUtilities.GetCompleteCrls(ADistributionPoint, ACert, APkixParams,
    AValidityDate);

  LValidCrlFound := False;
  LLastMessage := '';

  for LIdx := 0 to System.High(LCrls) do
  begin
    if (ACertStatus.Status <> TCertStatus.Unrevoked) or AReasonsMask.IsAllReasons then
      Break;

    LCrl := LCrls[LIdx];

    try
      TPkixCertPathValidatorUtilities.CheckCrlCriticalExtensions(LCrl);

      // (d)
      LInterimReasonsMask := ProcessCrlD(LCrl, ADistributionPoint);

      // (e) only a valid CRL may update the reasons mask, so a CRL without new reasons is ignored
      if not AReasonsMask.HasNewReasons(LInterimReasonsMask) then
        Continue;

      // (f)
      LKeys := ProcessCrlF(LCrl, ADefaultCrlSignCert, ADefaultCrlSignKey, APkixParams, ACertPathCerts);

      // (g)
      LKey := ProcessCrlG(LCrl, LKeys);

      // under the chain validity model a signature stays valid past expiry, so the certificate does
      // not have to lie inside the CRL validity time
      if APkixParams.ValidityModel <> TPkixParameters.ChainValidityModel then
      begin
        // an expired certificate drops off the CRL, so without this check a certificate that was
        // revoked and has since expired would be reported as valid
        if ACert.NotAfter < LCrl.ThisUpdate then
          raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SNoValidCrlForCurrentTime);
      end;

      // (b)(1)
      ProcessCrlB1(ADistributionPoint, ACert, LCrl);

      // (b)(2)
      ProcessCrlB2(ADistributionPoint, ACert, LCrl);

      if APkixParams.IsUseDeltasEnabled then
      begin
        LDeltaCrls := TPkixCertPathValidatorUtilities.GetDeltaCrls(AValidityDate, APkixParams, LCrl);

        // (h) only one valid delta CRL is wanted
        LDeltaCrl := ProcessCrlH(LDeltaCrls, LKey);
        if LDeltaCrl <> nil then
        begin
          TPkixCertPathValidatorUtilities.CheckCrlCriticalExtensions(LDeltaCrl);

          // (c)
          ProcessCrlC(LDeltaCrl, LCrl);

          // (i)
          ProcessCrlI(AValidityDate, LDeltaCrl, ACert, ACertStatus);
        end;
      end;

      // (j)
      ProcessCrlJ(AValidityDate, LCrl, ACert, ACertStatus);

      // (k)
      if ACertStatus.Status = TCrlReason.RemoveFromCrl then
        ACertStatus.Status := TCertStatus.Unrevoked;

      AReasonsMask.AddReasons(LInterimReasonsMask);
      LValidCrlFound := True;
    except
      on E: Exception do
        LLastMessage := E.Message;
    end;
  end;

  if not LValidCrlFound then
  begin
    if LLastMessage = '' then
      raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SNoValidCrlFound);
    raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SCrlCheckFailed, [LLastMessage]);
  end;
end;

class procedure TRfc3280CertPathUtilities.CheckCrls(const APkixParams: IPkixParameters;
  const ACert: IX509Certificate; ACurrentDate, AValidityDate: TDateTime; const ASign: IX509Certificate;
  const AWorkingPublicKey: IAsymmetricKeyParameter;
  const ACertPathCerts: TCryptoLibGenericArray<IX509Certificate>);
var
  LCrlDistPoint: ICrlDistPoint;
  LParsed: IAsn1Object;
  LPkixParamsCrlDp, LPkixParamsClone: IPkixParameters;
  LCertStatus: ICertStatus;
  LReasonsMask: IReasonsMask;
  LDistributionPoints: TCryptoLibGenericArray<IDistributionPoint>;
  LDistributionPoint: IDistributionPoint;
  LIdx: Int32;
  LValidCrlFound: Boolean;
  LLastMessage, LFormattedDate: String;
  LIssuer: IX509Name;
begin
  LCrlDistPoint := nil;
  LParsed := GetCertExtension(ACert, TX509Extensions.CrlDistributionPoints, 'CRL distribution point');
  if LParsed <> nil then
  begin
    try
      LCrlDistPoint := TCrlDistPoint.GetInstance(LParsed);
    except
      on E: Exception do
        raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SExtensionDecodeFailed,
          ['CRL distribution point', E.Message]);
    end;
  end;

  // the distribution point parameters are always a copy, even when no store is added to them
  LPkixParamsCrlDp := APkixParams.Clone();
  try
    TPkixCertPathValidatorUtilities.AddAdditionalStoresFromCrlDistributionPoint(LCrlDistPoint,
      LPkixParamsCrlDp);
  except
    on E: Exception do
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SAdditionalCrlLocationsFailed, [E.Message]);
  end;

  LCertStatus := TCertStatus.Create() as ICertStatus;
  LReasonsMask := TReasonsMask.Create() as IReasonsMask;

  LValidCrlFound := False;
  LLastMessage := '';

  if LCrlDistPoint <> nil then
  begin
    try
      LDistributionPoints := LCrlDistPoint.GetDistributionPoints();
    except
      on E: Exception do
        raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SDistributionPointsReadFailed, [E.Message]);
    end;

    LIdx := 0;
    while (LIdx <= System.High(LDistributionPoints)) and
      (LCertStatus.Status = TCertStatus.Unrevoked) and (not LReasonsMask.IsAllReasons) do
    begin
      try
        CheckCrl(LDistributionPoints[LIdx], LPkixParamsCrlDp, ACurrentDate, AValidityDate, ACert,
          ASign, AWorkingPublicKey, LCertStatus, LReasonsMask, ACertPathCerts);
        LValidCrlFound := True;
      except
        on E: Exception do
          LLastMessage := E.Message;
      end;
      System.Inc(LIdx);
    end;
  end;

  // when the status is still undetermined, repeat with any CRL issued by the certificate issuer
  // that no distribution point names
  if (LCertStatus.Status = TCertStatus.Unrevoked) and (not LReasonsMask.IsAllReasons) then
  begin
    try
      // assume a distribution point with the reasons and cRLIssuer fields omitted and a
      // distribution point name of the certificate issuer
      LIssuer := TPkixCertPathValidatorUtilities.GetIssuerPrincipal(ACert);
      LDistributionPoint := TDistributionPoint.Create(TDistributionPointName.Create
        (TGeneralNames.Create(TGeneralName.Create(TGeneralName.DirectoryName, LIssuer as IAsn1Encodable)
        as IGeneralName) as IGeneralNames) as IDistributionPointName, nil, nil) as IDistributionPoint;

      LPkixParamsClone := APkixParams.Clone();
      CheckCrl(LDistributionPoint, LPkixParamsClone, ACurrentDate, AValidityDate, ACert, ASign,
        AWorkingPublicKey, LCertStatus, LReasonsMask, ACertPathCerts);
      LValidCrlFound := True;
    except
      on E: Exception do
        LLastMessage := E.Message;
    end;
  end;

  if not LValidCrlFound then
  begin
    if LLastMessage = '' then
      raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SNoValidCrlFound);
    raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SCrlCheckFailed, [LLastMessage]);
  end;

  if LCertStatus.Status <> TCertStatus.Unrevoked then
  begin
    LFormattedDate := '';
    if LCertStatus.RevocationDate.HasValue then
      LFormattedDate := TPkixCertPathValidatorUtilities.FormatUtcInstant
        (LCertStatus.RevocationDate.Value);

    raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SCertificateRevoked,
      [LFormattedDate, CrlReasonName(LCertStatus.Status)]);
  end;

  if (LCertStatus.Status = TCertStatus.Unrevoked) and (not LReasonsMask.IsAllReasons) then
    LCertStatus.Status := TCertStatus.Undetermined;

  if LCertStatus.Status = TCertStatus.Undetermined then
    raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SCertStatusUndetermined);
end;

class procedure TRfc3280CertPathUtilities.ProcessCertA(const ACertPath: IPkixCertPath;
  const APkixParams: IPkixParameters; AValidityDate: TDateTime;
  const ARevocationChecker: IPkixCertRevocationChecker; AIndex: Int32;
  const AWorkingPublicKey: IAsymmetricKeyParameter; AVerificationAlreadyPerformed: Boolean;
  const AWorkingIssuerName: IX509Name; const ASign: IX509Certificate);
var
  LCerts: TCryptoLibGenericArray<IX509Certificate>;
  LCert: IX509Certificate;
  LValidityDate: TDateTime;
  LIssuer: IX509Name;
begin
  LCerts := ACertPath.Certificates;
  LCert := LCerts[AIndex];

  // (a)(1) verify the signature
  if not AVerificationAlreadyPerformed then
  begin
    try
      LCert.Verify(AWorkingPublicKey);
    except
      on E: Exception do
        raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SSignatureValidationFailed, [E.Message]);
    end;
  end;

  try
    LValidityDate := TPkixCertPathValidatorUtilities.GetValidCertDateFromValidityModel(AValidityDate,
      APkixParams.ValidityModel, ACertPath, AIndex);
  except
    on E: Exception do
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SValidityTimeFailed, [E.Message]);
  end;

  // (a)(2) the certificate must be valid at that time
  try
    LCert.CheckValidity(LValidityDate);
  except
    on E: Exception do
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SCertificateValidityFailed, [E.Message]);
  end;

  // (a)(3) revocation status, settled by whatever mechanisms the checker holds. The checker
  // attributes its own failures to this position in the path.
  if ARevocationChecker <> nil then
  begin
    ARevocationChecker.Initialize(TPkixCertRevocationCheckerParameters.Create(APkixParams,
      LValidityDate, ACertPath, AIndex, ASign, AWorkingPublicKey)
      as IPkixCertRevocationCheckerParameters);
    ARevocationChecker.Check(LCert);
  end;

  // (a)(4) name chaining
  LIssuer := TPkixCertPathValidatorUtilities.GetIssuerPrincipal(LCert);
  if not LIssuer.Equivalent(AWorkingIssuerName, True) then
    raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SNameChainingFailed,
      [LIssuer.ToString(), AWorkingIssuerName.ToString()]);
end;

class procedure TRfc3280CertPathUtilities.ProcessCertBC(const ACertPath: IPkixCertPath; AIndex: Int32;
  const ANameConstraintValidator: IPkixNameConstraintValidator; AIsForCrlCheck: Boolean);
var
  LCerts: TCryptoLibGenericArray<IX509Certificate>;
  LCert, LIssuerCert: IX509Certificate;
  LCount, LDepth, LIdx: Int32;
  LPrincipal: IX509Name;
  LAltName: IGeneralNames;
  LGenNames: TCryptoLibGenericArray<IGeneralName>;
  LEmails: TCryptoLibStringArray;
  LSgp22: Boolean;
begin
  LCerts := ACertPath.Certificates;
  LCert := LCerts[AIndex];
  LCount := System.Length(LCerts);
  // the depth as named in RFC 5280 6.1
  LDepth := LCount - AIndex;

  // (b)(c) permitted and excluded subtree checking. RFC 5280 4.2.1.10: name constraints are not
  // applied to a self-issued certificate unless it ends the path; a CRL check never ends the path
  if ((LDepth < LCount) or AIsForCrlCheck) and TPkixCertPathValidatorUtilities.IsSelfIssued(LCert) then
    Exit;

  LPrincipal := LCert.SubjectDN;

  // GSMA SGP.22: an eUICC subject issued by an EUM gets the relaxed directoryName matching for this
  // one check. Both markers are required, since it is the issuer's EUM role that authorises the
  // relaxation; the trust anchor is not in the path and is never an EUM. The subject marker is
  // tested first so an ordinary chain never pays for the issuer lookup.
  LSgp22 := False;
  if AIndex + 1 < LCount then
  begin
    LIssuerCert := LCerts[AIndex + 1];
    try
      LSgp22 := HasCertificatePolicy(LCert, TGsmaObjectIdentifiers.IdRspRoleEuicc) and
        HasCertificatePolicy(LIssuerCert, TGsmaObjectIdentifiers.IdRspRoleEum);
    except
      // a malformed policies extension falls back to strict matching (fail closed, never relaxed)
      // and is reported by the later policy processing step instead
      on E: Exception do
        LSgp22 := False;
    end;
  end;

  try
    if LSgp22 then
      ANameConstraintValidator.CheckDNSgp22(LPrincipal)
    else
      ANameConstraintValidator.CheckDN(LPrincipal);
  except
    on E: Exception do
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SSubtreeCheckFailed,
        ['subject', E.Message]);
  end;

  try
    LAltName := LCert.GetSubjectAlternativeNameExtension();
  except
    on E: Exception do
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SExtensionDecodeFailed,
        ['subject alternative name', E.Message]);
  end;

  // every emailAddress of the subject DN is constrained as an rfc822Name, including the ones held
  // in a multi-valued RDN alongside other attribute types
  LEmails := nil;
  if LPrincipal <> nil then
    LEmails := LPrincipal.GetValues(TX509Name.EmailAddress);

  for LIdx := 0 to System.High(LEmails) do
  begin
    try
      ANameConstraintValidator.CheckEmail(LEmails[LIdx]);
    except
      on E: Exception do
        raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SSubtreeCheckFailed,
          ['subject alternative email', E.Message]);
    end;
  end;

  if LAltName = nil then
    Exit;

  try
    LGenNames := LAltName.GetNames();
  except
    on E: Exception do
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SExtensionContentsDecodeFailed,
        ['subject alternative name', E.Message]);
  end;

  for LIdx := 0 to System.High(LGenNames) do
  begin
    try
      ANameConstraintValidator.CheckName(LGenNames[LIdx]);
    except
      on E: Exception do
        raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SSubtreeCheckFailed,
          ['subject alternative name', E.Message]);
    end;
  end;
end;

class procedure TRfc3280CertPathUtilities.PrepareNextCertA(const ACertPath: IPkixCertPath; AIndex: Int32);
var
  LCert: IX509Certificate;
  LParsed: IAsn1Object;
  LMappings, LMapping: IAsn1Sequence;
  LIdx: Int32;
  LIssuerDomainPolicy, LSubjectDomainPolicy: IDerObjectIdentifier;
begin
  LCert := ACertPath.Certificates[AIndex];

  // (a) check the policy mappings
  LParsed := GetCertExtension(LCert, TX509Extensions.PolicyMappings, 'policy mappings');
  if LParsed = nil then
    Exit;

  try
    LMappings := TAsn1Sequence.GetInstance(LParsed);
  except
    on E: Exception do
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SExtensionDecodeFailed,
        ['policy mappings', E.Message]);
  end;

  for LIdx := 0 to LMappings.Count - 1 do
  begin
    try
      LMapping := TAsn1Sequence.GetInstance(LMappings[LIdx]);
      LIssuerDomainPolicy := TDerObjectIdentifier.GetInstance(LMapping[0]);
      LSubjectDomainPolicy := TDerObjectIdentifier.GetInstance(LMapping[1]);
    except
      on E: Exception do
        raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SExtensionContentsDecodeFailed,
          ['policy mappings', E.Message]);
    end;

    if LIssuerDomainPolicy.GetID() = AnyPolicy then
      raise EPkixCertPathValidatorCryptoLibException.CreateResAt(AIndex, @SIssuerDomainPolicyIsAnyPolicy);

    if LSubjectDomainPolicy.GetID() = AnyPolicy then
      raise EPkixCertPathValidatorCryptoLibException.CreateResAt(AIndex, @SSubjectDomainPolicyIsAnyPolicy);
  end;
end;

class function TRfc3280CertPathUtilities.ProcessCertD(const ACertPath: IPkixCertPath; AIndex: Int32;
  const AAcceptablePolicies: TList<String>; const AValidPolicyTree: IPkixPolicyNode;
  const APolicyNodes: TPkixPolicyNodeLevels; AInhibitAnyPolicy: Int32;
  AIsForCrlCheck: Boolean): IPkixPolicyNode;
var
  LCerts: TCryptoLibGenericArray<IX509Certificate>;
  LCert: IX509Certificate;
  LCount, LDepth, LIdx, LNodeIdx, LPolicyIdx: Int32;
  LParsed: IAsn1Object;
  LCertPolicies: IAsn1Sequence;
  LPolicyInformation: IPolicyInformation;
  LPolicyOid: IDerObjectIdentifier;
  LQualifiers: TCryptoLibGenericArray<IPolicyQualifierInfo>;
  LPols, LRetained, LChildExpectedPolicies, LExpectedPolicies: TCryptoLibStringArray;
  LNode, LChild: IPkixPolicyNode;
  LValidPolicyTree: IPkixPolicyNode;
begin
  LCerts := ACertPath.Certificates;
  LCert := LCerts[AIndex];
  LCount := System.Length(LCerts);
  LDepth := LCount - AIndex;
  LValidPolicyTree := AValidPolicyTree;

  // (d) policy information checked against the initial policies and the policy mappings
  LParsed := GetCertExtension(LCert, TX509Extensions.CertificatePolicies, 'certificate policies');

  if (LParsed = nil) or (LValidPolicyTree = nil) then
  begin
    Result := nil;
    Exit;
  end;

  try
    LCertPolicies := TAsn1Sequence.GetInstance(LParsed);
  except
    on E: Exception do
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SExtensionDecodeFailed,
        ['certificate policies', E.Message]);
  end;

  // (d)(1)
  LPols := nil;
  for LIdx := 0 to LCertPolicies.Count - 1 do
  begin
    LPolicyInformation := TPolicyInformation.GetInstance(LCertPolicies[LIdx]);
    LPolicyOid := LPolicyInformation.PolicyIdentifier;

    if not ContainsString(LPols, LPolicyOid.GetID()) then
    begin
      System.SetLength(LPols, System.Length(LPols) + 1);
      LPols[System.High(LPols)] := LPolicyOid.GetID();
    end;

    if LPolicyOid.GetID() = AnyPolicy then
      Continue;

    try
      LQualifiers := TPkixCertPathValidatorUtilities.GetQualifierSet(LPolicyInformation.PolicyQualifiers);
    except
      on E: Exception do
        raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SPolicyQualifierSetFailed, [E.Message]);
    end;

    if not TPkixCertPathValidatorUtilities.ProcessCertD1i(LDepth, APolicyNodes, LPolicyOid, LQualifiers) then
      TPkixCertPathValidatorUtilities.ProcessCertD1ii(LDepth, APolicyNodes, LPolicyOid, LQualifiers);
  end;

  if (AAcceptablePolicies.Count < 1) or AAcceptablePolicies.Contains(AnyPolicy) then
  begin
    AAcceptablePolicies.Clear;
    for LIdx := 0 to System.High(LPols) do
    begin
      AAcceptablePolicies.Add(LPols[LIdx]);
    end;
  end
  else
  begin
    LRetained := nil;
    for LIdx := 0 to AAcceptablePolicies.Count - 1 do
    begin
      if ContainsString(LPols, AAcceptablePolicies[LIdx]) then
        AppendString(LRetained, AAcceptablePolicies[LIdx]);
    end;

    AAcceptablePolicies.Clear;
    for LIdx := 0 to System.High(LRetained) do
    begin
      AAcceptablePolicies.Add(LRetained[LIdx]);
    end;
  end;

  // (d)(2) anyPolicy expands the tree while it is not inhibited
  if (AInhibitAnyPolicy > 0) or (((LDepth < LCount) or AIsForCrlCheck) and
    TPkixCertPathValidatorUtilities.IsSelfIssued(LCert)) then
  begin
    for LIdx := 0 to LCertPolicies.Count - 1 do
    begin
      LPolicyInformation := TPolicyInformation.GetInstance(LCertPolicies[LIdx]);
      if LPolicyInformation.PolicyIdentifier.GetID() <> AnyPolicy then
        Continue;

      LQualifiers := TPkixCertPathValidatorUtilities.GetQualifierSet(LPolicyInformation.PolicyQualifiers);

      for LNodeIdx := 0 to APolicyNodes[LDepth - 1].Count - 1 do
      begin
        LNode := APolicyNodes[LDepth - 1][LNodeIdx];
        LExpectedPolicies := LNode.ExpectedPolicies;

        for LPolicyIdx := 0 to System.High(LExpectedPolicies) do
        begin
          if FindValidPolicy(LNode.Children, LExpectedPolicies[LPolicyIdx]) <> nil then
          begin
            Continue;
          end;

          System.SetLength(LChildExpectedPolicies, 1);
          LChildExpectedPolicies[0] := LExpectedPolicies[LPolicyIdx];

          LChild := TPkixPolicyNode.Create(nil, LDepth, LChildExpectedPolicies, LNode, LQualifiers,
            LExpectedPolicies[LPolicyIdx], False) as IPkixPolicyNode;
          LNode.AddChild(LChild);
          APolicyNodes[LDepth].Add(LChild);
        end;
      end;

      Break;
    end;
  end;

  // (d)(3)
  LValidPolicyTree := TPkixCertPathValidatorUtilities.RemoveChildlessPolicyNodes(LValidPolicyTree,
    APolicyNodes, LDepth);

  // (d)(4)
  if TPkixCertPathValidatorUtilities.HasCriticalExtension(LCert, TX509Extensions.CertificatePolicies) then
  begin
    for LNodeIdx := 0 to APolicyNodes[LDepth].Count - 1 do
    begin
      APolicyNodes[LDepth][LNodeIdx].IsCritical := True;
    end;
  end;

  TPkixCertPathValidatorUtilities.CheckPolicyTreeSize(APolicyNodes);

  Result := LValidPolicyTree;
end;

class function TRfc3280CertPathUtilities.ProcessCertE(const ACertPath: IPkixCertPath; AIndex: Int32;
  const AValidPolicyTree: IPkixPolicyNode): IPkixPolicyNode;
var
  LCert: IX509Certificate;
begin
  LCert := ACertPath.Certificates[AIndex];

  // (e) a certificate without a certificate policies extension clears the tree
  if GetCertExtension(LCert, TX509Extensions.CertificatePolicies, 'certificate policies') = nil then
    Result := nil
  else
    Result := AValidPolicyTree;
end;

class procedure TRfc3280CertPathUtilities.ProcessCertF(AIndex: Int32;
  const AValidPolicyTree: IPkixPolicyNode; AExplicitPolicy: Int32);
begin
  // (f)
  if (AExplicitPolicy <= 0) and (AValidPolicyTree = nil) then
    raise EPkixCertPathValidatorCryptoLibException.CreateResAt(AIndex, @SNoValidPolicyTree);
end;

class function TRfc3280CertPathUtilities.PrepareCertB(const ACertPath: IPkixCertPath; AIndex: Int32;
  const APolicyNodes: TPkixPolicyNodeLevels; const AValidPolicyTree: IPkixPolicyNode;
  APolicyMapping: Int32): IPkixPolicyNode;
var
  LCerts: TCryptoLibGenericArray<IX509Certificate>;
  LCert: IX509Certificate;
  LCount, LDepth, LIdx, LInner, LSeek: Int32;
  LParsed: IAsn1Object;
  LMappings, LMapping, LPolicies: IAsn1Sequence;
  LIssuerDomainPolicies: TCryptoLibStringArray;
  LSubjectDomainPolicies: TCryptoLibGenericArray<TCryptoLibStringArray>;
  LIssuerDomainPolicy, LSubjectDomainPolicy: String;
  LFound, LCritical: Boolean;
  LNodes: TList<IPkixPolicyNode>;
  LNode, LValidPolicyNode, LAnyPolicyNode, LParentNode, LChildNode: IPkixPolicyNode;
  LQualifiers: TCryptoLibGenericArray<IPolicyQualifierInfo>;
  LPolicyInformation: IPolicyInformation;
  LValidPolicyTree: IPkixPolicyNode;
begin
  LCerts := ACertPath.Certificates;
  LCert := LCerts[AIndex];
  LCount := System.Length(LCerts);
  LDepth := LCount - AIndex;
  LValidPolicyTree := AValidPolicyTree;

  // (b)
  LParsed := GetCertExtension(LCert, TX509Extensions.PolicyMappings, 'policy mappings');
  if LParsed = nil then
  begin
    Result := LValidPolicyTree;
    Exit;
  end;

  try
    LMappings := TAsn1Sequence.GetInstance(LParsed);
  except
    on E: Exception do
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SExtensionDecodeFailed,
        ['policy mappings', E.Message]);
  end;

  // group the subject domain policies by issuer domain policy, keeping the encounter order
  LIssuerDomainPolicies := nil;
  LSubjectDomainPolicies := nil;

  for LIdx := 0 to LMappings.Count - 1 do
  begin
    LMapping := TAsn1Sequence.GetInstance(LMappings[LIdx]);
    LIssuerDomainPolicy := TDerObjectIdentifier.GetInstance(LMapping[0]).GetID();
    LSubjectDomainPolicy := TDerObjectIdentifier.GetInstance(LMapping[1]).GetID();

    LSeek := -1;
    for LInner := 0 to System.High(LIssuerDomainPolicies) do
    begin
      if LIssuerDomainPolicies[LInner] = LIssuerDomainPolicy then
      begin
        LSeek := LInner;
        Break;
      end;
    end;

    if LSeek < 0 then
    begin
      System.SetLength(LIssuerDomainPolicies, System.Length(LIssuerDomainPolicies) + 1);
      System.SetLength(LSubjectDomainPolicies, System.Length(LIssuerDomainPolicies));
      LSeek := System.High(LIssuerDomainPolicies);
      LIssuerDomainPolicies[LSeek] := LIssuerDomainPolicy;
    end;

    if not ContainsString(LSubjectDomainPolicies[LSeek], LSubjectDomainPolicy) then
      AppendString(LSubjectDomainPolicies[LSeek], LSubjectDomainPolicy);
  end;

  for LIdx := 0 to System.High(LIssuerDomainPolicies) do
  begin
    LIssuerDomainPolicy := LIssuerDomainPolicies[LIdx];

    // (2) mapping is inhibited, so the mapped nodes are deleted
    if APolicyMapping <= 0 then
    begin
      LNodes := APolicyNodes[LDepth];

      for LInner := LNodes.Count - 1 downto 0 do
      begin
        LNode := LNodes[LInner];
        if LNode.ValidPolicy = LIssuerDomainPolicy then
        begin
          LNode.Parent.RemoveChild(LNode);
          LNodes.Delete(LInner);
        end;
      end;

      LValidPolicyTree := TPkixCertPathValidatorUtilities.RemoveChildlessPolicyNodes(LValidPolicyTree,
        APolicyNodes, LDepth);

      Continue;
    end;

    // (1) mapping is permitted, so the expected policies of the mapped node are replaced
    LValidPolicyNode := TPkixCertPathValidatorUtilities.FindValidPolicy(APolicyNodes[LDepth],
      LIssuerDomainPolicy);
    if LValidPolicyNode <> nil then
    begin
      LValidPolicyNode.ExpectedPolicies := LSubjectDomainPolicies[LIdx];
      Continue;
    end;

    LAnyPolicyNode := TPkixCertPathValidatorUtilities.FindValidPolicy(APolicyNodes[LDepth], AnyPolicy);
    if LAnyPolicyNode = nil then
      Continue;

    LParsed := GetCertExtension(LCert, TX509Extensions.CertificatePolicies, 'certificate policies');
    if LParsed = nil then
      Continue;

    try
      LPolicies := TAsn1Sequence.GetInstance(LParsed);
    except
      on E: Exception do
        raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SExtensionDecodeFailed,
          ['certificate policies', E.Message]);
    end;

    LQualifiers := nil;
    LFound := False;

    for LInner := 0 to LPolicies.Count - 1 do
    begin
      try
        LPolicyInformation := TPolicyInformation.GetInstance(LPolicies[LInner]);
      except
        on E: Exception do
          raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SExtensionContentsDecodeFailed,
            ['certificate policies', E.Message]);
      end;

      if LPolicyInformation.PolicyIdentifier.GetID() <> AnyPolicy then
        Continue;

      try
        LQualifiers := TPkixCertPathValidatorUtilities.GetQualifierSet(LPolicyInformation.PolicyQualifiers);
      except
        on E: Exception do
          raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SPolicyQualifierSetFailed, [E.Message]);
      end;

      LFound := True;
      Break;
    end;

    if not LFound then
      LQualifiers := nil;

    LCritical := TPkixCertPathValidatorUtilities.HasCriticalExtension(LCert,
      TX509Extensions.CertificatePolicies);

    LParentNode := LAnyPolicyNode.Parent;
    if (LParentNode <> nil) and (LParentNode.ValidPolicy = AnyPolicy) then
    begin
      LChildNode := TPkixPolicyNode.Create(nil, LDepth, LSubjectDomainPolicies[LIdx], LParentNode,
        LQualifiers, LIssuerDomainPolicy, LCritical) as IPkixPolicyNode;
      LParentNode.AddChild(LChildNode);
      APolicyNodes[LDepth].Add(LChildNode);
    end;
  end;

  Result := LValidPolicyTree;
end;

class procedure TRfc3280CertPathUtilities.PrepareNextCertG(const ACertPath: IPkixCertPath; AIndex: Int32;
  const ANameConstraintValidator: IPkixNameConstraintValidator);
var
  LCert: IX509Certificate;
  LParsed: IAsn1Object;
  LNameConstraints: INameConstraints;
  LPermitted, LExcluded: IGeneralSubtrees;
  LSubtrees: TCryptoLibGenericArray<IGeneralSubtree>;
  LIdx: Int32;
begin
  LCert := ACertPath.Certificates[AIndex];

  // (g) handle the name constraints extension
  LParsed := GetCertExtension(LCert, TX509Extensions.NameConstraints, 'name constraints');
  if LParsed = nil then
    Exit;

  try
    LNameConstraints := TNameConstraints.GetInstance(LParsed);
  except
    on E: Exception do
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SExtensionDecodeFailed,
        ['name constraints', E.Message]);
  end;

  // (g)(1) permitted subtrees
  LPermitted := LNameConstraints.PermittedSubtrees;
  if LPermitted <> nil then
  begin
    try
      ANameConstraintValidator.IntersectPermittedSubtree(LPermitted.Elements);
    except
      on E: Exception do
        raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SPermittedSubtreesFailed, [E.Message]);
    end;
  end;

  // (g)(2) excluded subtrees
  LExcluded := LNameConstraints.ExcludedSubtrees;
  if LExcluded <> nil then
  begin
    try
      LSubtrees := LExcluded.GetSubtrees();
      for LIdx := 0 to System.High(LSubtrees) do
      begin
        ANameConstraintValidator.AddExcludedSubtree(LSubtrees[LIdx]);
      end;
    except
      on E: Exception do
        raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SExcludedSubtreesFailed, [E.Message]);
    end;
  end;
end;

class function TRfc3280CertPathUtilities.PrepareNextCertH1(const ACertPath: IPkixCertPath; AIndex: Int32;
  AExplicitPolicy: Int32): Int32;
begin
  // (h)(1)
  Result := AExplicitPolicy;
  if TPkixCertPathValidatorUtilities.IsSelfIssued(ACertPath.Certificates[AIndex]) then
    Exit;
  if AExplicitPolicy <> 0 then
    Result := AExplicitPolicy - 1;
end;

class function TRfc3280CertPathUtilities.PrepareNextCertH2(const ACertPath: IPkixCertPath; AIndex: Int32;
  APolicyMapping: Int32): Int32;
begin
  // (h)(2)
  Result := APolicyMapping;
  if TPkixCertPathValidatorUtilities.IsSelfIssued(ACertPath.Certificates[AIndex]) then
    Exit;
  if APolicyMapping <> 0 then
    Result := APolicyMapping - 1;
end;

class function TRfc3280CertPathUtilities.PrepareNextCertH3(const ACertPath: IPkixCertPath; AIndex: Int32;
  AInhibitAnyPolicy: Int32): Int32;
begin
  // (h)(3)
  Result := AInhibitAnyPolicy;
  if TPkixCertPathValidatorUtilities.IsSelfIssued(ACertPath.Certificates[AIndex]) then
    Exit;
  if AInhibitAnyPolicy <> 0 then
    Result := AInhibitAnyPolicy - 1;
end;

class function TRfc3280CertPathUtilities.PrepareNextCertI1(const ACertPath: IPkixCertPath; AIndex: Int32;
  AExplicitPolicy: Int32): Int32;
var
  LCert: IX509Certificate;
  LParsed: IAsn1Object;
  LPolicyConstraints: IAsn1Sequence;
  LIdx, LValue: Int32;
  LConstraint: IAsn1TaggedObject;
begin
  LCert := ACertPath.Certificates[AIndex];
  Result := AExplicitPolicy;

  // (i)(1) requireExplicitPolicy
  LParsed := GetCertExtension(LCert, TX509Extensions.PolicyConstraints, 'policy constraints');
  if LParsed = nil then
    Exit;

  LPolicyConstraints := TAsn1Sequence.GetInstance(LParsed);

  for LIdx := 0 to LPolicyConstraints.Count - 1 do
  begin
    try
      LConstraint := TAsn1TaggedObject.GetInstance(LPolicyConstraints[LIdx]);
      if not LConstraint.HasContextTag(0) then
        Continue;

      LValue := TDerInteger.GetTagged(LConstraint, False).IntValueExact;
    except
      on E: Exception do
        raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SExtensionContentsDecodeFailed,
          ['policy constraints', E.Message]);
    end;

    if LValue < AExplicitPolicy then
      Result := LValue;

    Exit;
  end;
end;

class function TRfc3280CertPathUtilities.PrepareNextCertI2(const ACertPath: IPkixCertPath; AIndex: Int32;
  APolicyMapping: Int32): Int32;
var
  LCert: IX509Certificate;
  LParsed: IAsn1Object;
  LPolicyConstraints: IAsn1Sequence;
  LIdx, LValue: Int32;
  LConstraint: IAsn1TaggedObject;
begin
  LCert := ACertPath.Certificates[AIndex];
  Result := APolicyMapping;

  // (i)(2) inhibitPolicyMapping
  LParsed := GetCertExtension(LCert, TX509Extensions.PolicyConstraints, 'policy constraints');
  if LParsed = nil then
    Exit;

  LPolicyConstraints := TAsn1Sequence.GetInstance(LParsed);

  for LIdx := 0 to LPolicyConstraints.Count - 1 do
  begin
    try
      LConstraint := TAsn1TaggedObject.GetInstance(LPolicyConstraints[LIdx]);
      if not LConstraint.HasContextTag(1) then
        Continue;

      LValue := TDerInteger.GetTagged(LConstraint, False).IntValueExact;
    except
      on E: Exception do
        raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SExtensionContentsDecodeFailed,
          ['policy constraints', E.Message]);
    end;

    if LValue < APolicyMapping then
      Result := LValue;

    Exit;
  end;
end;

class function TRfc3280CertPathUtilities.PrepareNextCertJ(const ACertPath: IPkixCertPath; AIndex: Int32;
  AInhibitAnyPolicy: Int32): Int32;
var
  LCert: IX509Certificate;
  LParsed: IAsn1Object;
  LValue: Int32;
begin
  LCert := ACertPath.Certificates[AIndex];
  Result := AInhibitAnyPolicy;

  // (j)
  LParsed := GetCertExtension(LCert, TX509Extensions.InhibitAnyPolicy, 'inhibit any-policy');
  if LParsed = nil then
    Exit;

  try
    LValue := TDerInteger.GetInstance(LParsed).IntValueExact;
  except
    on E: Exception do
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SExtensionDecodeFailed,
        ['inhibit any-policy', E.Message]);
  end;

  if LValue < AInhibitAnyPolicy then
    Result := LValue;
end;

class function TRfc3280CertPathUtilities.PrepareNextCertK(const ACertPath: IPkixCertPath;
  AIndex: Int32): IBasicConstraints;
var
  LCert: IX509Certificate;
  LParsed: IAsn1Object;
begin
  LCert := ACertPath.Certificates[AIndex];

  // (k)
  LParsed := GetCertExtension(LCert, TX509Extensions.BasicConstraints, 'basic constraints');
  if LParsed = nil then
    raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SIntermediateLacksBasicConstraints, [AIndex]);

  try
    Result := TBasicConstraints.GetInstance(LParsed);
  except
    on E: Exception do
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SExtensionDecodeFailed,
        ['basic constraints', E.Message]);
  end;

  if not Result.IsCA() then
    raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SNotACACertificate, [AIndex]);
end;

class function TRfc3280CertPathUtilities.PrepareNextCertL(const ACertPath: IPkixCertPath; AIndex: Int32;
  AMaxPathLength: Int32): Int32;
begin
  // (l) a self-issued certificate does not consume path length
  if TPkixCertPathValidatorUtilities.IsSelfIssued(ACertPath.Certificates[AIndex]) then
  begin
    Result := AMaxPathLength;
    Exit;
  end;

  if AMaxPathLength <= 0 then
    raise EPkixCertPathValidatorCryptoLibException.CreateResAt(AIndex, @SMaxPathLengthExhausted);

  Result := AMaxPathLength - 1;
end;

class function TRfc3280CertPathUtilities.PrepareNextCertM(const ACertPath: IPkixCertPath; AIndex: Int32;
  AMaxPathLength: Int32; const ACaBasicConstraints: IBasicConstraints): Int32;
var
  LPathLenConstraint: TBigInteger;
  LNewPathLength: Int32;
begin
  Result := AMaxPathLength;

  // (m)
  LPathLenConstraint := ACaBasicConstraints.PathLenConstraint;
  if not LPathLenConstraint.IsInitialized then
    Exit;

  if LPathLenConstraint.SignValue < 0 then
    raise EPkixCertPathValidatorCryptoLibException.CreateResAt(AIndex, @SInvalidPathLengthConstraint);

  try
    LNewPathLength := LPathLenConstraint.Int32ValueExact;
  except
    on E: Exception do
      // a constraint that does not fit an Int32 can never be the smaller bound
      Exit;
  end;

  if LNewPathLength < AMaxPathLength then
    Result := LNewPathLength;
end;

class procedure TRfc3280CertPathUtilities.PrepareNextCertN(const ACertPath: IPkixCertPath; AIndex: Int32);
var
  LKeyUsage: TCryptoLibBooleanArray;
begin
  // (n)
  LKeyUsage := ACertPath.Certificates[AIndex].GetKeyUsage();

  if (LKeyUsage <> nil) and ((System.Length(LKeyUsage) <= TPkixCertPathValidatorUtilities.KeyCertSign) or
    (not LKeyUsage[TPkixCertPathValidatorUtilities.KeyCertSign])) then
  begin
    raise EPkixCertPathValidatorCryptoLibException.CreateResAt(AIndex, @SKeyUsageNoKeyCertSign);
  end;
end;

class function TRfc3280CertPathUtilities.JoinCriticalExtensions(const ACriticalExtensions
  : TList<String>): String;
var
  LSorted: TCryptoLibStringArray;
  LIdx, LInner: Int32;
  LPivot: String;
begin
  // Sorted so the message is reproducible: the caller's list carries whatever order the extensions
  // were collected in, which is not stable. Sorts a copy - the caller's list is still being consumed
  // by the checkers.
  System.SetLength(LSorted, ACriticalExtensions.Count);
  for LIdx := 0 to ACriticalExtensions.Count - 1 do
  begin
    LSorted[LIdx] := ACriticalExtensions[LIdx];
  end;

  // insertion sort: this list is a handful of OIDs at most
  for LIdx := 1 to System.High(LSorted) do
  begin
    LPivot := LSorted[LIdx];
    LInner := LIdx - 1;
    while (LInner >= 0) and (LSorted[LInner] > LPivot) do
    begin
      LSorted[LInner + 1] := LSorted[LInner];
      System.Dec(LInner);
    end;
    LSorted[LInner + 1] := LPivot;
  end;

  Result := '';
  for LIdx := 0 to System.High(LSorted) do
  begin
    if LIdx > 0 then
      Result := Result + ', ';
    Result := Result + LSorted[LIdx];
  end;
end;

class procedure TRfc3280CertPathUtilities.PrepareNextCertO(const ACertPath: IPkixCertPath; AIndex: Int32;
  const ACriticalExtensions: TList<String>;
  const ACheckers: TCryptoLibGenericArray<IPkixCertPathChecker>);
var
  LCert: IX509Certificate;
  LIdx: Int32;
begin
  LCert := ACertPath.Certificates[AIndex];

  // (o)
  for LIdx := 0 to System.High(ACheckers) do
  begin
    ACheckers[LIdx].Check(LCert, ACriticalExtensions);
  end;

  if ACriticalExtensions.Count > 0 then
    raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SUnsupportedCriticalExtensions,
      [AIndex, JoinCriticalExtensions(ACriticalExtensions)]);
end;

class function TRfc3280CertPathUtilities.WrapupCertA(AExplicitPolicy: Int32;
  const ACert: IX509Certificate): Int32;
begin
  // (a)
  Result := AExplicitPolicy;
  if (not TPkixCertPathValidatorUtilities.IsSelfIssued(ACert)) and (AExplicitPolicy <> 0) then
    Result := AExplicitPolicy - 1;
end;

class function TRfc3280CertPathUtilities.WrapupCertB(const ACertPath: IPkixCertPath; AIndex: Int32;
  AExplicitPolicy: Int32): Int32;
var
  LCert: IX509Certificate;
  LParsed: IAsn1Object;
  LPolicyConstraints: IAsn1Sequence;
  LIdx, LValue: Int32;
  LConstraint: IAsn1TaggedObject;
begin
  LCert := ACertPath.Certificates[AIndex];
  Result := AExplicitPolicy;

  // (b)
  LParsed := GetCertExtension(LCert, TX509Extensions.PolicyConstraints, 'policy constraints');
  if LParsed = nil then
    Exit;

  LPolicyConstraints := TAsn1Sequence.GetInstance(LParsed);

  for LIdx := 0 to LPolicyConstraints.Count - 1 do
  begin
    LConstraint := TAsn1TaggedObject.GetInstance(LPolicyConstraints[LIdx]);
    if not LConstraint.HasContextTag(0) then
      Continue;

    try
      LValue := TDerInteger.GetTagged(LConstraint, False).IntValueExact;
    except
      on E: Exception do
        raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SExtensionContentsDecodeFailed,
          ['policy constraints requireExplicitPolicy field', E.Message]);
    end;

    if LValue = 0 then
      Result := 0;

    Exit;
  end;
end;

class procedure TRfc3280CertPathUtilities.WrapupCertF(const ACertPath: IPkixCertPath; AIndex: Int32;
  const ACheckers: TCryptoLibGenericArray<IPkixCertPathChecker>;
  const ACriticalExtensions: TList<String>);
var
  LCert: IX509Certificate;
  LIdx: Int32;
begin
  LCert := ACertPath.Certificates[AIndex];

  // (f)
  for LIdx := 0 to System.High(ACheckers) do
  begin
    try
      ACheckers[LIdx].Check(LCert, ACriticalExtensions);
    except
      on E: Exception do
        raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SCertPathCheckerFailed, [E.Message]);
    end;
  end;

  if ACriticalExtensions.Count > 0 then
    raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex, @SUnsupportedCriticalExtensions,
      [AIndex, JoinCriticalExtensions(ACriticalExtensions)]);
end;

class function TRfc3280CertPathUtilities.WrapupCertG(const ACertPath: IPkixCertPath;
  const APkixParams: IPkixParameters; const AUserInitialPolicySet: TCryptoLibStringArray; AIndex: Int32;
  const APolicyNodes: TPkixPolicyNodeLevels; const AValidPolicyTree: IPkixPolicyNode;
  const AAcceptablePolicies: TList<String>): IPkixPolicyNode;
var
  LCount, LDepth, LNodeIdx, LChildIdx: Int32;
  LNode: IPkixPolicyNode;
  LChildren: TCryptoLibGenericArray<IPkixPolicyNode>;
  LValidPolicyNodes: TCryptoLibGenericArray<IPkixPolicyNode>;
  LValidPolicyTree: IPkixPolicyNode;
begin
  LCount := System.Length(ACertPath.Certificates);
  LValidPolicyTree := AValidPolicyTree;

  // (g)(i)
  if LValidPolicyTree = nil then
  begin
    if APkixParams.IsExplicitPolicyRequired then
      raise EPkixCertPathValidatorCryptoLibException.CreateResAt(AIndex, @SExplicitPolicyUnavailable);

    Result := nil;
    Exit;
  end;

  // (g)(ii) the user initial policy set is any-policy
  if TPkixCertPathValidatorUtilities.IsAnyPolicy(AUserInitialPolicySet) then
  begin
    if APkixParams.IsExplicitPolicyRequired then
    begin
      if AAcceptablePolicies.Count < 1 then
        raise EPkixCertPathValidatorCryptoLibException.CreateResAt(AIndex, @SExplicitPolicyUnavailable);

      // nodes outside the acceptable policies are not pruned here; the childless sweep below is
      // what constrains the tree
      LValidPolicyTree := TPkixCertPathValidatorUtilities.RemoveChildlessPolicyNodes(LValidPolicyTree,
        APolicyNodes, LCount);
    end;

    Result := LValidPolicyTree;
    Exit;
  end;

  // (g)(iii). This is not exactly the procedure of RFC 5280, but produces an equivalent validation
  // result; the two differ only in whether anyPolicy remains in the tree.
  // (g)(iii)(1)
  LValidPolicyNodes := nil;

  for LDepth := 0 to System.High(APolicyNodes) do
  begin
    for LNodeIdx := 0 to APolicyNodes[LDepth].Count - 1 do
    begin
      LNode := APolicyNodes[LDepth][LNodeIdx];
      if LNode.ValidPolicy <> AnyPolicy then
        Continue;

      LChildren := LNode.Children;
      for LChildIdx := 0 to System.High(LChildren) do
      begin
        if LChildren[LChildIdx].ValidPolicy = AnyPolicy then
          Continue;

        System.SetLength(LValidPolicyNodes, System.Length(LValidPolicyNodes) + 1);
        LValidPolicyNodes[System.High(LValidPolicyNodes)] := LChildren[LChildIdx];
      end;
    end;
  end;

  // (g)(iii)(2)
  for LNodeIdx := 0 to System.High(LValidPolicyNodes) do
  begin
    if not ContainsString(AUserInitialPolicySet, LValidPolicyNodes[LNodeIdx].ValidPolicy) then
    begin
      LValidPolicyTree := TPkixCertPathValidatorUtilities.RemovePolicyNode(LValidPolicyTree,
        APolicyNodes, LValidPolicyNodes[LNodeIdx]);
    end;
  end;

  // (g)(iii)(4)
  LValidPolicyTree := TPkixCertPathValidatorUtilities.RemoveChildlessPolicyNodes(LValidPolicyTree,
    APolicyNodes, LCount);

  Result := LValidPolicyTree;
end;

end.
