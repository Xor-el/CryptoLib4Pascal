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

unit ClpPkixCertPathValidatorUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpIStore,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIX509Extension,
  ClpIX509Certificate,
  ClpIX509Crl,
  ClpIX509CrlEntry,
  ClpIX509V2AttributeCertificate,
  ClpIX509StoreSelectors,
  ClpX509StoreSelectors,
  ClpIAsymmetricKeyParameter,
  ClpIDsaParameters,
  ClpDsaParameters,
  ClpSubjectPublicKeyInfoFactory,
  ClpIPkixTypes,
  ClpPkixPolicyNode,
  ClpPkixParameters,
  ClpPkixCrlUtilities,
  ClpBigInteger,
  ClpNullable,
  ClpCryptoLibConfig,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  STrustAnchorValidationFailed = 'trust anchor found but certificate validation failed: %s';
  SAttrCertIssuerHasNoPrincipal = 'attribute certificate issuer has no principal name';
  SSubjectPublicKeyDecodeFailed = 'subject public key cannot be decoded: %s';
  SPolicyQualifierDecodeFailed = 'policy qualifier info cannot be decoded: %s';
  SPolicyTreeTooLarge = 'certificate policy tree exceeds %d nodes';
  SExtensionDecodeFailed = '%s extension could not be decoded: %s';
  SDsaParametersNotInherited = 'DSA parameters cannot be inherited from previous certificate';
  SCrlIssuerDecodeFailed = 'CRL issuer information from distribution point cannot be decoded: %s';
  SCrlIssuerOmitted = 'CRL issuer is omitted from distribution point but no distributionPoint field present';
  SDistributionPointIssuerFailed = 'could not get issuer information from distribution point: %s';
  SNoCrlsFound = 'no CRLs found for issuer "%s"';
  SIssuerCertSearchFailed = 'issuer certificate cannot be searched: %s';
  SCrlUnsupportedCriticalExtensions = 'CRL has unsupported critical extensions';
  SCrlEntryUnsupportedCriticalExtensions = 'CRL entry has unsupported critical extensions';

type
  /// <summary>
  /// One list of valid policy tree nodes per certificate depth, as used by RFC 5280 6.1.
  /// </summary>
  TPkixPolicyNodeLevels = TCryptoLibGenericArray<TList<IPkixPolicyNode>>;

  /// <summary>
  /// Shared helpers for PKIX certification path validation and building (RFC 5280 6.1, 6.3).
  /// </summary>
  TPkixCertPathValidatorUtilities = class sealed(TObject)

  strict private
    /// <summary>OID of the date-of-certificate-generation attribute certificate extension.</summary>
    class function DateOfCertGenOid: IDerObjectIdentifier; static;
    class function GetCertExtensions(const ACert: IX509Certificate): IX509Extensions; static;
    class function GetCrlExtensions(const ACrl: IX509Crl): IX509Extensions; static;
    class procedure DoGetCertStatus(AValidDate: TDateTime; const ACrl: IX509Crl;
      const AIssuer: IX509Name; const ASerialNumber: TBigInteger; const ACertStatus: ICertStatus); static;
    class function DoGetCompleteCrls(const ADistributionPoint: IDistributionPoint;
      const AIssuer: IX509Name; const ACrlSelect: IX509CrlStoreSelector;
      const APkixParams: IPkixParameters; AValidityDate: TDateTime): TCryptoLibGenericArray<IX509Crl>; static;
    class function EquivalentName(const AFirst, ASecond: IX509Name): Boolean; static;
    class function HasCriticalExtension(const AExtensions: IX509Extensions;
      const AExtensionOid: IDerObjectIdentifier): Boolean; overload; static;
    class procedure RemovePolicyNodeRecurse(const APolicyNodes: TPkixPolicyNodeLevels;
      const ANode: IPkixPolicyNode); static;
    class function IsDeltaCrl(const ACrl: IX509Crl): Boolean; static;
    /// <summary>ACrls reduced to the delta CRLs it holds.</summary>
    class function RetainDeltaCrls(const ACrls: TCryptoLibGenericArray<IX509Crl>)
      : TCryptoLibGenericArray<IX509Crl>; static;

  public
    const
      /// <summary>The anyPolicy policy identifier of RFC 5280 4.2.1.4.</summary>
      AnyPolicy = '2.5.29.32.0';
      /// <summary>keyCertSign bit of the key usage extension.</summary>
      KeyCertSign = Int32(5);
      /// <summary>cRLSign bit of the key usage extension.</summary>
      CrlSign = Int32(6);

    /// <summary>
    /// The trust anchor among ATrustAnchors that issued ACert, or nil when there is none.
    /// </summary>
    class function FindTrustAnchor(const ACert: IX509Certificate;
      const ATrustAnchors: TCryptoLibGenericArray<ITrustAnchor>): ITrustAnchor; static;

    class function IsIssuerTrustAnchor(const ACert: IX509Certificate;
      const ATrustAnchors: TCryptoLibGenericArray<ITrustAnchor>): Boolean; static;

    /// <summary>Stores advertised in an issuer alternative name are not supported.</summary>
    class procedure AddAdditionalStoresFromAltNames(const ACert: IX509Certificate;
      const APkixParams: IPkixParameters); static;

    /// <summary>The time the path must be valid at: the configured one, else ACurrentDate.</summary>
    class function GetValidityDate(const APkixParams: IPkixParameters;
      ACurrentDate: TDateTime): TDateTime; static;

    /// <summary>Render AInstant for an error message; every date of this layer is UTC.</summary>
    class function FormatUtcInstant(AInstant: TDateTime): String; static;

    class function GetIssuerPrincipal(const ACert: IX509Certificate): IX509Name; overload; static;
    class function GetIssuerPrincipal(const AAttrCert: IX509V2AttributeCertificate): IX509Name; overload; static;

    class function IsSelfIssued(const ACert: IX509Certificate): Boolean; static;

    class function GetAlgorithmIdentifier(const AKey: IAsymmetricKeyParameter): IAlgorithmIdentifier; static;

    /// <summary>True when APolicySet is absent, empty, or names anyPolicy.</summary>
    class function IsAnyPolicy(const APolicySet: TCryptoLibStringArray): Boolean; static;

    /// <summary>The distinct policy qualifiers of a policy information qualifiers sequence.</summary>
    class function GetQualifierSet(const AQualifiers: IAsn1Sequence)
      : TCryptoLibGenericArray<IPolicyQualifierInfo>; static;

    /// <summary>RFC 5280 6.1.5 (g)(iii): prune nodes that have no children left.</summary>
    class function RemoveChildlessPolicyNodes(const AValidPolicyTree: IPkixPolicyNode;
      const APolicyNodes: TPkixPolicyNodeLevels; ADepthLimit: Int32): IPkixPolicyNode; static;

    class function RemovePolicyNode(const AValidPolicyTree: IPkixPolicyNode;
      const APolicyNodes: TPkixPolicyNodeLevels; const ANode: IPkixPolicyNode): IPkixPolicyNode; static;

    /// <summary>
    /// Bound the valid policy tree, so that policy mapping and anyPolicy expansion (RFC 5280
    /// 6.1.3/6.1.4) on a crafted chain cannot grow it multiplicatively per certificate.
    /// </summary>
    class procedure CheckPolicyTreeSize(const APolicyNodes: TPkixPolicyNodeLevels); static;

    /// <summary>RFC 5280 6.3.3 (i)/(j): set ACertStatus from the CRL entry for ACertObj.</summary>
    class procedure GetCertStatus(AValidDate: TDateTime; const ACrl: IX509Crl;
      const ACert: IX509Certificate; const ACertStatus: ICertStatus); overload; static;
    /// <summary>RFC 3281: the attribute certificate variant of the above.</summary>
    class procedure GetCertStatus(AValidDate: TDateTime; const ACrl: IX509Crl;
      const AAttrCert: IX509V2AttributeCertificate; const ACertStatus: ICertStatus); overload; static;

    /// <summary>
    /// The public key of ACerts[AIndex], with DSA parameters inherited from a later certificate
    /// of the path when the key itself carries none.
    /// </summary>
    class function GetNextWorkingKey(const ACerts: TCryptoLibGenericArray<IX509Certificate>;
      AIndex: Int32): IAsymmetricKeyParameter; static;

    /// <summary>Under the chain validity model a certificate is checked at its issue time.</summary>
    class function GetValidCertDateFromValidityModel(AValidityDate: TDateTime; AValidityModel: Int32;
      const ACertPath: IPkixCertPath; AIndex: Int32): TDateTime; static;

    /// <summary>
    /// Set the CRL issuer criterion of ASelector from the distribution point's cRLIssuer field,
    /// or from AIssuerPrincipals when that field is absent.
    /// </summary>
    class procedure GetCrlIssuersFromDistributionPoint(const ADistributionPoint: IDistributionPoint;
      const AIssuerPrincipals: TCryptoLibGenericArray<IX509Name>; const ASelector: IX509CrlStoreSelector;
      const APkixParams: IPkixParameters); static;

    /// <summary>Complete CRLs for ACertObj at ADistributionPoint.</summary>
    class function GetCompleteCrls(const ADistributionPoint: IDistributionPoint;
      const ACert: IX509Certificate; const APkixParams: IPkixParameters;
      AValidityDate: TDateTime): TCryptoLibGenericArray<IX509Crl>; overload; static;
    /// <summary>RFC 3281: the attribute certificate variant of the above.</summary>
    class function GetCompleteCrls(const ADistributionPoint: IDistributionPoint;
      const AAttrCert: IX509V2AttributeCertificate; const APkixParams: IPkixParameters;
      AValidityDate: TDateTime): TCryptoLibGenericArray<IX509Crl>; overload; static;

    /// <summary>Delta CRLs for ACompleteCrl per RFC 5280 5.2.4.</summary>
    class function GetDeltaCrls(AValidityDate: TDateTime; const APkixParams: IPkixParameters;
      const ACompleteCrl: IX509Crl): TCryptoLibGenericArray<IX509Crl>; static;

    /// <summary>Stores advertised in a CRL distribution point are not supported.</summary>
    class procedure AddAdditionalStoresFromCrlDistributionPoint(const ACrlDistPoint: ICrlDistPoint;
      const APkixParams: IPkixParameters); static;

    /// <summary>RFC 5280 6.1.3 (d)(1)(i): grow the tree under every node expecting APolicyOid.</summary>
    class function ProcessCertD1i(AIndex: Int32; const APolicyNodes: TPkixPolicyNodeLevels;
      const APolicyOid: IDerObjectIdentifier;
      const AQualifiers: TCryptoLibGenericArray<IPolicyQualifierInfo>): Boolean; static;

    /// <summary>RFC 5280 6.1.3 (d)(1)(ii): grow the tree under the anyPolicy node.</summary>
    class procedure ProcessCertD1ii(AIndex: Int32; const APolicyNodes: TPkixPolicyNodeLevels;
      const APolicyOid: IDerObjectIdentifier;
      const AQualifiers: TCryptoLibGenericArray<IPolicyQualifierInfo>); static;

    /// <summary>Candidate issuer certificates of ACert.</summary>
    class function FindIssuerCerts(const ACert: IX509Certificate;
      const APkixBuilderParameters: IPkixBuilderParameters): TCryptoLibGenericArray<IX509Certificate>; static;

    /// <summary>Only the CRL extensions this library understands may be critical.</summary>
    class procedure CheckCrlCriticalExtensions(const ACrl: IX509Crl); static;

    /// <summary>No CRL entry extension is supported as critical.</summary>
    class procedure CheckCrlEntryCriticalExtensions(const ACrlEntry: IX509CrlEntry); static;

    class function FindValidPolicy(const APolicyNodes: TList<IPkixPolicyNode>;
      const APolicy: String): IPkixPolicyNode; static;

    class function HasCriticalExtension(const ACertificate: IX509Certificate;
      const AExtensionOid: IDerObjectIdentifier): Boolean; overload; static;

    class function HasCriticalExtension(const ACrl: IX509Crl;
      const AExtensionOid: IDerObjectIdentifier): Boolean; overload; static;
  end;

implementation

{ TPkixCertPathValidatorUtilities }

class function TPkixCertPathValidatorUtilities.DateOfCertGenOid: IDerObjectIdentifier;
begin
  Result := TDerObjectIdentifier.Create('1.3.36.8.3.1');
end;

class function TPkixCertPathValidatorUtilities.GetCertExtensions(const ACert: IX509Certificate): IX509Extensions;
begin
  Result := ACert.CertificateStructure.TbsCertificate.Extensions;
end;

class function TPkixCertPathValidatorUtilities.GetCrlExtensions(const ACrl: IX509Crl): IX509Extensions;
begin
  Result := ACrl.CertificateList.TbsCertList.Extensions;
end;

class function TPkixCertPathValidatorUtilities.EquivalentName(const AFirst, ASecond: IX509Name): Boolean;
begin
  Result := (AFirst <> nil) and (ASecond <> nil) and AFirst.Equivalent(ASecond, True);
end;

class function TPkixCertPathValidatorUtilities.FindTrustAnchor(const ACert: IX509Certificate;
  const ATrustAnchors: TCryptoLibGenericArray<ITrustAnchor>): ITrustAnchor;
var
  LIdx: Int32;
  LTrust: ITrustAnchor;
  LTrustPublicKey: IAsymmetricKeyParameter;
  LSelector: IX509CertStoreSelector;
  LCaName: IX509Name;
  LInvalidKeyMessage: String;
begin
  LSelector := TX509CertStoreSelector.Create() as IX509CertStoreSelector;
  LSelector.Subject := GetIssuerPrincipal(ACert);

  Result := nil;
  LInvalidKeyMessage := '';

  for LIdx := 0 to System.High(ATrustAnchors) do
  begin
    LTrust := ATrustAnchors[LIdx];
    LTrustPublicKey := nil;

    if LTrust.TrustedCert <> nil then
    begin
      if LSelector.Match(LTrust.TrustedCert) then
        LTrustPublicKey := LTrust.TrustedCert.GetPublicKey()
      else
        LTrust := nil;
    end
    else if (LTrust.CAName <> '') and (LTrust.CAPublicKey <> nil) then
    begin
      try
        LCaName := LTrust.CA;
        if (LCaName = nil) and (LTrust.CAName <> '') then
          LCaName := TX509Name.Create(LTrust.CAName) as IX509Name;

        if EquivalentName(GetIssuerPrincipal(ACert), LCaName) then
          LTrustPublicKey := LTrust.CAPublicKey
        else
          LTrust := nil;
      except
        on E: Exception do
          LTrust := nil;
      end;
    end
    else
    begin
      LTrust := nil;
    end;

    if LTrustPublicKey <> nil then
    begin
      try
        ACert.Verify(LTrustPublicKey);
      except
        on E: Exception do
        begin
          LInvalidKeyMessage := E.Message;
          LTrust := nil;
        end;
      end;
    end;

    if LTrust <> nil then
    begin
      Result := LTrust;
      Exit;
    end;
  end;

  if LInvalidKeyMessage <> '' then
    raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@STrustAnchorValidationFailed,
      [LInvalidKeyMessage]);
end;

class function TPkixCertPathValidatorUtilities.IsIssuerTrustAnchor(const ACert: IX509Certificate;
  const ATrustAnchors: TCryptoLibGenericArray<ITrustAnchor>): Boolean;
begin
  try
    Result := FindTrustAnchor(ACert, ATrustAnchors) <> nil;
  except
    on E: Exception do
      Result := False;
  end;
end;

class procedure TPkixCertPathValidatorUtilities.AddAdditionalStoresFromAltNames(const ACert: IX509Certificate;
  const APkixParams: IPkixParameters);
begin
  // stores fetched from a location named in a certificate or CRL are not supported
end;

class function TPkixCertPathValidatorUtilities.GetValidityDate(const APkixParams: IPkixParameters;
  ACurrentDate: TDateTime): TDateTime;
var
  LValidityDate: TNullable<TDateTime>;
begin
  LValidityDate := APkixParams.Date;
  if LValidityDate.HasValue then
    Result := LValidityDate.Value
  else
    Result := ACurrentDate;
end;

class function TPkixCertPathValidatorUtilities.FormatUtcInstant(AInstant: TDateTime): String;
begin
  Result := FormatDateTime('yyyy"-"mm"-"dd hh":"nn":"ss', AInstant) + ' Z';
end;

class function TPkixCertPathValidatorUtilities.GetIssuerPrincipal(const ACert: IX509Certificate): IX509Name;
begin
  Result := ACert.IssuerDN;
end;

class function TPkixCertPathValidatorUtilities.GetIssuerPrincipal(const AAttrCert
  : IX509V2AttributeCertificate): IX509Name;
var
  LPrincipals: TCryptoLibGenericArray<IX509Name>;
begin
  LPrincipals := AAttrCert.Issuer.GetPrincipals();
  if System.Length(LPrincipals) < 1 then
    raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SAttrCertIssuerHasNoPrincipal);
  Result := LPrincipals[0];
end;

class function TPkixCertPathValidatorUtilities.IsSelfIssued(const ACert: IX509Certificate): Boolean;
begin
  Result := EquivalentName(ACert.SubjectDN, ACert.IssuerDN);
end;

class function TPkixCertPathValidatorUtilities.GetAlgorithmIdentifier(const AKey: IAsymmetricKeyParameter)
  : IAlgorithmIdentifier;
begin
  try
    Result := TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(AKey).Algorithm;
  except
    on E: Exception do
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SSubjectPublicKeyDecodeFailed, [E.Message]);
  end;
end;

class function TPkixCertPathValidatorUtilities.IsAnyPolicy(const APolicySet: TCryptoLibStringArray): Boolean;
var
  LIdx: Int32;
begin
  // an absent and an empty policy set both mean "any policy", so a plain array loses nothing here
  if System.Length(APolicySet) < 1 then
  begin
    Result := True;
    Exit;
  end;
  for LIdx := 0 to System.High(APolicySet) do
  begin
    if APolicySet[LIdx] = AnyPolicy then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := False;
end;

class function TPkixCertPathValidatorUtilities.GetQualifierSet(const AQualifiers: IAsn1Sequence)
  : TCryptoLibGenericArray<IPolicyQualifierInfo>;
var
  LList: TList<IPolicyQualifierInfo>;
  LOuter, LInner: Int32;
  LQualifier: IPolicyQualifierInfo;
  LSeen: Boolean;
begin
  if AQualifiers = nil then
  begin
    Result := nil;
    Exit;
  end;

  LList := TList<IPolicyQualifierInfo>.Create();
  try
    for LOuter := 0 to AQualifiers.Count - 1 do
    begin
      try
        LQualifier := TPolicyQualifierInfo.GetInstance(AQualifiers[LOuter].ToAsn1Object());
      except
        on E: Exception do
          raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SPolicyQualifierDecodeFailed, [E.Message]);
      end;

      LSeen := False;
      for LInner := 0 to LList.Count - 1 do
      begin
        if LList[LInner].Equals(LQualifier as IAsn1Convertible) then
        begin
          LSeen := True;
          Break;
        end;
      end;

      if not LSeen then
        LList.Add(LQualifier);
    end;
    Result := LList.ToArray();
  finally
    LList.Free;
  end;
end;

class function TPkixCertPathValidatorUtilities.RemoveChildlessPolicyNodes(const AValidPolicyTree: IPkixPolicyNode;
  const APolicyNodes: TPkixPolicyNodeLevels; ADepthLimit: Int32): IPkixPolicyNode;
var
  LDepth, LIdx: Int32;
  LLevel: TList<IPkixPolicyNode>;
  LNode, LParent: IPkixPolicyNode;
begin
  if AValidPolicyTree = nil then
  begin
    Result := nil;
    Exit;
  end;

  LDepth := ADepthLimit;
  while LDepth > 0 do
  begin
    System.Dec(LDepth);
    LLevel := APolicyNodes[LDepth];

    LIdx := LLevel.Count;
    while LIdx > 0 do
    begin
      System.Dec(LIdx);
      LNode := LLevel[LIdx];
      if LNode.HasChildren then
        Continue;

      LLevel.Delete(LIdx);

      LParent := LNode.Parent;
      if LParent = nil then
      begin
        Result := nil;
        Exit;
      end;

      LParent.RemoveChild(LNode);
    end;
  end;

  Result := AValidPolicyTree;
end;

class procedure TPkixCertPathValidatorUtilities.RemovePolicyNodeRecurse(const APolicyNodes: TPkixPolicyNodeLevels;
  const ANode: IPkixPolicyNode);
var
  LLevel: TList<IPkixPolicyNode>;
  LIdx: Int32;
  LChildren: TCryptoLibGenericArray<IPkixPolicyNode>;
begin
  LLevel := APolicyNodes[ANode.Depth];
  for LIdx := LLevel.Count - 1 downto 0 do
  begin
    if LLevel[LIdx] = ANode then
      LLevel.Delete(LIdx);
  end;

  LChildren := ANode.Children;
  for LIdx := 0 to System.High(LChildren) do
  begin
    RemovePolicyNodeRecurse(APolicyNodes, LChildren[LIdx]);
  end;
end;

class function TPkixCertPathValidatorUtilities.RemovePolicyNode(const AValidPolicyTree: IPkixPolicyNode;
  const APolicyNodes: TPkixPolicyNodeLevels; const ANode: IPkixPolicyNode): IPkixPolicyNode;
var
  LParent: IPkixPolicyNode;
  LIdx: Int32;
begin
  if AValidPolicyTree = nil then
  begin
    Result := nil;
    Exit;
  end;

  LParent := ANode.Parent;
  if LParent = nil then
  begin
    for LIdx := 0 to System.High(APolicyNodes) do
    begin
      APolicyNodes[LIdx].Clear;
    end;
    Result := nil;
    Exit;
  end;

  LParent.RemoveChild(ANode);
  RemovePolicyNodeRecurse(APolicyNodes, ANode);

  Result := AValidPolicyTree;
end;

class procedure TPkixCertPathValidatorUtilities.CheckPolicyTreeSize(const APolicyNodes: TPkixPolicyNodeLevels);
var
  LIdx, LTotal: Int32;
begin
  LTotal := 0;
  for LIdx := 0 to System.High(APolicyNodes) do
  begin
    LTotal := LTotal + APolicyNodes[LIdx].Count;
    if LTotal > TCryptoLibConfig.X509.MaxPolicyNodes then
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SPolicyTreeTooLarge, [TCryptoLibConfig.X509.MaxPolicyNodes]);
  end;
end;

class procedure TPkixCertPathValidatorUtilities.GetCertStatus(AValidDate: TDateTime;
  const ACrl: IX509Crl; const ACert: IX509Certificate; const ACertStatus: ICertStatus);
begin
  DoGetCertStatus(AValidDate, ACrl, ACert.IssuerDN, ACert.SerialNumber, ACertStatus);
end;

class procedure TPkixCertPathValidatorUtilities.GetCertStatus(AValidDate: TDateTime;
  const ACrl: IX509Crl; const AAttrCert: IX509V2AttributeCertificate; const ACertStatus: ICertStatus);
begin
  DoGetCertStatus(AValidDate, ACrl, GetIssuerPrincipal(AAttrCert), AAttrCert.SerialNumber, ACertStatus);
end;

class procedure TPkixCertPathValidatorUtilities.DoGetCertStatus(AValidDate: TDateTime;
  const ACrl: IX509Crl; const AIssuer: IX509Name; const ASerialNumber: TBigInteger;
  const ACertStatus: ICertStatus);
var
  LCrlEntry: IX509CrlEntry;
  LIssuer: IX509Name;
  LReasonCodeValue: Int32;
  LExtensions: IX509Extensions;
  LParsed: IAsn1Object;
  LRevocationDate: TDateTime;
begin
  LCrlEntry := ACrl.GetRevokedCertificate(ASerialNumber);
  if LCrlEntry = nil then
    Exit;

  LIssuer := AIssuer;

  if (not EquivalentName(LIssuer, LCrlEntry.GetCertificateIssuer())) and
    (not EquivalentName(LIssuer, ACrl.IssuerDN)) then
  begin
    Exit;
  end;

  LReasonCodeValue := TCrlReason.Unspecified;

  if LCrlEntry.HasExtensions then
  begin
    CheckCrlEntryCriticalExtensions(LCrlEntry);

    try
      LExtensions := LCrlEntry.CrlEntry.Extensions;
      if LExtensions <> nil then
      begin
        LParsed := LExtensions.GetExtensionParsedValue(TX509Extensions.ReasonCode);
        if LParsed <> nil then
          LReasonCodeValue := TDerEnumerated.GetInstance(LParsed).IntValueExact;
      end;
    except
      on E: Exception do
        raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SExtensionDecodeFailed,
          ['reason code CRL entry', E.Message]);
    end;
  end;

  LRevocationDate := LCrlEntry.RevocationDate;
  if AValidDate < LRevocationDate then
  begin
    // a revocation dated after the checked time still counts only for the irreversible reasons
    case LReasonCodeValue of
      TCrlReason.Unspecified, TCrlReason.KeyCompromise, TCrlReason.CACompromise, TCrlReason.AACompromise:
        ;
    else
      Exit;
    end;
  end;

  // RFC 5280 6.3.3 (i) or (j)
  ACertStatus.Status := LReasonCodeValue;
  ACertStatus.RevocationDate := TNullable<TDateTime>.Some(LRevocationDate);
end;

class function TPkixCertPathValidatorUtilities.GetNextWorkingKey(const ACerts
  : TCryptoLibGenericArray<IX509Certificate>; AIndex: Int32): IAsymmetricKeyParameter;
var
  LPubKey: IAsymmetricKeyParameter;
  LDsaPubKey, LPrevDsaPubKey: IDsaPublicKeyParameters;
  LIdx: Int32;
  LDsaParams: IDsaParameters;
begin
  LPubKey := ACerts[AIndex].GetPublicKey();

  if not Supports(LPubKey, IDsaPublicKeyParameters, LDsaPubKey) then
  begin
    Result := LPubKey;
    Exit;
  end;

  if LDsaPubKey.Parameters <> nil then
  begin
    Result := LDsaPubKey;
    Exit;
  end;

  // the DSA parameters are inherited from the nearest ancestor certificate that carries them
  for LIdx := AIndex + 1 to System.High(ACerts) do
  begin
    LPubKey := ACerts[LIdx].GetPublicKey();

    if not Supports(LPubKey, IDsaPublicKeyParameters, LPrevDsaPubKey) then
      raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SDsaParametersNotInherited);

    LDsaParams := LPrevDsaPubKey.Parameters;
    if LDsaParams = nil then
      Continue;

    Result := TDsaPublicKeyParameters.Create(LDsaPubKey.Y, LDsaParams) as IDsaPublicKeyParameters;
    Exit;
  end;

  raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SDsaParametersNotInherited);
end;

class function TPkixCertPathValidatorUtilities.GetValidCertDateFromValidityModel(AValidityDate: TDateTime;
  AValidityModel: Int32; const ACertPath: IPkixCertPath; AIndex: Int32): TDateTime;
var
  LIssuedCert: IX509Certificate;
  LExtensions: IX509Extensions;
  LParsed: IAsn1Object;
begin
  if (TPkixParameters.ChainValidityModel <> AValidityModel) or (AIndex <= 0) then
  begin
    // use the given signing/encryption time, or the current date
    Result := AValidityDate;
    Exit;
  end;

  LIssuedCert := ACertPath.Certificates[AIndex - 1];

  if (AIndex - 1) = 0 then
  begin
    try
      LParsed := nil;
      LExtensions := GetCertExtensions(LIssuedCert);
      if LExtensions <> nil then
        LParsed := LExtensions.GetExtensionParsedValue(DateOfCertGenOid());

      if LParsed <> nil then
      begin
        Result := TAsn1GeneralizedTime.GetInstance(LParsed).ToDateTime();
        Exit;
      end;
    except
      on E: Exception do
        raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SExtensionDecodeFailed,
          ['date of cert gen', E.Message]);
    end;
  end;

  Result := LIssuedCert.NotBefore;
end;

class procedure TPkixCertPathValidatorUtilities.GetCrlIssuersFromDistributionPoint(const ADistributionPoint
  : IDistributionPoint; const AIssuerPrincipals: TCryptoLibGenericArray<IX509Name>;
  const ASelector: IX509CrlStoreSelector; const APkixParams: IPkixParameters);
var
  LIssuers: TCryptoLibGenericArray<IX509Name>;
  LGenNames: TCryptoLibGenericArray<IGeneralName>;
  LIdx, LCount: Int32;
begin
  LIssuers := nil;
  LCount := 0;

  if ADistributionPoint.CrlIssuer <> nil then
  begin
    // indirect CRL: only the directoryName choices name a CRL issuer
    LGenNames := ADistributionPoint.CrlIssuer.GetNames();
    System.SetLength(LIssuers, System.Length(LGenNames));
    for LIdx := 0 to System.High(LGenNames) do
    begin
      if LGenNames[LIdx].TagNo = TGeneralName.DirectoryName then
      begin
        try
          LIssuers[LCount] := TX509Name.GetInstance(LGenNames[LIdx].Name.ToAsn1Object());
          System.Inc(LCount);
        except
          on E: Exception do
            raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SCrlIssuerDecodeFailed, [E.Message]);
        end;
      end;
    end;
    System.SetLength(LIssuers, LCount);
  end
  else
  begin
    // the certificate issuer is the CRL issuer, so distributionPoint MUST be present
    if ADistributionPoint.DistributionPointName = nil then
      raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SCrlIssuerOmitted);

    System.SetLength(LIssuers, System.Length(AIssuerPrincipals));
    for LIdx := 0 to System.High(AIssuerPrincipals) do
    begin
      LIssuers[LIdx] := AIssuerPrincipals[LIdx];
    end;
  end;

  ASelector.Issuers := LIssuers;
end;

class function TPkixCertPathValidatorUtilities.GetCompleteCrls(
  const ADistributionPoint: IDistributionPoint; const ACert: IX509Certificate;
  const APkixParams: IPkixParameters; AValidityDate: TDateTime): TCryptoLibGenericArray<IX509Crl>;
var
  LCrlSelect: IX509CrlStoreSelector;
begin
  LCrlSelect := TX509CrlStoreSelector.Create() as IX509CrlStoreSelector;
  LCrlSelect.CertificateChecking := ACert;
  Result := DoGetCompleteCrls(ADistributionPoint, ACert.IssuerDN, LCrlSelect, APkixParams, AValidityDate);
end;

class function TPkixCertPathValidatorUtilities.GetCompleteCrls(
  const ADistributionPoint: IDistributionPoint; const AAttrCert: IX509V2AttributeCertificate;
  const APkixParams: IPkixParameters; AValidityDate: TDateTime): TCryptoLibGenericArray<IX509Crl>;
var
  LCrlSelect: IX509CrlStoreSelector;
begin
  LCrlSelect := TX509CrlStoreSelector.Create() as IX509CrlStoreSelector;
  LCrlSelect.AttrCertChecking := AAttrCert;
  Result := DoGetCompleteCrls(ADistributionPoint, GetIssuerPrincipal(AAttrCert), LCrlSelect,
    APkixParams, AValidityDate);
end;

class function TPkixCertPathValidatorUtilities.DoGetCompleteCrls(
  const ADistributionPoint: IDistributionPoint; const AIssuer: IX509Name;
  const ACrlSelect: IX509CrlStoreSelector; const APkixParams: IPkixParameters;
  AValidityDate: TDateTime): TCryptoLibGenericArray<IX509Crl>;
var
  LCertObjIssuer: IX509Name;
  LCrlSelect: IX509CrlStoreSelector;
  LIssuers: TCryptoLibGenericArray<IX509Name>;
begin
  LCertObjIssuer := AIssuer;
  LCrlSelect := ACrlSelect;

  System.SetLength(LIssuers, 1);
  LIssuers[0] := LCertObjIssuer;
  try
    GetCrlIssuersFromDistributionPoint(ADistributionPoint, LIssuers, LCrlSelect, APkixParams);
  except
    on E: Exception do
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SDistributionPointIssuerFailed, [E.Message]);
  end;

  LCrlSelect.CompleteCrlEnabled := True;

  Result := TPkixCrlUtilities.FindCrls(LCrlSelect, APkixParams, AValidityDate);
  if System.Length(Result) < 1 then
    raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SNoCrlsFound, [LCertObjIssuer.ToString()]);
end;

class function TPkixCertPathValidatorUtilities.IsDeltaCrl(const ACrl: IX509Crl): Boolean;
begin
  Result := HasCriticalExtension(ACrl, TX509Extensions.DeltaCrlIndicator);
end;

class function TPkixCertPathValidatorUtilities.RetainDeltaCrls(const ACrls: TCryptoLibGenericArray<IX509Crl>)
  : TCryptoLibGenericArray<IX509Crl>;
var
  LIdx, LCount: Int32;
begin
  System.SetLength(Result, System.Length(ACrls));
  LCount := 0;
  for LIdx := 0 to System.High(ACrls) do
  begin
    if IsDeltaCrl(ACrls[LIdx]) then
    begin
      Result[LCount] := ACrls[LIdx];
      System.Inc(LCount);
    end;
  end;
  System.SetLength(Result, LCount);
end;

class function TPkixCertPathValidatorUtilities.GetDeltaCrls(AValidityDate: TDateTime;
  const APkixParams: IPkixParameters; const ACompleteCrl: IX509Crl): TCryptoLibGenericArray<IX509Crl>;
var
  LDeltaSelect: IX509CrlStoreSelector;
  LExtensions: IX509Extensions;
  LParsed: IAsn1Object;
  LCompleteCrlNumber: TBigInteger;
  LIdp: TCryptoLibByteArray;
  LIssuers: TCryptoLibGenericArray<IX509Name>;
begin
  LDeltaSelect := TX509CrlStoreSelector.Create() as IX509CrlStoreSelector;

  // RFC 5280 5.2.4 (a)
  System.SetLength(LIssuers, 1);
  LIssuers[0] := ACompleteCrl.IssuerDN;
  LDeltaSelect.Issuers := LIssuers;

  LExtensions := GetCrlExtensions(ACompleteCrl);

  LCompleteCrlNumber := Default (TBigInteger);
  try
    LParsed := nil;
    if LExtensions <> nil then
      LParsed := LExtensions.GetExtensionParsedValue(TX509Extensions.CrlNumber);
    if LParsed <> nil then
      LCompleteCrlNumber := TDerInteger.GetInstance(LParsed).GetPositiveValue();
  except
    on E: Exception do
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SExtensionDecodeFailed,
        ['CRL number', E.Message]);
  end;

  // RFC 5280 5.2.4 (b)
  LIdp := nil;
  try
    LParsed := nil;
    if LExtensions <> nil then
      LParsed := LExtensions.GetExtensionParsedValue(TX509Extensions.IssuingDistributionPoint);
    if LParsed <> nil then
      LIdp := TIssuingDistributionPoint.GetInstance(LParsed).GetDerEncoded();
  except
    on E: Exception do
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SExtensionDecodeFailed,
        ['issuing distribution point', E.Message]);
  end;

  // RFC 5280 5.2.4 (d)
  if LCompleteCrlNumber.IsInitialized then
    LDeltaSelect.MinCrlNumber := LCompleteCrlNumber.Add(TBigInteger.One);

  LDeltaSelect.IssuingDistributionPoint := LIdp;
  LDeltaSelect.IssuingDistributionPointEnabled := True;

  // RFC 5280 5.2.4 (c)
  LDeltaSelect.MaxBaseCrlNumber := LCompleteCrlNumber;

  // the selector does not require a critical delta CRL indicator, so filter the rest out here
  LDeltaSelect.DeltaCrlIndicatorEnabled := True;

  Result := RetainDeltaCrls(TPkixCrlUtilities.FindCrls(LDeltaSelect, APkixParams, AValidityDate));
end;

class procedure TPkixCertPathValidatorUtilities.AddAdditionalStoresFromCrlDistributionPoint(const ACrlDistPoint
  : ICrlDistPoint; const APkixParams: IPkixParameters);
begin
  // stores fetched from a location named in a certificate or CRL are not supported
end;

class function TPkixCertPathValidatorUtilities.ProcessCertD1i(AIndex: Int32;
  const APolicyNodes: TPkixPolicyNodeLevels; const APolicyOid: IDerObjectIdentifier;
  const AQualifiers: TCryptoLibGenericArray<IPolicyQualifierInfo>): Boolean;
var
  LPolicy: String;
  LIdx: Int32;
  LNode, LChild: IPkixPolicyNode;
  LChildExpectedPolicies: TCryptoLibStringArray;
begin
  LPolicy := APolicyOid.GetID();

  for LIdx := 0 to APolicyNodes[AIndex - 1].Count - 1 do
  begin
    LNode := APolicyNodes[AIndex - 1][LIdx];
    if not LNode.HasExpectedPolicy(LPolicy) then
      Continue;

    System.SetLength(LChildExpectedPolicies, 1);
    LChildExpectedPolicies[0] := LPolicy;

    LChild := TPkixPolicyNode.Create(nil, AIndex, LChildExpectedPolicies, LNode, AQualifiers,
      LPolicy, False) as IPkixPolicyNode;
    LNode.AddChild(LChild);
    APolicyNodes[AIndex].Add(LChild);

    Result := True;
    Exit;
  end;

  Result := False;
end;

class procedure TPkixCertPathValidatorUtilities.ProcessCertD1ii(AIndex: Int32;
  const APolicyNodes: TPkixPolicyNodeLevels; const APolicyOid: IDerObjectIdentifier;
  const AQualifiers: TCryptoLibGenericArray<IPolicyQualifierInfo>);
var
  LAnyPolicyNode, LChild: IPkixPolicyNode;
  LPolicy: String;
  LChildExpectedPolicies: TCryptoLibStringArray;
begin
  LAnyPolicyNode := FindValidPolicy(APolicyNodes[AIndex - 1], AnyPolicy);
  if LAnyPolicyNode = nil then
    Exit;

  LPolicy := APolicyOid.GetID();

  System.SetLength(LChildExpectedPolicies, 1);
  LChildExpectedPolicies[0] := LPolicy;

  LChild := TPkixPolicyNode.Create(nil, AIndex, LChildExpectedPolicies, LAnyPolicyNode, AQualifiers,
    LPolicy, False) as IPkixPolicyNode;
  LAnyPolicyNode.AddChild(LChild);
  APolicyNodes[AIndex].Add(LChild);
end;

class function TPkixCertPathValidatorUtilities.FindIssuerCerts(const ACert: IX509Certificate;
  const APkixBuilderParameters: IPkixBuilderParameters): TCryptoLibGenericArray<IX509Certificate>;
var
  LSelector: IX509CertStoreSelector;
  LStores: TCryptoLibGenericArray<IStore<IX509Certificate>>;
  LMatches: TCryptoLibGenericArray<IX509Certificate>;
  LOuter, LInner, LSeek, LCount: Int32;
  LSeen: Boolean;
begin
  LSelector := TX509CertStoreSelector.Create() as IX509CertStoreSelector;
  LSelector.Subject := ACert.IssuerDN;

  Result := nil;
  LCount := 0;

  LStores := APkixBuilderParameters.GetStoresCert();
  for LOuter := 0 to System.High(LStores) do
  begin
    try
      LMatches := LStores[LOuter].EnumerateMatches(LSelector);
    except
      on E: Exception do
        raise EPkixCertPathBuilderCryptoLibException.CreateResFmt(@SIssuerCertSearchFailed, [E.Message]);
    end;

    for LInner := 0 to System.High(LMatches) do
    begin
      LSeen := False;
      for LSeek := 0 to LCount - 1 do
      begin
        if Result[LSeek].Equals(LMatches[LInner]) then
        begin
          LSeen := True;
          Break;
        end;
      end;
      if not LSeen then
      begin
        System.SetLength(Result, LCount + 1);
        Result[LCount] := LMatches[LInner];
        System.Inc(LCount);
      end;
    end;
  end;
end;

class procedure TPkixCertPathValidatorUtilities.CheckCrlCriticalExtensions(const ACrl: IX509Crl);
var
  LTbs: ITbsCertificateList;
  LExtensions: IX509Extensions;
  LOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
  LIdx: Int32;
  LExtension: IX509Extension;
begin
  // only our own CRL implementation is expected, so the extensions it supports are known here
  LTbs := ACrl.CertificateList.TbsCertList;
  if LTbs.Version < 2 then
    Exit;

  LExtensions := LTbs.Extensions;
  if LExtensions = nil then
    Exit;

  LOids := LExtensions.GetExtensionOids();
  for LIdx := 0 to System.High(LOids) do
  begin
    if TX509Extensions.IssuingDistributionPoint.Equals(LOids[LIdx] as IAsn1Convertible) or
      TX509Extensions.DeltaCrlIndicator.Equals(LOids[LIdx] as IAsn1Convertible) then
    begin
      Continue;
    end;

    LExtension := LExtensions.GetExtension(LOids[LIdx]);
    if (LExtension <> nil) and LExtension.IsCritical then
      raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SCrlUnsupportedCriticalExtensions);
  end;
end;

class procedure TPkixCertPathValidatorUtilities.CheckCrlEntryCriticalExtensions(const ACrlEntry: IX509CrlEntry);
var
  LExtensions: IX509Extensions;
begin
  LExtensions := ACrlEntry.CrlEntry.Extensions;
  if (LExtensions <> nil) and LExtensions.HasAnyCriticalExtensions() then
    raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SCrlEntryUnsupportedCriticalExtensions);
end;

class function TPkixCertPathValidatorUtilities.FindValidPolicy(const APolicyNodes: TList<IPkixPolicyNode>;
  const APolicy: String): IPkixPolicyNode;
var
  LIdx: Int32;
begin
  if APolicyNodes <> nil then
  begin
    for LIdx := 0 to APolicyNodes.Count - 1 do
    begin
      if APolicy = APolicyNodes[LIdx].ValidPolicy then
      begin
        Result := APolicyNodes[LIdx];
        Exit;
      end;
    end;
  end;
  Result := nil;
end;

class function TPkixCertPathValidatorUtilities.HasCriticalExtension(const AExtensions: IX509Extensions;
  const AExtensionOid: IDerObjectIdentifier): Boolean;
var
  LExtension: IX509Extension;
begin
  Result := False;
  if AExtensions = nil then
    Exit;
  LExtension := AExtensions.GetExtension(AExtensionOid);
  if LExtension <> nil then
    Result := LExtension.IsCritical;
end;

class function TPkixCertPathValidatorUtilities.HasCriticalExtension(const ACertificate: IX509Certificate;
  const AExtensionOid: IDerObjectIdentifier): Boolean;
var
  LTbs: ITbsCertificateStructure;
begin
  LTbs := ACertificate.CertificateStructure.TbsCertificate;
  Result := (LTbs.Version >= 3) and HasCriticalExtension(LTbs.Extensions, AExtensionOid);
end;

class function TPkixCertPathValidatorUtilities.HasCriticalExtension(const ACrl: IX509Crl;
  const AExtensionOid: IDerObjectIdentifier): Boolean;
var
  LTbs: ITbsCertificateList;
begin
  LTbs := ACrl.CertificateList.TbsCertList;
  Result := (LTbs.Version >= 2) and HasCriticalExtension(LTbs.Extensions, AExtensionOid);
end;

end.
