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

unit ClpRfc3281CertPathUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpIStore,
  ClpIAsn1Core,
  ClpAsn1Core,
  ClpIAsn1Objects,
  ClpAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpX509ExtensionUtilities,
  ClpIX509Certificate,
  ClpIX509Crl,
  ClpIX509V2AttributeCertificate,
  ClpIX509StoreSelectors,
  ClpX509StoreSelectors,
  ClpIAsymmetricKeyParameter,
  ClpIPkixTypes,
  ClpPkixParameters,
  ClpPkixBuilderParameters,
  ClpRfc3280CertPathUtilities,
  ClpPkixCertPathValidatorUtilities,
  ClpCertStatus,
  ClpReasonsMask,
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  STargetInformationReadFailed = 'the target information extension could not be read: %s';
  SUnsupportedCriticalExtensions =
    'the attribute certificate contains unsupported critical extensions: [%s]';
  SNoRevAvailWithPointer =
    'the noRevAvail extension is set but the attribute certificate also carries a revocation pointer';
  SCrlDistPointReadFailed = 'the CRL distribution point extension could not be read: %s';
  SAdditionalCrlLocationsFailed = 'no additional CRL locations could be decoded from the CRL ' +
    'distribution point extension: %s';
  SDistributionPointsReadFailed = 'the distribution points could not be read: %s';
  SNoValidCrlFound = 'no valid CRL found for the attribute certificate';
  SCrlCheckFailed = 'the attribute certificate revocation status could not be checked: %s';
  SAttrCertRevoked = 'attribute certificate revocation after %s, reason: %s';
  SAttrCertStatusUndetermined = 'the attribute certificate status could not be determined';
  SValidationTimeInFuture = 'the validation time is in the future';
  SNoValidCrlForCurrentTime = 'no valid CRL for the current time found';
  SProhibitedAttribute = 'the attribute certificate contains a prohibited attribute: %s';
  SMissingNecessaryAttribute = 'the attribute certificate does not contain a necessary attribute: %s';
  SAttrCertNotValid = 'the attribute certificate is not valid: %s';
  SIssuerCannotSignDigitalSignatures = 'the attribute certificate issuer public key cannot be used ' +
    'to validate digital signatures';
  SIssuerIsAlsoPublicKeyIssuer = 'the attribute certificate issuer is also a public key certificate issuer';
  SIssuerNotDirectlyTrusted = 'the attribute certificate issuer is not directly trusted';
  SIssuerPathValidationFailed = 'the certification path for the issuer certificate of the attribute ' +
    'certificate could not be validated: %s';
  SSignatureVerificationFailed = 'the attribute certificate signature could not be verified: %s';
  SHolderSearchFailed = 'the public key certificate for the attribute certificate cannot be searched: %s';
  SHolderNotFoundBaseId = 'the public key certificate specified in the base certificate ID for the ' +
    'attribute certificate cannot be found';
  SHolderNotFoundEntityName = 'the public key certificate specified in the entity name for the ' +
    'attribute certificate cannot be found';
  SHolderPathBuildFailed = 'the certification path for the public key certificate of the attribute ' +
    'certificate could not be built: %s';

type
  /// <summary>
  /// The attribute certificate path processing of RFC 3281 5: locating and validating the holder and
  /// issuer public key certificates, verifying the AC signature, revocation and validity, and the
  /// attribute and extension checks.
  /// </summary>
  TRfc3281CertPathUtilities = class sealed(TObject)

  strict private
    class function ParseExtension(const AExtensionValue: IAsn1OctetString): IAsn1Object; static;

    class function ContainsCertificate(const ACerts: TCryptoLibGenericArray<IX509Certificate>;
      const ACert: IX509Certificate): Boolean; static;
    class procedure AppendCertificate(var ACerts: TCryptoLibGenericArray<IX509Certificate>;
      const ACert: IX509Certificate); static;

    /// <summary>Collect every certificate of the stores that matches ASelector, without duplicates.</summary>
    class procedure CollectHolderMatches(var ACerts: TCryptoLibGenericArray<IX509Certificate>;
      const ASelector: IX509CertStoreSelector;
      const AStores: TCryptoLibGenericArray<IStore<IX509Certificate>>); static;

    class function JoinCriticalExtensions(const AOids: TList<String>): String; static;

    /// <summary>RFC 3281 revocation: check the attribute certificate against one distribution point.</summary>
    class procedure CheckCrl(const ADistributionPoint: IDistributionPoint;
      const AAttrCert: IX509V2AttributeCertificate; const APkixParams: IPkixParameters;
      ACurrentDate, AValidityDate: TDateTime; const AIssuerCert: IX509Certificate;
      const ACertStatus: ICertStatus; const AReasonsMask: IReasonsMask;
      const ACertPathCerts: TCryptoLibGenericArray<IX509Certificate>); static;

  public
    /// <summary>
    /// RFC 3281 5 step 1: find the holder public key certificate(s) and build a validated
    /// certification path to one of them.
    /// </summary>
    class function ProcessAttrCert1(const AAttrCert: IX509V2AttributeCertificate;
      const APkixParams: IPkixParameters): IPkixCertPath; static;

    /// <summary>RFC 3281 5 step 2 (a): validate the certification path of the AC issuer certificate.</summary>
    class function ProcessAttrCert2A(const ACertPath: IPkixCertPath;
      const APkixParams: IPkixParameters): IPkixCertPathValidatorResult; static;

    /// <summary>RFC 3281 5 step 2 (b): the AC signature must verify under the issuer public key.</summary>
    class procedure ProcessAttrCert2B(const AAttrCert: IX509V2AttributeCertificate;
      const AIssuerCert: IX509Certificate); static;

    /// <summary>
    /// RFC 3281 5 step 3: the AC issuer key must permit digital signatures and the issuer must not
    /// also be a public key certificate issuer.
    /// </summary>
    class procedure ProcessAttrCert3(const AIssuerCert: IX509Certificate;
      const APkixParams: IPkixParameters); static;

    /// <summary>RFC 3281 5 step 4: the AC issuer must be one of the directly trusted AC issuers.</summary>
    class procedure ProcessAttrCert4(const AIssuerCert: IX509Certificate;
      const APkixParams: IPkixParameters); static;

    /// <summary>RFC 3281 5 step 5: the attribute certificate must be within its validity period.</summary>
    class procedure ProcessAttrCert5(const AAttrCert: IX509V2AttributeCertificate;
      AValidityDate: TDateTime); static;

    /// <summary>
    /// RFC 3281 5 step 7: process the AC extensions, running every configured checker and rejecting
    /// any critical extension left unresolved.
    /// </summary>
    class procedure ProcessAttrCert7(const AAttrCert: IX509V2AttributeCertificate;
      const ACertPath, AHolderCertPath: IPkixCertPath; const APkixParams: IPkixParameters); static;

    /// <summary>
    /// RFC 3281 4.3: reject an attribute certificate carrying a prohibited attribute or lacking a
    /// necessary one.
    /// </summary>
    class procedure AdditionalChecks(const AAttrCert: IX509V2AttributeCertificate;
      const APkixParams: IPkixParameters); static;

    /// <summary>
    /// RFC 3281 revocation: check the attribute certificate against every distribution point it
    /// names, and against any CRL issued by its issuer that no distribution point names.
    /// </summary>
    class procedure CheckCrls(const AAttrCert: IX509V2AttributeCertificate;
      const APkixParams: IPkixParameters; ACurrentDate, AValidityDate: TDateTime;
      const AIssuerCert: IX509Certificate;
      const ACertPathCerts: TCryptoLibGenericArray<IX509Certificate>); static;
  end;

implementation

uses
  ClpPkixCertPathValidator,
  ClpPkixCertPathBuilder;

{ TRfc3281CertPathUtilities }

class function TRfc3281CertPathUtilities.ParseExtension(const AExtensionValue: IAsn1OctetString): IAsn1Object;
begin
  if AExtensionValue = nil then
    Result := nil
  else
    Result := TX509ExtensionUtilities.FromExtensionValue(AExtensionValue);
end;

class function TRfc3281CertPathUtilities.ContainsCertificate(const ACerts
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

class procedure TRfc3281CertPathUtilities.AppendCertificate(var ACerts
  : TCryptoLibGenericArray<IX509Certificate>; const ACert: IX509Certificate);
begin
  System.SetLength(ACerts, System.Length(ACerts) + 1);
  ACerts[System.High(ACerts)] := ACert;
end;

class procedure TRfc3281CertPathUtilities.CollectHolderMatches(var ACerts
  : TCryptoLibGenericArray<IX509Certificate>; const ASelector: IX509CertStoreSelector;
  const AStores: TCryptoLibGenericArray<IStore<IX509Certificate>>);
var
  LOuter, LInner: Int32;
  LMatches: TCryptoLibGenericArray<IX509Certificate>;
begin
  for LOuter := 0 to System.High(AStores) do
  begin
    LMatches := AStores[LOuter].EnumerateMatches(ASelector);
    for LInner := 0 to System.High(LMatches) do
    begin
      if not ContainsCertificate(ACerts, LMatches[LInner]) then
        AppendCertificate(ACerts, LMatches[LInner]);
    end;
  end;
end;

class function TRfc3281CertPathUtilities.JoinCriticalExtensions(const AOids: TList<String>): String;
var
  LIdx: Int32;
begin
  Result := '';
  for LIdx := 0 to AOids.Count - 1 do
  begin
    if LIdx > 0 then
      Result := Result + ', ';
    Result := Result + AOids[LIdx];
  end;
end;

class function TRfc3281CertPathUtilities.ProcessAttrCert1(const AAttrCert: IX509V2AttributeCertificate;
  const APkixParams: IPkixParameters): IPkixCertPath;
var
  LHolderPKCs: TCryptoLibGenericArray<IX509Certificate>;
  LSelector, LCertSelector: IX509CertStoreSelector;
  LPrincipals: TCryptoLibGenericArray<IX509Name>;
  LIdx: Int32;
  LParameters: IPkixBuilderParameters;
  LResult: IPkixCertPathBuilderResult;
  LLastMessage: String;
  LHasLastException: Boolean;
begin
  LHolderPKCs := nil;

  // holder identified by base certificate ID (issuer name plus serial number)
  LPrincipals := AAttrCert.Holder.GetIssuer();
  if LPrincipals <> nil then
  begin
    LSelector := TX509CertStoreSelector.Create() as IX509CertStoreSelector;
    LSelector.SerialNumber := AAttrCert.Holder.SerialNumber;
    for LIdx := 0 to System.High(LPrincipals) do
    begin
      try
        LSelector.Issuer := LPrincipals[LIdx];
        CollectHolderMatches(LHolderPKCs, LSelector, APkixParams.GetStoresCert());
      except
        on E: EPkixCertPathValidatorCryptoLibException do
          raise;
        on E: Exception do
          raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SHolderSearchFailed, [E.Message]);
      end;
    end;
    if System.Length(LHolderPKCs) < 1 then
      raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SHolderNotFoundBaseId);
  end;

  // holder identified by entity name
  LPrincipals := AAttrCert.Holder.GetEntityNames();
  if LPrincipals <> nil then
  begin
    LSelector := TX509CertStoreSelector.Create() as IX509CertStoreSelector;
    for LIdx := 0 to System.High(LPrincipals) do
    begin
      try
        LSelector.Issuer := LPrincipals[LIdx];
        CollectHolderMatches(LHolderPKCs, LSelector, APkixParams.GetStoresCert());
      except
        on E: EPkixCertPathValidatorCryptoLibException do
          raise;
        on E: Exception do
          raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SHolderSearchFailed, [E.Message]);
      end;
    end;
    if System.Length(LHolderPKCs) < 1 then
      raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SHolderNotFoundEntityName);
  end;

  // build and validate a certification path for each holder public key certificate
  LParameters := TPkixBuilderParameters.GetInstance(APkixParams);

  LResult := nil;
  LLastMessage := '';
  LHasLastException := False;

  for LIdx := 0 to System.High(LHolderPKCs) do
  begin
    LCertSelector := TX509CertStoreSelector.Create() as IX509CertStoreSelector;
    LCertSelector.Certificate := LHolderPKCs[LIdx];
    LParameters.SetTargetConstraintsCert(LCertSelector);

    try
      LResult := (TPkixCertPathBuilder.Create() as IPkixCertPathBuilder).Build(LParameters);
    except
      on E: Exception do
      begin
        LLastMessage := E.Message;
        LHasLastException := True;
      end;
    end;
  end;

  if LHasLastException then
    raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SHolderPathBuildFailed, [LLastMessage]);

  Result := LResult.CertPath;
end;

class function TRfc3281CertPathUtilities.ProcessAttrCert2A(const ACertPath: IPkixCertPath;
  const APkixParams: IPkixParameters): IPkixCertPathValidatorResult;
begin
  try
    Result := (TPkixCertPathValidator.Create() as IPkixCertPathValidator).Validate(ACertPath, APkixParams);
  except
    on E: Exception do
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SIssuerPathValidationFailed, [E.Message]);
  end;
end;

class procedure TRfc3281CertPathUtilities.ProcessAttrCert2B(const AAttrCert: IX509V2AttributeCertificate;
  const AIssuerCert: IX509Certificate);
var
  LMessage: String;
begin
  // the AC signature must be cryptographically correct under the issuer public key
  try
    if AAttrCert.IsSignatureValid(AIssuerCert.GetPublicKey()) then
      Exit;
    LMessage := '';
  except
    on E: Exception do
      LMessage := E.Message;
  end;

  raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SSignatureVerificationFailed, [LMessage]);
end;

class procedure TRfc3281CertPathUtilities.ProcessAttrCert3(const AIssuerCert: IX509Certificate;
  const APkixParams: IPkixParameters);
var
  LKeyUsage: TCryptoLibBooleanArray;
begin
  LKeyUsage := AIssuerCert.GetKeyUsage();

  // digitalSignature (0) or nonRepudiation (1) must be asserted when a key usage is present
  if (LKeyUsage <> nil) and
    (not (((System.Length(LKeyUsage) > 0) and LKeyUsage[0]) or
    ((System.Length(LKeyUsage) > 1) and LKeyUsage[1]))) then
    raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SIssuerCannotSignDigitalSignatures);

  if AIssuerCert.GetBasicConstraints() <> -1 then
    raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SIssuerIsAlsoPublicKeyIssuer);
end;

class procedure TRfc3281CertPathUtilities.ProcessAttrCert4(const AIssuerCert: IX509Certificate;
  const APkixParams: IPkixParameters);
var
  LAnchors: TCryptoLibGenericArray<ITrustAnchor>;
  LIdx: Int32;
  LSubject: String;
begin
  LAnchors := APkixParams.GetTrustedACIssuers();
  // the RFC 2253 rendering of the subject name is compared against each trusted issuer name; the
  // two-argument ToString lives on the concrete X.509 name, not on the interface
  LSubject := (AIssuerCert.SubjectDN as TX509Name).ToString(False, TX509Name.RFC2253Symbols);

  for LIdx := 0 to System.High(LAnchors) do
  begin
    if (LSubject = LAnchors[LIdx].CAName) or AIssuerCert.Equals(LAnchors[LIdx].TrustedCert) then
      Exit; // directly trusted
  end;

  raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SIssuerNotDirectlyTrusted);
end;

class procedure TRfc3281CertPathUtilities.ProcessAttrCert5(const AAttrCert: IX509V2AttributeCertificate;
  AValidityDate: TDateTime);
begin
  try
    AAttrCert.CheckValidity(AValidityDate);
  except
    on E: Exception do
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SAttrCertNotValid, [E.Message]);
  end;
end;

class procedure TRfc3281CertPathUtilities.ProcessAttrCert7(const AAttrCert: IX509V2AttributeCertificate;
  const ACertPath, AHolderCertPath: IPkixCertPath; const APkixParams: IPkixParameters);
var
  LCritOids: TList<String>;
  LOidsArray: TCryptoLibStringArray;
  LTargetInfoId: String;
  LOctets: IAsn1OctetString;
  LIdx: Int32;
  LCheckers: TCryptoLibGenericArray<IPkixAttrCertChecker>;
begin
  // TODO: AA Controls, attribute encryption and proxy handling are not yet supported

  LCritOids := TList<String>.Create;
  try
    LOidsArray := AAttrCert.GetCriticalExtensionOids();
    for LIdx := 0 to System.High(LOidsArray) do
      LCritOids.Add(LOidsArray[LIdx]);

    // 7.1 the target information is already checked in step 6 / the AC store selector; here only
    // confirm the extension decodes
    LTargetInfoId := TX509Extensions.TargetInformation.Id;
    if LCritOids.Contains(LTargetInfoId) then
    begin
      try
        LOctets := AAttrCert.GetExtensionValue(TX509Extensions.TargetInformation);
        TTargetInformation.GetInstance(ParseExtension(LOctets));
      except
        on E: Exception do
          raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@STargetInformationReadFailed,
            [E.Message]);
      end;
    end;
    LCritOids.Remove(LTargetInfoId);

    LCheckers := APkixParams.GetAttrCertCheckers();
    for LIdx := 0 to System.High(LCheckers) do
      LCheckers[LIdx].Check(AAttrCert, ACertPath, AHolderCertPath, LCritOids);

    if LCritOids.Count > 0 then
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SUnsupportedCriticalExtensions,
        [JoinCriticalExtensions(LCritOids)]);
  finally
    LCritOids.Free;
  end;
end;

class procedure TRfc3281CertPathUtilities.AdditionalChecks(const AAttrCert: IX509V2AttributeCertificate;
  const APkixParams: IPkixParameters);
var
  LOids: TCryptoLibStringArray;
  LIdx: Int32;
begin
  LOids := APkixParams.GetProhibitedACAttributes();
  for LIdx := 0 to System.High(LOids) do
  begin
    if AAttrCert.GetAttributes(LOids[LIdx]) <> nil then
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SProhibitedAttribute, [LOids[LIdx]]);
  end;

  LOids := APkixParams.GetNecessaryACAttributes();
  for LIdx := 0 to System.High(LOids) do
  begin
    if AAttrCert.GetAttributes(LOids[LIdx]) = nil then
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SMissingNecessaryAttribute, [LOids[LIdx]]);
  end;
end;

class procedure TRfc3281CertPathUtilities.CheckCrl(const ADistributionPoint: IDistributionPoint;
  const AAttrCert: IX509V2AttributeCertificate; const APkixParams: IPkixParameters;
  ACurrentDate, AValidityDate: TDateTime; const AIssuerCert: IX509Certificate;
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
  // RFC 3281 4.3.6: a noRevAvail attribute certificate has no revocation information to consult
  if AAttrCert.GetExtensionValue(TX509Extensions.NoRevAvail) <> nil then
    Exit;

  if AValidityDate > ACurrentDate then
    raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SValidationTimeInFuture);

  // (a) timely valid CRLs are always used, so there is no step (a)(1) here: locally cached CRLs are
  // assumed to be in the configured CRL stores
  LCrls := TPkixCertPathValidatorUtilities.GetCompleteCrls(ADistributionPoint, AAttrCert, APkixParams,
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
      LInterimReasonsMask := TRfc3280CertPathUtilities.ProcessCrlD(LCrl, ADistributionPoint);

      // (e) only a valid CRL may update the reasons mask, so a CRL without new reasons is ignored
      if not AReasonsMask.HasNewReasons(LInterimReasonsMask) then
        Continue;

      // (f) no path is pre-validated for the AC issuer, so no default CRL signer is supplied
      LKeys := TRfc3280CertPathUtilities.ProcessCrlF(LCrl, nil, nil, APkixParams, ACertPathCerts);

      // (g)
      LKey := TRfc3280CertPathUtilities.ProcessCrlG(LCrl, LKeys);

      // under the chain validity model a signature stays valid past expiry, so the certificate does
      // not have to lie inside the CRL validity time
      if APkixParams.ValidityModel <> TPkixParameters.ChainValidityModel then
      begin
        // an expired certificate drops off the CRL, so without this check an AC that was revoked and
        // has since expired would be reported as valid
        if AAttrCert.NotAfter < LCrl.ThisUpdate then
          raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SNoValidCrlForCurrentTime);
      end;

      // (b)(1)
      TRfc3280CertPathUtilities.ProcessCrlB1(ADistributionPoint, AAttrCert, LCrl);

      // (b)(2)
      TRfc3280CertPathUtilities.ProcessCrlB2(ADistributionPoint, AAttrCert, LCrl);

      if APkixParams.IsUseDeltasEnabled then
      begin
        LDeltaCrls := TPkixCertPathValidatorUtilities.GetDeltaCrls(AValidityDate, APkixParams, LCrl);

        // (h) only one valid delta CRL is wanted
        LDeltaCrl := TRfc3280CertPathUtilities.ProcessCrlH(LDeltaCrls, LKey);
        if LDeltaCrl <> nil then
        begin
          TPkixCertPathValidatorUtilities.CheckCrlCriticalExtensions(LDeltaCrl);

          // (c)
          TRfc3280CertPathUtilities.ProcessCrlC(LDeltaCrl, LCrl);

          // (i)
          TRfc3280CertPathUtilities.ProcessCrlI(AValidityDate, LDeltaCrl, AAttrCert, ACertStatus);
        end;
      end;

      // (j)
      TRfc3280CertPathUtilities.ProcessCrlJ(AValidityDate, LCrl, AAttrCert, ACertStatus);

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

class procedure TRfc3281CertPathUtilities.CheckCrls(const AAttrCert: IX509V2AttributeCertificate;
  const APkixParams: IPkixParameters; ACurrentDate, AValidityDate: TDateTime;
  const AIssuerCert: IX509Certificate;
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
  if not APkixParams.IsRevocationEnabled then
    Exit;

  // RFC 3281 4.3.6: a noRevAvail attribute certificate must not also point at revocation information
  if AAttrCert.GetExtensionValue(TX509Extensions.NoRevAvail) <> nil then
  begin
    if (AAttrCert.GetExtensionValue(TX509Extensions.CrlDistributionPoints) <> nil) or
      (AAttrCert.GetExtensionValue(TX509Extensions.AuthorityInfoAccess) <> nil) then
      raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SNoRevAvailWithPointer);
    Exit;
  end;

  LCrlDistPoint := nil;
  LParsed := ParseExtension(AAttrCert.GetExtensionValue(TX509Extensions.CrlDistributionPoints));
  if LParsed <> nil then
  begin
    try
      LCrlDistPoint := TCrlDistPoint.GetInstance(LParsed);
    except
      on E: Exception do
        raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SCrlDistPointReadFailed, [E.Message]);
    end;
  end;

  // the distribution point parameters are always a copy, even when no store is added to them
  LPkixParamsCrlDp := APkixParams.Clone();
  try
    TPkixCertPathValidatorUtilities.AddAdditionalStoresFromCrlDistributionPoint(LCrlDistPoint,
      LPkixParamsCrlDp);
  except
    on E: EPkixCertPathValidatorCryptoLibException do
      raise;
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
        CheckCrl(LDistributionPoints[LIdx], AAttrCert, LPkixParamsCrlDp, ACurrentDate, AValidityDate,
          AIssuerCert, LCertStatus, LReasonsMask, ACertPathCerts);
        LValidCrlFound := True;
      except
        on E: Exception do
          LLastMessage := E.Message;
      end;
      System.Inc(LIdx);
    end;
  end;

  // when the status is still undetermined, repeat with any CRL issued by the AC issuer that no
  // distribution point names
  if (LCertStatus.Status = TCertStatus.Unrevoked) and (not LReasonsMask.IsAllReasons) then
  begin
    try
      // assume a distribution point with the reasons and cRLIssuer fields omitted and a
      // distribution point name of the attribute certificate issuer
      LIssuer := TPkixCertPathValidatorUtilities.GetIssuerPrincipal(AAttrCert);
      LDistributionPoint := TDistributionPoint.Create(TDistributionPointName.Create
        (TGeneralNames.Create(TGeneralName.Create(TGeneralName.DirectoryName, LIssuer as IAsn1Encodable)
        as IGeneralName) as IGeneralNames) as IDistributionPointName, nil, nil) as IDistributionPoint;

      LPkixParamsClone := APkixParams.Clone();
      CheckCrl(LDistributionPoint, AAttrCert, LPkixParamsClone, ACurrentDate, AValidityDate, AIssuerCert,
        LCertStatus, LReasonsMask, ACertPathCerts);
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
      LFormattedDate := TPkixCertPathValidatorUtilities.FormatUtcInstant(LCertStatus.RevocationDate.Value);

    raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SAttrCertRevoked,
      [LFormattedDate, TRfc3280CertPathUtilities.CrlReasonName(LCertStatus.Status)]);
  end;

  if (LCertStatus.Status = TCertStatus.Unrevoked) and (not LReasonsMask.IsAllReasons) then
    LCertStatus.Status := TCertStatus.Undetermined;

  if LCertStatus.Status = TCertStatus.Undetermined then
    raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SAttrCertStatusUndetermined);
end;

end.
