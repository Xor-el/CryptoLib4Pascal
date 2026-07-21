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

unit ClpPkixCertPathValidator;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpIStore,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIX509Certificate,
  ClpIAsymmetricKeyParameter,
  ClpIPkixTypes,
  ClpPkixPolicyNode,
  ClpPkixNameConstraintValidator,
  ClpPkixCertPathValidatorResult,
  ClpPkixCertPathValidatorUtilities,
  ClpRfc3280CertPathUtilities,
  ClpPkixRevocationChecker,
  ClpDateTimeHelper,
  ClpCryptoLibTypes;

resourcestring
  STrustAnchorsNil = 'trust anchors cannot be nil for certification path validation';
  SCertPathEmpty = 'certification path is empty';
  STrustAnchorSearchFailed = 'trust anchor for the certification path could not be determined: %s';
  STrustAnchorNotFound = 'trust anchor for the certification path not found';
  STrustAnchorSubjectFailed = 'subject of the trust anchor could not be established: %s';
  SWorkingAlgorithmFailed = 'algorithm identifier of the public key of the trust anchor could not ' +
    'be read: %s';
  STargetConstraintsMismatch = 'target certificate in the certification path does not match the ' +
    'target constraints';
  SVersion1CACertificate = 'the version 1 certificate at index %d cannot be used as a CA certificate';
  SNextWorkingKeyFailed = 'the next working key at index %d could not be retrieved: %s';
  SPolicyProcessingFailed = 'path processing failed on policy';
  SMultipleRevocationCheckers = 'only one revocation checker is allowed among the certification '
    + 'path checkers';

type
  /// <summary>
  /// Validates an X.509 certification path against a set of trust anchors and parameters, following
  /// the basic path validation algorithm of RFC 5280 6.1.
  /// </summary>
  /// <remarks>
  /// Instances keep no state between calls, but they are not otherwise thread safe: callers sharing
  /// one instance must serialize access themselves.
  /// </remarks>
  TPkixCertPathValidator = class(TInterfacedObject, IPkixCertPathValidator)

  strict private
  var
    FIsForCrlCheck: Boolean;

    /// <summary>The critical extension OIDs of ACert that this algorithm does not itself resolve.</summary>
    /// <param name="AIsFinalCert">
    /// True for the RFC 5280 6.1.5 (f) wrap-up, which also resolves the CRL distribution points and
    /// extended key usage extensions.
    /// </param>
    class procedure CollectUnresolvedCriticalExtensions(const ACert: IX509Certificate;
      const AResult: TList<String>; AIsFinalCert: Boolean); static;

  public
    constructor Create(); overload;
    /// <summary>AIsForCrlCheck relaxes the checks that do not apply when validating a CRL signer.</summary>
    constructor Create(AIsForCrlCheck: Boolean); overload;

    function Validate(const ACertPath: IPkixCertPath; const AParams: IPkixParameters)
      : IPkixCertPathValidatorResult;
  end;

implementation

{ TPkixCertPathValidator }

constructor TPkixCertPathValidator.Create();
begin
  Create(False);
end;

constructor TPkixCertPathValidator.Create(AIsForCrlCheck: Boolean);
begin
  inherited Create();
  FIsForCrlCheck := AIsForCrlCheck;
end;

class procedure TPkixCertPathValidator.CollectUnresolvedCriticalExtensions(const ACert: IX509Certificate;
  const AResult: TList<String>; AIsFinalCert: Boolean);
var
  LOids: TCryptoLibStringArray;
  LIdx: Int32;
begin
  AResult.Clear;

  LOids := ACert.GetCriticalExtensionOids();
  for LIdx := 0 to System.High(LOids) do
  begin
    AResult.Add(LOids[LIdx]);
  end;

  // these extensions are resolved by the path processing algorithm itself
  AResult.Remove(TX509Extensions.KeyUsage.Id);
  AResult.Remove(TX509Extensions.CertificatePolicies.Id);
  AResult.Remove(TX509Extensions.PolicyMappings.Id);
  AResult.Remove(TX509Extensions.InhibitAnyPolicy.Id);
  AResult.Remove(TX509Extensions.IssuingDistributionPoint.Id);
  AResult.Remove(TX509Extensions.DeltaCrlIndicator.Id);
  AResult.Remove(TX509Extensions.PolicyConstraints.Id);
  AResult.Remove(TX509Extensions.BasicConstraints.Id);
  AResult.Remove(TX509Extensions.SubjectAlternativeName.Id);
  AResult.Remove(TX509Extensions.NameConstraints.Id);

  if AIsFinalCert then
  begin
    AResult.Remove(TX509Extensions.CrlDistributionPoints.Id);
    AResult.Remove(TX509Extensions.ExtendedKeyUsage.Id);
  end;
end;

function TPkixCertPathValidator.Validate(const ACertPath: IPkixCertPath; const AParams: IPkixParameters)
  : IPkixCertPathValidatorResult;
var
  LCerts: TCryptoLibGenericArray<IX509Certificate>;
  LCheckers: TCryptoLibGenericArray<IPkixCertPathChecker>;
  LUserInitialPolicySet, LInitialExpectedPolicies: TCryptoLibStringArray;
  LTargetConstraints: ISelector<IX509Certificate>;
  LTrust: ITrustAnchor;
  LCurrentDate, LValidityDate: TDateTime;
  LN, LI, LIndex, LIdx: Int32;
  LExplicitPolicy, LInhibitAnyPolicy, LPolicyMapping, LMaxPathLength: Int32;
  LPolicyNodes: TPkixPolicyNodeLevels;
  LAcceptablePolicies, LCriticalExtensions: TList<String>;
  LValidPolicyTree, LIntersection: IPkixPolicyNode;
  LNameConstraintValidator: IPkixNameConstraintValidator;
  LRevocationChecker, LFoundChecker: IPkixCertRevocationChecker;
  LWorkingPublicKey: IAsymmetricKeyParameter;
  LWorkingIssuerName: IX509Name;
  LWorkingAlgID: IAlgorithmIdentifier;
  LCaBasicConstraints: IBasicConstraints;
  LCert, LSign: IX509Certificate;
begin
  if AParams.GetTrustAnchors() = nil then
    raise EArgumentCryptoLibException.CreateRes(@STrustAnchorsNil);

  //
  // 6.1.1 - inputs
  //

  // (a)
  LCerts := ACertPath.Certificates;
  LN := System.Length(LCerts);

  if LN = 0 then
    raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SCertPathEmpty);

  // (b)
  LCurrentDate := Now.ToUniversalTime();
  LValidityDate := TPkixCertPathValidatorUtilities.GetValidityDate(AParams, LCurrentDate);

  // (c)
  LUserInitialPolicySet := AParams.GetInitialPolicies();

  // (d)
  try
    LTrust := TPkixCertPathValidatorUtilities.FindTrustAnchor(LCerts[LN - 1], AParams.GetTrustAnchors());
  except
    on E: Exception do
      raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@STrustAnchorSearchFailed, [E.Message]);
  end;

  if LTrust = nil then
    raise EPkixCertPathValidatorCryptoLibException.CreateRes(@STrustAnchorNotFound);

  // RFC 5280: CRLs must originate from the same trust anchor as the target certificate

  // a path checker that also settles revocation status takes over RFC 5280 6.1.3 (a)(3); it is
  // not run as an ordinary path checker as well
  LRevocationChecker := nil;
  LCheckers := AParams.GetCertPathCheckers();
  for LIdx := 0 to System.High(LCheckers) do
  begin
    LCheckers[LIdx].Init(False);
    if Supports(LCheckers[LIdx], IPkixCertRevocationChecker, LFoundChecker) then
    begin
      if LRevocationChecker <> nil then
        raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SMultipleRevocationCheckers);
      LRevocationChecker := LFoundChecker;
    end;
  end;

  // with no checker supplied, revocation checking is the default over both mechanisms
  if (LRevocationChecker = nil) and AParams.IsRevocationEnabled then
    LRevocationChecker := TPkixRevocationChecker.Create(nil) as IPkixCertRevocationChecker;

  //
  // (e), (f), (g) are part of the parameters
  //

  //
  // 6.1.2 - setup
  //

  // (a)
  System.SetLength(LPolicyNodes, LN + 1);
  for LIdx := 0 to System.High(LPolicyNodes) do
  begin
    LPolicyNodes[LIdx] := TList<IPkixPolicyNode>.Create();
  end;

  LAcceptablePolicies := TList<String>.Create();
  LCriticalExtensions := TList<String>.Create();
  try
    System.SetLength(LInitialExpectedPolicies, 1);
    LInitialExpectedPolicies[0] := TRfc3280CertPathUtilities.AnyPolicy;

    LValidPolicyTree := TPkixPolicyNode.Create(nil, 0, LInitialExpectedPolicies, nil, nil,
      TRfc3280CertPathUtilities.AnyPolicy, False) as IPkixPolicyNode;

    LPolicyNodes[0].Add(LValidPolicyTree);

    // (b) and (c)
    LNameConstraintValidator := TPkixNameConstraintValidator.Create() as IPkixNameConstraintValidator;

    // (d)
    if AParams.IsExplicitPolicyRequired then
      LExplicitPolicy := 0
    else
      LExplicitPolicy := LN + 1;

    // (e)
    if AParams.IsAnyPolicyInhibited then
      LInhibitAnyPolicy := 0
    else
      LInhibitAnyPolicy := LN + 1;

    // (f)
    if AParams.IsPolicyMappingInhibited then
      LPolicyMapping := 0
    else
      LPolicyMapping := LN + 1;

    // (g), (h), (i), (j)
    LSign := LTrust.TrustedCert;
    try
      if LSign <> nil then
      begin
        LWorkingIssuerName := LSign.SubjectDN;
        LWorkingPublicKey := LSign.GetPublicKey();
      end
      else
      begin
        LWorkingIssuerName := LTrust.CA;
        LWorkingPublicKey := LTrust.CAPublicKey;
      end;
    except
      on E: Exception do
        raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@STrustAnchorSubjectFailed, [E.Message]);
    end;

    try
      LWorkingAlgID := TPkixCertPathValidatorUtilities.GetAlgorithmIdentifier(LWorkingPublicKey);
    except
      on E: Exception do
        raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SWorkingAlgorithmFailed, [E.Message]);
    end;

    // (k)
    LMaxPathLength := LN;

    //
    // 6.1.3
    //

    LTargetConstraints := AParams.GetTargetConstraintsCert();
    if (LTargetConstraints <> nil) and (not LTargetConstraints.Match(LCerts[0])) then
      raise EPkixCertPathValidatorCryptoLibException.CreateRes(@STargetConstraintsMismatch);

    LCert := nil;

    for LI := LN - 1 downto 0 do
    begin
      LIndex := LI;

      // sign, working public key and working issuer name are set at the end of the previous
      // round, and first of all from the trust anchor
      LCert := LCerts[LIndex];

      //
      // 6.1.3
      //

      TRfc3280CertPathUtilities.ProcessCertA(ACertPath, AParams, LValidityDate, LRevocationChecker,
        LIndex, LWorkingPublicKey, LIndex = (LN - 1), LWorkingIssuerName, LSign);

      TRfc3280CertPathUtilities.ProcessCertBC(ACertPath, LIndex, LNameConstraintValidator, FIsForCrlCheck);

      LValidPolicyTree := TRfc3280CertPathUtilities.ProcessCertD(ACertPath, LIndex, LAcceptablePolicies,
        LValidPolicyTree, LPolicyNodes, LInhibitAnyPolicy, FIsForCrlCheck);

      LValidPolicyTree := TRfc3280CertPathUtilities.ProcessCertE(ACertPath, LIndex, LValidPolicyTree);

      TRfc3280CertPathUtilities.ProcessCertF(LIndex, LValidPolicyTree, LExplicitPolicy);

      //
      // 6.1.4 - prepare for the next certificate, unless this is the target certificate
      //

      if LIndex <> 0 then
      begin
        if LCert.Version = 1 then
        begin
          // the trust anchor at the top of the path: ignore it and keep going
          if (LIndex = (LN - 1)) and LCert.Equals(LTrust.TrustedCert) then
            Continue;

          raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SVersion1CACertificate, [LIndex]);
        end;

        TRfc3280CertPathUtilities.PrepareNextCertA(ACertPath, LIndex);

        LValidPolicyTree := TRfc3280CertPathUtilities.PrepareCertB(ACertPath, LIndex, LPolicyNodes,
          LValidPolicyTree, LPolicyMapping);

        TRfc3280CertPathUtilities.PrepareNextCertG(ACertPath, LIndex, LNameConstraintValidator);

        // (h)
        LExplicitPolicy := TRfc3280CertPathUtilities.PrepareNextCertH1(ACertPath, LIndex, LExplicitPolicy);
        LPolicyMapping := TRfc3280CertPathUtilities.PrepareNextCertH2(ACertPath, LIndex, LPolicyMapping);
        LInhibitAnyPolicy := TRfc3280CertPathUtilities.PrepareNextCertH3(ACertPath, LIndex, LInhibitAnyPolicy);

        // (i)
        LExplicitPolicy := TRfc3280CertPathUtilities.PrepareNextCertI1(ACertPath, LIndex, LExplicitPolicy);
        LPolicyMapping := TRfc3280CertPathUtilities.PrepareNextCertI2(ACertPath, LIndex, LPolicyMapping);

        // (j)
        LInhibitAnyPolicy := TRfc3280CertPathUtilities.PrepareNextCertJ(ACertPath, LIndex, LInhibitAnyPolicy);

        // (k)
        LCaBasicConstraints := TRfc3280CertPathUtilities.PrepareNextCertK(ACertPath, LIndex);

        // (l)
        LMaxPathLength := TRfc3280CertPathUtilities.PrepareNextCertL(ACertPath, LIndex, LMaxPathLength);

        // (m)
        LMaxPathLength := TRfc3280CertPathUtilities.PrepareNextCertM(ACertPath, LIndex, LMaxPathLength,
          LCaBasicConstraints);

        // (n)
        TRfc3280CertPathUtilities.PrepareNextCertN(ACertPath, LIndex);

        // (o)
        CollectUnresolvedCriticalExtensions(LCert, LCriticalExtensions, False);
        TRfc3280CertPathUtilities.PrepareNextCertO(ACertPath, LIndex, LCriticalExtensions, LCheckers);

        // set the signing certificate for the next round
        LSign := LCert;

        // (c)
        LWorkingIssuerName := LSign.SubjectDN;

        // (d)
        try
          LWorkingPublicKey := TPkixCertPathValidatorUtilities.GetNextWorkingKey(ACertPath.Certificates,
            LIndex);
        except
          on E: Exception do
            raise EPkixCertPathValidatorCryptoLibException.CreateResFmt(@SNextWorkingKeyFailed,
              [LIndex, E.Message]);
        end;

        // (e), (f)
        LWorkingAlgID := TPkixCertPathValidatorUtilities.GetAlgorithmIdentifier(LWorkingPublicKey);
      end;
    end;

    // the loop ran down past zero, so the wrap-up index below is zero
    LIndex := -1;

    //
    // 6.1.5 Wrap-up procedure
    //

    // (a)
    LExplicitPolicy := TRfc3280CertPathUtilities.WrapupCertA(LExplicitPolicy, LCert);

    // (b)
    LExplicitPolicy := TRfc3280CertPathUtilities.WrapupCertB(ACertPath, LIndex + 1, LExplicitPolicy);

    //
    // (c), (d) and (e) are already done
    //

    // (f)
    CollectUnresolvedCriticalExtensions(LCert, LCriticalExtensions, True);
    TRfc3280CertPathUtilities.WrapupCertF(ACertPath, LIndex + 1, LCheckers, LCriticalExtensions);

    // (g)
    LIntersection := TRfc3280CertPathUtilities.WrapupCertG(ACertPath, AParams, LUserInitialPolicySet,
      LIndex + 1, LPolicyNodes, LValidPolicyTree, LAcceptablePolicies);

    if (LExplicitPolicy > 0) or (LIntersection <> nil) then
    begin
      Result := TPkixCertPathValidatorResult.Create(LTrust, LIntersection, LCert.GetPublicKey())
        as IPkixCertPathValidatorResult;
      Exit;
    end;

    raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SPolicyProcessingFailed);
  finally
    LCriticalExtensions.Free;
    LAcceptablePolicies.Free;
    for LIdx := 0 to System.High(LPolicyNodes) do
    begin
      LPolicyNodes[LIdx].Free;
    end;
  end;
end;

end.
