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

unit ClpPkixCertPathBuilder;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpIX509Certificate,
  ClpIPkixTypes,
  ClpPkixCertPath,
  ClpPkixCertPathValidator,
  ClpPkixCertPathValidatorResult,
  ClpPkixCertPathValidatorReason,
  ClpPkixCertPathValidatorUtilities,
  ClpCryptoLibConfig,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SNodeBudgetExceeded = 'certification path build exceeded the node limit set by ' +
    'TCryptoLibConfig.X509.MaxCertPathBuildNodes';
  SCertPathNotFound = 'unable to find certificate chain';
  SCertPathConstructionFailed = 'certification path could not be constructed from the certificate ' +
    'list: %s';
  SCertPathValidationFailed = 'certification path could not be validated: %s';
  SAdditionalStoresFailed = 'no additional X.509 stores can be added from the certificate locations: %s';
  SIssuerCertSearchFailed = 'cannot find the issuer certificate for a certificate in the ' +
    'certification path: %s';
  SNoIssuerCertFound = 'no issuer certificate for a certificate in the certification path found';

type
  /// <summary>
  /// Builds and validates an X.509 certification path from a target certificate up to a trust
  /// anchor, following the path building and validation algorithm of RFC 5280 6.1.
  /// </summary>
  /// <remarks>
  /// One instance carries the build's failure state across its recursion, so it is neither reentrant
  /// nor thread safe: callers sharing an instance must serialize access themselves.
  /// </remarks>
  TPkixCertPathBuilder = class(TInterfacedObject, IPkixCertPathBuilder)

  strict private
  var
    FIsForCrlCheck: Boolean;
    /// <summary>The most specific failure of the chains tried so far, carried across the recursion.</summary>
    FHasFailure: Boolean;
    FFailureMessage: String;
    FFailureReason: TPkixCertPathValidatorReason;
    /// <summary>Per-build node-visit budget (from config) and running count, bounding the DFS.</summary>
    FMaxNodes: Int32;
    FNodesVisited: Int32;

    class function ContainsCert(const ACerts: TList<IX509Certificate>;
      const ACert: IX509Certificate): Boolean; overload; static;
    class function ContainsCert(const ACerts: TCryptoLibGenericArray<IX509Certificate>;
      const ACert: IX509Certificate): Boolean; overload; static;
    class procedure RemoveCert(const ACerts: TList<IX509Certificate>;
      const ACert: IX509Certificate); static;
    class function ToCertArray(const ACerts: TList<IX509Certificate>)
      : TCryptoLibGenericArray<IX509Certificate>; static;
    class function FailureRank(AReason: TPkixCertPathValidatorReason): Int32; static;
    class function ReasonOf(const AException: Exception): TPkixCertPathValidatorReason; static;

    /// <summary>Keeps the failure unless one of higher rank is already remembered.</summary>
    procedure RememberFailure(const AMessage: String; AReason: TPkixCertPathValidatorReason);

    /// <summary>Try to complete ATbvPath through ATbvCert; nil when no chain could be built.</summary>
    function BuildPath(const ATbvCert: IX509Certificate; const AParams: IPkixBuilderParameters;
      const ATbvPath: TList<IX509Certificate>): IPkixCertPathBuilderResult;

  public
    constructor Create(); overload;
    /// <summary>AIsForCrlCheck relaxes the checks that do not apply when validating a CRL signer.</summary>
    constructor Create(AIsForCrlCheck: Boolean); overload;

    function Build(const AParams: IPkixBuilderParameters): IPkixCertPathBuilderResult;
  end;

implementation

type
  /// <summary>Raised internally to abort a build once the node-visit budget is exhausted.</summary>
  ENodeBudgetExceededCryptoLibException = class(ECryptoLibException);

{ TPkixCertPathBuilder }

constructor TPkixCertPathBuilder.Create();
begin
  Create(False);
end;

constructor TPkixCertPathBuilder.Create(AIsForCrlCheck: Boolean);
begin
  inherited Create();
  FIsForCrlCheck := AIsForCrlCheck;
end;

class function TPkixCertPathBuilder.ContainsCert(const ACerts: TList<IX509Certificate>;
  const ACert: IX509Certificate): Boolean;
var
  LIdx: Int32;
begin
  for LIdx := 0 to ACerts.Count - 1 do
  begin
    if ACerts[LIdx].Equals(ACert) then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := False;
end;

class function TPkixCertPathBuilder.ContainsCert(const ACerts: TCryptoLibGenericArray<IX509Certificate>;
  const ACert: IX509Certificate): Boolean;
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

class procedure TPkixCertPathBuilder.RemoveCert(const ACerts: TList<IX509Certificate>;
  const ACert: IX509Certificate);
var
  LIdx: Int32;
begin
  for LIdx := 0 to ACerts.Count - 1 do
  begin
    if ACerts[LIdx].Equals(ACert) then
    begin
      ACerts.Delete(LIdx);
      Exit;
    end;
  end;
end;

class function TPkixCertPathBuilder.ToCertArray(const ACerts: TList<IX509Certificate>)
  : TCryptoLibGenericArray<IX509Certificate>;
var
  LIdx: Int32;
begin
  System.SetLength(Result, ACerts.Count);
  for LIdx := 0 to ACerts.Count - 1 do
  begin
    Result[LIdx] := ACerts[LIdx];
  end;
end;

class function TPkixCertPathBuilder.FailureRank(AReason: TPkixCertPathValidatorReason): Int32;
begin
  // ranked by how useful the cause is to a caller deciding what to fix or retry
  case AReason of
    TPkixCertPathValidatorReason.Expired, TPkixCertPathValidatorReason.NotYetValid:
      Result := 6;
    TPkixCertPathValidatorReason.Revoked,
      TPkixCertPathValidatorReason.UndeterminedRevocationStatus:
      Result := 5;
    TPkixCertPathValidatorReason.InvalidSignature:
      Result := 4;
    TPkixCertPathValidatorReason.AlgorithmConstrained:
      Result := 3;
    TPkixCertPathValidatorReason.InvalidKeyUsage, TPkixCertPathValidatorReason.NotCACertificate,
      TPkixCertPathValidatorReason.PathTooLong, TPkixCertPathValidatorReason.InvalidPolicy,
      TPkixCertPathValidatorReason.InvalidName:
      Result := 2;
    TPkixCertPathValidatorReason.NameChaining:
      Result := 1;
    TPkixCertPathValidatorReason.UnrecognizedCriticalExtension:
      Result := 0;
  else
    Result := -1;
  end;
end;

class function TPkixCertPathBuilder.ReasonOf(const AException: Exception)
  : TPkixCertPathValidatorReason;
begin
  if AException is EPkixCertPathValidatorCryptoLibException then
    Result := EPkixCertPathValidatorCryptoLibException(AException).Reason
  else if AException is EPkixCertPathBuilderCryptoLibException then
    Result := EPkixCertPathBuilderCryptoLibException(AException).Reason
  else
    Result := TPkixCertPathValidatorReason.Unspecified;
end;

procedure TPkixCertPathBuilder.RememberFailure(const AMessage: String;
  AReason: TPkixCertPathValidatorReason);
begin
  if FHasFailure and (FailureRank(AReason) < FailureRank(FFailureReason)) then
    Exit;
  FHasFailure := True;
  FFailureMessage := AMessage;
  FFailureReason := AReason;
end;

function TPkixCertPathBuilder.BuildPath(const ATbvCert: IX509Certificate;
  const AParams: IPkixBuilderParameters; const ATbvPath: TList<IX509Certificate>)
  : IPkixCertPathBuilderResult;
var
  LCertPath: IPkixCertPath;
  LValidator: IPkixCertPathValidator;
  LValidatorResult: IPkixCertPathValidatorResult;
  LIssuers: TCryptoLibGenericArray<IX509Certificate>;
  LIdx: Int32;
  LIsAnchored: Boolean;
begin
  Result := nil;

  // Bound the depth-first search: candidate issuers are matched by subject name only, so a store full
  // of like-named certificates that never chain to a trust anchor could otherwise be explored as a very
  // large number of partial paths (see TCryptoLibConfig.X509.MaxCertPathBuildNodes).
  System.Inc(FNodesVisited);
  if FNodesVisited > FMaxNodes then
    raise ENodeBudgetExceededCryptoLibException.CreateRes(@SNodeBudgetExceeded);

  // the certificate is already on the path, so following it would cycle in the PKI graph
  if ContainsCert(ATbvPath, ATbvCert) then
    Exit;

  // the certificate is not allowed to appear in a certification chain
  if AParams.IsExcludedCert(ATbvCert) then
    Exit;

  // only non-self-issued intermediates count against the maximum path length
  if (AParams.MaxPathLength <> -1) and
    (TPkixCertPathValidatorUtilities.CountIntermediates(ATbvPath, ATbvCert) > AParams.MaxPathLength) then
    Exit;

  ATbvPath.Add(ATbvCert);

  try
    try
      LIsAnchored := False;
      try
        LIsAnchored := TPkixCertPathValidatorUtilities.FindTrustAnchor(ATbvCert,
          AParams.GetTrustAnchors()) <> nil;
      except
        on E: EPkixCertPathValidatorCryptoLibException do
          // a named anchor whose key does not verify the certificate; pooled issuers may still work
          RememberFailure(E.Message, E.Reason);
        on Exception do
          ;
      end;

      if LIsAnchored then
      begin
        try
          LCertPath := TPkixCertPath.Create(ToCertArray(ATbvPath)) as IPkixCertPath;
        except
          on E: Exception do
            raise EPkixCertPathBuilderCryptoLibException.CreateResFmt(@SCertPathConstructionFailed,
              [E.Message]);
        end;

        try
          LValidator := TPkixCertPathValidator.Create(FIsForCrlCheck) as IPkixCertPathValidator;
          LValidatorResult := LValidator.Validate(LCertPath, AParams);
        except
          on E: Exception do
            raise EPkixCertPathBuilderCryptoLibException.CreateResFmtReason(ReasonOf(E),
              @SCertPathValidationFailed, [E.Message]);
        end;

        // the path is kept: this chain is the answer
        Result := TPkixCertPathBuilderResult.Create(LCertPath, LValidatorResult.TrustAnchor,
          LValidatorResult.PolicyTree, LValidatorResult.SubjectPublicKey) as IPkixCertPathBuilderResult;
        Exit;
      end;

      // add additional X.509 stores from locations in the certificate
      try
        TPkixCertPathValidatorUtilities.AddAdditionalStoresFromAltNames(ATbvCert, AParams);
      except
        on E: Exception do
          raise EPkixCertPathBuilderCryptoLibException.CreateResFmt(@SAdditionalStoresFailed, [E.Message]);
      end;

      try
        LIssuers := TPkixCertPathValidatorUtilities.FindIssuerCerts(ATbvCert, AParams);
      except
        on E: Exception do
          raise EPkixCertPathBuilderCryptoLibException.CreateResFmt(@SIssuerCertSearchFailed, [E.Message]);
      end;

      if System.Length(LIssuers) < 1 then
        raise EPkixCertPathBuilderCryptoLibException.CreateResReason(
          TPkixCertPathValidatorReason.NoTrustAnchor, @SNoIssuerCertFound);

      for LIdx := 0 to System.High(LIssuers) do
      begin
        Result := BuildPath(LIssuers[LIdx], AParams, ATbvPath);
        if Result <> nil then
          Break;
      end;
    except
      on E: ENodeBudgetExceededCryptoLibException do
        // the whole build is over-budget; let it unwind to Build rather than trying more chains
        raise;
      on E: Exception do
      begin
        // remembered for the caller; other candidate chains may still succeed
        RememberFailure(E.Message, ReasonOf(E));
        Result := nil;
      end;
    end;
  finally
    // undo the add on every exit: the success path (the path was built from a copy of ATbvPath),
    // a stashed failure, and an unwinding node-budget exception
    RemoveCert(ATbvPath, ATbvCert);
  end;
end;

function TPkixCertPathBuilder.Build(const AParams: IPkixBuilderParameters): IPkixCertPathBuilderResult;
var
  LTargets: TCryptoLibGenericArray<IX509Certificate>;
  LPath: TList<IX509Certificate>;
  LIdx: Int32;
begin
  Result := nil;
  FHasFailure := False;
  FFailureMessage := '';
  FFailureReason := TPkixCertPathValidatorReason.Unspecified;
  FMaxNodes := TCryptoLibConfig.X509.MaxCertPathBuildNodes;
  FNodesVisited := 0;

  LPath := TList<IX509Certificate>.Create();
  try
    try
      // the target certificates: store matches, or one named directly on the selector
      LTargets := TPkixCertPathValidatorUtilities.FindTargets(AParams);

      // check all potential target certificates
      for LIdx := 0 to System.High(LTargets) do
      begin
        Result := BuildPath(LTargets[LIdx], AParams, LPath);
        if Result <> nil then
          Break;
      end;
    except
      on E: ENodeBudgetExceededCryptoLibException do
        raise EPkixCertPathBuilderCryptoLibException.CreateReason(
          TPkixCertPathValidatorReason.LimitExceeded, E.Message);
    end;
  finally
    LPath.Free;
  end;

  if Result <> nil then
    Exit;

  if FHasFailure then
    raise EPkixCertPathBuilderCryptoLibException.CreateReason(FFailureReason, FFailureMessage);

  raise EPkixCertPathBuilderCryptoLibException.CreateResReason(
    TPkixCertPathValidatorReason.NoTrustAnchor, @SCertPathNotFound);
end;

end.
