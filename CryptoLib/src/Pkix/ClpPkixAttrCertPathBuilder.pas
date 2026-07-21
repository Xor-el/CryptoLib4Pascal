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

unit ClpPkixAttrCertPathBuilder;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpIStore,
  ClpIX509Asn1Objects,
  ClpIX509Certificate,
  ClpIX509V2AttributeCertificate,
  ClpIX509StoreSelectors,
  ClpX509StoreSelectors,
  ClpX509Comparers,
  ClpCryptoLibHashSet,
  ClpIPkixTypes,
  ClpPkixCertPath,
  ClpPkixCertPathValidatorResult,
  ClpPkixAttrCertPathValidator,
  ClpPkixCertPathValidatorUtilities,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  STargetConstraintsNotAttrCert =
    'the target constraints must be an attribute certificate store selector';
  STargetAttrCertSearchFailed = 'error finding target attribute certificate: %s';
  SNoTargetAttrCertFound = 'no attribute certificate found matching the target constraints';
  SIssuerPkcSearchFailed = 'the public key certificate for the attribute certificate cannot be ' +
    'searched: %s';
  SNoIssuerPkcFound = 'the public key certificate for the attribute certificate cannot be found';
  SAttrCertPathNotValidated = 'possible certificate chain could not be validated: %s';
  SAttrCertPathNotFound = 'unable to find certificate chain';
  SCertPathValidationFailed = 'certification path could not be validated: %s';
  SAdditionalStoresFailed = 'no additional X.509 stores can be added from the certificate locations: %s';
  SIssuerCertSearchFailed = 'cannot find the issuer certificate for a certificate in the ' +
    'certification path: %s';
  SNoIssuerCertFound = 'no issuer certificate for a certificate in the certification path found';

type
  /// <summary>
  /// Builds and validates a certification path from an attribute certificate up to a trust anchor,
  /// following the path building of RFC 3281 5.
  /// </summary>
  /// <remarks>
  /// One instance carries the last build failure across its recursion, so it is neither reentrant
  /// nor thread safe: callers sharing an instance must serialize access themselves.
  /// </remarks>
  TPkixAttrCertPathBuilder = class(TInterfacedObject, IPkixAttrCertPathBuilder)

  strict private
  var
    /// <summary>The failure of the most recently tried chain, carried across the recursion.</summary>
    FCertPathException: String;

    class function ContainsCert(const ACerts: TList<IX509Certificate>;
      const ACert: IX509Certificate): Boolean; static;
    class procedure RemoveCert(const ACerts: TList<IX509Certificate>;
      const ACert: IX509Certificate); static;
    class function ToCertArray(const ACerts: TList<IX509Certificate>)
      : TCryptoLibGenericArray<IX509Certificate>; static;

    /// <summary>Collect every attribute certificate of the stores that matches ASelector.</summary>
    class function FindAttributeCertificates(const ASelector: IX509AttrCertStoreSelector;
      const AStores: TCryptoLibGenericArray<IStore<IX509V2AttributeCertificate>>)
      : TCryptoLibGenericArray<IX509V2AttributeCertificate>; static;

    /// <summary>Try to complete ATbvPath through ATbvCert; nil when no chain could be built.</summary>
    function BuildPath(const AAttrCert: IX509V2AttributeCertificate; const ATbvCert: IX509Certificate;
      const AParams: IPkixBuilderParameters; const ATbvPath: TList<IX509Certificate>)
      : IPkixCertPathBuilderResult;

  public
    function Build(const AParams: IPkixBuilderParameters): IPkixCertPathBuilderResult;
  end;

implementation

{ TPkixAttrCertPathBuilder }

class function TPkixAttrCertPathBuilder.ContainsCert(const ACerts: TList<IX509Certificate>;
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

class procedure TPkixAttrCertPathBuilder.RemoveCert(const ACerts: TList<IX509Certificate>;
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

class function TPkixAttrCertPathBuilder.ToCertArray(const ACerts: TList<IX509Certificate>)
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

class function TPkixAttrCertPathBuilder.FindAttributeCertificates(
  const ASelector: IX509AttrCertStoreSelector;
  const AStores: TCryptoLibGenericArray<IStore<IX509V2AttributeCertificate>>)
  : TCryptoLibGenericArray<IX509V2AttributeCertificate>;
var
  LOuter, LInner, LScan: Int32;
  LMatches: TCryptoLibGenericArray<IX509V2AttributeCertificate>;
  LFound: Boolean;
begin
  Result := nil;
  for LOuter := 0 to System.High(AStores) do
  begin
    LMatches := AStores[LOuter].EnumerateMatches(ASelector);
    for LInner := 0 to System.High(LMatches) do
    begin
      LFound := False;
      for LScan := 0 to System.High(Result) do
      begin
        if Result[LScan].Equals(LMatches[LInner]) then
        begin
          LFound := True;
          Break;
        end;
      end;
      if not LFound then
      begin
        System.SetLength(Result, System.Length(Result) + 1);
        Result[System.High(Result)] := LMatches[LInner];
      end;
    end;
  end;
end;

function TPkixAttrCertPathBuilder.BuildPath(const AAttrCert: IX509V2AttributeCertificate;
  const ATbvCert: IX509Certificate; const AParams: IPkixBuilderParameters;
  const ATbvPath: TList<IX509Certificate>): IPkixCertPathBuilderResult;
var
  LCertPath: IPkixCertPath;
  LValidatorResult: IPkixCertPathValidatorResult;
  LIssuers: TCryptoLibGenericArray<IX509Certificate>;
  LIssuer: IX509Certificate;
begin
  Result := nil;

  // the certificate is already on the path, so following it would cycle in the PKI graph
  if ContainsCert(ATbvPath, ATbvCert) then
    Exit;

  // the certificate is not allowed to appear in a certification chain
  for LIssuer in AParams.GetExcludedCerts() do
  begin
    if LIssuer.Equals(ATbvCert) then
      Exit;
  end;

  if (AParams.MaxPathLength <> -1) and ((ATbvPath.Count - 1) > AParams.MaxPathLength) then
    Exit;

  ATbvPath.Add(ATbvCert);

  try
    // the issuer of the certificate is a trust anchor: this chain is complete
    if TPkixCertPathValidatorUtilities.IsIssuerTrustAnchor(ATbvCert, AParams.GetTrustAnchors()) then
    begin
      LCertPath := TPkixCertPath.Create(ToCertArray(ATbvPath)) as IPkixCertPath;

      try
        LValidatorResult := (TPkixAttrCertPathValidator.Create() as IPkixAttrCertPathValidator)
          .Validate(LCertPath, AParams);
      except
        on E: Exception do
          raise EPkixCertPathBuilderCryptoLibException.CreateResFmt(@SCertPathValidationFailed,
            [E.Message]);
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
      raise EPkixCertPathBuilderCryptoLibException.CreateRes(@SNoIssuerCertFound);

    for LIssuer in LIssuers do
    begin
      // an untrusted self signed certificate cannot extend the chain
      if TPkixCertPathValidatorUtilities.IsSelfIssued(LIssuer) then
        Continue;

      Result := BuildPath(AAttrCert, LIssuer, AParams, ATbvPath);
      if Result <> nil then
        Break;
    end;
  except
    on E: Exception do
    begin
      // remembered for the caller; other candidate chains may still succeed
      FCertPathException := E.Message;
      Result := nil;
    end;
  end;

  if Result = nil then
    RemoveCert(ATbvPath, ATbvCert);
end;

function TPkixAttrCertPathBuilder.Build(const AParams: IPkixBuilderParameters): IPkixCertPathBuilderResult;
var
  LAttrCertSelector: IX509AttrCertStoreSelector;
  LTargets: TCryptoLibGenericArray<IX509V2AttributeCertificate>;
  LTarget: IX509V2AttributeCertificate;
  LCertSelector: IX509CertStoreSelector;
  LPrincipals: TCryptoLibGenericArray<IX509Name>;
  LIssuers: TCryptoLibHashSet<IX509Certificate>;
  LStores: TCryptoLibGenericArray<IStore<IX509Certificate>>;
  LIssuer: IX509Certificate;
  LPath: TList<IX509Certificate>;
  LIdx, LStoreIdx: Int32;
begin
  Result := nil;
  FCertPathException := '';

  // search the target attribute certificates
  if not Supports(AParams.GetTargetConstraintsAttrCert(), IX509AttrCertStoreSelector, LAttrCertSelector) then
    raise EPkixCertPathBuilderCryptoLibException.CreateRes(@STargetConstraintsNotAttrCert);

  try
    LTargets := FindAttributeCertificates(LAttrCertSelector, AParams.GetStoresAttrCert());
  except
    on E: Exception do
      raise EPkixCertPathBuilderCryptoLibException.CreateResFmt(@STargetAttrCertSearchFailed, [E.Message]);
  end;

  if System.Length(LTargets) < 1 then
    raise EPkixCertPathBuilderCryptoLibException.CreateRes(@SNoTargetAttrCertFound);

  LStores := AParams.GetStoresCert();

  // check all potential target attribute certificates
  for LTarget in LTargets do
  begin
    // find the public key certificate(s) of the attribute certificate issuer
    LIssuers := TCryptoLibHashSet<IX509Certificate>.Create(TX509Comparers.CertificateEqualityComparer);
    try
      LCertSelector := TX509CertStoreSelector.Create() as IX509CertStoreSelector;
      LPrincipals := LTarget.Issuer.GetPrincipals();
      for LIdx := 0 to System.High(LPrincipals) do
      begin
        try
          LCertSelector.Subject := LPrincipals[LIdx];
          for LStoreIdx := 0 to System.High(LStores) do
          begin
            LIssuers.AddRange(LStores[LStoreIdx].EnumerateMatches(LCertSelector));
          end;
        except
          on E: Exception do
            raise EPkixCertPathBuilderCryptoLibException.CreateResFmt(@SIssuerPkcSearchFailed, [E.Message]);
        end;
      end;

      if LIssuers.Count < 1 then
        raise EPkixCertPathBuilderCryptoLibException.CreateRes(@SNoIssuerPkcFound);

      LPath := TList<IX509Certificate>.Create();
      try
        for LIssuer in LIssuers do
        begin
          Result := BuildPath(LTarget, LIssuer, AParams, LPath);
          if Result <> nil then
            Break;
        end;
      finally
        LPath.Free;
      end;
    finally
      LIssuers.Free;
    end;

    if Result <> nil then
      Break;
  end;

  if Result <> nil then
    Exit;

  if FCertPathException <> '' then
    raise EPkixCertPathBuilderCryptoLibException.CreateResFmt(@SAttrCertPathNotValidated,
      [FCertPathException]);

  raise EPkixCertPathBuilderCryptoLibException.CreateRes(@SAttrCertPathNotFound);
end;

end.
