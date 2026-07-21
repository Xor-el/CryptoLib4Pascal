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
  ClpIStore,
  ClpIX509Certificate,
  ClpX509Comparers,
  ClpCryptoLibHashSet,
  ClpIPkixTypes,
  ClpPkixCertPath,
  ClpPkixCertPathValidator,
  ClpPkixCertPathValidatorResult,
  ClpPkixCertPathValidatorUtilities,
  ClpCryptoLibTypes;

resourcestring
  STargetCertSearchFailed = 'error finding target certificate: %s';
  SNoTargetCertFound = 'no certificate found matching the target constraints';
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
  /// One instance carries the last build failure across its recursion, so it is neither reentrant
  /// nor thread safe: callers sharing an instance must serialize access themselves.
  /// </remarks>
  TPkixCertPathBuilder = class(TInterfacedObject, IPkixCertPathBuilder)

  strict private
  var
    FIsForCrlCheck: Boolean;
    /// <summary>The failure of the most recently tried chain, carried across the recursion.</summary>
    FCertPathException: String;

    class function ContainsCert(const ACerts: TList<IX509Certificate>;
      const ACert: IX509Certificate): Boolean; overload; static;
    class function ContainsCert(const ACerts: TCryptoLibGenericArray<IX509Certificate>;
      const ACert: IX509Certificate): Boolean; overload; static;
    class procedure RemoveCert(const ACerts: TList<IX509Certificate>;
      const ACert: IX509Certificate); static;
    class function ToCertArray(const ACerts: TList<IX509Certificate>)
      : TCryptoLibGenericArray<IX509Certificate>; static;

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

function TPkixCertPathBuilder.BuildPath(const ATbvCert: IX509Certificate;
  const AParams: IPkixBuilderParameters; const ATbvPath: TList<IX509Certificate>)
  : IPkixCertPathBuilderResult;
var
  LCertPath: IPkixCertPath;
  LValidatorResult: IPkixCertPathValidatorResult;
  LIssuers: TCryptoLibGenericArray<IX509Certificate>;
  LIdx: Int32;
begin
  Result := nil;

  // the certificate is already on the path, so following it would cycle in the PKI graph
  if ContainsCert(ATbvPath, ATbvCert) then
    Exit;

  // the certificate is not allowed to appear in a certification chain
  if ContainsCert(AParams.GetExcludedCerts(), ATbvCert) then
    Exit;

  if (AParams.MaxPathLength <> -1) and ((ATbvPath.Count - 1) > AParams.MaxPathLength) then
    Exit;

  ATbvPath.Add(ATbvCert);

  try
    if TPkixCertPathValidatorUtilities.IsIssuerTrustAnchor(ATbvCert, AParams.GetTrustAnchors()) then
    begin
      try
        LCertPath := TPkixCertPath.Create(ToCertArray(ATbvPath)) as IPkixCertPath;
      except
        on E: Exception do
          raise EPkixCertPathBuilderCryptoLibException.CreateResFmt(@SCertPathConstructionFailed,
            [E.Message]);
      end;

      try
        LValidatorResult := (TPkixCertPathValidator.Create(FIsForCrlCheck) as IPkixCertPathValidator)
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

    for LIdx := 0 to System.High(LIssuers) do
    begin
      Result := BuildPath(LIssuers[LIdx], AParams, ATbvPath);
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

function TPkixCertPathBuilder.Build(const AParams: IPkixBuilderParameters): IPkixCertPathBuilderResult;
var
  LSelector: ISelector<IX509Certificate>;
  LStores: TCryptoLibGenericArray<IStore<IX509Certificate>>;
  LTargets: TCryptoLibHashSet<IX509Certificate>;
  LPath: TList<IX509Certificate>;
  LCert: IX509Certificate;
  LIdx: Int32;
begin
  Result := nil;
  FCertPathException := '';

  // search the target certificates
  LSelector := AParams.GetTargetConstraintsCert();

  LTargets := TCryptoLibHashSet<IX509Certificate>.Create(TX509Comparers.CertificateEqualityComparer);
  try
    try
      LStores := AParams.GetStoresCert();
      for LIdx := 0 to System.High(LStores) do
      begin
        LTargets.AddRange(LStores[LIdx].EnumerateMatches(LSelector));
      end;
    except
      on E: Exception do
        raise EPkixCertPathBuilderCryptoLibException.CreateResFmt(@STargetCertSearchFailed, [E.Message]);
    end;

    if LTargets.Count < 1 then
      raise EPkixCertPathBuilderCryptoLibException.CreateRes(@SNoTargetCertFound);

    LPath := TList<IX509Certificate>.Create();
    try
      // check all potential target certificates
      for LCert in LTargets do
      begin
        Result := BuildPath(LCert, AParams, LPath);
        if Result <> nil then
          Break;
      end;
    finally
      LPath.Free;
    end;
  finally
    LTargets.Free;
  end;

  if Result <> nil then
    Exit;

  if FCertPathException <> '' then
    raise EPkixCertPathBuilderCryptoLibException.Create(FCertPathException);

  raise EPkixCertPathBuilderCryptoLibException.CreateRes(@SCertPathNotFound);
end;

end.
