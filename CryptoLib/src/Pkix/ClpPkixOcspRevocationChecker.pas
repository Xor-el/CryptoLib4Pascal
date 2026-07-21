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

unit ClpPkixOcspRevocationChecker;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIAsn1Objects,
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpIX509Certificate,
  ClpIAsymmetricKeyParameter,
  ClpIOcspProtocolObjects,
  ClpIPkixTypes,
  ClpPkixCertPathValidatorUtilities,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SOcspCertificateRevoked =
    'certificate revoked by an OCSP response, revocation date: %s, reason: %s';
  SOcspStatusUndetermined = 'no OCSP response settled the revocation status of the certificate';
  SOcspNotInitialized = 'the OCSP revocation checker was not initialized';

type
  /// <summary>
  /// Settles the revocation status of a certificate from the OCSP responses it was built with
  /// (RFC 6960).
  /// </summary>
  /// <remarks>
  /// This is a responder-free checker: it never fetches anything. The caller supplies whatever
  /// responses it already has (stapled, cached, or fetched by its own transport), and only a
  /// response that both authenticates and answers for the certificate in question counts.
  /// Everything else - no response, an unrelated one, an unauthorised signer, a stale validity
  /// window, an "unknown" status - leaves the status undecided, which is raised as a recoverable
  /// failure so a peer mechanism still gets its turn.
  /// </remarks>
  TPkixOcspRevocationChecker = class sealed(TInterfacedObject, IPkixCertRevocationChecker)

  strict private
  var
    FResponses: TCryptoLibGenericArray<IBasicOcspResp>;
    FParameters: IPkixCertRevocationCheckerParameters;

    /// <summary>
    /// Whether AResponse is signed by the certificate issuer itself or by a responder the issuer
    /// delegated to (RFC 6960 sec. 4.2.2.2).
    /// </summary>
    class function IsAuthorised(const AResponse: IBasicOcspResp;
      const AIssuerCert: IX509Certificate; const AIssuerPublicKey: IAsymmetricKeyParameter;
      AValidityDate: TDateTime): Boolean; static;

    class function IsDelegatedResponder(const AResponderCert, AIssuerCert: IX509Certificate;
      const AIssuerPublicKey: IAsymmetricKeyParameter; AValidityDate: TDateTime): Boolean; static;

    /// <summary>Whether ASingleResp is inside its thisUpdate/nextUpdate window.</summary>
    class function IsCurrent(const ASingleResp: ISingleResp; AValidityDate: TDateTime)
      : Boolean; static;

    class function ReasonName(const AStatus: IRevokedStatus): String; static;

    /// <summary>
    /// True when a response settled the status as good. False leaves the status undecided.
    /// </summary>
    function TryCheck(const ACert: IX509Certificate; AValidityDate: TDateTime;
      const AIssuerCert: IX509Certificate; const AIssuerPublicKey: IAsymmetricKeyParameter;
      AIndex: Int32): Boolean;

  public
    /// <summary>Build a checker over the responses the caller already holds.</summary>
    constructor Create(const AResponses: TCryptoLibGenericArray<IBasicOcspResp>);

    procedure Initialize(const AParameters: IPkixCertRevocationCheckerParameters);

    /// <exception cref="EPkixCertPathValidatorCryptoLibException">
    /// When an authoritative response reports the certificate as revoked.
    /// </exception>
    /// <exception cref="ERecoverablePkixCertPathValidatorCryptoLibException">
    /// When no response settles the status, so a peer mechanism must answer.
    /// </exception>
    procedure Check(const ACert: IX509Certificate);
  end;

implementation

{ TPkixOcspRevocationChecker }

constructor TPkixOcspRevocationChecker.Create(const AResponses
  : TCryptoLibGenericArray<IBasicOcspResp>);
begin
  inherited Create();
  FResponses := System.Copy(AResponses);
end;

procedure TPkixOcspRevocationChecker.Initialize(const AParameters
  : IPkixCertRevocationCheckerParameters);
begin
  FParameters := AParameters;
end;

class function TPkixOcspRevocationChecker.IsDelegatedResponder(const AResponderCert,
  AIssuerCert: IX509Certificate; const AIssuerPublicKey: IAsymmetricKeyParameter;
  AValidityDate: TDateTime): Boolean;
var
  LKeyPurposes: TCryptoLibGenericArray<IDerObjectIdentifier>;
  LIdx: Int32;
  LHasOcspSigning: Boolean;
begin
  Result := False;

  // the delegation is only valid if the issuer itself issued the responder certificate
  if not AResponderCert.IssuerDN.Equivalent(AIssuerCert.SubjectDN, True) then
    Exit;

  try
    AResponderCert.CheckValidity(AValidityDate);
    AResponderCert.Verify(AIssuerPublicKey);
  except
    // a responder certificate that does not verify or is out of date delegates nothing
    on E: Exception do
      Exit;
  end;

  try
    LKeyPurposes := AResponderCert.GetExtendedKeyUsage();
  except
    on E: Exception do
      Exit;
  end;

  LHasOcspSigning := False;
  for LIdx := 0 to System.High(LKeyPurposes) do
  begin
    if TKeyPurposeId.IdKpOcspSigning.Equals(LKeyPurposes[LIdx]) then
    begin
      LHasOcspSigning := True;
      Break;
    end;
  end;

  Result := LHasOcspSigning;
end;

class function TPkixOcspRevocationChecker.IsAuthorised(const AResponse: IBasicOcspResp;
  const AIssuerCert: IX509Certificate; const AIssuerPublicKey: IAsymmetricKeyParameter;
  AValidityDate: TDateTime): Boolean;
var
  LCerts: TCryptoLibGenericArray<IX509Certificate>;
  LIdx: Int32;
begin
  try
    if AResponse.Verify(AIssuerPublicKey) then
    begin
      Result := True;
      Exit;
    end;
  except
    // a signature this key cannot even be applied to is simply not the issuer's
    on E: Exception do
      ;
  end;

  LCerts := AResponse.GetCerts();
  for LIdx := 0 to System.High(LCerts) do
  begin
    if not IsDelegatedResponder(LCerts[LIdx], AIssuerCert, AIssuerPublicKey, AValidityDate) then
      Continue;

    try
      if AResponse.Verify(LCerts[LIdx].GetPublicKey()) then
      begin
        Result := True;
        Exit;
      end;
    except
      on E: Exception do
        ;
    end;
  end;

  Result := False;
end;

class function TPkixOcspRevocationChecker.IsCurrent(const ASingleResp: ISingleResp;
  AValidityDate: TDateTime): Boolean;
begin
  if ASingleResp.ThisUpdate > AValidityDate then
  begin
    Result := False;
    Exit;
  end;

  // nextUpdate is optional; its absence means the responder has no newer information, so the
  // response stays usable (RFC 6960 sec. 2.4)
  Result := (not ASingleResp.NextUpdate.HasValue) or
    (AValidityDate < ASingleResp.NextUpdate.Value);
end;

class function TPkixOcspRevocationChecker.ReasonName(const AStatus: IRevokedStatus): String;
begin
  if AStatus.HasRevocationReason then
    Result := SysUtils.IntToStr(AStatus.RevocationReason)
  else
    Result := 'unspecified';
end;

function TPkixOcspRevocationChecker.TryCheck(const ACert: IX509Certificate;
  AValidityDate: TDateTime; const AIssuerCert: IX509Certificate;
  const AIssuerPublicKey: IAsymmetricKeyParameter; AIndex: Int32): Boolean;
var
  LBasic: IBasicOcspResp;
  LSingleResponses: TCryptoLibGenericArray<ISingleResp>;
  LRespIdx, LSingleIdx: Int32;
  LCertId: ICertificateID;
  LStatus: ICertificateStatus;
  LRevoked: IRevokedStatus;
  LAuthorised: Boolean;
begin
  Result := False;

  if (AIssuerCert = nil) or (AIssuerPublicKey = nil) then
    Exit;

  for LRespIdx := 0 to System.High(FResponses) do
  begin
    LBasic := FResponses[LRespIdx];
    if LBasic = nil then
      Continue;

    // the signer is only checked once a matching entry is found, so an unrelated response costs
    // nothing more than the identifier comparison
    LAuthorised := False;

    LSingleResponses := LBasic.GetResponses();
    for LSingleIdx := 0 to System.High(LSingleResponses) do
    begin
      LCertId := LSingleResponses[LSingleIdx].GetCertID();
      if not ACert.SerialNumber.Equals(LCertId.SerialNumber) then
        Continue;
      if not LCertId.MatchesIssuer(AIssuerCert) then
        Continue;
      if not IsCurrent(LSingleResponses[LSingleIdx], AValidityDate) then
        Continue;

      if not LAuthorised then
      begin
        LAuthorised := IsAuthorised(LBasic, AIssuerCert, AIssuerPublicKey, AValidityDate);
        if not LAuthorised then
          Break;
      end;

      LStatus := LSingleResponses[LSingleIdx].GetCertStatus();
      if LStatus = nil then
      begin
        Result := True;
        Exit;
      end;

      if Supports(LStatus, IRevokedStatus, LRevoked) then
      begin
        raise EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex,
          @SOcspCertificateRevoked,
          [TPkixCertPathValidatorUtilities.FormatUtcInstant(LRevoked.RevocationTime),
          ReasonName(LRevoked)]);
      end;

      // an "unknown" status settles nothing, so keep looking
    end;
  end;
end;

procedure TPkixOcspRevocationChecker.Check(const ACert: IX509Certificate);
var
  LParameters: IPkixCertRevocationCheckerParameters;
begin
  LParameters := FParameters;
  if LParameters = nil then
    raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SOcspNotInitialized);

  if not TryCheck(ACert, LParameters.ValidDate, LParameters.SigningCert,
    LParameters.WorkingPublicKey, LParameters.Index) then
    raise ERecoverablePkixCertPathValidatorCryptoLibException.CreateResAt(LParameters.Index,
      @SOcspStatusUndetermined);
end;

end.
