{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpAttributeCertificateIssuer;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpIAttributeCertificateIssuer,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIX509Certificate,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Implementation of AttributeCertificateIssuer.
  /// </summary>
  TAttributeCertificateIssuer = class sealed(TInterfacedObject,
    IAttributeCertificateIssuer)

  strict private
    FForm: IAsn1Encodable;

    function GetForm: IAsn1Encodable;
    function GetNames: TCryptoLibGenericArray<IX509Name>;
    function MatchesDN(const ASubject: IX509Name;
      const ATargets: IGeneralNames): Boolean;

  public
    /// <summary>
    /// Set the issuer directly with the ASN.1 structure.
    /// </summary>
    constructor Create(const AIssuer: IAttCertIssuer); overload;
    /// <summary>
    /// Create from X.509 principal (issuer name).
    /// </summary>
    constructor Create(const APrincipal: IX509Name); overload;

    function GetAttCertIssuer: IAttCertIssuer;
    function GetPrincipals: TCryptoLibGenericArray<IX509Name>;
    function Clone: IAttributeCertificateIssuer;
    function Match(const AX509Cert: IX509Certificate): Boolean;
    function Equals(const AOther: IAttributeCertificateIssuer): Boolean;
  end;

implementation

{ TAttributeCertificateIssuer }

constructor TAttributeCertificateIssuer.Create(const AIssuer: IAttCertIssuer);
begin
  inherited Create();
  FForm := AIssuer.GetIssuer;
end;

constructor TAttributeCertificateIssuer.Create(const APrincipal: IX509Name);
begin
  inherited Create();
  FForm := TV2Form.Create(TGeneralNames.Create(TGeneralName.Create(APrincipal) as IGeneralName) as IGeneralNames);
end;

function TAttributeCertificateIssuer.GetNames
  : TCryptoLibGenericArray<IX509Name>;
var
  LName: IGeneralNames;
  LNames: TCryptoLibGenericArray<IGeneralName>;
  I: Int32;
  LList: TList<IX509Name>;
  LV2: IV2Form;
begin
  if Supports(FForm, IV2Form, LV2) then
    LName := LV2.IssuerName
  else
    LName := FForm as IGeneralNames;

  LNames := LName.GetNames;
  LList := TList<IX509Name>.Create;
  try
    for I := 0 to System.High(LNames) do
      if LNames[I].TagNo = TGeneralName.DirectoryName then
        LList.Add(TX509Name.GetInstance(LNames[I].Name));
    Result := LList.ToArray;
  finally
    LList.Free;
  end;
end;

function TAttributeCertificateIssuer.GetAttCertIssuer: IAttCertIssuer;
var
  LV2: IV2Form;
  LGN: IGeneralNames;
begin
  if Supports(FForm, IV2Form, LV2) then
    Result := TAttCertIssuer.Create(LV2)
  else if Supports(FForm, IGeneralNames, LGN) then
    Result := TAttCertIssuer.Create(LGN)
  else
    raise EArgumentCryptoLibException.Create('Unexpected form in AttributeCertificateIssuer');
end;

function TAttributeCertificateIssuer.GetForm: IAsn1Encodable;
begin
  Result := FForm;
end;

function TAttributeCertificateIssuer.GetPrincipals
  : TCryptoLibGenericArray<IX509Name>;
begin
  Result := GetNames;
end;

function TAttributeCertificateIssuer.MatchesDN(const ASubject: IX509Name;
  const ATargets: IGeneralNames): Boolean;
var
  LNames: TCryptoLibGenericArray<IGeneralName>;
  I: Int32;
  LGn: IGeneralName;
  LName: IX509Name;
begin
  if ATargets = nil then
  begin
    Result := False;
    Exit;
  end;
  LNames := ATargets.GetNames;
  for I := 0 to System.High(LNames) do
  begin
    LGn := LNames[I];
    if LGn.TagNo = TGeneralName.DirectoryName then
    begin
      try
        LName := TX509Name.GetInstance(LGn.Name);
        if LName.Equivalent(ASubject) then
        begin
          Result := True;
          Exit;
        end;
      except
        // ignore
      end;
    end;
  end;
  Result := False;
end;

function TAttributeCertificateIssuer.Clone: IAttributeCertificateIssuer;
var
  LIssuer: IAttCertIssuer;
  LV2: IV2Form;
  LGN: IGeneralNames;
begin
  if Supports(FForm, IV2Form, LV2) then
    LIssuer := TAttCertIssuer.Create(LV2)
  else if Supports(FForm, IGeneralNames, LGN) then
    LIssuer := TAttCertIssuer.Create(LGN)
  else
    raise EArgumentCryptoLibException.Create('Unexpected form in AttributeCertificateIssuer');
  Result := TAttributeCertificateIssuer.Create(LIssuer);
end;

function TAttributeCertificateIssuer.Match(const AX509Cert: IX509Certificate)
  : Boolean;
var
  LV2: IV2Form;
  LBaseId: IIssuerSerial;
  LGeneralNames: IGeneralNames;
begin
  Result := False;
  if AX509Cert = nil then
    Exit;

  if Supports(FForm, IV2Form, LV2) then
  begin
    LBaseId := LV2.BaseCertificateID;
    if LBaseId <> nil then
      Result := LBaseId.Serial.Value.Equals(AX509Cert.SerialNumber) and
        MatchesDN(AX509Cert.IssuerDN, LBaseId.Issuer)
    else
      Result := MatchesDN(AX509Cert.SubjectDN, LV2.IssuerName);
  end
  else
  begin
    LGeneralNames := FForm as IGeneralNames;
    Result := MatchesDN(AX509Cert.SubjectDN, LGeneralNames);
  end;
end;

function TAttributeCertificateIssuer.Equals(const AOther
  : IAttributeCertificateIssuer): Boolean;
begin
  if AOther = nil then
  begin
    Result := False;
    Exit;
  end;
  if Self = (AOther as TAttributeCertificateIssuer) then
  begin
    Result := True;
    Exit;
  end;
  Result := FForm.ToAsn1Object.Equals(AOther.Form.ToAsn1Object);
end;

end.
