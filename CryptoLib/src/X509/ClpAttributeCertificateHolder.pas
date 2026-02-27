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

unit ClpAttributeCertificateHolder;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Generics.Collections,
  ClpIAsn1Objects,
  ClpIAttributeCertificateHolder,
  ClpIX509Asn1Objects,
  ClpIX509Certificate,
  ClpIDigest,
  ClpAsn1Objects,
  ClpX509Asn1Objects,
  ClpX509Utilities,
  ClpDigestUtilities,
  ClpArrayUtilities,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Implementation of AttributeCertificateHolder.
  /// </summary>
  TAttributeCertificateHolder = class sealed(TInterfacedObject, IAttributeCertificateHolder)

  strict private
    FHolder: IHolder;

    function MatchesDN(const ASubject: IX509Name;
      const ATargets: IGeneralNames): Boolean;
    function GetPrincipals(const AGeneralNames: IGeneralNames)
      : TCryptoLibGenericArray<IX509Name>;

  strict protected
    function GetDigestedObjectType: Int32;
    function GetDigestAlgorithm: String;
    function GetObjectDigest: TCryptoLibByteArray;
    function GetOtherObjectTypeID: String;
    function GetHolder: IHolder;
    function GetSerialNumber: TBigInteger;

  public
    /// <summary>
    /// Create from ASN.1 sequence.
    /// </summary>
    constructor Create(const ASeq: IAsn1Sequence); overload;
    /// <summary>
    /// Create from issuer name and serial number.
    /// </summary>
    constructor Create(const AIssuerName: IX509Name;
      const ASerialNumber: TBigInteger); overload;
    /// <summary>
    /// Create from issuer name and serial (DerInteger).
    /// </summary>
    constructor Create(const AIssuerName: IX509Name;
      const ASerialNumber: IDerInteger); overload;
    /// <summary>
    /// Create from X.509 certificate.
    /// </summary>
    constructor Create(const ACert: IX509Certificate); overload;
    /// <summary>
    /// Create from entity name (principal).
    /// </summary>
    constructor Create(const APrincipal: IX509Name); overload;
    /// <summary>
    /// Create from object digest info.
    /// </summary>
    constructor Create(ADigestedObjectType: Int32; const ADigestAlgorithm: String;
      const AOtherObjectTypeID: String;
      const AObjectDigest: TCryptoLibByteArray); overload;

    function GetEntityNames: TCryptoLibGenericArray<IX509Name>;
    function GetIssuer: TCryptoLibGenericArray<IX509Name>;
    function Clone: IAttributeCertificateHolder;
    function Match(const AX509Cert: IX509Certificate): Boolean;
    function Equals(const AOther: IAttributeCertificateHolder): Boolean; reintroduce;
  end;

implementation

{ TAttributeCertificateHolder }

constructor TAttributeCertificateHolder.Create(const ASeq: IAsn1Sequence);
begin
  inherited Create();
  FHolder := THolder.GetInstance(ASeq);
end;

constructor TAttributeCertificateHolder.Create(const AIssuerName: IX509Name;
  const ASerialNumber: TBigInteger);
begin
  Create(AIssuerName, TDerInteger.Create(ASerialNumber) as IDerInteger);
end;

constructor TAttributeCertificateHolder.Create(const AIssuerName: IX509Name;
  const ASerialNumber: IDerInteger);
begin
  inherited Create();
  FHolder := THolder.Create(TIssuerSerial.Create(AIssuerName, ASerialNumber) as IIssuerSerial);
end;

constructor TAttributeCertificateHolder.Create(const ACert: IX509Certificate);
begin
  inherited Create();
  FHolder := THolder.Create(TX509Utilities.CreateIssuerSerial(ACert));
end;

constructor TAttributeCertificateHolder.Create(const APrincipal: IX509Name);
begin
  inherited Create();
  FHolder := THolder.Create(TGeneralNames.Create(TGeneralName.Create(APrincipal) as IGeneralName) as IGeneralNames);
end;

constructor TAttributeCertificateHolder.Create(ADigestedObjectType: Int32;
  const ADigestAlgorithm, AOtherObjectTypeID: String;
  const AObjectDigest: TCryptoLibByteArray);
var
  LDigestAlgID: IAlgorithmIdentifier;
  LObjectDigestInfo: IObjectDigestInfo;
  LOtherOid: String;
begin
  inherited Create();
  LDigestAlgID := TAlgorithmIdentifier.Create
    (TDerObjectIdentifier.Create(ADigestAlgorithm));
  if ADigestedObjectType = TObjectDigestInfo.OtherObjectDigest then
    LOtherOid := AOtherObjectTypeID
  else
    LOtherOid := '';
  LObjectDigestInfo := TObjectDigestInfo.Create(ADigestedObjectType, LOtherOid,
    LDigestAlgID, AObjectDigest);
  FHolder := THolder.Create(LObjectDigestInfo);
end;

function TAttributeCertificateHolder.GetDigestedObjectType: Int32;
var
  LOdi: IObjectDigestInfo;
begin
  LOdi := FHolder.ObjectDigestInfo;
  if LOdi = nil then
    Result := -1
  else
    Result := LOdi.DigestedObjectType.IntValueExact;
end;

function TAttributeCertificateHolder.GetDigestAlgorithm: String;
var
  LOdi: IObjectDigestInfo;
begin
  LOdi := FHolder.ObjectDigestInfo;
  if LOdi = nil then
    Result := ''
  else
    Result := LOdi.DigestAlgorithm.Algorithm.Id;
end;

function TAttributeCertificateHolder.GetObjectDigest: TCryptoLibByteArray;
var
  LOdi: IObjectDigestInfo;
begin
  LOdi := FHolder.ObjectDigestInfo;
  if LOdi = nil then
    Result := nil
  else
    Result := LOdi.ObjectDigest.GetOctets;
end;

function TAttributeCertificateHolder.GetOtherObjectTypeID: String;
var
  LOdi: IObjectDigestInfo;
begin
  LOdi := FHolder.ObjectDigestInfo;
  if (LOdi = nil) or (LOdi.OtherObjectTypeID = nil) then
    Result := ''
  else
    Result := LOdi.OtherObjectTypeID.Id;
end;

function TAttributeCertificateHolder.GetHolder: IHolder;
begin
  Result := FHolder;
end;

function TAttributeCertificateHolder.GetSerialNumber: TBigInteger;
var
  LBaseId: IIssuerSerial;
begin
  LBaseId := FHolder.BaseCertificateID;
  if LBaseId = nil then
    Result := TBigInteger.GetDefault
  else
    Result := LBaseId.Serial.Value;
end;

function TAttributeCertificateHolder.GetPrincipals(const AGeneralNames
  : IGeneralNames): TCryptoLibGenericArray<IX509Name>;
var
  LNames: TCryptoLibGenericArray<IGeneralName>;
  LList: TList<IX509Name>;
  I: Int32;
  LGn: IGeneralName;
begin
  if AGeneralNames = nil then
  begin
    Result := nil;
    Exit;
  end;
  LNames := AGeneralNames.GetNames;
  LList := TList<IX509Name>.Create;
  try
    for I := 0 to System.High(LNames) do
    begin
      LGn := LNames[I];
      if LGn.TagNo = TGeneralName.DirectoryName then
        LList.Add(TX509Name.GetInstance(LGn.Name));
    end;
    Result := LList.ToArray;
  finally
    LList.Free;
  end;
end;

function TAttributeCertificateHolder.GetEntityNames
  : TCryptoLibGenericArray<IX509Name>;
begin
  Result := GetPrincipals(FHolder.EntityName);
end;

function TAttributeCertificateHolder.GetIssuer
  : TCryptoLibGenericArray<IX509Name>;
var
  LBaseId: IIssuerSerial;
begin
  LBaseId := FHolder.BaseCertificateID;
  if LBaseId = nil then
    Result := nil
  else
    Result := GetPrincipals(LBaseId.Issuer);
end;

function TAttributeCertificateHolder.MatchesDN(const ASubject: IX509Name;
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

function TAttributeCertificateHolder.Clone: IAttributeCertificateHolder;
var
  LSeq: IAsn1Sequence;
begin
  LSeq := TAsn1Sequence.GetInstance(FHolder.ToAsn1Object);
  Result := TAttributeCertificateHolder.Create(LSeq);
end;

function TAttributeCertificateHolder.Match(const AX509Cert: IX509Certificate)
  : Boolean;
var
  LBaseId: IIssuerSerial;
  LEntityName: IGeneralNames;
  LObjDigest: IObjectDigestInfo;
  LDigest: IDigest;
  LData, LComputed, LExpected: TCryptoLibByteArray;
  LTyp: Int32;
begin
  Result := False;
  if AX509Cert = nil then
    Exit;
  try
    LBaseId := FHolder.BaseCertificateID;
    if LBaseId <> nil then
    begin
      if LBaseId.Serial.Value.Equals(AX509Cert.SerialNumber) and
        MatchesDN(AX509Cert.IssuerDN, LBaseId.Issuer) then
      begin
        Result := True;
        Exit;
      end;
    end;

    LEntityName := FHolder.EntityName;
    if LEntityName <> nil then
    begin
      if MatchesDN(AX509Cert.SubjectDN, LEntityName) then
      begin
        Result := True;
        Exit;
      end;
    end;

    LObjDigest := FHolder.ObjectDigestInfo;
    if LObjDigest <> nil then
    begin
      LDigest := TDigestUtilities.GetDigest(LObjDigest.DigestAlgorithm.Algorithm);
      LTyp := LObjDigest.DigestedObjectType.IntValueExact;
      case LTyp of
        TObjectDigestInfo.PublicKey:
          LData := AX509Cert.SubjectPublicKeyInfo.ToAsn1Object.GetEncoded;
        TObjectDigestInfo.PublicKeyCert:
          LData := AX509Cert.GetEncoded;
      else
        LData := nil;
      end;
      if LData <> nil then
      begin
        LDigest.BlockUpdate(LData, 0, System.Length(LData));
        LComputed := TDigestUtilities.DoFinal(LDigest);
        LExpected := GetObjectDigest;
        if TArrayUtilities.FixedTimeEquals(LComputed, LExpected) then
          Result := True;
      end;
    end;
  except
    // return False
  end;
end;

function TAttributeCertificateHolder.Equals(const AOther
  : IAttributeCertificateHolder): Boolean;
begin
  if AOther = nil then
  begin
    Result := False;
    Exit;
  end;
  if Self = (AOther as TAttributeCertificateHolder) then
  begin
    Result := True;
    Exit;
  end;
  Result := FHolder.ToAsn1Object.Equals(AOther.Holder.ToAsn1Object);
end;

end.
