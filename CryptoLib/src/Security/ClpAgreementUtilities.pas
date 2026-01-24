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

unit ClpAgreementUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpAsn1Objects,
  ClpCollectionUtilities,
  ClpCryptoLibComparers,
  ClpCryptoLibTypes,
  ClpDHBasicAgreement,
  ClpECDHBasicAgreement,
  ClpECDHCBasicAgreement,
  ClpEdECObjectIdentifiers,
  ClpIBasicAgreement,
  ClpIDHBasicAgreement,
  ClpIECDHBasicAgreement,
  ClpIECDHCBasicAgreement,
  ClpIAsn1Objects,
  ClpIRawAgreement,
  ClpIX25519Agreement,
  ClpX25519Agreement;

resourcestring
  SOidNil = 'OID Cannot be Nil';
  SAlgorithmNil = 'Algorithm Cannot be Nil';
  SWrapAlgorithmNil = 'Wrap Algorithm Cannot be Nil';
  SBasicAgreementOidNotRecognised = 'Basic Agreement OID not recognised.';
  SBasicAgreementNotRecognised = 'Basic Agreement "%s" not recognised.';
  SBasicAgreementWithKdfOidNotRecognised = 'Basic Agreement (with KDF) OID not recognised.';
  SBasicAgreementWithKdfNotRecognised = 'Basic Agreement (with KDF) %s not recognised.';
  SRawAgreementOidNotRecognised = 'Raw Agreement OID not recognised.';
  SRawAgreementNotRecognised = 'Raw Agreement "%s" not recognised.';

type
  /// <summary>
  /// Utility class for creating IBasicAgreement and IRawAgreement objects from their names/OIDs.
  /// </summary>
  TAgreementUtilities = class sealed(TObject)
  strict private
    class var
      FAlgorithmMap: TDictionary<String, String>;
      FAlgorithmOidMap: TDictionary<IDerObjectIdentifier, String>;

    class function GetMechanism(const AAlgorithm: String): String; static;
    class function GetBasicAgreementForMechanism(const AMechanism: String): IBasicAgreement; static;
    class function GetBasicAgreementWithKdfForMechanism(const AMechanism, AWrapAlgorithm: String): IBasicAgreement; static;
    class function GetRawAgreementForMechanism(const AMechanism: String): IRawAgreement; static;
    class procedure Boot; static;
    class constructor Create;
    class destructor Destroy;
  public
    class function GetAlgorithmName(const AOid: IDerObjectIdentifier): String; static;
    class function GetBasicAgreement(const AOid: IDerObjectIdentifier): IBasicAgreement; overload; static;
    class function GetBasicAgreement(const AAlgorithm: String): IBasicAgreement; overload; static;
    class function GetBasicAgreementWithKdf(const AAgreeAlgOid, AWrapAlgOid: IDerObjectIdentifier): IBasicAgreement; overload; static;
    class function GetBasicAgreementWithKdf(const AOid: IDerObjectIdentifier; const AWrapAlgorithm: String): IBasicAgreement; overload; static;
    class function GetBasicAgreementWithKdf(const AAgreeAlgorithm, AWrapAlgorithm: String): IBasicAgreement; overload; static;
    class function GetRawAgreement(const AOid: IDerObjectIdentifier): IRawAgreement; overload; static;
    class function GetRawAgreement(const AAlgorithm: String): IRawAgreement; overload; static;
  end;

implementation

{ TAgreementUtilities }

class procedure TAgreementUtilities.Boot;
begin
  FAlgorithmMap := TDictionary<String, String>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FAlgorithmMap.Add('DIFFIEHELLMAN', 'DH');
  FAlgorithmMap.Add('ECCDH', 'ECDHC');

  FAlgorithmOidMap := TDictionary<IDerObjectIdentifier, String>.Create(TCryptoLibComparers.OidEqualityComparer);
  FAlgorithmOidMap.AddOrSetValue(TEdECObjectIdentifiers.IdX25519, 'X25519');
end;

class constructor TAgreementUtilities.Create;
begin
  Boot;
end;

class destructor TAgreementUtilities.Destroy;
begin
  FAlgorithmMap.Free;
  FAlgorithmOidMap.Free;
end;

class function TAgreementUtilities.GetMechanism(const AAlgorithm: String): String;
var
  LOid: IDerObjectIdentifier;
  LMechanism: String;
begin
  if FAlgorithmMap.TryGetValue(AAlgorithm, LMechanism) then
  begin
    Result := LMechanism;
    Exit;
  end;
  if TDerObjectIdentifier.TryFromID(AAlgorithm, LOid) and FAlgorithmOidMap.TryGetValue(LOid, LMechanism) then
  begin
    Result := LMechanism;
    Exit;
  end;
  Result := '';
end;

class function TAgreementUtilities.GetAlgorithmName(const AOid: IDerObjectIdentifier): String;
begin
  Result := TCollectionUtilities.GetValueOrNull<IDerObjectIdentifier, String>(FAlgorithmOidMap, AOid);
end;

class function TAgreementUtilities.GetBasicAgreementForMechanism(const AMechanism: String): IBasicAgreement;
begin
  Result := nil;
  if AMechanism = 'DH' then
    Result := TDHBasicAgreement.Create() as IDHBasicAgreement
  else if AMechanism = 'ECDH' then
    Result := TECDHBasicAgreement.Create() as IECDHBasicAgreement
  else if AMechanism = 'ECDHC' then
    Result := TECDHCBasicAgreement.Create() as IECDHCBasicAgreement;
end;

class function TAgreementUtilities.GetBasicAgreementWithKdfForMechanism(const AMechanism, AWrapAlgorithm: String): IBasicAgreement;
begin
  Result := nil;
end;

class function TAgreementUtilities.GetBasicAgreement(const AOid: IDerObjectIdentifier): IBasicAgreement;
var
  LMechanism: String;
  LAgreement: IBasicAgreement;
begin
  if AOid = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOidNil);
  if FAlgorithmOidMap.TryGetValue(AOid, LMechanism) then
  begin
    LAgreement := GetBasicAgreementForMechanism(LMechanism);
    if LAgreement <> nil then
    begin
      Result := LAgreement;
      Exit;
    end;
  end;
  raise ESecurityUtilityCryptoLibException.CreateRes(@SBasicAgreementOidNotRecognised);
end;

class function TAgreementUtilities.GetBasicAgreement(const AAlgorithm: String): IBasicAgreement;
var
  LMechanism: String;
  LAgreement: IBasicAgreement;
begin
  if AAlgorithm = '' then
    raise EArgumentNilCryptoLibException.CreateRes(@SAlgorithmNil);
  LMechanism := GetMechanism(AAlgorithm);
  if LMechanism = '' then
    LMechanism := UpperCase(AAlgorithm);
  LAgreement := GetBasicAgreementForMechanism(LMechanism);
  if LAgreement <> nil then
  begin
    Result := LAgreement;
    Exit;
  end;
  raise ESecurityUtilityCryptoLibException.CreateResFmt(@SBasicAgreementNotRecognised, [AAlgorithm]);
end;

class function TAgreementUtilities.GetBasicAgreementWithKdf(const AAgreeAlgOid, AWrapAlgOid: IDerObjectIdentifier): IBasicAgreement;
var
  LWrap: String;
begin
  if AWrapAlgOid <> nil then
    LWrap := AWrapAlgOid.ID
  else
    LWrap := '';
  Result := GetBasicAgreementWithKdf(AAgreeAlgOid, LWrap);
end;

class function TAgreementUtilities.GetBasicAgreementWithKdf(const AOid: IDerObjectIdentifier; const AWrapAlgorithm: String): IBasicAgreement;
var
  LMechanism: String;
  LAgreement: IBasicAgreement;
begin
  if AOid = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOidNil);
  if AWrapAlgorithm = '' then
    raise EArgumentNilCryptoLibException.CreateRes(@SWrapAlgorithmNil);
  if FAlgorithmOidMap.TryGetValue(AOid, LMechanism) then
  begin
    LAgreement := GetBasicAgreementWithKdfForMechanism(LMechanism, AWrapAlgorithm);
    if LAgreement <> nil then
    begin
      Result := LAgreement;
      Exit;
    end;
  end;
  raise ESecurityUtilityCryptoLibException.CreateRes(@SBasicAgreementWithKdfOidNotRecognised);
end;

class function TAgreementUtilities.GetBasicAgreementWithKdf(const AAgreeAlgorithm, AWrapAlgorithm: String): IBasicAgreement;
var
  LMechanism: String;
  LAgreement: IBasicAgreement;
begin
  if AAgreeAlgorithm = '' then
    raise EArgumentNilCryptoLibException.CreateRes(@SAlgorithmNil);
  if AWrapAlgorithm = '' then
    raise EArgumentNilCryptoLibException.CreateRes(@SWrapAlgorithmNil);
  LMechanism := GetMechanism(AAgreeAlgorithm);
  if LMechanism = '' then
    LMechanism := UpperCase(AAgreeAlgorithm);
  LAgreement := GetBasicAgreementWithKdfForMechanism(LMechanism, AWrapAlgorithm);
  if LAgreement <> nil then
  begin
    Result := LAgreement;
    Exit;
  end;
  raise ESecurityUtilityCryptoLibException.CreateResFmt(@SBasicAgreementWithKdfNotRecognised, [AAgreeAlgorithm]);
end;

class function TAgreementUtilities.GetRawAgreementForMechanism(const AMechanism: String): IRawAgreement;
begin
  Result := nil;
  if AMechanism = 'X25519' then
    Result := TX25519Agreement.Create() as IX25519Agreement;
end;

class function TAgreementUtilities.GetRawAgreement(const AOid: IDerObjectIdentifier): IRawAgreement;
var
  LMechanism: String;
  LAgreement: IRawAgreement;
begin
  if AOid = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOidNil);
  if FAlgorithmOidMap.TryGetValue(AOid, LMechanism) then
  begin
    LAgreement := GetRawAgreementForMechanism(LMechanism);
    if LAgreement <> nil then
    begin
      Result := LAgreement;
      Exit;
    end;
  end;
  raise ESecurityUtilityCryptoLibException.CreateRes(@SRawAgreementOidNotRecognised);
end;

class function TAgreementUtilities.GetRawAgreement(const AAlgorithm: String): IRawAgreement;
var
  LMechanism: String;
  LAgreement: IRawAgreement;
begin
  if AAlgorithm = '' then
    raise EArgumentNilCryptoLibException.CreateRes(@SAlgorithmNil);
  LMechanism := GetMechanism(AAlgorithm);
  if LMechanism = '' then
    LMechanism := UpperCase(AAlgorithm);
  LAgreement := GetRawAgreementForMechanism(LMechanism);
  if LAgreement <> nil then
  begin
    Result := LAgreement;
    Exit;
  end;
  raise ESecurityUtilityCryptoLibException.CreateResFmt(@SRawAgreementNotRecognised, [AAlgorithm]);
end;

end.
