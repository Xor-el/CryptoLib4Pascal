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

unit ClpKemUtilities;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpAsn1Objects,
  ClpAsn1Comparers,
  ClpCryptoLibComparers,
  ClpCryptoLibExceptions,
  ClpIAsn1Objects,
  ClpIMlKemParameters,
  ClpMlKemParameters,
  ClpIKemEncapsulator,
  ClpIKemDecapsulator,
  ClpMlKemEncapsulator,
  ClpMlKemDecapsulator;

resourcestring
  SOidNil = 'OID cannot be nil';
  SNameNil = 'name cannot be nil';
  SKemOidNotRecognised = 'KEM OID not recognised.';
  SKemNameNotRecognised = 'KEM name not recognised.';

type
  TKemUtilities = class sealed(TObject)
  strict private
  class var
    FByName: TDictionary<String, String>;
    FByOid: TDictionary<IDerObjectIdentifier, String>;

    class function TryGetMechanism(const AName: String; out AMechanism: String): Boolean; overload; static;
    class function TryGetMechanism(const AOid: IDerObjectIdentifier; out AMechanism: String): Boolean; overload; static;
    class function GetEncapForMechanism(const AMechanism: String): IKemEncapsulator; static;
    class function GetDecapForMechanism(const AMechanism: String): IKemDecapsulator; static;
    class procedure Register(const AName: String; const AOid: IDerObjectIdentifier); static;
    class constructor Create;
    class destructor Destroy;
  public
    class function GetDecapsulator(const AOid: IDerObjectIdentifier): IKemDecapsulator; overload; static;
    class function GetDecapsulator(const AName: String): IKemDecapsulator; overload; static;
    class function GetEncapsulator(const AOid: IDerObjectIdentifier): IKemEncapsulator; overload; static;
    class function GetEncapsulator(const AName: String): IKemEncapsulator; overload; static;
    class function TryGetDecapsulator(const AOid: IDerObjectIdentifier;
      out ADecapsulator: IKemDecapsulator): Boolean; overload; static;
    class function TryGetDecapsulator(const AName: String;
      out ADecapsulator: IKemDecapsulator): Boolean; overload; static;
    class function TryGetEncapsulator(const AOid: IDerObjectIdentifier;
      out AEncapsulator: IKemEncapsulator): Boolean; overload; static;
    class function TryGetEncapsulator(const AName: String;
      out AEncapsulator: IKemEncapsulator): Boolean; overload; static;
  end;

implementation

{ TKemUtilities }

class constructor TKemUtilities.Create;
var
  LPair: TPair<String, IMlKemParameters>;
begin
  FByName := TDictionary<String, String>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FByOid := TDictionary<IDerObjectIdentifier, String>.Create(TAsn1Comparers.OidEqualityComparer);
  for LPair in TMlKemParameters.ByName do
    Register(LPair.Key, LPair.Value.Oid);
end;

class destructor TKemUtilities.Destroy;
begin
  FByName.Free;
  FByOid.Free;
end;

class procedure TKemUtilities.Register(const AName: String; const AOid: IDerObjectIdentifier);
begin
  if AName = '' then
    raise EArgumentNilCryptoLibException.CreateRes(@SNameNil);
  FByName.Add(AName, AName);
  if AOid <> nil then
    FByOid.Add(AOid, AName);
end;

class function TKemUtilities.TryGetMechanism(const AOid: IDerObjectIdentifier;
  out AMechanism: String): Boolean;
begin
  if AOid = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOidNil);
  Result := FByOid.TryGetValue(AOid, AMechanism);
end;

class function TKemUtilities.TryGetMechanism(const AName: String;
  out AMechanism: String): Boolean;
var
  LOid: IDerObjectIdentifier;
begin
  if AName = '' then
    raise EArgumentNilCryptoLibException.CreateRes(@SNameNil);
  if TDerObjectIdentifier.TryFromID(AName, LOid) then
    Exit(TryGetMechanism(LOid, AMechanism));
  Result := FByName.TryGetValue(AName, AMechanism);
end;

class function TKemUtilities.GetEncapForMechanism(const AMechanism: String): IKemEncapsulator;
var
  LParams: IMlKemParameters;
begin
  LParams := TMlKemParameters.GetByName(AMechanism);
  if LParams <> nil then
    Result := TMlKemEncapsulator.Create(LParams)
  else
    Result := nil;
end;

class function TKemUtilities.GetDecapForMechanism(const AMechanism: String): IKemDecapsulator;
var
  LParams: IMlKemParameters;
begin
  LParams := TMlKemParameters.GetByName(AMechanism);
  if LParams <> nil then
    Result := TMlKemDecapsulator.Create(LParams)
  else
    Result := nil;
end;

class function TKemUtilities.TryGetDecapsulator(const AOid: IDerObjectIdentifier;
  out ADecapsulator: IKemDecapsulator): Boolean;
var
  LMechanism: String;
  LDecap: IKemDecapsulator;
begin
  if TryGetMechanism(AOid, LMechanism) then
  begin
    LDecap := GetDecapForMechanism(LMechanism);
    if LDecap <> nil then
    begin
      ADecapsulator := LDecap;
      Exit(True);
    end;
  end;
  ADecapsulator := nil;
  Result := False;
end;

class function TKemUtilities.TryGetDecapsulator(const AName: String;
  out ADecapsulator: IKemDecapsulator): Boolean;
var
  LMechanism: String;
  LDecap: IKemDecapsulator;
begin
  if TryGetMechanism(AName, LMechanism) then
  begin
    LDecap := GetDecapForMechanism(LMechanism);
    if LDecap <> nil then
    begin
      ADecapsulator := LDecap;
      Exit(True);
    end;
  end;
  ADecapsulator := nil;
  Result := False;
end;

class function TKemUtilities.TryGetEncapsulator(const AOid: IDerObjectIdentifier;
  out AEncapsulator: IKemEncapsulator): Boolean;
var
  LMechanism: String;
  LEncap: IKemEncapsulator;
begin
  if TryGetMechanism(AOid, LMechanism) then
  begin
    LEncap := GetEncapForMechanism(LMechanism);
    if LEncap <> nil then
    begin
      AEncapsulator := LEncap;
      Exit(True);
    end;
  end;
  AEncapsulator := nil;
  Result := False;
end;

class function TKemUtilities.TryGetEncapsulator(const AName: String;
  out AEncapsulator: IKemEncapsulator): Boolean;
var
  LMechanism: String;
  LEncap: IKemEncapsulator;
begin
  if TryGetMechanism(AName, LMechanism) then
  begin
    LEncap := GetEncapForMechanism(LMechanism);
    if LEncap <> nil then
    begin
      AEncapsulator := LEncap;
      Exit(True);
    end;
  end;
  AEncapsulator := nil;
  Result := False;
end;

class function TKemUtilities.GetDecapsulator(const AOid: IDerObjectIdentifier): IKemDecapsulator;
begin
  if TryGetDecapsulator(AOid, Result) then
    Exit;
  raise ESecurityUtilityCryptoLibException.CreateRes(@SKemOidNotRecognised);
end;

class function TKemUtilities.GetDecapsulator(const AName: String): IKemDecapsulator;
begin
  if TryGetDecapsulator(AName, Result) then
    Exit;
  raise ESecurityUtilityCryptoLibException.CreateRes(@SKemNameNotRecognised);
end;

class function TKemUtilities.GetEncapsulator(const AOid: IDerObjectIdentifier): IKemEncapsulator;
begin
  if TryGetEncapsulator(AOid, Result) then
    Exit;
  raise ESecurityUtilityCryptoLibException.CreateRes(@SKemOidNotRecognised);
end;

class function TKemUtilities.GetEncapsulator(const AName: String): IKemEncapsulator;
begin
  if TryGetEncapsulator(AName, Result) then
    Exit;
  raise ESecurityUtilityCryptoLibException.CreateRes(@SKemNameNotRecognised);
end;

end.
