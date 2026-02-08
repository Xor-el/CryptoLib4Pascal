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

unit ClpNistNamedCurves;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpAsn1Comparers,
  ClpCryptoLibComparers,
  ClpCollectionUtilities,
  ClpSecNamedCurves,
  ClpSecObjectIdentifiers,
  ClpCryptoLibTypes,
  ClpIAsn1Objects,
  ClpIX9ECAsn1Objects,
  ClpIX9ECParametersHolder;

type
  TNistNamedCurves = class sealed(TObject)

  strict private
    class var
      FObjIds: TDictionary<String, IDerObjectIdentifier>;
      FNames: TDictionary<IDerObjectIdentifier, String>;

    class function GetNames: TCryptoLibStringArray; static; inline;
    class procedure DefineCurveAlias(const AName: String;
      const AOid: IDerObjectIdentifier); static;

    class procedure Boot; static;
    class constructor CreateNistNamedCurves;
    class destructor DestroyNistNamedCurves;

  public
    class function GetByName(const AName: String): IX9ECParameters;
      static; inline;
    class function GetByNameLazy(const AName: String): IX9ECParametersHolder;
      static; inline;
    class function GetByOid(const AOid: IDerObjectIdentifier): IX9ECParameters;
      static; inline;
    class function GetByOidLazy(const AOid: IDerObjectIdentifier)
      : IX9ECParametersHolder; static; inline;
    class function GetName(const AOid: IDerObjectIdentifier): String;
      static; inline;
    class function GetOid(const AName: String): IDerObjectIdentifier;
      static; inline;
    class property Names: TCryptoLibStringArray read GetNames;

  end;

implementation

{ TNistNamedCurves }

class procedure TNistNamedCurves.DefineCurveAlias(const AName: String;
  const AOid: IDerObjectIdentifier);
var
  LName: String;
begin
  if TSecNamedCurves.GetByOidLazy(AOid) = nil then
    raise EInvalidOperationCryptoLibException.Create('NIST alias OID not in SEC registry');
  LName := AName;
  FNames.Add(AOid, LName);
  FObjIds.Add(LName, AOid);
end;

class procedure TNistNamedCurves.Boot;
begin
  FObjIds := TDictionary<String, IDerObjectIdentifier>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FNames := TDictionary<IDerObjectIdentifier, String>.Create(TAsn1Comparers.OidEqualityComparer);

  DefineCurveAlias('B-163', TSecObjectIdentifiers.SecT163r2);
  DefineCurveAlias('B-233', TSecObjectIdentifiers.SecT233r1);
  DefineCurveAlias('B-283', TSecObjectIdentifiers.SecT283r1);
  DefineCurveAlias('B-409', TSecObjectIdentifiers.SecT409r1);
  DefineCurveAlias('B-571', TSecObjectIdentifiers.SecT571r1);

  DefineCurveAlias('K-163', TSecObjectIdentifiers.SecT163k1);
  DefineCurveAlias('K-233', TSecObjectIdentifiers.SecT233k1);
  DefineCurveAlias('K-283', TSecObjectIdentifiers.SecT283k1);
  DefineCurveAlias('K-409', TSecObjectIdentifiers.SecT409k1);
  DefineCurveAlias('K-571', TSecObjectIdentifiers.SecT571k1);

  DefineCurveAlias('P-192', TSecObjectIdentifiers.SecP192r1);
  DefineCurveAlias('P-224', TSecObjectIdentifiers.SecP224r1);
  DefineCurveAlias('P-256', TSecObjectIdentifiers.SecP256r1);
  DefineCurveAlias('P-384', TSecObjectIdentifiers.SecP384r1);
  DefineCurveAlias('P-521', TSecObjectIdentifiers.SecP521r1);
end;

class constructor TNistNamedCurves.CreateNistNamedCurves;
begin
  Boot;
end;

class destructor TNistNamedCurves.DestroyNistNamedCurves;
begin
  FObjIds.Free;
  FNames.Free;
end;

class function TNistNamedCurves.GetNames: TCryptoLibStringArray;
begin
  Result := TCollectionUtilities.Keys<String, IDerObjectIdentifier>(FObjIds);
end;

class function TNistNamedCurves.GetByName(const AName: String): IX9ECParameters;
var
  LOid: IDerObjectIdentifier;
begin
  LOid := GetOid(AName);
  if LOid = nil then
    Result := nil
  else
    Result := GetByOid(LOid);
end;

class function TNistNamedCurves.GetByNameLazy(const AName: String)
  : IX9ECParametersHolder;
var
  LOid: IDerObjectIdentifier;
begin
  LOid := GetOid(AName);
  if LOid = nil then
    Result := nil
  else
    Result := GetByOidLazy(LOid);
end;

class function TNistNamedCurves.GetByOid(const AOid: IDerObjectIdentifier)
  : IX9ECParameters;
begin
  if FNames.ContainsKey(AOid) then
    Result := TSecNamedCurves.GetByOid(AOid)
  else
    Result := nil;
end;

class function TNistNamedCurves.GetByOidLazy(const AOid: IDerObjectIdentifier)
  : IX9ECParametersHolder;
begin
  if FNames.ContainsKey(AOid) then
    Result := TSecNamedCurves.GetByOidLazy(AOid)
  else
    Result := nil;
end;

class function TNistNamedCurves.GetName(const AOid: IDerObjectIdentifier): String;
begin
  if not FNames.TryGetValue(AOid, Result) then
    Result := '';
end;

class function TNistNamedCurves.GetOid(const AName: String): IDerObjectIdentifier;
begin
  if not FObjIds.TryGetValue(UpperCase(AName), Result) then
    Result := nil;
end;

end.
