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

unit ClpECNamedCurveTable;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Generics.Collections,
  ClpCryptoLibTypes,
  ClpCollectionUtilities,
  ClpSecNamedCurves,
  ClpNistNamedCurves,
  ClpTeleTrusTNamedCurves,
  ClpECGost3410NamedCurves,
  ClpX962NamedCurves,
  ClpIAsn1Objects,
  ClpIX9ECAsn1Objects,
  ClpIX9ECParametersHolder;

type
  /// <summary>
  /// A general class that reads all X9.62 style EC curve tables.
  /// </summary>
  TECNamedCurveTable = class sealed(TObject)

  strict private

    class function GetNames: TCryptoLibStringArray; static;

  public
    /// <summary>Look up the X9ECParameters for the curve with the given name.</summary>
    class function GetByName(const AName: String): IX9ECParameters; static;

    /// <summary>Look up an X9ECParametersHolder for the curve with the given name (lazy).</summary>
    class function GetByNameLazy(const AName: String): IX9ECParametersHolder; static;

    /// <summary>Look up the X9ECParameters for the curve with the given OID.</summary>
    class function GetByOid(const AOid: IDerObjectIdentifier): IX9ECParameters; static;

    /// <summary>Look up an X9ECParametersHolder for the curve with the given OID (lazy).</summary>
    class function GetByOidLazy(const AOid: IDerObjectIdentifier): IX9ECParametersHolder; static;

    /// <summary>Look up the name of the curve with the given OID.</summary>
    class function GetName(const AOid: IDerObjectIdentifier): String; static;

    /// <summary>Look up the OID of the curve with the given name.</summary>
    class function GetOid(const AName: String): IDerObjectIdentifier; static;

    /// <summary>Enumerate the available curve names in all the registries.</summary>
    class property Names: TCryptoLibStringArray read GetNames;

  end;

implementation

{ TECNamedCurveTable }

class function TECNamedCurveTable.GetByName(const AName: String): IX9ECParameters;
var
  LEcP: IX9ECParameters;
begin
  LEcP := TX962NamedCurves.GetByName(AName);
  if LEcP = nil then
    LEcP := TSecNamedCurves.GetByName(AName);
  if LEcP = nil then
    LEcP := TNistNamedCurves.GetByName(AName);
  if LEcP = nil then
    LEcP := TTeleTrusTNamedCurves.GetByName(AName);
  if LEcP = nil then
    LEcP := TECGost3410NamedCurves.GetByName(AName);
  Result := LEcP;
end;

class function TECNamedCurveTable.GetByNameLazy(const AName: String): IX9ECParametersHolder;
var
  LHolder: IX9ECParametersHolder;
begin
  LHolder := TX962NamedCurves.GetByNameLazy(AName);
  if LHolder = nil then
    LHolder := TSecNamedCurves.GetByNameLazy(AName);
  if LHolder = nil then
    LHolder := TNistNamedCurves.GetByNameLazy(AName);
  if LHolder = nil then
    LHolder := TTeleTrusTNamedCurves.GetByNameLazy(AName);
  if LHolder = nil then
    LHolder := TECGost3410NamedCurves.GetByNameLazy(AName);
  Result := LHolder;
end;

class function TECNamedCurveTable.GetByOid(const AOid: IDerObjectIdentifier): IX9ECParameters;
var
  LEcP: IX9ECParameters;
begin
  LEcP := TX962NamedCurves.GetByOid(AOid);
  if LEcP = nil then
    LEcP := TSecNamedCurves.GetByOid(AOid);
  // NOTE: All the NIST curves are currently from SEC, so no point in redundant OID lookup
  if LEcP = nil then
    LEcP := TTeleTrusTNamedCurves.GetByOid(AOid);
  if LEcP = nil then
    LEcP := TECGost3410NamedCurves.GetByOid(AOid);
  Result := LEcP;
end;

class function TECNamedCurveTable.GetByOidLazy(const AOid: IDerObjectIdentifier): IX9ECParametersHolder;
var
  LHolder: IX9ECParametersHolder;
begin
  LHolder := TX962NamedCurves.GetByOidLazy(AOid);
  if LHolder = nil then
    LHolder := TSecNamedCurves.GetByOidLazy(AOid);
  // NOTE: All the NIST curves are currently from SEC, so no point in redundant OID lookup
  if LHolder = nil then
    LHolder := TTeleTrusTNamedCurves.GetByOidLazy(AOid);
  if LHolder = nil then
    LHolder := TECGost3410NamedCurves.GetByOidLazy(AOid);
  Result := LHolder;
end;

class function TECNamedCurveTable.GetName(const AOid: IDerObjectIdentifier): String;
var
  LName: String;
begin
  LName := TX962NamedCurves.GetName(AOid);
  if LName = '' then
    LName := TSecNamedCurves.GetName(AOid);
  if LName = '' then
    LName := TNistNamedCurves.GetName(AOid);
  if LName = '' then
    LName := TTeleTrusTNamedCurves.GetName(AOid);
  if LName = '' then
    LName := TECGost3410NamedCurves.GetName(AOid);
  Result := LName;
end;

class function TECNamedCurveTable.GetOid(const AName: String): IDerObjectIdentifier;
var
  LOid: IDerObjectIdentifier;
begin
  LOid := TX962NamedCurves.GetOid(AName);
  if LOid = nil then
    LOid := TSecNamedCurves.GetOid(AName);
  if LOid = nil then
    LOid := TNistNamedCurves.GetOid(AName);
  if LOid = nil then
    LOid := TTeleTrusTNamedCurves.GetOid(AName);
  if LOid = nil then
    LOid := TECGost3410NamedCurves.GetOid(AName);
  Result := LOid;
end;

class function TECNamedCurveTable.GetNames: TCryptoLibStringArray;
var
  LTemp: TList<String>;
begin
  LTemp := TList<String>.Create();
  try
    LTemp.AddRange(TX962NamedCurves.Names);
    LTemp.AddRange(TSecNamedCurves.Names);
    LTemp.AddRange(TNistNamedCurves.Names);
    LTemp.AddRange(TTeleTrusTNamedCurves.Names);
    LTemp.AddRange(TECGost3410NamedCurves.Names);
    Result := TCollectionUtilities.ToArray<String>(LTemp);
  finally
    LTemp.Free;
  end;
end;

end.
