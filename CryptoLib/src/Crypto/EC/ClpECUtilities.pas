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

unit ClpECUtilities;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIX9ECAsn1Objects,
  ClpIX9ECParametersHolder,
  ClpCustomNamedCurves,
  ClpECNamedCurveTable;

type
  /// <summary>
  /// Utility class for finding EC curves by name or OID.
  /// </summary>
  TECUtilities = class sealed(TObject)

  public
    /// <summary>
    /// Find EC curve parameters by name.
    /// </summary>
    /// <param name="AName">The name of the curve.</param>
    /// <returns>X9ECParameters or nil if not found.</returns>
    class function FindECCurveByName(const AName: String): IX9ECParameters; static;

    /// <summary>
    /// Find EC curve holder by name (lazy).
    /// </summary>
    /// <param name="AName">The name of the curve.</param>
    /// <returns>X9ECParametersHolder or nil if not found.</returns>
    class function FindECCurveByNameLazy(const AName: String): IX9ECParametersHolder; static;

    /// <summary>
    /// Find EC curve parameters by OID.
    /// </summary>
    /// <param name="AOid">The OID of the curve.</param>
    /// <returns>X9ECParameters or nil if not found.</returns>
    class function FindECCurveByOid(const AOid: IDerObjectIdentifier): IX9ECParameters; static;

    /// <summary>
    /// Find EC curve holder by OID (lazy).
    /// </summary>
    /// <param name="AOid">The OID of the curve.</param>
    /// <returns>X9ECParametersHolder or nil if not found.</returns>
    class function FindECCurveByOidLazy(const AOid: IDerObjectIdentifier): IX9ECParametersHolder; static;

    /// <summary>
    /// Find EC curve OID by name.
    /// </summary>
    /// <param name="AName">The name of the curve.</param>
    /// <returns>DerObjectIdentifier or nil if not found.</returns>
    class function FindECCurveOid(const AName: String): IDerObjectIdentifier; static;

  end;

implementation

{ TECUtilities }

class function TECUtilities.FindECCurveByName(const AName: String): IX9ECParameters;
var
  LResult: IX9ECParameters;
begin
  LResult := TCustomNamedCurves.GetByName(AName);
  if LResult = nil then
    LResult := TECNamedCurveTable.GetByName(AName);
  Result := LResult;
end;

class function TECUtilities.FindECCurveByNameLazy(const AName: String): IX9ECParametersHolder;
var
  LHolder: IX9ECParametersHolder;
begin
  LHolder := TCustomNamedCurves.GetByNameLazy(AName);
  if LHolder = nil then
    LHolder := TECNamedCurveTable.GetByNameLazy(AName);
  Result := LHolder;
end;

class function TECUtilities.FindECCurveByOid(const AOid: IDerObjectIdentifier): IX9ECParameters;
var
  LResult: IX9ECParameters;
begin
  LResult := TCustomNamedCurves.GetByOid(AOid);
  if LResult = nil then
    LResult := TECNamedCurveTable.GetByOid(AOid);
  Result := LResult;
end;

class function TECUtilities.FindECCurveByOidLazy(const AOid: IDerObjectIdentifier): IX9ECParametersHolder;
var
  LHolder: IX9ECParametersHolder;
begin
  LHolder := TCustomNamedCurves.GetByOidLazy(AOid);
  if LHolder = nil then
    LHolder := TECNamedCurveTable.GetByOidLazy(AOid);
  Result := LHolder;
end;

class function TECUtilities.FindECCurveOid(const AName: String): IDerObjectIdentifier;
var
  LResult: IDerObjectIdentifier;
begin
  LResult := TCustomNamedCurves.GetOid(AName);
  if LResult = nil then
    LResult := TECNamedCurveTable.GetOid(AName);
  Result := LResult;
end;

end.
