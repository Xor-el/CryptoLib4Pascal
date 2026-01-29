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
    /// Find EC curve parameters by OID.
    /// </summary>
    /// <param name="AOid">The OID of the curve.</param>
    /// <returns>X9ECParameters or nil if not found.</returns>
    class function FindECCurveByOid(const AOid: IDerObjectIdentifier): IX9ECParameters; static;

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
  begin
    LResult := TECNamedCurveTable.GetByName(AName);
  end;
  Result := LResult;
end;

class function TECUtilities.FindECCurveByOid(const AOid: IDerObjectIdentifier): IX9ECParameters;
var
  LResult: IX9ECParameters;
begin
  LResult := TCustomNamedCurves.GetByOid(AOid);
  if LResult = nil then
  begin
    LResult := TECNamedCurveTable.GetByOid(AOid);
  end;
  Result := LResult;
end;

class function TECUtilities.FindECCurveOid(const AName: String): IDerObjectIdentifier;
var
  LResult: IDerObjectIdentifier;
begin
  LResult := TCustomNamedCurves.GetOid(AName);
  if LResult = nil then
  begin
    LResult := TECNamedCurveTable.GetOid(AName);
  end;
  Result := LResult;
end;

end.
