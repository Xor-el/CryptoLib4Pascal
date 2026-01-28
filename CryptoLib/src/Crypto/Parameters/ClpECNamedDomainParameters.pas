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

unit ClpECNamedDomainParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIAsn1Objects,
  ClpIECC,
  ClpIECDomainParameters,
  ClpIECNamedDomainParameters,
  ClpIX9ECParameters,
  ClpX9Asn1Objects,
  ClpIX9Asn1Objects,
  ClpECDomainParameters,
  ClpECUtilities,
  ClpCryptoLibTypes;

resourcestring
  SOidNil = 'OID Cannot be Nil';
  SOidNotValid = 'OID is not a valid public key parameter set';

type
  TECNamedDomainParameters = class sealed(TECDomainParameters, IECNamedDomainParameters)

  strict private
  var
    FName: IDerObjectIdentifier;

    function GetName: IDerObjectIdentifier; inline;

  public
    class function LookupOid(const AOid: IDerObjectIdentifier): IECNamedDomainParameters; static;

    constructor Create(const AName: IDerObjectIdentifier; const ADp: IECDomainParameters); overload;
    constructor Create(const AName: IDerObjectIdentifier; const AX9: IX9ECParameters); overload;
    constructor Create(const AName: IDerObjectIdentifier; const ACurve: IECCurve; const AG: IECPoint; const AN: TBigInteger); overload;
    constructor Create(const AName: IDerObjectIdentifier; const ACurve: IECCurve; const AG: IECPoint; const AN, AH: TBigInteger); overload;
    constructor Create(const AName: IDerObjectIdentifier; const ACurve: IECCurve; const AG: IECPoint; const AN, AH: TBigInteger; const ASeed: TCryptoLibByteArray); overload;

    function ToX962Parameters: IX962Parameters; reintroduce;

    property Name: IDerObjectIdentifier read GetName;

  end;

implementation

{ TECNamedDomainParameters }

class function TECNamedDomainParameters.LookupOid(const AOid: IDerObjectIdentifier): IECNamedDomainParameters;
var
  LX9: IX9ECParameters;
begin
  if AOid = nil then
    raise EArgumentNilCryptoLibException.Create(SOidNil);

  LX9 := TECUtilities.FindECCurveByOid(AOid);

  if LX9 = nil then
    raise EArgumentCryptoLibException.Create(SOidNotValid);

  Result := TECNamedDomainParameters.Create(AOid, LX9);
end;

function TECNamedDomainParameters.GetName: IDerObjectIdentifier;
begin
  Result := FName;
end;

constructor TECNamedDomainParameters.Create(const AName: IDerObjectIdentifier; const ADp: IECDomainParameters);
begin
  inherited Create(ADp.Curve, ADp.G, ADp.N, ADp.H, ADp.Seed);
  FName := AName;
end;

constructor TECNamedDomainParameters.Create(const AName: IDerObjectIdentifier; const AX9: IX9ECParameters);
begin
  inherited Create(AX9.Curve, AX9.G, AX9.N, AX9.H, AX9.GetSeed());
  FName := AName;
end;

constructor TECNamedDomainParameters.Create(const AName: IDerObjectIdentifier; const ACurve: IECCurve; const AG: IECPoint; const AN: TBigInteger);
begin
  inherited Create(ACurve, AG, AN);
  FName := AName;
end;

constructor TECNamedDomainParameters.Create(const AName: IDerObjectIdentifier; const ACurve: IECCurve; const AG: IECPoint; const AN, AH: TBigInteger);
begin
  inherited Create(ACurve, AG, AN, AH);
  FName := AName;
end;

constructor TECNamedDomainParameters.Create(const AName: IDerObjectIdentifier; const ACurve: IECCurve; const AG: IECPoint; const AN, AH: TBigInteger; const ASeed: TCryptoLibByteArray);
begin
  inherited Create(ACurve, AG, AN, AH, ASeed);
  FName := AName;
end;

function TECNamedDomainParameters.ToX962Parameters: IX962Parameters;
begin
  Result := TX962Parameters.Create(FName);
end;

end.
