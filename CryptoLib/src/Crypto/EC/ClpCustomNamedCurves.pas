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

unit ClpCustomNamedCurves;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpHex,
  ClpGlvTypeBParameters,
  ClpIGlvTypeBEndomorphism,
  ClpSecObjectIdentifiers,
  ClpCryptoLibTypes,
  ClpBigInteger,
  ClpECCurve,
  ClpSecP256K1Curve,
  ClpISecP256K1Curve,
  ClpIECInterface,
  ClpX9ECPoint,
  ClpIX9ECPoint,
  ClpIDerObjectIdentifier,
  ClpGlvTypeBEndomorphism,
  ClpX9ECParameters,
  ClpIX9ECParameters,
  ClpX9ECParametersHolder,
  ClpIX9ECParametersHolder,
  ClpIGlvTypeBParameters;

type
  TCustomNamedCurves = class sealed(TObject)

  strict private

  class var

    FnameToCurve: TDictionary<String, IX9ECParametersHolder>;
    FnameToOid: TDictionary<String, IDerObjectIdentifier>;
    FoidToCurve: TDictionary<IDerObjectIdentifier, IX9ECParametersHolder>;
    FoidToName: TDictionary<IDerObjectIdentifier, String>;

    Fnames: TList<String>;

    class function GetNames: TCryptoLibStringArray; static; inline;

    // class procedure DefineCurve(const name: String;
    // const holder: IX9ECParametersHolder); static; inline;

    class procedure DefineCurveWithOid(const name: String;
      const oid: IDerObjectIdentifier; const holder: IX9ECParametersHolder);
      static; inline;

    // class procedure DefineCurveAlias(const name: String;
    // const oid: IDerObjectIdentifier); static; inline;

    // class function ConfigureCurve(const curve: IECCurve): IECCurve;
    // static; inline;
    class function ConfigureCurveGlv(const c: IECCurve;
      const p: IGlvTypeBParameters): IECCurve; static; inline;

    class constructor CreateSecNamedCurves();
    class destructor DestroySecNamedCurves();

  public
    class function GetByName(const name: String): IX9ECParameters;
      static; inline;
    // /**
    // * return the X9ECParameters object for the named curve represented by
    // * the passed in object identifier. Null if the curve isn't present.
    // *
    // * @param oid an object identifier representing a named curve, if present.
    // */
    class function GetByOid(const oid: IDerObjectIdentifier): IX9ECParameters;
      static; inline;
    // /**
    // * return the object identifier signified by the passed in name. Null
    // * if there is no object identifier associated with name.
    // *
    // * @return the object identifier associated with name, if present.
    // */
    class function GetOid(const name: String): IDerObjectIdentifier;
      static; inline;
    // /**
    // * return the named curve name represented by the given object identifier.
    // */
    class function GetName(const oid: IDerObjectIdentifier): String;
      static; inline;
    // /**
    // * returns an enumeration containing the name strings for curves
    // * contained in this structure.
    // */
    class property Names: TCryptoLibStringArray read GetNames;

  type

    /// <summary>
    /// secp256k1
    /// </summary>
    TSecP256k1Holder = class sealed(TX9ECParametersHolder,
      IX9ECParametersHolder)

    strict protected
      function CreateParameters(): IX9ECParameters; override;

    public
      class function Instance(): IX9ECParametersHolder; static;

    end;

  end;

implementation

{ TCustomNamedCurves }

// class procedure TCustomNamedCurves.DefineCurve(const name: String;
// const holder: IX9ECParametersHolder);
// var
// LName: string;
// begin
// LName := name;
// Fnames.Add(LName);
// LName := UpperCase(LName);
// FnameToCurve.Add(LName, holder);
// end;

class procedure TCustomNamedCurves.DefineCurveWithOid(const name: String;
  const oid: IDerObjectIdentifier; const holder: IX9ECParametersHolder);
var
  LName: string;
begin
  LName := name;
  Fnames.Add(LName);
  FoidToName.Add(oid, LName);
  FoidToCurve.Add(oid, holder);
  LName := UpperCase(LName);
  FnameToOid.Add(LName, oid);
  FnameToCurve.Add(LName, holder);
end;

// class procedure TCustomNamedCurves.DefineCurveAlias(const name: String;
// const oid: IDerObjectIdentifier);
// var
// curve: IX9ECParametersHolder;
// LName: string;
// begin
// LName := name;
// if not(FoidToCurve.TryGetValue(oid, curve)) then
// begin
// raise EInvalidOperationCryptoLibException.Create('');
// end;
// LName := UpperCase(LName);
// FnameToOid.Add(LName, oid);
// FnameToCurve.Add(LName, curve);
// end;
//
// class function TCustomNamedCurves.ConfigureCurve(const curve: IECCurve)
// : IECCurve;
// begin
// result := curve;
// end;

class function TCustomNamedCurves.ConfigureCurveGlv(const c: IECCurve;
  const p: IGlvTypeBParameters): IECCurve;
var
  glv: IGlvTypeBEndomorphism;
begin
  glv := TGlvTypeBEndomorphism.Create(c, p);
  result := c.Configure().SetEndomorphism(glv).CreateCurve();
end;

class function TCustomNamedCurves.GetByOid(const oid: IDerObjectIdentifier)
  : IX9ECParameters;
var
  holder: IX9ECParametersHolder;
begin
  if FoidToCurve.TryGetValue(oid, holder) then
  begin
    result := holder.Parameters
  end
  else
  begin
    result := Nil;
  end;
end;

class function TCustomNamedCurves.GetOid(const name: String)
  : IDerObjectIdentifier;
begin
  if not(FnameToOid.TryGetValue(UpperCase(name), result)) then
  begin
    result := Nil;
  end;
end;

class function TCustomNamedCurves.GetByName(const name: String)
  : IX9ECParameters;
var
  holder: IX9ECParametersHolder;
begin
  if FnameToCurve.TryGetValue(UpperCase(name), holder) then
  begin
    result := holder.Parameters
  end
  else
  begin
    result := Nil;
  end;
end;

class function TCustomNamedCurves.GetName
  (const oid: IDerObjectIdentifier): String;
begin
  if not(FoidToName.TryGetValue(oid, result)) then
  begin
    result := '';
  end;
end;

class function TCustomNamedCurves.GetNames: TCryptoLibStringArray;
begin
  result := Fnames.ToArray();
end;

class constructor TCustomNamedCurves.CreateSecNamedCurves;
begin
  FnameToCurve := TDictionary<String, IX9ECParametersHolder>.Create();
  FnameToOid := TDictionary<String, IDerObjectIdentifier>.Create();
  FoidToCurve := TDictionary<IDerObjectIdentifier,
    IX9ECParametersHolder>.Create();
  FoidToName := TDictionary<IDerObjectIdentifier, String>.Create();

  Fnames := TList<String>.Create();

  DefineCurveWithOid('secp256k1', TSecObjectIdentifiers.SecP256k1,
    TSecP256k1Holder.Instance);

end;

class destructor TCustomNamedCurves.DestroySecNamedCurves;
begin
  FnameToCurve.Free;
  FnameToOid.Free;
  FoidToCurve.Free;
  FoidToName.Free;
  Fnames.Free;
end;

{ TCustomNamedCurves.TSecP256k1Holder }

function TCustomNamedCurves.TSecP256k1Holder.CreateParameters: IX9ECParameters;
var
  curve: IECCurve;
  G: IX9ECPoint;
  S: TCryptoLibByteArray;
  glv: IGlvTypeBParameters;
begin
  S := Nil;
  glv := TGlvTypeBParameters.Create
    (TBigInteger.Create
    ('7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee', 16),
    TBigInteger.Create
    ('5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72', 16),
    TCryptoLibGenericArray<TBigInteger>.Create
    (TBigInteger.Create('3086d221a7d46bcde86c90e49284eb15', 16),
    TBigInteger.Create('-e4437ed6010e88286f547fa90abfe4c3', 16)),
    TCryptoLibGenericArray<TBigInteger>.Create
    (TBigInteger.Create('114ca50f7a8e2f3f657c1108d9d44cfd8', 16),
    TBigInteger.Create('3086d221a7d46bcde86c90e49284eb15', 16)),
    TBigInteger.Create('3086d221a7d46bcde86c90e49284eb153dab', 16),
    TBigInteger.Create('e4437ed6010e88286f547fa90abfe4c42212', 16), 272);
  curve := ConfigureCurveGlv(TSecP256K1Curve.Create() as ISecP256K1Curve, glv);
  G := TX9ECPoint.Create(curve,
    THex.Decode('04' +
    '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798' +
    '483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8'));
  result := TX9ECParameters.Create(curve, G, curve.Order, curve.Cofactor, S);
end;

class function TCustomNamedCurves.TSecP256k1Holder.Instance
  : IX9ECParametersHolder;
begin
  result := TSecP256k1Holder.Create();
end;

end.
