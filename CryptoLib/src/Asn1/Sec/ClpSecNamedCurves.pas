{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                    Copyright (c) 2018 Ugochukwu Mmaduekwe                       * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *        Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring        * }
{ *                        the development of this library                          * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpSecNamedCurves;

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
  TSecNamedCurves = class sealed(TObject)

  strict private

  class var
    FobjIds: TDictionary<String, IDerObjectIdentifier>;
    Fnames: TDictionary<IDerObjectIdentifier, String>;
    Fcurves: TDictionary<IDerObjectIdentifier, IX9ECParametersHolder>;

    class function GetNames: TCryptoLibStringArray; static; inline;
    class procedure DefineCurve(const name: String;
      const oid: IDerObjectIdentifier; const holder: IX9ECParametersHolder);
      static; inline;

    class function ConfigureCurve(const curve: IECCurve): IECCurve;
      static; inline;
    class function ConfigureCurveGlv(const c: IECCurve;
      const p: IGlvTypeBParameters): IECCurve; static; inline;
    class function FromHex(const Hex: String): TBigInteger; static; inline;

  public
    class function GetByName(const name: String): IX9ECParameters; static;
    // /**
    // * return the X9ECParameters object for the named curve represented by
    // * the passed in object identifier. Null if the curve isn't present.
    // *
    // * @param oid an object identifier representing a named curve, if present.
    // */
    class function GetByOid(const oid: IDerObjectIdentifier)
      : IX9ECParameters; static;
    // /**
    // * return the object identifier signified by the passed in name. Null
    // * if there is no object identifier associated with name.
    // *
    // * @return the object identifier associated with name, if present.
    // */
    class function GetOid(const name: String): IDerObjectIdentifier; static;
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
    TSecp256k1Holder = class sealed(TX9ECParametersHolder,
      IX9ECParametersHolder)

    strict protected
      function CreateParameters(): IX9ECParameters; override;

    public
      class function Instance(): IX9ECParametersHolder; static; inline;

    end;

  type

    /// <summary>
    /// secp384r1
    /// </summary>
    TSecp384r1Holder = class sealed(TX9ECParametersHolder,
      IX9ECParametersHolder)

    strict protected
      function CreateParameters(): IX9ECParameters; override;

    public
      class function Instance(): IX9ECParametersHolder; static; inline;

    end;

  type

    /// <summary>
    /// sect283k1
    /// </summary>
    TSect283k1Holder = class sealed(TX9ECParametersHolder,
      IX9ECParametersHolder)

    strict private
    const
      Fm = Int32(283);
      Fk1 = Int32(5);
      Fk2 = Int32(7);
      Fk3 = Int32(12);

    strict protected
      function CreateParameters(): IX9ECParameters; override;

    public
      class function Instance(): IX9ECParametersHolder; static; inline;

    end;

  type

    /// <summary>
    /// secp521r1
    /// </summary>
    TSecp521r1Holder = class sealed(TX9ECParametersHolder,
      IX9ECParametersHolder)

    strict protected
      function CreateParameters(): IX9ECParameters; override;

    public
      class function Instance(): IX9ECParametersHolder; static; inline;

    end;

  class constructor CreateSecNamedCurves();
  class destructor DestroySecNamedCurves();

  end;

implementation

{ TSecNamedCurves }

class procedure TSecNamedCurves.DefineCurve(const name: String;
  const oid: IDerObjectIdentifier; const holder: IX9ECParametersHolder);
begin
  FobjIds.Add(UpperCase(name), oid);
  Fnames.Add(oid, name);
  Fcurves.Add(oid, holder);
end;

class function TSecNamedCurves.ConfigureCurve(const curve: IECCurve): IECCurve;
begin
  result := curve;
end;

class function TSecNamedCurves.ConfigureCurveGlv(const c: IECCurve;
  const p: IGlvTypeBParameters): IECCurve;
var
  glv: IGlvTypeBEndomorphism;
begin
  glv := TGlvTypeBEndomorphism.Create(c, p);
  result := c.Configure().SetEndomorphism(glv).CreateCurve();
end;

class constructor TSecNamedCurves.CreateSecNamedCurves;
begin
  FobjIds := TDictionary<String, IDerObjectIdentifier>.Create();
  Fnames := TDictionary<IDerObjectIdentifier, String>.Create();
  Fcurves := TDictionary<IDerObjectIdentifier, IX9ECParametersHolder>.Create();

  TSecObjectIdentifiers.Boot;
  DefineCurve('secp256k1', TSecObjectIdentifiers.SecP256k1,
    TSecp256k1Holder.Instance);
  DefineCurve('secp384r1', TSecObjectIdentifiers.SecP384r1,
    TSecp384r1Holder.Instance);
  DefineCurve('sect283k1', TSecObjectIdentifiers.SecT283k1,
    TSect283k1Holder.Instance);
  DefineCurve('secp521r1', TSecObjectIdentifiers.SecP521r1,
    TSecp521r1Holder.Instance);
end;

class destructor TSecNamedCurves.DestroySecNamedCurves;
begin
  FobjIds.Free;
  Fnames.Free;
  Fcurves.Free;
end;

class function TSecNamedCurves.FromHex(const Hex: String): TBigInteger;
begin
  result := TBigInteger.Create(1, THex.Decode(Hex));
end;

class function TSecNamedCurves.GetByOid(const oid: IDerObjectIdentifier)
  : IX9ECParameters;
var
  holder: IX9ECParametersHolder;
begin
  if Fcurves.TryGetValue(oid, holder) then
  begin
    result := holder.Parameters
  end
  else
  begin
    result := Nil;
  end;
end;

class function TSecNamedCurves.GetOid(const name: String): IDerObjectIdentifier;
begin
  if not(FobjIds.TryGetValue(UpperCase(name), result)) then
  begin
    result := Nil;
  end;
end;

class function TSecNamedCurves.GetByName(const name: String): IX9ECParameters;
var
  oid: IDerObjectIdentifier;
begin
  oid := GetOid(name);
  if oid = Nil then
  begin
    result := Nil;
  end
  else
  begin
    result := GetByOid(oid);
  end;

end;

class function TSecNamedCurves.GetName(const oid: IDerObjectIdentifier): String;
begin
  if not(Fnames.TryGetValue(oid, result)) then
  begin
    result := '';
  end;
end;

class function TSecNamedCurves.GetNames: TCryptoLibStringArray;
begin
  result := Fnames.Values.ToArray();
end;

{ TSecNamedCurves.TSecp256k1Holder }

function TSecNamedCurves.TSecp256k1Holder.CreateParameters: IX9ECParameters;
var
  p, a, b, n, h: TBigInteger;
  curve: IECCurve;
  G: IX9ECPoint;
  S: TCryptoLibByteArray;
  glv: IGlvTypeBParameters;
begin
  // p := 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
  p := FromHex
    ('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F');
  a := TBigInteger.Zero;
  b := TBigInteger.ValueOf(7);
  S := Nil;
  n := FromHex
    ('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
  h := TBigInteger.One;

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

  curve := ConfigureCurveGlv(TFpCurve.Create(p, a, b, n, h) as IFpCurve, glv);
  G := TX9ECPoint.Create(curve,
    THex.Decode('04' +
    '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798' +
    '483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8'));

  result := TX9ECParameters.Create(curve, G, n, h, S);
end;

class function TSecNamedCurves.TSecp256k1Holder.Instance: IX9ECParametersHolder;
begin
  result := TSecp256k1Holder.Create();
end;

{ TSecNamedCurves.TSecp384r1Holder }

function TSecNamedCurves.TSecp384r1Holder.CreateParameters: IX9ECParameters;
var
  p, a, b, n, h: TBigInteger;
  curve: IECCurve;
  G: IX9ECPoint;
  S: TCryptoLibByteArray;
begin
  // p := 2^384 - 2^128 - 2^96 + 2^32 - 1
  p := FromHex
    ('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF');
  a := FromHex
    ('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC');
  b := FromHex
    ('B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF');
  S := THex.Decode('A335926AA319A27A1D00896A6773A4827ACDAC73');
  n := FromHex
    ('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973');
  h := TBigInteger.One;

  curve := ConfigureCurve(TFpCurve.Create(p, a, b, n, h) as IFpCurve);
  G := TX9ECPoint.Create(curve,
    THex.Decode('04' +
    'AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7'
    + '3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F')
    );

  result := TX9ECParameters.Create(curve, G, n, h, S);
end;

class function TSecNamedCurves.TSecp384r1Holder.Instance: IX9ECParametersHolder;
begin
  result := TSecp384r1Holder.Create();
end;

{ TSecNamedCurves.TSect283k1Holder }

function TSecNamedCurves.TSect283k1Holder.CreateParameters: IX9ECParameters;
var
  a, b, n, h: TBigInteger;
  S: TCryptoLibByteArray;
  curve: IECCurve;
  G: IX9ECPoint;
begin
  a := TBigInteger.Zero;
  b := TBigInteger.One;
  S := Nil;
  n := FromHex
    ('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE9AE2ED07577265DFF7F94451E061E163C61');
  h := TBigInteger.ValueOf(4);

  curve := TF2mCurve.Create(Fm, Fk1, Fk2, Fk3, a, b, n, h);
  G := TX9ECPoint.Create(curve,
    THex.Decode('04' +
    '0503213F78CA44883F1A3B8162F188E553CD265F23C1567A16876913B0C2AC2458492836' +
    '01CCDA380F1C9E318D90F95D07E5426FE87E45C0E8184698E45962364E34116177DD2259')
    );

  result := TX9ECParameters.Create(curve, G, n, h, S);
end;

class function TSecNamedCurves.TSect283k1Holder.Instance: IX9ECParametersHolder;
begin
  result := TSect283k1Holder.Create();
end;

function TSecNamedCurves.TSecp521r1Holder.CreateParameters: IX9ECParameters;
var
  p, a, b, n, h: TBigInteger;
  curve: IECCurve;
  G: IX9ECPoint;
  S: TCryptoLibByteArray;
begin
  // p := 2^521 - 1
  p := FromHex
    ('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF');
  a := FromHex
    ('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC');
  b := FromHex
    ('0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00');
  S := THex.Decode('D09E8800291CB85396CC6717393284AAA0DA64BA');
  n := FromHex
    ('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409');
  h := TBigInteger.One;

  curve := ConfigureCurve(TFpCurve.Create(p, a, b, n, h) as IFpCurve);
  G := TX9ECPoint.Create(curve,
    THex.Decode('04' +
    '00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66'
    + '011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650')
    );

  result := TX9ECParameters.Create(curve, G, n, h, S);
end;

class function TSecNamedCurves.TSecp521r1Holder.Instance: IX9ECParametersHolder;
begin
  result := TSecp521r1Holder.Create();
end;

end.
