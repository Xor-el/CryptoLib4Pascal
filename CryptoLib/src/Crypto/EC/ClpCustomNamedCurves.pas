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
  ClpAsn1Comparers,
  ClpCollectionUtilities,
  ClpCryptoLibComparers,
  ClpEncoders,
  ClpGlvTypeBParameters,
  ClpIGlvTypeBEndomorphism,
  ClpSecObjectIdentifiers,
  ClpCryptoLibTypes,
  ClpBigInteger,
  ClpECCurve,
  ClpSecP256K1Custom,
  ClpISecP256K1Custom,
  ClpSecP256R1Custom,
  ClpISecP256R1Custom,
  ClpSecP384R1Custom,
  ClpISecP384R1Custom,
  ClpSecP521R1Custom,
  ClpISecP521R1Custom,
  ClpSecT283K1Custom,
  ClpISecT283K1Custom,
  ClpIECCommon,
  ClpIAsn1Objects,
  ClpWnafUtilities,
  ClpScalarSplitParameters,
  ClpIScalarSplitParameters,
  ClpGlvTypeBEndomorphism,
  ClpX9ECAsn1Objects,
  ClpIX9ECAsn1Objects,
  ClpX9ECParametersHolder,
  ClpIX9ECParametersHolder,
  ClpIGlvTypeBParameters;

type
  /// <summary>Elliptic curve registry for various customized curve implementations (Custom/Sec subset).</summary>
  TCustomNamedCurves = class sealed(TObject)

  strict private
    class var
      FObjIds: TDictionary<String, IDerObjectIdentifier>;
      FCurves: TDictionary<IDerObjectIdentifier, IX9ECParametersHolder>;
      FNames: TDictionary<IDerObjectIdentifier, String>;

    class function GetNames: TCryptoLibStringArray; static; inline;
    class procedure DefineCurve(const AName: String;
      const AOid: IDerObjectIdentifier; const AHolder: IX9ECParametersHolder);
      static; inline;
    class procedure DefineCurveAlias(const AName: String;
      const AOid: IDerObjectIdentifier); static; inline;
    class function ConfigureCurve(const ACurve: IECCurve): IECCurve;
      static; inline;
    class function ConfigureCurveGlv(const AC: IECCurve;
      const AP: IGlvTypeBParameters): IECCurve; static; inline;
    class function ConfigureBasepoint(const ACurve: IECCurve;
      const AEncoding: String): IX9ECPoint; static;
    class procedure Boot; static;
    class constructor CreateCustomNamedCurves;
    class destructor DestroyCustomNamedCurves;

  public
    class function GetByName(const AName: String): IX9ECParameters; static; inline;
    class function GetByNameLazy(const AName: String): IX9ECParametersHolder; static; inline;
    class function GetByOid(const AOid: IDerObjectIdentifier): IX9ECParameters; static; inline;
    class function GetByOidLazy(const AOid: IDerObjectIdentifier): IX9ECParametersHolder; static; inline;
    class function GetOid(const AName: String): IDerObjectIdentifier; static; inline;
    class function GetName(const AOid: IDerObjectIdentifier): String; static; inline;
    class property Names: TCryptoLibStringArray read GetNames;

  type
    TSecP256K1Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
      strict protected
        function CreateParameters: IX9ECParameters; override;
      public
        class function Instance: IX9ECParametersHolder; static;
    end;
    TSecP256R1Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
      strict protected
        function CreateParameters: IX9ECParameters; override;
      public
        class function Instance: IX9ECParametersHolder; static;
    end;
    TSecP384R1Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
      strict protected
        function CreateParameters: IX9ECParameters; override;
      public
        class function Instance: IX9ECParametersHolder; static;
    end;
    TSecP521R1Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
      strict protected
        function CreateParameters: IX9ECParameters; override;
      public
        class function Instance: IX9ECParametersHolder; static;
    end;
    TSecT283K1Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
      strict protected
        function CreateParameters: IX9ECParameters; override;
      public
        class function Instance: IX9ECParametersHolder; static;
    end;

  end;

implementation

{ TCustomNamedCurves }

class function TCustomNamedCurves.ConfigureBasepoint(const ACurve: IECCurve;
  const AEncoding: String): IX9ECPoint;
begin
  Result := TX9ECPoint.Create(ACurve, THex.Decode(AEncoding));
  TWnafUtilities.ConfigureBasepoint(Result.Point);
end;

class procedure TCustomNamedCurves.DefineCurve(const AName: String;
  const AOid: IDerObjectIdentifier; const AHolder: IX9ECParametersHolder);
begin
  FObjIds.Add(AName, AOid);
  FNames.Add(AOid, AName);
  FCurves.Add(AOid, AHolder);
end;

class procedure TCustomNamedCurves.DefineCurveAlias(const AName: String;
  const AOid: IDerObjectIdentifier);
begin
  if not FCurves.ContainsKey(AOid) then
    raise EInvalidOperationCryptoLibException.Create('');
  FObjIds.Add(AName, AOid);
end;

class function TCustomNamedCurves.ConfigureCurve(const ACurve: IECCurve): IECCurve;
begin
  Result := ACurve;
end;

class function TCustomNamedCurves.ConfigureCurveGlv(const AC: IECCurve;
  const AP: IGlvTypeBParameters): IECCurve;
var
  LGlv: IGlvTypeBEndomorphism;
begin
  LGlv := TGlvTypeBEndomorphism.Create(AC, AP);
  Result := AC.Configure().SetEndomorphism(LGlv).CreateCurve();
end;

class function TCustomNamedCurves.GetByOid(const AOid: IDerObjectIdentifier): IX9ECParameters;
var
  LHolder: IX9ECParametersHolder;
begin
  LHolder := GetByOidLazy(AOid);
  if LHolder <> nil then
    Result := LHolder.Parameters
  else
    Result := nil;
end;

class function TCustomNamedCurves.GetByNameLazy(const AName: String): IX9ECParametersHolder;
var
  LOid: IDerObjectIdentifier;
begin
  LOid := GetOid(AName);
  if LOid = nil then
    Result := nil
  else
    Result := GetByOidLazy(LOid);
end;

class function TCustomNamedCurves.GetByOidLazy(const AOid: IDerObjectIdentifier): IX9ECParametersHolder;
begin
  Result := nil;
  FCurves.TryGetValue(AOid, Result);
end;

class function TCustomNamedCurves.GetOid(const AName: String): IDerObjectIdentifier;
begin
  if not FObjIds.TryGetValue(UpperCase(AName), Result) then
    Result := nil;
end;

class function TCustomNamedCurves.GetByName(const AName: String): IX9ECParameters;
var
  LOid: IDerObjectIdentifier;
begin
  LOid := GetOid(AName);
  if LOid = nil then
    Result := nil
  else
    Result := GetByOid(LOid);
end;

class function TCustomNamedCurves.GetName(const AOid: IDerObjectIdentifier): String;
begin
  if not FNames.TryGetValue(AOid, Result) then
    Result := '';
end;

class function TCustomNamedCurves.GetNames: TCryptoLibStringArray;
begin
  Result := TCollectionUtilities.Keys<String, IDerObjectIdentifier>(FObjIds);
end;

class procedure TCustomNamedCurves.Boot;
begin
  FObjIds := TDictionary<String, IDerObjectIdentifier>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FCurves := TDictionary<IDerObjectIdentifier, IX9ECParametersHolder>.Create(TAsn1Comparers.OidEqualityComparer);
  FNames := TDictionary<IDerObjectIdentifier, String>.Create(TAsn1Comparers.OidEqualityComparer);

  DefineCurve('secp256k1', TSecObjectIdentifiers.SecP256k1, TSecP256K1Holder.Instance);
  DefineCurve('secp256r1', TSecObjectIdentifiers.SecP256r1, TSecP256R1Holder.Instance);
  DefineCurve('secp384r1', TSecObjectIdentifiers.SecP384r1, TSecP384R1Holder.Instance);
  DefineCurve('secp521r1', TSecObjectIdentifiers.SecP521r1, TSecP521R1Holder.Instance);
  DefineCurve('sect283k1', TSecObjectIdentifiers.SecT283k1, TSecT283K1Holder.Instance);

  DefineCurveAlias('K-283', TSecObjectIdentifiers.SecT283k1);
  DefineCurveAlias('P-256', TSecObjectIdentifiers.SecP256r1);
  DefineCurveAlias('P-384', TSecObjectIdentifiers.SecP384r1);
  DefineCurveAlias('P-521', TSecObjectIdentifiers.SecP521r1);
end;

class constructor TCustomNamedCurves.CreateCustomNamedCurves;
begin
  Boot;
end;

class destructor TCustomNamedCurves.DestroyCustomNamedCurves;
begin
  FObjIds.Free;
  FCurves.Free;
  FNames.Free;
end;

{ TCustomNamedCurves.TSecP256K1Holder }

function TCustomNamedCurves.TSecP256K1Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LGlv: IGlvTypeBParameters;
begin
  LGlv := TGlvTypeBParameters.Create(
    TBigInteger.Create('7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee', 16),
    TBigInteger.Create('5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72', 16),
    TScalarSplitParameters.Create(
      TCryptoLibGenericArray<TBigInteger>.Create(
        TBigInteger.Create('3086d221a7d46bcde86c90e49284eb15', 16),
        TBigInteger.Create('-e4437ed6010e88286f547fa90abfe4c3', 16)),
      TCryptoLibGenericArray<TBigInteger>.Create(
        TBigInteger.Create('114ca50f7a8e2f3f657c1108d9d44cfd8', 16),
        TBigInteger.Create('3086d221a7d46bcde86c90e49284eb15', 16)),
      TBigInteger.Create('3086d221a7d46bcde86c90e49284eb153dab', 16),
      TBigInteger.Create('e4437ed6010e88286f547fa90abfe4c42212', 16), 272)
      as IScalarSplitParameters);
  LBaseCurve := TSecP256K1Curve.Create();
  LCurve := TCustomNamedCurves.ConfigureCurveGlv(LBaseCurve, LGlv);
  LG := TCustomNamedCurves.ConfigureBasepoint(LCurve,
    '0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor);
end;

class function TCustomNamedCurves.TSecP256K1Holder.Instance: IX9ECParametersHolder;
begin
  Result := TSecP256K1Holder.Create;
end;

{ TCustomNamedCurves.TSecP256R1Holder }

function TCustomNamedCurves.TSecP256R1Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LS: TCryptoLibByteArray;
begin
  LS := THex.Decode('C49D360886E704936A6678E1139D26B7819F7E90');
  LBaseCurve := TSecP256R1Curve.Create();
  LCurve := TCustomNamedCurves.ConfigureCurve(LBaseCurve);
  LG := TCustomNamedCurves.ConfigureBasepoint(LCurve,
    '046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor, LS);
end;

class function TCustomNamedCurves.TSecP256R1Holder.Instance: IX9ECParametersHolder;
begin
  Result := TSecP256R1Holder.Create;
end;

{ TCustomNamedCurves.TSecP384R1Holder }

function TCustomNamedCurves.TSecP384R1Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LS: TCryptoLibByteArray;
begin
  LS := THex.Decode('A335926AA319A27A1D00896A6773A4827ACDAC73');
  LBaseCurve := TSecP384R1Curve.Create();
  LCurve := TCustomNamedCurves.ConfigureCurve(LBaseCurve);
  LG := TCustomNamedCurves.ConfigureBasepoint(LCurve,
    '04' + 'AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7'
    + '3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor, LS);
end;

class function TCustomNamedCurves.TSecP384R1Holder.Instance: IX9ECParametersHolder;
begin
  Result := TSecP384R1Holder.Create;
end;

{ TCustomNamedCurves.TSecP521R1Holder }

function TCustomNamedCurves.TSecP521R1Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LS: TCryptoLibByteArray;
begin
  LS := THex.Decode('D09E8800291CB85396CC6717393284AAA0DA64BA');
  LBaseCurve := TSecP521R1Curve.Create();
  LCurve := TCustomNamedCurves.ConfigureCurve(LBaseCurve);
  LG := TCustomNamedCurves.ConfigureBasepoint(LCurve,
    '04' + '00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66'
    + '011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor, LS);
end;

class function TCustomNamedCurves.TSecP521R1Holder.Instance: IX9ECParametersHolder;
begin
  Result := TSecP521R1Holder.Create;
end;

{ TCustomNamedCurves.TSecT283K1Holder }

function TCustomNamedCurves.TSecT283K1Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
begin
  LBaseCurve := TSecT283K1Curve.Create();
  LCurve := TCustomNamedCurves.ConfigureCurve(LBaseCurve);
  LG := TCustomNamedCurves.ConfigureBasepoint(LCurve,
    '04' + '0503213F78CA44883F1A3B8162F188E553CD265F23C1567A16876913B0C2AC2458492836'
    + '01CCDA380F1C9E318D90F95D07E5426FE87E45C0E8184698E45962364E34116177DD2259');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor);
end;

class function TCustomNamedCurves.TSecT283K1Holder.Instance: IX9ECParametersHolder;
begin
  Result := TSecT283K1Holder.Create;
end;

end.
