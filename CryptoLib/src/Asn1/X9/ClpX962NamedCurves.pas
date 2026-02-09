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

unit ClpX962NamedCurves;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpAsn1Comparers,
  ClpCryptoLibComparers,
  ClpCollectionUtilities,
  ClpEncoders,
  ClpX9ObjectIdentifiers,
  ClpCryptoLibTypes,
  ClpBigInteger,
  ClpECCurve,
  ClpWnafUtilities,
  ClpIECCommon,
  ClpIAsn1Objects,
  ClpX9ECAsn1Objects,
  ClpIX9ECAsn1Objects,
  ClpX9ECParametersHolder,
  ClpIX9ECParametersHolder;

type
  /// <summary>Elliptic curve registry for the curves defined in X.962 EC-DSA.</summary>
  TX962NamedCurves = class sealed(TObject)

  strict private
    class var
      FObjIds: TDictionary<String, IDerObjectIdentifier>;
      FCurves: TDictionary<IDerObjectIdentifier, IX9ECParametersHolder>;
      FNames: TDictionary<IDerObjectIdentifier, String>;

    class function GetNames: TCryptoLibStringArray; static; inline;
    class function FromHex(const AHex: String): TBigInteger; static;
    class function ConfigureBasepoint(const ACurve: IECCurve;
      const AEncoding: String): IX9ECPoint; static;
    class function ConfigureCurve(const ACurve: IECCurve): IECCurve;
      static; inline;
    class procedure DefineCurve(const AName: String;
      const AOid: IDerObjectIdentifier;
      const AHolder: IX9ECParametersHolder); static;

    class procedure Boot; static;
    class constructor CreateX962NamedCurves;
    class destructor DestroyX962NamedCurves;

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

type
  TPrime192v1Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  TPrime192v2Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  TPrime192v3Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  TPrime239v1Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  TPrime239v2Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  TPrime239v3Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  TPrime256v1Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  TC2pnb163v1Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  TC2pnb163v2Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  TC2pnb163v3Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  TC2pnb176w1Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  TC2tnb191v1Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  TC2tnb191v2Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  TC2tnb191v3Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  TC2pnb208w1Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  TC2tnb239v1Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  TC2tnb239v2Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  TC2tnb239v3Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  TC2pnb272w1Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  TC2pnb304w1Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  TC2tnb359v1Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  TC2pnb368w1Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  TC2tnb431r1Holder = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  end;

implementation

{ TX962NamedCurves }

class function TX962NamedCurves.FromHex(const AHex: String): TBigInteger;
begin
  Result := TBigInteger.Create(1, THex.Decode(AHex));
end;

class function TX962NamedCurves.ConfigureBasepoint(const ACurve: IECCurve;
  const AEncoding: String): IX9ECPoint;
begin
  Result := TX9ECPoint.Create(ACurve, THex.Decode(AEncoding));
  TWnafUtilities.ConfigureBasepoint(Result.Point);
end;

class function TX962NamedCurves.ConfigureCurve(const ACurve: IECCurve): IECCurve;
begin
  Result := ACurve;
end;

class procedure TX962NamedCurves.DefineCurve(const AName: String;
  const AOid: IDerObjectIdentifier;
  const AHolder: IX9ECParametersHolder);
var
  LName: String;
begin
  LName := AName;
  FNames.Add(AOid, LName);
  FCurves.Add(AOid, AHolder);
  FObjIds.Add(UpperCase(LName), AOid);
end;

class procedure TX962NamedCurves.Boot;
begin
  FObjIds := TDictionary<String, IDerObjectIdentifier>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FCurves := TDictionary<IDerObjectIdentifier, IX9ECParametersHolder>.Create(TAsn1Comparers.OidEqualityComparer);
  FNames := TDictionary<IDerObjectIdentifier, String>.Create(TAsn1Comparers.OidEqualityComparer);

  DefineCurve('prime192v1', TX9ObjectIdentifiers.Prime192v1, TPrime192v1Holder.Instance);
  DefineCurve('prime192v2', TX9ObjectIdentifiers.Prime192v2, TPrime192v2Holder.Instance);
  DefineCurve('prime192v3', TX9ObjectIdentifiers.Prime192v3, TPrime192v3Holder.Instance);
  DefineCurve('prime239v1', TX9ObjectIdentifiers.Prime239v1, TPrime239v1Holder.Instance);
  DefineCurve('prime239v2', TX9ObjectIdentifiers.Prime239v2, TPrime239v2Holder.Instance);
  DefineCurve('prime239v3', TX9ObjectIdentifiers.Prime239v3, TPrime239v3Holder.Instance);
  DefineCurve('prime256v1', TX9ObjectIdentifiers.Prime256v1, TPrime256v1Holder.Instance);
  DefineCurve('c2pnb163v1', TX9ObjectIdentifiers.C2Pnb163v1, TC2pnb163v1Holder.Instance);
  DefineCurve('c2pnb163v2', TX9ObjectIdentifiers.C2Pnb163v2, TC2pnb163v2Holder.Instance);
  DefineCurve('c2pnb163v3', TX9ObjectIdentifiers.C2Pnb163v3, TC2pnb163v3Holder.Instance);
  DefineCurve('c2pnb176w1', TX9ObjectIdentifiers.C2Pnb176w1, TC2pnb176w1Holder.Instance);
  DefineCurve('c2tnb191v1', TX9ObjectIdentifiers.C2Tnb191v1, TC2tnb191v1Holder.Instance);
  DefineCurve('c2tnb191v2', TX9ObjectIdentifiers.C2Tnb191v2, TC2tnb191v2Holder.Instance);
  DefineCurve('c2tnb191v3', TX9ObjectIdentifiers.C2Tnb191v3, TC2tnb191v3Holder.Instance);
  DefineCurve('c2pnb208w1', TX9ObjectIdentifiers.C2Pnb208w1, TC2pnb208w1Holder.Instance);
  DefineCurve('c2tnb239v1', TX9ObjectIdentifiers.C2Tnb239v1, TC2tnb239v1Holder.Instance);
  DefineCurve('c2tnb239v2', TX9ObjectIdentifiers.C2Tnb239v2, TC2tnb239v2Holder.Instance);
  DefineCurve('c2tnb239v3', TX9ObjectIdentifiers.C2Tnb239v3, TC2tnb239v3Holder.Instance);
  DefineCurve('c2pnb272w1', TX9ObjectIdentifiers.C2Pnb272w1, TC2pnb272w1Holder.Instance);
  DefineCurve('c2pnb304w1', TX9ObjectIdentifiers.C2Pnb304w1, TC2pnb304w1Holder.Instance);
  DefineCurve('c2tnb359v1', TX9ObjectIdentifiers.C2Tnb359v1, TC2tnb359v1Holder.Instance);
  DefineCurve('c2pnb368w1', TX9ObjectIdentifiers.C2Pnb368w1, TC2pnb368w1Holder.Instance);
  DefineCurve('c2tnb431r1', TX9ObjectIdentifiers.C2Tnb431r1, TC2tnb431r1Holder.Instance);
end;

class constructor TX962NamedCurves.CreateX962NamedCurves;
begin
  Boot;
end;

class destructor TX962NamedCurves.DestroyX962NamedCurves;
begin
  FObjIds.Free;
  FCurves.Free;
  FNames.Free;
end;

class function TX962NamedCurves.GetNames: TCryptoLibStringArray;
begin
  Result := TCollectionUtilities.Keys<String, IDerObjectIdentifier>(FObjIds);
end;

class function TX962NamedCurves.GetByName(const AName: String): IX9ECParameters;
var
  LOid: IDerObjectIdentifier;
begin
  LOid := GetOid(AName);
  if LOid = nil then
    Result := nil
  else
    Result := GetByOid(LOid);
end;

class function TX962NamedCurves.GetByNameLazy(const AName: String): IX9ECParametersHolder;
var
  LOid: IDerObjectIdentifier;
begin
  LOid := GetOid(AName);
  if LOid = nil then
    Result := nil
  else
    Result := GetByOidLazy(LOid);
end;

class function TX962NamedCurves.GetByOid(const AOid: IDerObjectIdentifier): IX9ECParameters;
var
  LHolder: IX9ECParametersHolder;
begin
  LHolder := GetByOidLazy(AOid);
  if LHolder = nil then
    Result := nil
  else
    Result := LHolder.Parameters;
end;

class function TX962NamedCurves.GetByOidLazy(const AOid: IDerObjectIdentifier): IX9ECParametersHolder;
begin
  Result := TCollectionUtilities.GetValueOrNull<IDerObjectIdentifier, IX9ECParametersHolder>(FCurves, AOid);
end;

class function TX962NamedCurves.GetName(const AOid: IDerObjectIdentifier): String;
begin
  if not FNames.TryGetValue(AOid, Result) then
    Result := '';
end;

class function TX962NamedCurves.GetOid(const AName: String): IDerObjectIdentifier;
begin
  if not FObjIds.TryGetValue(UpperCase(AName), Result) then
    Result := nil;
end;

{ TX962NamedCurves.TPrime192v1Holder }

function TX962NamedCurves.TPrime192v1Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LN: TBigInteger;
  LS: TCryptoLibByteArray;
begin
  LN := TX962NamedCurves.FromHex('ffffffffffffffffffffffff99def836146bc9b1b4d22831');
  LBaseCurve := TFpCurve.Create(
    TX962NamedCurves.FromHex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF'),
    TX962NamedCurves.FromHex('fffffffffffffffffffffffffffffffefffffffffffffffc'),
    TX962NamedCurves.FromHex('64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1'),
    LN, TBigInteger.One, True);
  LCurve := TX962NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TX962NamedCurves.ConfigureBasepoint(LCurve, '03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012');
  LS := THex.Decode('3045AE6FC8422f64ED579528D38120EAE12196D5');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor, LS);
end;

class function TX962NamedCurves.TPrime192v1Holder.Instance: IX9ECParametersHolder;
begin
  Result := TPrime192v1Holder.Create();
end;

{ TX962NamedCurves.TPrime192v2Holder }

function TX962NamedCurves.TPrime192v2Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LN: TBigInteger;
  LS: TCryptoLibByteArray;
begin
  LN := TX962NamedCurves.FromHex('fffffffffffffffffffffffe5fb1a724dc80418648d8dd31');
  LBaseCurve := TFpCurve.Create(
    TX962NamedCurves.FromHex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF'),
    TX962NamedCurves.FromHex('fffffffffffffffffffffffffffffffefffffffffffffffc'),
    TX962NamedCurves.FromHex('cc22d6dfb95c6b25e49c0d6364a4e5980c393aa21668d953'),
    LN, TBigInteger.One, True);
  LCurve := TX962NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TX962NamedCurves.ConfigureBasepoint(LCurve, '03eea2bae7e1497842f2de7769cfe9c989c072ad696f48034a');
  LS := THex.Decode('31a92ee2029fd10d901b113e990710f0d21ac6b6');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor, LS);
end;

class function TX962NamedCurves.TPrime192v2Holder.Instance: IX9ECParametersHolder;
begin
  Result := TPrime192v2Holder.Create();
end;

{ TX962NamedCurves.TPrime192v3Holder }

function TX962NamedCurves.TPrime192v3Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LN: TBigInteger;
  LS: TCryptoLibByteArray;
begin
  LN := TX962NamedCurves.FromHex('ffffffffffffffffffffffff7a62d031c83f4294f640ec13');
  LBaseCurve := TFpCurve.Create(
    TX962NamedCurves.FromHex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF'),
    TX962NamedCurves.FromHex('fffffffffffffffffffffffffffffffefffffffffffffffc'),
    TX962NamedCurves.FromHex('22123dc2395a05caa7423daeccc94760a7d462256bd56916'),
    LN, TBigInteger.One, True);
  LCurve := TX962NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TX962NamedCurves.ConfigureBasepoint(LCurve, '027d29778100c65a1da1783716588dce2b8b4aee8e228f1896');
  LS := THex.Decode('c469684435deb378c4b65ca9591e2a5763059a2e');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor, LS);
end;

class function TX962NamedCurves.TPrime192v3Holder.Instance: IX9ECParametersHolder;
begin
  Result := TPrime192v3Holder.Create();
end;

{ TX962NamedCurves.TPrime239v1Holder }

function TX962NamedCurves.TPrime239v1Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LQ: TBigInteger;
  LG: IX9ECPoint;
  LN: TBigInteger;
  LS: TCryptoLibByteArray;
begin
  LQ := TBigInteger.Create('883423532389192164791648750360308885314476597252960362792450860609699839', 10);
  LN := TX962NamedCurves.FromHex('7fffffffffffffffffffffff7fffff9e5e9a9f5d9071fbd1522688909d0b');
  LBaseCurve := TFpCurve.Create(LQ,
    TX962NamedCurves.FromHex('7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc'),
    TX962NamedCurves.FromHex('6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a'),
    LN, TBigInteger.One, True);
  LCurve := TX962NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TX962NamedCurves.ConfigureBasepoint(LCurve, '020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf');
  LS := THex.Decode('e43bb460f0b80cc0c0b075798e948060f8321b7d');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor, LS);
end;

class function TX962NamedCurves.TPrime239v1Holder.Instance: IX9ECParametersHolder;
begin
  Result := TPrime239v1Holder.Create();
end;

{ TX962NamedCurves.TPrime239v2Holder }

function TX962NamedCurves.TPrime239v2Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LQ: TBigInteger;
  LG: IX9ECPoint;
  LN: TBigInteger;
  LS: TCryptoLibByteArray;
begin
  LQ := TBigInteger.Create('883423532389192164791648750360308885314476597252960362792450860609699839', 10);
  LN := TX962NamedCurves.FromHex('7fffffffffffffffffffffff800000cfa7e8594377d414c03821bc582063');
  LBaseCurve := TFpCurve.Create(LQ,
    TX962NamedCurves.FromHex('7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc'),
    TX962NamedCurves.FromHex('617fab6832576cbbfed50d99f0249c3fee58b94ba0038c7ae84c8c832f2c'),
    LN, TBigInteger.One, True);
  LCurve := TX962NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TX962NamedCurves.ConfigureBasepoint(LCurve, '0238af09d98727705120c921bb5e9e26296a3cdcf2f35757a0eafd87b830e7');
  LS := THex.Decode('e8b4011604095303ca3b8099982be09fcb9ae616');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor, LS);
end;

class function TX962NamedCurves.TPrime239v2Holder.Instance: IX9ECParametersHolder;
begin
  Result := TPrime239v2Holder.Create();
end;

{ TX962NamedCurves.TPrime239v3Holder }

function TX962NamedCurves.TPrime239v3Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LQ: TBigInteger;
  LG: IX9ECPoint;
  LN: TBigInteger;
  LS: TCryptoLibByteArray;
begin
  LQ := TBigInteger.Create('883423532389192164791648750360308885314476597252960362792450860609699839', 10);
  LN := TX962NamedCurves.FromHex('7fffffffffffffffffffffff7fffff975deb41b3a6057c3c432146526551');
  LBaseCurve := TFpCurve.Create(LQ,
    TX962NamedCurves.FromHex('7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc'),
    TX962NamedCurves.FromHex('255705fa2a306654b1f4cb03d6a750a30c250102d4988717d9ba15ab6d3e'),
    LN, TBigInteger.One, True);
  LCurve := TX962NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TX962NamedCurves.ConfigureBasepoint(LCurve, '036768ae8e18bb92cfcf005c949aa2c6d94853d0e660bbf854b1c9505fe95a');
  LS := THex.Decode('7d7374168ffe3471b60a857686a19475d3bfa2ff');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor, LS);
end;

class function TX962NamedCurves.TPrime239v3Holder.Instance: IX9ECParametersHolder;
begin
  Result := TPrime239v3Holder.Create();
end;

{ TX962NamedCurves.TPrime256v1Holder }

function TX962NamedCurves.TPrime256v1Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LQ: TBigInteger;
  LG: IX9ECPoint;
  LN: TBigInteger;
  LS: TCryptoLibByteArray;
begin
  LQ := TBigInteger.Create('115792089210356248762697446949407573530086143415290314195533631308867097853951', 10);
  LN := TX962NamedCurves.FromHex('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
  LBaseCurve := TFpCurve.Create(LQ,
    TX962NamedCurves.FromHex('ffffffff00000001000000000000000000000000fffffffffffffffffffffffc'),
    TX962NamedCurves.FromHex('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b'),
    LN, TBigInteger.One, True);
  LCurve := TX962NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TX962NamedCurves.ConfigureBasepoint(LCurve, '036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296');
  LS := THex.Decode('c49d360886e704936a6678e1139d26b7819f7e90');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor, LS);
end;

class function TX962NamedCurves.TPrime256v1Holder.Instance: IX9ECParametersHolder;
begin
  Result := TPrime256v1Holder.Create();
end;

{ TX962NamedCurves.TC2pnb163v1Holder }

function TX962NamedCurves.TC2pnb163v1Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LN: TBigInteger;
  LS: TCryptoLibByteArray;
begin
  LN := TX962NamedCurves.FromHex('0400000000000000000001E60FC8821CC74DAEAFC1');
  LBaseCurve := TF2mCurve.Create(163, 1, 2, 8,
    TX962NamedCurves.FromHex('072546B5435234A422E0789675F432C89435DE5242'),
    TX962NamedCurves.FromHex('00C9517D06D5240D3CFF38C74B20B6CD4D6F9DD4D9'),
    LN, TBigInteger.Two);
  LCurve := TX962NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TX962NamedCurves.ConfigureBasepoint(LCurve, '0307AF69989546103D79329FCC3D74880F33BBE803CB');
  LS := THex.Decode('D2C0FB15760860DEF1EEF4D696E6768756151754');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor, LS);
end;

class function TX962NamedCurves.TC2pnb163v1Holder.Instance: IX9ECParametersHolder;
begin
  Result := TC2pnb163v1Holder.Create();
end;

{ TX962NamedCurves.TC2pnb163v2Holder }

function TX962NamedCurves.TC2pnb163v2Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LN: TBigInteger;
begin
  LN := TX962NamedCurves.FromHex('03FFFFFFFFFFFFFFFFFFFDF64DE1151ADBB78F10A7');
  LBaseCurve := TF2mCurve.Create(163, 1, 2, 8,
    TX962NamedCurves.FromHex('0108B39E77C4B108BED981ED0E890E117C511CF072'),
    TX962NamedCurves.FromHex('0667ACEB38AF4E488C407433FFAE4F1C811638DF20'),
    LN, TBigInteger.Two);
  LCurve := TX962NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TX962NamedCurves.ConfigureBasepoint(LCurve, '030024266E4EB5106D0A964D92C4860E2671DB9B6CC5');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor);
end;

class function TX962NamedCurves.TC2pnb163v2Holder.Instance: IX9ECParametersHolder;
begin
  Result := TC2pnb163v2Holder.Create();
end;

{ TX962NamedCurves.TC2pnb163v3Holder }

function TX962NamedCurves.TC2pnb163v3Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LN: TBigInteger;
begin
  LN := TX962NamedCurves.FromHex('03FFFFFFFFFFFFFFFFFFFE1AEE140F110AFF961309');
  LBaseCurve := TF2mCurve.Create(163, 1, 2, 8,
    TX962NamedCurves.FromHex('07A526C63D3E25A256A007699F5447E32AE456B50E'),
    TX962NamedCurves.FromHex('03F7061798EB99E238FD6F1BF95B48FEEB4854252B'),
    LN, TBigInteger.Two);
  LCurve := TX962NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TX962NamedCurves.ConfigureBasepoint(LCurve, '0202F9F87B7C574D0BDECF8A22E6524775F98CDEBDCB');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor);
end;

class function TX962NamedCurves.TC2pnb163v3Holder.Instance: IX9ECParametersHolder;
begin
  Result := TC2pnb163v3Holder.Create();
end;

{ TX962NamedCurves.TC2pnb176w1Holder }

function TX962NamedCurves.TC2pnb176w1Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LN: TBigInteger;
  LH: TBigInteger;
begin
  LN := TX962NamedCurves.FromHex('010092537397ECA4F6145799D62B0A19CE06FE26AD');
  LH := TBigInteger.ValueOf(Int64($FF6E));
  LBaseCurve := TF2mCurve.Create(176, 1, 2, 43,
    TX962NamedCurves.FromHex('E4E6DB2995065C407D9D39B8D0967B96704BA8E9C90B'),
    TX962NamedCurves.FromHex('5DDA470ABE6414DE8EC133AE28E9BBD7FCEC0AE0FFF2'),
    LN, LH);
  LCurve := TX962NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TX962NamedCurves.ConfigureBasepoint(LCurve, '038D16C2866798B600F9F08BB4A8E860F3298CE04A5798');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor);
end;

class function TX962NamedCurves.TC2pnb176w1Holder.Instance: IX9ECParametersHolder;
begin
  Result := TC2pnb176w1Holder.Create();
end;

{ TX962NamedCurves.TC2tnb191v1Holder }

function TX962NamedCurves.TC2tnb191v1Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LN: TBigInteger;
  LS: TCryptoLibByteArray;
begin
  LN := TX962NamedCurves.FromHex('40000000000000000000000004A20E90C39067C893BBB9A5');
  LBaseCurve := TF2mCurve.Create(191, 9,
    TX962NamedCurves.FromHex('2866537B676752636A68F56554E12640276B649EF7526267'),
    TX962NamedCurves.FromHex('2E45EF571F00786F67B0081B9495A3D95462F5DE0AA185EC'),
    LN, TBigInteger.Two);
  LCurve := TX962NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TX962NamedCurves.ConfigureBasepoint(LCurve, '0236B3DAF8A23206F9C4F299D7B21A9C369137F2C84AE1AA0D');
  LS := THex.Decode('4E13CA542744D696E67687561517552F279A8C84');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor, LS);
end;

class function TX962NamedCurves.TC2tnb191v1Holder.Instance: IX9ECParametersHolder;
begin
  Result := TC2tnb191v1Holder.Create();
end;

{ TX962NamedCurves.TC2tnb191v2Holder }

function TX962NamedCurves.TC2tnb191v2Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LN: TBigInteger;
begin
  LN := TX962NamedCurves.FromHex('20000000000000000000000050508CB89F652824E06B8173');
  LBaseCurve := TF2mCurve.Create(191, 9,
    TX962NamedCurves.FromHex('401028774D7777C7B7666D1366EA432071274F89FF01E718'),
    TX962NamedCurves.FromHex('0620048D28BCBD03B6249C99182B7C8CD19700C362C46A01'),
    LN, TBigInteger.Four);
  LCurve := TX962NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TX962NamedCurves.ConfigureBasepoint(LCurve, '023809B2B7CC1B28CC5A87926AAD83FD28789E81E2C9E3BF10');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor);
end;

class function TX962NamedCurves.TC2tnb191v2Holder.Instance: IX9ECParametersHolder;
begin
  Result := TC2tnb191v2Holder.Create();
end;

{ TX962NamedCurves.TC2tnb191v3Holder }

function TX962NamedCurves.TC2tnb191v3Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LN: TBigInteger;
begin
  LN := TX962NamedCurves.FromHex('155555555555555555555555610C0B196812BFB6288A3EA3');
  LBaseCurve := TF2mCurve.Create(191, 9,
    TX962NamedCurves.FromHex('6C01074756099122221056911C77D77E77A777E7E7E77FCB'),
    TX962NamedCurves.FromHex('71FE1AF926CF847989EFEF8DB459F66394D90F32AD3F15E8'),
    LN, TBigInteger.Six);
  LCurve := TX962NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TX962NamedCurves.ConfigureBasepoint(LCurve, '03375D4CE24FDE434489DE8746E71786015009E66E38A926DD');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor);
end;

class function TX962NamedCurves.TC2tnb191v3Holder.Instance: IX9ECParametersHolder;
begin
  Result := TC2tnb191v3Holder.Create();
end;

{ TX962NamedCurves.TC2pnb208w1Holder }

function TX962NamedCurves.TC2pnb208w1Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LN: TBigInteger;
  LH: TBigInteger;
begin
  LN := TX962NamedCurves.FromHex('0101BAF95C9723C57B6C21DA2EFF2D5ED588BDD5717E212F9D');
  LH := TBigInteger.ValueOf(Int64($FE48));
  LBaseCurve := TF2mCurve.Create(208, 1, 2, 83,
    TBigInteger.Zero,
    TX962NamedCurves.FromHex('C8619ED45A62E6212E1160349E2BFA844439FAFC2A3FD1638F9E'),
    LN, LH);
  LCurve := TX962NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TX962NamedCurves.ConfigureBasepoint(LCurve, '0289FDFBE4ABE193DF9559ECF07AC0CE78554E2784EB8C1ED1A57A');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor);
end;

class function TX962NamedCurves.TC2pnb208w1Holder.Instance: IX9ECParametersHolder;
begin
  Result := TC2pnb208w1Holder.Create();
end;

{ TX962NamedCurves.TC2tnb239v1Holder }

function TX962NamedCurves.TC2tnb239v1Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LN: TBigInteger;
begin
  LN := TX962NamedCurves.FromHex('2000000000000000000000000000000F4D42FFE1492A4993F1CAD666E447');
  LBaseCurve := TF2mCurve.Create(239, 36,
    TX962NamedCurves.FromHex('32010857077C5431123A46B808906756F543423E8D27877578125778AC76'),
    TX962NamedCurves.FromHex('790408F2EEDAF392B012EDEFB3392F30F4327C0CA3F31FC383C422AA8C16'),
    LN, TBigInteger.Four);
  LCurve := TX962NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TX962NamedCurves.ConfigureBasepoint(LCurve, '0257927098FA932E7C0A96D3FD5B706EF7E5F5C156E16B7E7C86038552E91D');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor);
end;
class function TX962NamedCurves.TC2tnb239v1Holder.Instance: IX9ECParametersHolder;
begin
  Result := TC2tnb239v1Holder.Create();
end;

{ TX962NamedCurves.TC2tnb239v2Holder }

function TX962NamedCurves.TC2tnb239v2Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LN: TBigInteger;
begin
  LN := TX962NamedCurves.FromHex('1555555555555555555555555555553C6F2885259C31E3FCDF154624522D');
  LBaseCurve := TF2mCurve.Create(239, 36,
    TX962NamedCurves.FromHex('4230017757A767FAE42398569B746325D45313AF0766266479B75654E65F'),
    TX962NamedCurves.FromHex('5037EA654196CFF0CD82B2C14A2FCF2E3FF8775285B545722F03EACDB74B'),
    LN, TBigInteger.Six);
  LCurve := TX962NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TX962NamedCurves.ConfigureBasepoint(LCurve, '0228F9D04E900069C8DC47A08534FE76D2B900B7D7EF31F5709F200C4CA205');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor);
end;

class function TX962NamedCurves.TC2tnb239v2Holder.Instance: IX9ECParametersHolder;
begin
  Result := TC2tnb239v2Holder.Create();
end;

{ TX962NamedCurves.TC2tnb239v3Holder }

function TX962NamedCurves.TC2tnb239v3Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LN: TBigInteger;
begin
  LN := TX962NamedCurves.FromHex('0CCCCCCCCCCCCCCCCCCCCCCCCCCCCCAC4912D2D9DF903EF9888B8A0E4CFF');
  LBaseCurve := TF2mCurve.Create(239, 36,
    TX962NamedCurves.FromHex('01238774666A67766D6676F778E676B66999176666E687666D8766C66A9F'),
    TX962NamedCurves.FromHex('6A941977BA9F6A435199ACFC51067ED587F519C5ECB541B8E44111DE1D40'),
    LN, TBigInteger.Ten);
  LCurve := TX962NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TX962NamedCurves.ConfigureBasepoint(LCurve, '0370F6E9D04D289C4E89913CE3530BFDE903977D42B146D539BF1BDE4E9C92');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor);
end;

class function TX962NamedCurves.TC2tnb239v3Holder.Instance: IX9ECParametersHolder;
begin
  Result := TC2tnb239v3Holder.Create();
end;

{ TX962NamedCurves.TC2pnb272w1Holder }

function TX962NamedCurves.TC2pnb272w1Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LN: TBigInteger;
  LH: TBigInteger;
begin
  LN := TX962NamedCurves.FromHex('0100FAF51354E0E39E4892DF6E319C72C8161603FA45AA7B998A167B8F1E629521');
  LH := TBigInteger.ValueOf(Int64($FF06));
  LBaseCurve := TF2mCurve.Create(272, 1, 3, 56,
    TX962NamedCurves.FromHex('91A091F03B5FBA4AB2CCF49C4EDD220FB028712D42BE752B2C40094DBACDB586FB20'),
    TX962NamedCurves.FromHex('7167EFC92BB2E3CE7C8AAAFF34E12A9C557003D7C73A6FAF003F99F6CC8482E540F7'),
    LN, LH);
  LCurve := TX962NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TX962NamedCurves.ConfigureBasepoint(LCurve, '026108BABB2CEEBCF787058A056CBE0CFE622D7723A289E08A07AE13EF0D10D171DD8D');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor);
end;

class function TX962NamedCurves.TC2pnb272w1Holder.Instance: IX9ECParametersHolder;
begin
  Result := TC2pnb272w1Holder.Create();
end;

{ TX962NamedCurves.TC2pnb304w1Holder }

function TX962NamedCurves.TC2pnb304w1Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LN: TBigInteger;
  LH: TBigInteger;
begin
  LN := TX962NamedCurves.FromHex('0101D556572AABAC800101D556572AABAC8001022D5C91DD173F8FB561DA6899164443051D');
  LH := TBigInteger.ValueOf(Int64($FE2E));
  LBaseCurve := TF2mCurve.Create(304, 1, 2, 11,
    TX962NamedCurves.FromHex('FD0D693149A118F651E6DCE6802085377E5F882D1B510B44160074C1288078365A0396C8E681'),
    TX962NamedCurves.FromHex('BDDB97E555A50A908E43B01C798EA5DAA6788F1EA2794EFCF57166B8C14039601E55827340BE'),
    LN, LH);
  LCurve := TX962NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TX962NamedCurves.ConfigureBasepoint(LCurve, '02197B07845E9BE2D96ADB0F5F3C7F2CFFBD7A3EB8B6FEC35C7FD67F26DDF6285A644F740A2614');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor);
end;

class function TX962NamedCurves.TC2pnb304w1Holder.Instance: IX9ECParametersHolder;
begin
  Result := TC2pnb304w1Holder.Create();
end;

{ TX962NamedCurves.TC2tnb359v1Holder }

function TX962NamedCurves.TC2tnb359v1Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LN: TBigInteger;
  LH: TBigInteger;
begin
  LN := TX962NamedCurves.FromHex('01AF286BCA1AF286BCA1AF286BCA1AF286BCA1AF286BC9FB8F6B85C556892C20A7EB964FE7719E74F490758D3B');
  LH := TBigInteger.ValueOf(Int64($4C));
  LBaseCurve := TF2mCurve.Create(359, 68,
    TX962NamedCurves.FromHex('5667676A654B20754F356EA92017D946567C46675556F19556A04616B567D223A5E05656FB549016A96656A557'),
    TX962NamedCurves.FromHex('2472E2D0197C49363F1FE7F5B6DB075D52B6947D135D8CA445805D39BC345626089687742B6329E70680231988'),
    LN, LH);
  LCurve := TX962NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TX962NamedCurves.ConfigureBasepoint(LCurve, '033C258EF3047767E7EDE0F1FDAA79DAEE3841366A132E163ACED4ED2401DF9C6BDCDE98E8E707C07A2239B1B097');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor);
end;

class function TX962NamedCurves.TC2tnb359v1Holder.Instance: IX9ECParametersHolder;
begin
  Result := TC2tnb359v1Holder.Create();
end;

{ TX962NamedCurves.TC2pnb368w1Holder }

function TX962NamedCurves.TC2pnb368w1Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LN: TBigInteger;
  LH: TBigInteger;
begin
  LN := TX962NamedCurves.FromHex('010090512DA9AF72B08349D98A5DD4C7B0532ECA51CE03E2D10F3B7AC579BD87E909AE40A6F131E9CFCE5BD967');
  LH := TBigInteger.ValueOf(Int64($FF70));
  LBaseCurve := TF2mCurve.Create(368, 1, 2, 85,
    TX962NamedCurves.FromHex('E0D2EE25095206F5E2A4F9ED229F1F256E79A0E2B455970D8D0D865BD94778C576D62F0AB7519CCD2A1A906AE30D'),
    TX962NamedCurves.FromHex('FC1217D4320A90452C760A58EDCD30C8DD069B3C34453837A34ED50CB54917E1C2112D84D164F444F8F74786046A'),
    LN, LH);
  LCurve := TX962NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TX962NamedCurves.ConfigureBasepoint(LCurve, '021085E2755381DCCCE3C1557AFA10C2F0C0C2825646C5B34A394CBCFA8BC16B22E7E789E927BE216F02E1FB136A5F');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor);
end;

class function TX962NamedCurves.TC2pnb368w1Holder.Instance: IX9ECParametersHolder;
begin
  Result := TC2pnb368w1Holder.Create();
end;

{ TX962NamedCurves.TC2tnb431r1Holder }

function TX962NamedCurves.TC2tnb431r1Holder.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LN: TBigInteger;
  LH: TBigInteger;
begin
  LN := TX962NamedCurves.FromHex('0340340340340340340340340340340340340340340340340340340323C313FAB50589703B5EC68D3587FEC60D161CC149C1AD4A91');
  LH := TBigInteger.ValueOf(Int64($2760));
  LBaseCurve := TF2mCurve.Create(431, 120,
    TX962NamedCurves.FromHex('1A827EF00DD6FC0E234CAF046C6A5D8A85395B236CC4AD2CF32A0CADBDC9DDF620B0EB9906D0957F6C6FEACD615468DF104DE296CD8F'),
    TX962NamedCurves.FromHex('10D9B4A3D9047D8B154359ABFB1B7F5485B04CEB868237DDC9DEDA982A679A5A919B626D4E50A8DD731B107A9962381FB5D807BF2618'),
    LN, LH);
  LCurve := TX962NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TX962NamedCurves.ConfigureBasepoint(LCurve, '02120FC05D3C67A99DE161D2F4092622FECA701BE4F50F4758714E8A87BBF2A658EF8C21E7C5EFE965361F6C2999C0C247B0DBD70CE6B7');
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor);
end;

class function TX962NamedCurves.TC2tnb431r1Holder.Instance: IX9ECParametersHolder;
begin
  Result := TC2tnb431r1Holder.Create();
end;

end.
