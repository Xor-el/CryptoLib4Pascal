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

unit ClpECGost3410NamedCurves;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpAsn1Comparers,
  ClpCryptoLibComparers,
  ClpCollectionUtilities,
  ClpEncoders,
  ClpCryptoProObjectIdentifiers,
  ClpRosstandartObjectIdentifiers,
  ClpCryptoLibTypes,
  ClpBigInteger,
  ClpECCurve,
  ClpWnafUtilities,
  ClpIECCore,
  ClpIAsn1Objects,
  ClpX9ECAsn1Objects,
  ClpIX9ECAsn1Objects,
  ClpX9ECParametersHolder,
  ClpIX9ECParametersHolder;

type
  /// <summary>Elliptic curve registry for GOST 3410-2001 / 2012.</summary>
  TECGost3410NamedCurves = class sealed(TObject)

  strict private
    class var
      FObjIds: TDictionary<String, IDerObjectIdentifier>;
      FCurves: TDictionary<IDerObjectIdentifier, IX9ECParametersHolder>;
      FNames: TDictionary<IDerObjectIdentifier, String>;

    class function GetNames: TCryptoLibStringArray; static; inline;
    class function FromHex(const AHex: String): TBigInteger; static;
    class function ConfigureBasepoint(const ACurve: IECCurve; const AX,
      AY: TBigInteger): IX9ECPoint; static;
    class function ConfigureCurve(const ACurve: IECCurve): IECCurve;
      static; inline;
    class procedure DefineCurve(const AName: String;
      const AOid: IDerObjectIdentifier;
      const AHolder: IX9ECParametersHolder); static;

    class procedure Boot; static;
    class constructor CreateECGost3410NamedCurves;
    class destructor DestroyECGost3410NamedCurves;

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
  THolderGostR34102001CryptoProA = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  THolderGostR34102001CryptoProB = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  THolderGostR34102001CryptoProC = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  THolderIdTc26Gost341012256ParamSetA = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  THolderIdTc26Gost341012512ParamSetA = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  THolderIdTc26Gost341012512ParamSetB = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  THolderIdTc26Gost341012512ParamSetC = class sealed(TX9ECParametersHolder, IX9ECParametersHolder)
  strict protected
    function CreateParameters(): IX9ECParameters; override;
  public
    class function Instance(): IX9ECParametersHolder; static;
  end;

  end;

implementation

{ TECGost3410NamedCurves }

class function TECGost3410NamedCurves.FromHex(const AHex: String): TBigInteger;
begin
  Result := TBigInteger.Create(1, THex.Decode(AHex));
end;

class function TECGost3410NamedCurves.ConfigureBasepoint(const ACurve: IECCurve;
  const AX, AY: TBigInteger): IX9ECPoint;
var
  LPoint: IECPoint;
begin
  LPoint := ACurve.CreatePoint(AX, AY);
  TWnafUtilities.ConfigureBasepoint(LPoint);
  Result := TX9ECPoint.Create(LPoint, False);
end;

class function TECGost3410NamedCurves.ConfigureCurve(const ACurve: IECCurve)
  : IECCurve;
begin
  Result := ACurve;
end;

class procedure TECGost3410NamedCurves.DefineCurve(const AName: String;
  const AOid: IDerObjectIdentifier;
  const AHolder: IX9ECParametersHolder);
var
  LName: String;
begin
  LName := AName;
  FNames.Add(AOid, LName);
  FCurves.Add(AOid, AHolder);
  FObjIds.Add(LName, AOid);
end;

class procedure TECGost3410NamedCurves.Boot;
begin
  FObjIds := TDictionary<String, IDerObjectIdentifier>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FCurves := TDictionary<IDerObjectIdentifier, IX9ECParametersHolder>.Create(TAsn1Comparers.OidEqualityComparer);
  FNames := TDictionary<IDerObjectIdentifier, String>.Create(TAsn1Comparers.OidEqualityComparer);

  DefineCurve('GostR3410-2001-CryptoPro-A', TCryptoProObjectIdentifiers.GostR3410x2001CryptoProA, THolderGostR34102001CryptoProA.Instance);
  DefineCurve('GostR3410-2001-CryptoPro-B', TCryptoProObjectIdentifiers.GostR3410x2001CryptoProB, THolderGostR34102001CryptoProB.Instance);
  DefineCurve('GostR3410-2001-CryptoPro-C', TCryptoProObjectIdentifiers.GostR3410x2001CryptoProC, THolderGostR34102001CryptoProC.Instance);
  DefineCurve('GostR3410-2001-CryptoPro-XchA', TCryptoProObjectIdentifiers.GostR3410x2001CryptoProXchA, THolderGostR34102001CryptoProA.Instance);
  DefineCurve('GostR3410-2001-CryptoPro-XchB', TCryptoProObjectIdentifiers.GostR3410x2001CryptoProXchB, THolderGostR34102001CryptoProC.Instance);
  DefineCurve('Tc26-Gost-3410-12-256-paramSetA', TRosstandartObjectIdentifiers.IdTc26Gost3410_12_256ParamSetA, THolderIdTc26Gost341012256ParamSetA.Instance);
  DefineCurve('Tc26-Gost-3410-12-256-paramSetB', TRosstandartObjectIdentifiers.IdTc26Gost3410_12_256ParamSetB, THolderGostR34102001CryptoProA.Instance);
  DefineCurve('Tc26-Gost-3410-12-256-paramSetC', TRosstandartObjectIdentifiers.IdTc26Gost3410_12_256ParamSetC, THolderGostR34102001CryptoProB.Instance);
  DefineCurve('Tc26-Gost-3410-12-256-paramSetD', TRosstandartObjectIdentifiers.IdTc26Gost3410_12_256ParamSetD, THolderGostR34102001CryptoProC.Instance);
  DefineCurve('Tc26-Gost-3410-12-512-paramSetA', TRosstandartObjectIdentifiers.IdTc26Gost3410_12_512ParamSetA, THolderIdTc26Gost341012512ParamSetA.Instance);
  DefineCurve('Tc26-Gost-3410-12-512-paramSetB', TRosstandartObjectIdentifiers.IdTc26Gost3410_12_512ParamSetB, THolderIdTc26Gost341012512ParamSetB.Instance);
  DefineCurve('Tc26-Gost-3410-12-512-paramSetC', TRosstandartObjectIdentifiers.IdTc26Gost3410_12_512ParamSetC, THolderIdTc26Gost341012512ParamSetC.Instance);
end;

class constructor TECGost3410NamedCurves.CreateECGost3410NamedCurves;
begin
  Boot;
end;

class destructor TECGost3410NamedCurves.DestroyECGost3410NamedCurves;
begin
  FObjIds.Free;
  FCurves.Free;
  FNames.Free;
end;

class function TECGost3410NamedCurves.GetNames: TCryptoLibStringArray;
begin
  Result := TCollectionUtilities.Keys<String, IDerObjectIdentifier>(FObjIds);
end;

class function TECGost3410NamedCurves.GetByName(const AName: String): IX9ECParameters;
var
  LOid: IDerObjectIdentifier;
begin
  LOid := GetOid(AName);
  if LOid = nil then
    Result := nil
  else
    Result := GetByOid(LOid);
end;

class function TECGost3410NamedCurves.GetByNameLazy(const AName: String)
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

class function TECGost3410NamedCurves.GetByOid(const AOid: IDerObjectIdentifier)
  : IX9ECParameters;
var
  LHolder: IX9ECParametersHolder;
begin
  LHolder := GetByOidLazy(AOid);
  if LHolder = nil then
    Result := nil
  else
    Result := LHolder.Parameters;
end;

class function TECGost3410NamedCurves.GetByOidLazy(const AOid: IDerObjectIdentifier)
  : IX9ECParametersHolder;
begin
  Result := TCollectionUtilities.GetValueOrNull<IDerObjectIdentifier, IX9ECParametersHolder>(FCurves, AOid);
end;

class function TECGost3410NamedCurves.GetName(const AOid: IDerObjectIdentifier): String;
begin
  if not FNames.TryGetValue(AOid, Result) then
    Result := '';
end;

class function TECGost3410NamedCurves.GetOid(const AName: String): IDerObjectIdentifier;
begin
  if not FObjIds.TryGetValue(UpperCase(AName), Result) then
    Result := nil;
end;

{ TECGost3410NamedCurves.THolderGostR34102001CryptoProA }

function TECGost3410NamedCurves.THolderGostR34102001CryptoProA.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LModP, LModQ: TBigInteger;
begin
  LModP := TECGost3410NamedCurves.FromHex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97');
  LModQ := TECGost3410NamedCurves.FromHex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893');
  LBaseCurve := TFpCurve.Create(LModP,
    TECGost3410NamedCurves.FromHex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94'),
    TECGost3410NamedCurves.FromHex('A6'),
    LModQ, TBigInteger.One, True);
  LCurve := TECGost3410NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TECGost3410NamedCurves.ConfigureBasepoint(LCurve, TBigInteger.One,
    TECGost3410NamedCurves.FromHex('8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14'));
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor);
end;

class function TECGost3410NamedCurves.THolderGostR34102001CryptoProA.Instance: IX9ECParametersHolder;
begin
  Result := THolderGostR34102001CryptoProA.Create();
end;

{ TECGost3410NamedCurves.THolderGostR34102001CryptoProB }

function TECGost3410NamedCurves.THolderGostR34102001CryptoProB.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LModP, LModQ: TBigInteger;
begin
  LModP := TECGost3410NamedCurves.FromHex('8000000000000000000000000000000000000000000000000000000000000C99');
  LModQ := TECGost3410NamedCurves.FromHex('800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F');
  LBaseCurve := TFpCurve.Create(LModP,
    TECGost3410NamedCurves.FromHex('8000000000000000000000000000000000000000000000000000000000000C96'),
    TECGost3410NamedCurves.FromHex('3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B'),
    LModQ, TBigInteger.One, True);
  LCurve := TECGost3410NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TECGost3410NamedCurves.ConfigureBasepoint(LCurve, TBigInteger.One,
    TECGost3410NamedCurves.FromHex('3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC'));
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor);
end;

class function TECGost3410NamedCurves.THolderGostR34102001CryptoProB.Instance: IX9ECParametersHolder;
begin
  Result := THolderGostR34102001CryptoProB.Create();
end;

{ TECGost3410NamedCurves.THolderGostR34102001CryptoProC }

function TECGost3410NamedCurves.THolderGostR34102001CryptoProC.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LModP, LModQ: TBigInteger;
begin
  LModP := TECGost3410NamedCurves.FromHex('9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B');
  LModQ := TECGost3410NamedCurves.FromHex('9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9');
  LBaseCurve := TFpCurve.Create(LModP,
    TECGost3410NamedCurves.FromHex('9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598'),
    TECGost3410NamedCurves.FromHex('805A'),
    LModQ, TBigInteger.One, True);
  LCurve := TECGost3410NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TECGost3410NamedCurves.ConfigureBasepoint(LCurve, TBigInteger.Zero,
    TECGost3410NamedCurves.FromHex('41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67'));
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor);
end;

class function TECGost3410NamedCurves.THolderGostR34102001CryptoProC.Instance: IX9ECParametersHolder;
begin
  Result := THolderGostR34102001CryptoProC.Create();
end;

{ TECGost3410NamedCurves.THolderIdTc26Gost341012256ParamSetA }

function TECGost3410NamedCurves.THolderIdTc26Gost341012256ParamSetA.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LModP, LModQ: TBigInteger;
begin
  LModP := TECGost3410NamedCurves.FromHex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97');
  LModQ := TECGost3410NamedCurves.FromHex('400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67');
  LBaseCurve := TFpCurve.Create(LModP,
    TECGost3410NamedCurves.FromHex('C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335'),
    TECGost3410NamedCurves.FromHex('295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513'),
    LModQ, TBigInteger.Four, True);
  LCurve := TECGost3410NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TECGost3410NamedCurves.ConfigureBasepoint(LCurve,
    TECGost3410NamedCurves.FromHex('91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28'),
    TECGost3410NamedCurves.FromHex('32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C'));
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor);
end;

class function TECGost3410NamedCurves.THolderIdTc26Gost341012256ParamSetA.Instance: IX9ECParametersHolder;
begin
  Result := THolderIdTc26Gost341012256ParamSetA.Create();
end;

{ TECGost3410NamedCurves.THolderIdTc26Gost341012512ParamSetA }

function TECGost3410NamedCurves.THolderIdTc26Gost341012512ParamSetA.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LModP, LModQ: TBigInteger;
begin
  LModP := TECGost3410NamedCurves.FromHex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7');
  LModQ := TECGost3410NamedCurves.FromHex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275');
  LBaseCurve := TFpCurve.Create(LModP,
    TECGost3410NamedCurves.FromHex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4'),
    TECGost3410NamedCurves.FromHex('E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760'),
    LModQ, TBigInteger.One, True);
  LCurve := TECGost3410NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TECGost3410NamedCurves.ConfigureBasepoint(LCurve, TBigInteger.Three,
    TECGost3410NamedCurves.FromHex('7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4'));
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor);
end;

class function TECGost3410NamedCurves.THolderIdTc26Gost341012512ParamSetA.Instance: IX9ECParametersHolder;
begin
  Result := THolderIdTc26Gost341012512ParamSetA.Create();
end;

{ TECGost3410NamedCurves.THolderIdTc26Gost341012512ParamSetB }

function TECGost3410NamedCurves.THolderIdTc26Gost341012512ParamSetB.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LModP, LModQ: TBigInteger;
begin
  LModP := TECGost3410NamedCurves.FromHex('8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F');
  LModQ := TECGost3410NamedCurves.FromHex('800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD');
  LBaseCurve := TFpCurve.Create(LModP,
    TECGost3410NamedCurves.FromHex('8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006C'),
    TECGost3410NamedCurves.FromHex('687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116'),
    LModQ, TBigInteger.One, True);
  LCurve := TECGost3410NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TECGost3410NamedCurves.ConfigureBasepoint(LCurve, TBigInteger.Two,
    TECGost3410NamedCurves.FromHex('1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD'));
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor);
end;

class function TECGost3410NamedCurves.THolderIdTc26Gost341012512ParamSetB.Instance: IX9ECParametersHolder;
begin
  Result := THolderIdTc26Gost341012512ParamSetB.Create();
end;

{ TECGost3410NamedCurves.THolderIdTc26Gost341012512ParamSetC }

function TECGost3410NamedCurves.THolderIdTc26Gost341012512ParamSetC.CreateParameters: IX9ECParameters;
var
  LBaseCurve: IECCurve;
  LCurve: IECCurve;
  LG: IX9ECPoint;
  LModP, LModQ: TBigInteger;
begin
  LModP := TECGost3410NamedCurves.FromHex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7');
  LModQ := TECGost3410NamedCurves.FromHex('3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC98CDBA46506AB004C33A9FF5147502CC8EDA9E7A769A12694623CEF47F023ED');
  LBaseCurve := TFpCurve.Create(LModP,
    TECGost3410NamedCurves.FromHex('DC9203E514A721875485A529D2C722FB187BC8980EB866644DE41C68E143064546E861C0E2C9EDD92ADE71F46FCF50FF2AD97F951FDA9F2A2EB6546F39689BD3'),
    TECGost3410NamedCurves.FromHex('B4C4EE28CEBC6C2C8AC12952CF37F16AC7EFB6A9F69F4B57FFDA2E4F0DE5ADE038CBC2FFF719D2C18DE0284B8BFEF3B52B8CC7A5F5BF0A3C8D2319A5312557E1'),
    LModQ, TBigInteger.Four, True);
  LCurve := TECGost3410NamedCurves.ConfigureCurve(LBaseCurve);
  LG := TECGost3410NamedCurves.ConfigureBasepoint(LCurve,
    TECGost3410NamedCurves.FromHex('E2E31EDFC23DE7BDEBE241CE593EF5DE2295B7A9CBAEF021D385F7074CEA043AA27272A7AE602BF2A7B9033DB9ED3610C6FB85487EAE97AAC5BC7928C1950148'),
    TECGost3410NamedCurves.FromHex('F5CE40D95B5EB899ABBCCFF5911CB8577939804D6527378B8C108C3D2090FF9BE18E2D33E3021ED2EF32D85822423B6304F726AA854BAE07D0396E9A9ADDC40F'));
  Result := TX9ECParameters.Create(LCurve, LG, LCurve.Order, LCurve.Cofactor);
end;

class function TECGost3410NamedCurves.THolderIdTc26Gost341012512ParamSetC.Instance: IX9ECParametersHolder;
begin
  Result := THolderIdTc26Gost341012512ParamSetC.Create();
end;

end.
