{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit CryptoTestKeys;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpEncoders,
  ClpIDsaParameters,
  ClpDsaParameters,
  ClpIRsaParameters,
  ClpRsaParameters,
  ClpIX9ECAsn1Objects,
  ClpIECParameters,
  ClpECParameters,
  ClpECNamedCurveTable;

type
  /// <summary>
  /// Canonical fixed test keys.
  /// </summary>
  TCryptoTestKeys = class sealed
  strict private
    class var FWriterRsaModulus: string;
    class var FWriterRsaPubExp: string;
    class var FWriterRsaPrivExp: string;
    class var FWriterRsaP: string;
    class var FWriterRsaQ: string;
    class var FWriterRsaDP: string;
    class var FWriterRsaDQ: string;
    class var FWriterRsaQInv: string;
    class var FRsaEngineModulus: string;
    class var FRsaEnginePubExp: string;
    class var FRsaEnginePrivExp: string;
    class var FRsaEngineP: string;
    class var FRsaEngineQ: string;
    class var FRsaEngineDP: string;
    class var FRsaEngineDQ: string;
    class var FRsaEngineQInv: string;
    class var FWriterDsaP: string;
    class var FWriterDsaQ: string;
    class var FWriterDsaG: string;
    class var FRsaDigestSignerModulus: string;
    class var FRsaDigestSignerPubExp: string;
    class var FRsaDigestSignerPrivExp: string;
    class var FRsaDigestSignerP: string;
    class var FRsaDigestSignerQ: string;
    class var FRsaDigestSignerDP: string;
    class var FRsaDigestSignerDQ: string;
    class var FRsaDigestSignerQInv: string;
    class var FDsaWolfP: string;
    class var FDsaWolfQ: string;
    class var FDsaWolfG: string;
    class var FDsaWolfY: string;
    class var FDsaWolfX: string;
    class var FEcPrime239v1Gx: string;
    class var FEcPrime239v1Gy: string;
    class var FEcPrime239v1H: string;
    class var FEcPrime239v1N: string;
    class var FEcPrime239v1Qx: string;
    class var FEcPrime239v1Qy: string;
    class var FEcPrime239v1D: string;
    class var FWriterEcDsaPkcs8Hex: string;

  public
    class function GetWriterRsaCrtPublic: IRsaKeyParameters; static;
    class function GetWriterRsaCrtPrivate: IRsaPrivateCrtKeyParameters; static;
    class function GetWriterDsaParameters: IDsaParameters; static;
    class function GetRsaEngineDefaultPublic: IRsaKeyParameters; static;
    class function GetRsaEngineDefaultPrivate: IRsaPrivateCrtKeyParameters; static;
    class function GetRsaDigestSignerPublic: IRsaKeyParameters; static;
    class function GetRsaDigestSignerPrivate: IRsaPrivateCrtKeyParameters; static;
    class function GetDsaWolfParameters: IDsaParameters; static;
    class function GetDsaWolfPrivate: IDsaPrivateKeyParameters; static;
    class function GetDsaWolfPublic: IDsaPublicKeyParameters; static;
    class function GetEcPrime239v1Domain: IECDomainParameters; static;
    class function GetEcPrime239v1Private: IECPrivateKeyParameters; static;
    class function GetEcPrime239v1Public: IECPublicKeyParameters; static;
    class function GetWriterEcDsaPkcs8Bytes: TCryptoLibByteArray; static;
    class constructor Create;
  end;

implementation

{ TCryptoTestKeys }

class function TCryptoTestKeys.GetWriterRsaCrtPublic: IRsaKeyParameters;
begin
  Result := TRsaKeyParameters.Create(False,
    TBigInteger.Create(FWriterRsaModulus, 16),
    TBigInteger.Create(FWriterRsaPubExp, 16));
end;

class function TCryptoTestKeys.GetWriterRsaCrtPrivate: IRsaPrivateCrtKeyParameters;
begin
  Result := TRsaPrivateCrtKeyParameters.Create(
    TBigInteger.Create(FWriterRsaModulus, 16),
    TBigInteger.Create(FWriterRsaPubExp, 16),
    TBigInteger.Create(FWriterRsaPrivExp, 16),
    TBigInteger.Create(FWriterRsaP, 16),
    TBigInteger.Create(FWriterRsaQ, 16),
    TBigInteger.Create(FWriterRsaDP, 16),
    TBigInteger.Create(FWriterRsaDQ, 16),
    TBigInteger.Create(FWriterRsaQInv, 16));
end;

class function TCryptoTestKeys.GetWriterDsaParameters: IDsaParameters;
begin
  Result := TDsaParameters.Create(
    TBigInteger.Create(FWriterDsaP),
    TBigInteger.Create(FWriterDsaQ),
    TBigInteger.Create(FWriterDsaG));
end;

class function TCryptoTestKeys.GetRsaEngineDefaultPublic: IRsaKeyParameters;
begin
  Result := TRsaKeyParameters.Create(False,
    TBigInteger.Create(FRsaEngineModulus, 16),
    TBigInteger.Create(FRsaEnginePubExp, 16));
end;

class function TCryptoTestKeys.GetRsaEngineDefaultPrivate: IRsaPrivateCrtKeyParameters;
begin
  Result := TRsaPrivateCrtKeyParameters.Create(
    TBigInteger.Create(FRsaEngineModulus, 16),
    TBigInteger.Create(FRsaEnginePubExp, 16),
    TBigInteger.Create(FRsaEnginePrivExp, 16),
    TBigInteger.Create(FRsaEngineP, 16),
    TBigInteger.Create(FRsaEngineQ, 16),
    TBigInteger.Create(FRsaEngineDP, 16),
    TBigInteger.Create(FRsaEngineDQ, 16),
    TBigInteger.Create(FRsaEngineQInv, 16));
end;

class function TCryptoTestKeys.GetRsaDigestSignerPublic: IRsaKeyParameters;
begin
  Result := TRsaKeyParameters.Create(False,
    TBigInteger.Create(1, TBase64Encoder.Decode(FRsaDigestSignerModulus)),
    TBigInteger.Create(1, TBase64Encoder.Decode(FRsaDigestSignerPubExp)));
end;

class function TCryptoTestKeys.GetRsaDigestSignerPrivate: IRsaPrivateCrtKeyParameters;
begin
  Result := TRsaPrivateCrtKeyParameters.Create(
    TBigInteger.Create(1, TBase64Encoder.Decode(FRsaDigestSignerModulus)),
    TBigInteger.Create(1, TBase64Encoder.Decode(FRsaDigestSignerPubExp)),
    TBigInteger.Create(1, TBase64Encoder.Decode(FRsaDigestSignerPrivExp)),
    TBigInteger.Create(1, TBase64Encoder.Decode(FRsaDigestSignerP)),
    TBigInteger.Create(1, TBase64Encoder.Decode(FRsaDigestSignerQ)),
    TBigInteger.Create(1, TBase64Encoder.Decode(FRsaDigestSignerDP)),
    TBigInteger.Create(1, TBase64Encoder.Decode(FRsaDigestSignerDQ)),
    TBigInteger.Create(1, TBase64Encoder.Decode(FRsaDigestSignerQInv)));
end;

class function TCryptoTestKeys.GetDsaWolfParameters: IDsaParameters;
begin
  Result := TDsaParameters.Create(
    TBigInteger.Create(1, TBase64Encoder.Decode(FDsaWolfP)),
    TBigInteger.Create(1, TBase64Encoder.Decode(FDsaWolfQ)),
    TBigInteger.Create(1, TBase64Encoder.Decode(FDsaWolfG)));
end;

class function TCryptoTestKeys.GetDsaWolfPrivate: IDsaPrivateKeyParameters;
begin
  Result := TDsaPrivateKeyParameters.Create(
    TBigInteger.Create(1, TBase64Encoder.Decode(FDsaWolfX)),
    GetDsaWolfParameters);
end;

class function TCryptoTestKeys.GetDsaWolfPublic: IDsaPublicKeyParameters;
begin
  Result := TDsaPublicKeyParameters.Create(
    TBigInteger.Create(1, TBase64Encoder.Decode(FDsaWolfY)),
    GetDsaWolfParameters);
end;

class function TCryptoTestKeys.GetEcPrime239v1Domain: IECDomainParameters;
var
  LX9: IX9ECParameters;
  LGx, LGy, LH, LN: TBigInteger;
begin
  LX9 := TECNamedCurveTable.GetByName('prime239v1');
  LGx := TBigInteger.Create(1, TBase64Encoder.Decode(FEcPrime239v1Gx));
  LGy := TBigInteger.Create(1, TBase64Encoder.Decode(FEcPrime239v1Gy));
  LH := TBigInteger.Create(1, TBase64Encoder.Decode(FEcPrime239v1H));
  LN := TBigInteger.Create(1, TBase64Encoder.Decode(FEcPrime239v1N));
  Result := TECDomainParameters.Create(LX9.Curve,
    LX9.Curve.ValidatePoint(LGx, LGy), LN, LH);
end;

class function TCryptoTestKeys.GetEcPrime239v1Private: IECPrivateKeyParameters;
begin
  Result := TECPrivateKeyParameters.Create('ECDSA',
    TBigInteger.Create(1, TBase64Encoder.Decode(FEcPrime239v1D)),
    GetEcPrime239v1Domain);
end;

class function TCryptoTestKeys.GetEcPrime239v1Public: IECPublicKeyParameters;
var
  LX9: IX9ECParameters;
  LQx, LQy: TBigInteger;
begin
  LX9 := TECNamedCurveTable.GetByName('prime239v1');
  LQx := TBigInteger.Create(1, TBase64Encoder.Decode(FEcPrime239v1Qx));
  LQy := TBigInteger.Create(1, TBase64Encoder.Decode(FEcPrime239v1Qy));
  Result := TECPublicKeyParameters.Create('ECDSA',
    LX9.Curve.ValidatePoint(LQx, LQy), GetEcPrime239v1Domain);
end;

class function TCryptoTestKeys.GetWriterEcDsaPkcs8Bytes: TCryptoLibByteArray;
begin
  Result := THexEncoder.Decode(FWriterEcDsaPkcs8Hex);
end;

class constructor TCryptoTestKeys.Create;
begin
  FWriterRsaModulus := 'b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9' +
      '900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7';
  FWriterRsaPubExp := '11';
  FWriterRsaPrivExp := '9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae' +
      '79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89';
  FWriterRsaP := 'c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb';
  FWriterRsaQ := 'f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5';
  FWriterRsaDP := 'b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391';
  FWriterRsaDQ := 'd3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd';
  FWriterRsaQInv := 'b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19';
  FRsaEngineModulus := 'B259D2D6E627A768C94BE36164C2D9FC79D97AAB9253140E5BF17751197731D6' +
      'F7540D2509E7B9FFEE0A70A6E26D56E92D2EDD7F85ABA85600B69089F35F6BDB' +
      'F3C298E05842535D9F064E6B0391CB7D306E0A2D20C4DFB4E7B49A9640BDEA26' +
      'C10AD69C3F05007CE2513CEE44CFE01998E62B6C3637D3FC0391079B26EE36D5';
  FRsaEnginePubExp := '11';
  FRsaEnginePrivExp := '92E08F83CC9920746989CA5034DCB384A094FB9C5A6288FCC4304424AB8F5638' +
      '8F72652D8FAFC65A4B9020896F2CDE297080F2A540E7B7CE5AF0B3446E1258D1' +
      'DD7F245CF54124B4C6E17DA21B90A0EBD22605E6F45C9F136D7A13EAAC1C0F74' +
      '87DE8BD6D924972408EBB58AF71E76FD7B012A8D0E165F3AE2E5077A8648E619';
  FRsaEngineP := 'F75E80839B9B9379F1CF1128F321639757DBA514642C206BBBD99F9A4846208B' +
      '3E93FBBE5E0527CC59B1D4B929D9555853004C7C8B30EE6A213C3D1BB7415D03';
  FRsaEngineQ := 'B892D9EBDBFC37E397256DD8A5D3123534D1F03726284743DDC6BE3A709EDB69' +
      '6FC40C7D902ED804C6EEE730EEE3D5B20BF6BD8D87A296813C87D3B3CC9D7947';
  FRsaEngineDP := '1D1A2D3CA8E52068B3094D501C9A842FEC37F54DB16E9A67070A8B3F53CC03D4' +
      '257AD252A1A640EADD603724D7BF3737914B544AE332EEDF4F34436CAC25CEB5';
  FRsaEngineDQ := '6C929E4E81672FEF49D9C825163FEC97C4B7BA7ACB26C0824638AC22605D7201' +
      'C94625770984F78A56E6E25904FE7DB407099CAD9B14588841B94F5AB498DDED';
  FRsaEngineQInv := 'DAE7651EE69AD1D081EC5E7188AE126F6004FF39556BDE90E0B870962FA7B926' +
      'D070686D8244FE5A9AA709A95686A104614834B0ADA4B10F53197A5CB4C97339';
  FWriterDsaP := '7434410770759874867539421675728577177024889699586189000788950934' +
      '6793151646768520470583547588838332997026954281969620578712646852' +
      '91775577130504050839126673';
  FWriterDsaQ := '1138656671590261728308283492178581223478058193247';
  FWriterDsaG := '4182906737723181805517018315469082619513954319976782448649747742' +
      '9511890034828343211926926208564886396290115703811385427898038190' +
      '92529658402611668375788410';
  FRsaDigestSignerModulus := 'AIASoe2PQb1IP7bTyC9usjHP7FvnUMVpKW49iuFtrw/dMpYlsMMoIU2jupfifDpd' +
      'FxIktSB4P+6Ymg5WjvHKTIrvQ7SR4zV4jaPTu56Ys0pZ9EDA6gb3HLjtU+8Bb1mf' +
      'WM+yjKxcPDuFjwEtjGlPHg1Vq+CA9HNcMSKNn2+tW6qt';
  FRsaDigestSignerPubExp := 'EQ==';
  FRsaDigestSignerPrivExp := 'DxFAOhDajr00rBjqX+7nyZ/9sHWRCCp9WEN5wCsFiWVRPtdB+NeLcou7mWXwf1Y+' +
      '8xNgmmh//fPV45G2dsyBeZbXeJwB7bzx9NMEAfedchyOwjR8PYdjK3NpTLKtZlEJ' +
      '6Jkh4QihrXpZMO4fKZWUm9bid3+lmiq43FwW+Hof8/E=';
  FRsaDigestSignerP := 'AJ9StyTVW+AL/1s7RBtFwZGFBgd3zctBqzzwKPda6LbtIFDznmwDCqAlIQH9X14X' +
      '7UPLokCDhuAa76OnDXb1OiE=';
  FRsaDigestSignerQ := 'AM3JfD79dNJ5A3beScSzPtWxx/tSLi0QHFtkuhtSizeXdkv5FSba7lVzwEOGKHmW' +
      '829bRoNxThDy4ds1IihW1w0=';
  FRsaDigestSignerDP := 'JXzfzG5v+HtLJIZqYMUefJfFLu8DPuJGaLD6lI3cZ0babWZ/oPGoJa5iHpX4Ul/7' +
      'l3s1PFsuy1GhzCdOdlfRcQ==';
  FRsaDigestSignerDQ := 'YNdJhw3cn0gBoVmMIFRZzflPDNthBiWy/dUMSRfJCxoZjSnr1gysZHK01HteV1YY' +
      'NGcwPdr3j4FbOfri5c6DUQ==';
  FRsaDigestSignerQInv := 'Lt0g7wrsNsQxuDdB8q/rH8fSFeBXMGLtCIqfOec1j7FEIuYA/ACiRDgXkHa0WgN7' +
      'nLXSjHoy630wC5Toq8vvUg==';
  FDsaWolfP := 'AM2b/UeQA+ovv3dL05wlDHEKJ+qhnJBsRT5OB9WuyRC830G79y0R8wuq8jyIYWCY' +
      'cTn1TeqVPWqiTv6oAoiEeOs=';
  FDsaWolfQ := 'AIlJT7mcKL6SUBMmvm24zX1EvjNx';
  FDsaWolfG := 'AL0fxOTq10OHFbCf8YldyGembqEu08EDVzxyLL29Zn/t4It661YNol1rnhPIs+ci' +
      'rw+yf9zeCe+KL1IbZ/qIMZM=';
  FDsaWolfY := 'TtWy2GuT9yGBWOHi1/EpCDa/bWJCk2+yAdr56rAcqP0eHGkMnA9s9GJD2nGU8sFj' +
      'NHm55swpn6JQb8q0agrCfw==';
  FDsaWolfX := 'MMpBAxNlv7eYfxLTZ2BItJeD31A=';
  FEcPrime239v1Gx := 'D/qWPNyogWzMM7hkK+35BcPTWFc9Pyf7vTs8uaqv';
  FEcPrime239v1Gy := 'AhQXGxb1olGRv6s1LPRfuatMF+cx3ZTGgzSE/Q5R';
  FEcPrime239v1H := 'AQ==';
  FEcPrime239v1N := 'f///////////////f///nl6an12QcfvRUiaIkJ0L';
  FEcPrime239v1Qx := 'HWWi17Yb+Bm3PYr/DMjLOYNFhyOwX1QY7ZvqqM+l';
  FEcPrime239v1Qy := 'JrlJfxu3WGhqwtL/55BOs/wsUeiDFsvXcGhB8DGx';
  FEcPrime239v1D := 'GYQmd/NF1B+He1iMkWt3by2Az6Eu07t0ynJ4YCAo';
  FWriterEcDsaPkcs8Hex := '3081bf020100301006072a8648ce3d020106052b810400220481a73081a4' +
      '020101043092054defa3b89e78ab3400141a9b2ff29f195d7bb625afc1e6c9f2da36732b8c0c0' +
      'fa7d47e28c504841ef3c52017bfd2a00706052b81040022a1640362010432ca894ca60f93c81' +
      'e28f643d6a9a7c720e7bca3d2b5825bacfb0dac63c3883d041619be62e4b740ca2fd2b1cc14' +
      'db8ad9334ca22f7047a1da7d71cc3284bac56205c950e41c08dd9d9e8d4632896ce78f7b8a7e' +
      '602f9fb39f4c8cb11b72bf9a';
end;

end.
