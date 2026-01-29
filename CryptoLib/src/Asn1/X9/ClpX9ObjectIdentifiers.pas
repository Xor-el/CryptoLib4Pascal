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

unit ClpX9ObjectIdentifiers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsn1Objects,
  ClpIAsn1Objects;

type
  /// <summary>ansi-X9-62 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) ansi-x962(10045) }</summary>
  TX9ObjectIdentifiers = class abstract(TObject)
  strict private
    class var
      FIsBooted: Boolean;
      FAnsiX9_62, FIdFieldType, FPrimeField, FCharacteristicTwoField, FGNBasis,
      FTPBasis, FPPBasis, FIdEcSigType, FECDsaWithSha1, FIdPublicKeyType,
      FIdECPublicKey, FECDsaWithSha2, FECDsaWithSha224, FECDsaWithSha256,
      FECDsaWithSha384, FECDsaWithSha512, FEllipticCurve, FCTwoCurve,
      FC2Pnb163v1, FC2Pnb163v2, FC2Pnb163v3, FC2Pnb176w1, FC2Tnb191v1, FC2Tnb191v2,
      FC2Tnb191v3, FC2Onb191v4, FC2Onb191v5, FC2Pnb208w1, FC2Tnb239v1, FC2Tnb239v2,
      FC2Tnb239v3, FC2Onb239v4, FC2Onb239v5, FC2Pnb272w1, FC2Pnb304w1, FC2Tnb359v1,
      FC2Pnb368w1, FC2Tnb431r1, FPrimeCurve, FPrime192v1, FPrime192v2, FPrime192v3,
      FPrime239v1, FPrime239v2, FPrime239v3, FPrime256v1, FIdDsa, FIdDsaWithSha1,
      FX9x63Scheme, FDHSinglePassStdDHSha1KdfScheme, FDHSinglePassCofactorDHSha1KdfScheme,
      FMqvSinglePassSha1KdfScheme, FAnsiX9_42, FDHPublicNumber, FX9x42Schemes,
      FDHStatic, FDHEphem, FDHOneFlow, FDHHybrid1, FDHHybrid2, FDHHybridOneFlow, FMqv2, FMqv1: IDerObjectIdentifier;

    class function GetAnsiX9_62: IDerObjectIdentifier; static; inline;
    class function GetIdFieldType: IDerObjectIdentifier; static; inline;
    class function GetPrimeField: IDerObjectIdentifier; static; inline;
    class function GetCharacteristicTwoField: IDerObjectIdentifier; static; inline;
    class function GetGNBasis: IDerObjectIdentifier; static; inline;
    class function GetTPBasis: IDerObjectIdentifier; static; inline;
    class function GetPPBasis: IDerObjectIdentifier; static; inline;
    class function GetIdEcSigType: IDerObjectIdentifier; static; inline;
    class function GetECDsaWithSha1: IDerObjectIdentifier; static; inline;
    class function GetIdPublicKeyType: IDerObjectIdentifier; static; inline;
    class function GetIdECPublicKey: IDerObjectIdentifier; static; inline;
    class function GetECDsaWithSha2: IDerObjectIdentifier; static; inline;
    class function GetECDsaWithSha224: IDerObjectIdentifier; static; inline;
    class function GetECDsaWithSha256: IDerObjectIdentifier; static; inline;
    class function GetECDsaWithSha384: IDerObjectIdentifier; static; inline;
    class function GetECDsaWithSha512: IDerObjectIdentifier; static; inline;
    class function GetEllipticCurve: IDerObjectIdentifier; static; inline;
    class function GetCTwoCurve: IDerObjectIdentifier; static; inline;
    class function GetC2Pnb163v1: IDerObjectIdentifier; static; inline;
    class function GetC2Pnb163v2: IDerObjectIdentifier; static; inline;
    class function GetC2Pnb163v3: IDerObjectIdentifier; static; inline;
    class function GetC2Pnb176w1: IDerObjectIdentifier; static; inline;
    class function GetC2Tnb191v1: IDerObjectIdentifier; static; inline;
    class function GetC2Tnb191v2: IDerObjectIdentifier; static; inline;
    class function GetC2Tnb191v3: IDerObjectIdentifier; static; inline;
    class function GetC2Onb191v4: IDerObjectIdentifier; static; inline;
    class function GetC2Onb191v5: IDerObjectIdentifier; static; inline;
    class function GetC2Pnb208w1: IDerObjectIdentifier; static; inline;
    class function GetC2Tnb239v1: IDerObjectIdentifier; static; inline;
    class function GetC2Tnb239v2: IDerObjectIdentifier; static; inline;
    class function GetC2Tnb239v3: IDerObjectIdentifier; static; inline;
    class function GetC2Onb239v4: IDerObjectIdentifier; static; inline;
    class function GetC2Onb239v5: IDerObjectIdentifier; static; inline;
    class function GetC2Pnb272w1: IDerObjectIdentifier; static; inline;
    class function GetC2Pnb304w1: IDerObjectIdentifier; static; inline;
    class function GetC2Tnb359v1: IDerObjectIdentifier; static; inline;
    class function GetC2Pnb368w1: IDerObjectIdentifier; static; inline;
    class function GetC2Tnb431r1: IDerObjectIdentifier; static; inline;
    class function GetPrimeCurve: IDerObjectIdentifier; static; inline;
    class function GetPrime192v1: IDerObjectIdentifier; static; inline;
    class function GetPrime192v2: IDerObjectIdentifier; static; inline;
    class function GetPrime192v3: IDerObjectIdentifier; static; inline;
    class function GetPrime239v1: IDerObjectIdentifier; static; inline;
    class function GetPrime239v2: IDerObjectIdentifier; static; inline;
    class function GetPrime239v3: IDerObjectIdentifier; static; inline;
    class function GetPrime256v1: IDerObjectIdentifier; static; inline;
    class function GetIdDsa: IDerObjectIdentifier; static; inline;
    class function GetIdDsaWithSha1: IDerObjectIdentifier; static; inline;
    class function GetX9x63Scheme: IDerObjectIdentifier; static; inline;
    class function GetDHSinglePassStdDHSha1KdfScheme: IDerObjectIdentifier; static; inline;
    class function GetDHSinglePassCofactorDHSha1KdfScheme: IDerObjectIdentifier; static; inline;
    class function GetMqvSinglePassSha1KdfScheme: IDerObjectIdentifier; static; inline;
    class function GetAnsiX9_42: IDerObjectIdentifier; static; inline;
    class function GetDHPublicNumber: IDerObjectIdentifier; static; inline;
    class function GetX9x42Schemes: IDerObjectIdentifier; static; inline;
    class function GetDHStatic: IDerObjectIdentifier; static; inline;
    class function GetDHEphem: IDerObjectIdentifier; static; inline;
    class function GetDHOneFlow: IDerObjectIdentifier; static; inline;
    class function GetDHHybrid1: IDerObjectIdentifier; static; inline;
    class function GetDHHybrid2: IDerObjectIdentifier; static; inline;
    class function GetDHHybridOneFlow: IDerObjectIdentifier; static; inline;
    class function GetMqv2: IDerObjectIdentifier; static; inline;
    class function GetMqv1: IDerObjectIdentifier; static; inline;

    class constructor Create;
  public
    class property AnsiX9_62: IDerObjectIdentifier read GetAnsiX9_62;
    class property IdFieldType: IDerObjectIdentifier read GetIdFieldType;
    class property PrimeField: IDerObjectIdentifier read GetPrimeField;
    class property CharacteristicTwoField: IDerObjectIdentifier read GetCharacteristicTwoField;
    class property GNBasis: IDerObjectIdentifier read GetGNBasis;
    class property TPBasis: IDerObjectIdentifier read GetTPBasis;
    class property PPBasis: IDerObjectIdentifier read GetPPBasis;
    class property IdEcSigType: IDerObjectIdentifier read GetIdEcSigType;
    class property ECDsaWithSha1: IDerObjectIdentifier read GetECDsaWithSha1;
    class property IdPublicKeyType: IDerObjectIdentifier read GetIdPublicKeyType;
    class property IdECPublicKey: IDerObjectIdentifier read GetIdECPublicKey;
    class property ECDsaWithSha2: IDerObjectIdentifier read GetECDsaWithSha2;
    class property ECDsaWithSha224: IDerObjectIdentifier read GetECDsaWithSha224;
    class property ECDsaWithSha256: IDerObjectIdentifier read GetECDsaWithSha256;
    class property ECDsaWithSha384: IDerObjectIdentifier read GetECDsaWithSha384;
    class property ECDsaWithSha512: IDerObjectIdentifier read GetECDsaWithSha512;
    class property EllipticCurve: IDerObjectIdentifier read GetEllipticCurve;
    class property CTwoCurve: IDerObjectIdentifier read GetCTwoCurve;
    class property C2Pnb163v1: IDerObjectIdentifier read GetC2Pnb163v1;
    class property C2Pnb163v2: IDerObjectIdentifier read GetC2Pnb163v2;
    class property C2Pnb163v3: IDerObjectIdentifier read GetC2Pnb163v3;
    class property C2Pnb176w1: IDerObjectIdentifier read GetC2Pnb176w1;
    class property C2Tnb191v1: IDerObjectIdentifier read GetC2Tnb191v1;
    class property C2Tnb191v2: IDerObjectIdentifier read GetC2Tnb191v2;
    class property C2Tnb191v3: IDerObjectIdentifier read GetC2Tnb191v3;
    class property C2Onb191v4: IDerObjectIdentifier read GetC2Onb191v4;
    class property C2Onb191v5: IDerObjectIdentifier read GetC2Onb191v5;
    class property C2Pnb208w1: IDerObjectIdentifier read GetC2Pnb208w1;
    class property C2Tnb239v1: IDerObjectIdentifier read GetC2Tnb239v1;
    class property C2Tnb239v2: IDerObjectIdentifier read GetC2Tnb239v2;
    class property C2Tnb239v3: IDerObjectIdentifier read GetC2Tnb239v3;
    class property C2Onb239v4: IDerObjectIdentifier read GetC2Onb239v4;
    class property C2Onb239v5: IDerObjectIdentifier read GetC2Onb239v5;
    class property C2Pnb272w1: IDerObjectIdentifier read GetC2Pnb272w1;
    class property C2Pnb304w1: IDerObjectIdentifier read GetC2Pnb304w1;
    class property C2Tnb359v1: IDerObjectIdentifier read GetC2Tnb359v1;
    class property C2Pnb368w1: IDerObjectIdentifier read GetC2Pnb368w1;
    class property C2Tnb431r1: IDerObjectIdentifier read GetC2Tnb431r1;
    class property PrimeCurve: IDerObjectIdentifier read GetPrimeCurve;
    class property Prime192v1: IDerObjectIdentifier read GetPrime192v1;
    class property Prime192v2: IDerObjectIdentifier read GetPrime192v2;
    class property Prime192v3: IDerObjectIdentifier read GetPrime192v3;
    class property Prime239v1: IDerObjectIdentifier read GetPrime239v1;
    class property Prime239v2: IDerObjectIdentifier read GetPrime239v2;
    class property Prime239v3: IDerObjectIdentifier read GetPrime239v3;
    class property Prime256v1: IDerObjectIdentifier read GetPrime256v1;
    class property IdDsa: IDerObjectIdentifier read GetIdDsa;
    class property IdDsaWithSha1: IDerObjectIdentifier read GetIdDsaWithSha1;
    class property X9x63Scheme: IDerObjectIdentifier read GetX9x63Scheme;
    class property DHSinglePassStdDHSha1KdfScheme: IDerObjectIdentifier read GetDHSinglePassStdDHSha1KdfScheme;
    class property DHSinglePassCofactorDHSha1KdfScheme: IDerObjectIdentifier read GetDHSinglePassCofactorDHSha1KdfScheme;
    class property MqvSinglePassSha1KdfScheme: IDerObjectIdentifier read GetMqvSinglePassSha1KdfScheme;
    class property AnsiX9_42: IDerObjectIdentifier read GetAnsiX9_42;
    class property DHPublicNumber: IDerObjectIdentifier read GetDHPublicNumber;
    class property X9x42Schemes: IDerObjectIdentifier read GetX9x42Schemes;
    class property DHStatic: IDerObjectIdentifier read GetDHStatic;
    class property DHEphem: IDerObjectIdentifier read GetDHEphem;
    class property DHOneFlow: IDerObjectIdentifier read GetDHOneFlow;
    class property DHHybrid1: IDerObjectIdentifier read GetDHHybrid1;
    class property DHHybrid2: IDerObjectIdentifier read GetDHHybrid2;
    class property DHHybridOneFlow: IDerObjectIdentifier read GetDHHybridOneFlow;
    class property Mqv2: IDerObjectIdentifier read GetMqv2;
    class property Mqv1: IDerObjectIdentifier read GetMqv1;

    class procedure Boot; static;
  end;

implementation

{ TX9ObjectIdentifiers }

class constructor TX9ObjectIdentifiers.Create;
begin
  Boot;
end;

class procedure TX9ObjectIdentifiers.Boot;
var
  LHashAlgs, LAes, FSigAlgs, FKems: IDerObjectIdentifier;
begin
  if not FIsBooted then
  begin
    FAnsiX9_62 := TDerObjectIdentifier.Create('1.2.840.10045');
    FIdFieldType := FAnsiX9_62.Branch('1');
    FPrimeField := FIdFieldType.Branch('1');
    FCharacteristicTwoField := FIdFieldType.Branch('2');
    FGNBasis := FCharacteristicTwoField.Branch('3.1');
    FTPBasis := FCharacteristicTwoField.Branch('3.2');
    FPPBasis := FCharacteristicTwoField.Branch('3.3');
    FIdEcSigType := FAnsiX9_62.Branch('4');
    FECDsaWithSha1 := FIdEcSigType.Branch('1');
    FIdPublicKeyType := FAnsiX9_62.Branch('2');
    FIdECPublicKey := FIdPublicKeyType.Branch('1');
    FECDsaWithSha2 := FIdEcSigType.Branch('3');
    FECDsaWithSha224 := FECDsaWithSha2.Branch('1');
    FECDsaWithSha256 := FECDsaWithSha2.Branch('2');
    FECDsaWithSha384 := FECDsaWithSha2.Branch('3');
    FECDsaWithSha512 := FECDsaWithSha2.Branch('4');
    FEllipticCurve := FAnsiX9_62.Branch('3');
    FCTwoCurve := FEllipticCurve.Branch('0');
    FC2Pnb163v1 := FCTwoCurve.Branch('1');
    FC2Pnb163v2 := FCTwoCurve.Branch('2');
    FC2Pnb163v3 := FCTwoCurve.Branch('3');
    FC2Pnb176w1 := FCTwoCurve.Branch('4');
    FC2Tnb191v1 := FCTwoCurve.Branch('5');
    FC2Tnb191v2 := FCTwoCurve.Branch('6');
    FC2Tnb191v3 := FCTwoCurve.Branch('7');
    FC2Onb191v4 := FCTwoCurve.Branch('8');
    FC2Onb191v5 := FCTwoCurve.Branch('9');
    FC2Pnb208w1 := FCTwoCurve.Branch('10');
    FC2Tnb239v1 := FCTwoCurve.Branch('11');
    FC2Tnb239v2 := FCTwoCurve.Branch('12');
    FC2Tnb239v3 := FCTwoCurve.Branch('13');
    FC2Onb239v4 := FCTwoCurve.Branch('14');
    FC2Onb239v5 := FCTwoCurve.Branch('15');
    FC2Pnb272w1 := FCTwoCurve.Branch('16');
    FC2Pnb304w1 := FCTwoCurve.Branch('17');
    FC2Tnb359v1 := FCTwoCurve.Branch('18');
    FC2Pnb368w1 := FCTwoCurve.Branch('19');
    FC2Tnb431r1 := FCTwoCurve.Branch('20');
    FPrimeCurve := FEllipticCurve.Branch('1');
    FPrime192v1 := FPrimeCurve.Branch('1');
    FPrime192v2 := FPrimeCurve.Branch('2');
    FPrime192v3 := FPrimeCurve.Branch('3');
    FPrime239v1 := FPrimeCurve.Branch('4');
    FPrime239v2 := FPrimeCurve.Branch('5');
    FPrime239v3 := FPrimeCurve.Branch('6');
    FPrime256v1 := FPrimeCurve.Branch('7');
    FIdDsa := TDerObjectIdentifier.Create('1.2.840.10040.4.1');
    FIdDsaWithSha1 := TDerObjectIdentifier.Create('1.2.840.10040.4.3');
    FX9x63Scheme := TDerObjectIdentifier.Create('1.3.133.16.840.63.0');
    FDHSinglePassStdDHSha1KdfScheme := FX9x63Scheme.Branch('2');
    FDHSinglePassCofactorDHSha1KdfScheme := FX9x63Scheme.Branch('3');
    FMqvSinglePassSha1KdfScheme := FX9x63Scheme.Branch('16');
    FAnsiX9_42 := TDerObjectIdentifier.Create('1.2.840.10046');
    FDHPublicNumber := FAnsiX9_42.Branch('2.1');
    FX9x42Schemes := FAnsiX9_42.Branch('2.3');
    FDHStatic := FX9x42Schemes.Branch('1');
    FDHEphem := FX9x42Schemes.Branch('2');
    FDHOneFlow := FX9x42Schemes.Branch('3');
    FDHHybrid1 := FX9x42Schemes.Branch('4');
    FDHHybrid2 := FX9x42Schemes.Branch('5');
    FDHHybridOneFlow := FX9x42Schemes.Branch('6');
    FMqv2 := FX9x42Schemes.Branch('7');
    FMqv1 := FX9x42Schemes.Branch('8');

    FIsBooted := True;
  end;
end;

class function TX9ObjectIdentifiers.GetAnsiX9_42: IDerObjectIdentifier;
begin
  Result := FAnsiX9_42;
end;

class function TX9ObjectIdentifiers.GetAnsiX9_62: IDerObjectIdentifier;
begin
  Result := FAnsiX9_62;
end;

class function TX9ObjectIdentifiers.GetC2Onb191v4: IDerObjectIdentifier;
begin
  Result := FC2Onb191v4;
end;

class function TX9ObjectIdentifiers.GetC2Onb191v5: IDerObjectIdentifier;
begin
  Result := FC2Onb191v5;
end;

class function TX9ObjectIdentifiers.GetC2Onb239v4: IDerObjectIdentifier;
begin
  Result := FC2Onb239v4;
end;

class function TX9ObjectIdentifiers.GetC2Onb239v5: IDerObjectIdentifier;
begin
  Result := FC2Onb239v5;
end;

class function TX9ObjectIdentifiers.GetC2Pnb163v1: IDerObjectIdentifier;
begin
  Result := FC2Pnb163v1;
end;

class function TX9ObjectIdentifiers.GetC2Pnb163v2: IDerObjectIdentifier;
begin
  Result := FC2Pnb163v2;
end;

class function TX9ObjectIdentifiers.GetC2Pnb163v3: IDerObjectIdentifier;
begin
  Result := FC2Pnb163v3;
end;

class function TX9ObjectIdentifiers.GetC2Pnb176w1: IDerObjectIdentifier;
begin
  Result := FC2Pnb176w1;
end;

class function TX9ObjectIdentifiers.GetC2Pnb208w1: IDerObjectIdentifier;
begin
  Result := FC2Pnb208w1;
end;

class function TX9ObjectIdentifiers.GetC2Pnb272w1: IDerObjectIdentifier;
begin
  Result := FC2Pnb272w1;
end;

class function TX9ObjectIdentifiers.GetC2Pnb304w1: IDerObjectIdentifier;
begin
  Result := FC2Pnb304w1;
end;

class function TX9ObjectIdentifiers.GetC2Pnb368w1: IDerObjectIdentifier;
begin
  Result := FC2Pnb368w1;
end;

class function TX9ObjectIdentifiers.GetC2Tnb191v1: IDerObjectIdentifier;
begin
  Result := FC2Tnb191v1;
end;

class function TX9ObjectIdentifiers.GetC2Tnb191v2: IDerObjectIdentifier;
begin
  Result := FC2Tnb191v2;
end;

class function TX9ObjectIdentifiers.GetC2Tnb191v3: IDerObjectIdentifier;
begin
  Result := FC2Tnb191v3;
end;

class function TX9ObjectIdentifiers.GetC2Tnb239v1: IDerObjectIdentifier;
begin
  Result := FC2Tnb239v1;
end;

class function TX9ObjectIdentifiers.GetC2Tnb239v2: IDerObjectIdentifier;
begin
  Result := FC2Tnb239v2;
end;

class function TX9ObjectIdentifiers.GetC2Tnb239v3: IDerObjectIdentifier;
begin
  Result := FC2Tnb239v3;
end;

class function TX9ObjectIdentifiers.GetC2Tnb359v1: IDerObjectIdentifier;
begin
  Result := FC2Tnb359v1;
end;

class function TX9ObjectIdentifiers.GetC2Tnb431r1: IDerObjectIdentifier;
begin
  Result := FC2Tnb431r1;
end;

class function TX9ObjectIdentifiers.GetCharacteristicTwoField: IDerObjectIdentifier;
begin
  Result := FCharacteristicTwoField;
end;

class function TX9ObjectIdentifiers.GetCTwoCurve: IDerObjectIdentifier;
begin
  Result := FCTwoCurve;
end;

class function TX9ObjectIdentifiers.GetDHHybrid1: IDerObjectIdentifier;
begin
  Result := FDHHybrid1;
end;

class function TX9ObjectIdentifiers.GetDHHybrid2: IDerObjectIdentifier;
begin
  Result := FDHHybrid2;
end;

class function TX9ObjectIdentifiers.GetDHHybridOneFlow: IDerObjectIdentifier;
begin
  Result := FDHHybridOneFlow;
end;

class function TX9ObjectIdentifiers.GetDHEphem: IDerObjectIdentifier;
begin
  Result := FDHEphem;
end;

class function TX9ObjectIdentifiers.GetDHOneFlow: IDerObjectIdentifier;
begin
  Result := FDHOneFlow;
end;

class function TX9ObjectIdentifiers.GetDHPublicNumber: IDerObjectIdentifier;
begin
  Result := FDHPublicNumber;
end;

class function TX9ObjectIdentifiers.GetDHSinglePassCofactorDHSha1KdfScheme: IDerObjectIdentifier;
begin
  Result := FDHSinglePassCofactorDHSha1KdfScheme;
end;

class function TX9ObjectIdentifiers.GetDHSinglePassStdDHSha1KdfScheme: IDerObjectIdentifier;
begin
  Result := FDHSinglePassStdDHSha1KdfScheme;
end;

class function TX9ObjectIdentifiers.GetDHStatic: IDerObjectIdentifier;
begin
  Result := FDHStatic;
end;

class function TX9ObjectIdentifiers.GetECDsaWithSha1: IDerObjectIdentifier;
begin
  Result := FECDsaWithSha1;
end;

class function TX9ObjectIdentifiers.GetECDsaWithSha224: IDerObjectIdentifier;
begin
  Result := FECDsaWithSha224;
end;

class function TX9ObjectIdentifiers.GetECDsaWithSha256: IDerObjectIdentifier;
begin
  Result := FECDsaWithSha256;
end;

class function TX9ObjectIdentifiers.GetECDsaWithSha384: IDerObjectIdentifier;
begin
  Result := FECDsaWithSha384;
end;

class function TX9ObjectIdentifiers.GetECDsaWithSha512: IDerObjectIdentifier;
begin
  Result := FECDsaWithSha512;
end;

class function TX9ObjectIdentifiers.GetECDsaWithSha2: IDerObjectIdentifier;
begin
  Result := FECDsaWithSha2;
end;

class function TX9ObjectIdentifiers.GetEllipticCurve: IDerObjectIdentifier;
begin
  Result := FEllipticCurve;
end;

class function TX9ObjectIdentifiers.GetGNBasis: IDerObjectIdentifier;
begin
  Result := FGNBasis;
end;

class function TX9ObjectIdentifiers.GetIdDsa: IDerObjectIdentifier;
begin
  Result := FIdDsa;
end;

class function TX9ObjectIdentifiers.GetIdDsaWithSha1: IDerObjectIdentifier;
begin
  Result := FIdDsaWithSha1;
end;

class function TX9ObjectIdentifiers.GetIdEcSigType: IDerObjectIdentifier;
begin
  Result := FIdEcSigType;
end;

class function TX9ObjectIdentifiers.GetIdECPublicKey: IDerObjectIdentifier;
begin
  Result := FIdECPublicKey;
end;

class function TX9ObjectIdentifiers.GetIdFieldType: IDerObjectIdentifier;
begin
  Result := FIdFieldType;
end;

class function TX9ObjectIdentifiers.GetIdPublicKeyType: IDerObjectIdentifier;
begin
  Result := FIdPublicKeyType;
end;

class function TX9ObjectIdentifiers.GetMqv1: IDerObjectIdentifier;
begin
  Result := FMqv1;
end;

class function TX9ObjectIdentifiers.GetMqv2: IDerObjectIdentifier;
begin
  Result := FMqv2;
end;

class function TX9ObjectIdentifiers.GetMqvSinglePassSha1KdfScheme: IDerObjectIdentifier;
begin
  Result := FMqvSinglePassSha1KdfScheme;
end;

class function TX9ObjectIdentifiers.GetPPBasis: IDerObjectIdentifier;
begin
  Result := FPPBasis;
end;

class function TX9ObjectIdentifiers.GetPrime192v1: IDerObjectIdentifier;
begin
  Result := FPrime192v1;
end;

class function TX9ObjectIdentifiers.GetPrime192v2: IDerObjectIdentifier;
begin
  Result := FPrime192v2;
end;

class function TX9ObjectIdentifiers.GetPrime192v3: IDerObjectIdentifier;
begin
  Result := FPrime192v3;
end;

class function TX9ObjectIdentifiers.GetPrime239v1: IDerObjectIdentifier;
begin
  Result := FPrime239v1;
end;

class function TX9ObjectIdentifiers.GetPrime239v2: IDerObjectIdentifier;
begin
  Result := FPrime239v2;
end;

class function TX9ObjectIdentifiers.GetPrime239v3: IDerObjectIdentifier;
begin
  Result := FPrime239v3;
end;

class function TX9ObjectIdentifiers.GetPrime256v1: IDerObjectIdentifier;
begin
  Result := FPrime256v1;
end;

class function TX9ObjectIdentifiers.GetPrimeCurve: IDerObjectIdentifier;
begin
  Result := FPrimeCurve;
end;

class function TX9ObjectIdentifiers.GetPrimeField: IDerObjectIdentifier;
begin
  Result := FPrimeField;
end;

class function TX9ObjectIdentifiers.GetTPBasis: IDerObjectIdentifier;
begin
  Result := FTPBasis;
end;

class function TX9ObjectIdentifiers.GetX9x42Schemes: IDerObjectIdentifier;
begin
  Result := FX9x42Schemes;
end;

class function TX9ObjectIdentifiers.GetX9x63Scheme: IDerObjectIdentifier;
begin
  Result := FX9x63Scheme;
end;

end.
