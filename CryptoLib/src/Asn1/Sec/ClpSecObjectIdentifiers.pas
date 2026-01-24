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

unit ClpSecObjectIdentifiers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpX9ObjectIdentifiers;

type
  /// <summary>EllipticCurve OBJECT IDENTIFIER ::= { iso(1) identified-organization(3) certicom(132) curve(0) }</summary>
  TSecObjectIdentifiers = class abstract(TObject)
  strict private
    class var
      FIsBooted: Boolean;
      FEllipticCurve, FSecT163k1, FSecT163r1, FSecT239k1, FSecT113r1, FSecT113r2,
      FSecP112r1, FSecP112r2, FSecP160r1, FSecP160k1, FSecP256k1, FSecT163r2,
      FSecT283k1, FSecT283r1, FSecT131r1, FSecT131r2, FSecT193r1, FSecT193r2,
      FSecT233k1, FSecT233r1, FSecP128r1, FSecP128r2, FSecP160r2, FSecP192k1,
      FSecP224k1, FSecP224r1, FSecP384r1, FSecP521r1, FSecT409k1, FSecT409r1,
      FSecT571k1, FSecT571r1, FSecP192r1, FSecP256r1, FSecgScheme,
      FDhSinglePassStdDHSha224KdfScheme, FDhSinglePassStdDHSha256KdfScheme,
      FDhSinglePassStdDHSha384KdfScheme, FDhSinglePassStdDHSha512KdfScheme,
      FDhSinglePassCofactorDHSha224KdfScheme, FDhSinglePassCofactorDHSha256KdfScheme,
      FDhSinglePassCofactorDHSha384KdfScheme, FDhSinglePassCofactorDHSha512KdfScheme,
      FMqvSinglePassSha224KdfScheme, FMqvSinglePassSha256KdfScheme,
      FMqvSinglePassSha384KdfScheme, FMqvSinglePassSha512KdfScheme,
      FMqvFullSha224KdfScheme, FMqvFullSha256KdfScheme, FMqvFullSha384KdfScheme,
      FMqvFullSha512KdfScheme: IDerObjectIdentifier;

    class function GetEllipticCurve: IDerObjectIdentifier; static; inline;
    class function GetSecT163k1: IDerObjectIdentifier; static; inline;
    class function GetSecT163r1: IDerObjectIdentifier; static; inline;
    class function GetSecT239k1: IDerObjectIdentifier; static; inline;
    class function GetSecT113r1: IDerObjectIdentifier; static; inline;
    class function GetSecT113r2: IDerObjectIdentifier; static; inline;
    class function GetSecP112r1: IDerObjectIdentifier; static; inline;
    class function GetSecP112r2: IDerObjectIdentifier; static; inline;
    class function GetSecP160r1: IDerObjectIdentifier; static; inline;
    class function GetSecP160k1: IDerObjectIdentifier; static; inline;
    class function GetSecP256k1: IDerObjectIdentifier; static; inline;
    class function GetSecT163r2: IDerObjectIdentifier; static; inline;
    class function GetSecT283k1: IDerObjectIdentifier; static; inline;
    class function GetSecT283r1: IDerObjectIdentifier; static; inline;
    class function GetSecT131r1: IDerObjectIdentifier; static; inline;
    class function GetSecT131r2: IDerObjectIdentifier; static; inline;
    class function GetSecT193r1: IDerObjectIdentifier; static; inline;
    class function GetSecT193r2: IDerObjectIdentifier; static; inline;
    class function GetSecT233k1: IDerObjectIdentifier; static; inline;
    class function GetSecT233r1: IDerObjectIdentifier; static; inline;
    class function GetSecP128r1: IDerObjectIdentifier; static; inline;
    class function GetSecP128r2: IDerObjectIdentifier; static; inline;
    class function GetSecP160r2: IDerObjectIdentifier; static; inline;
    class function GetSecP192k1: IDerObjectIdentifier; static; inline;
    class function GetSecP224k1: IDerObjectIdentifier; static; inline;
    class function GetSecP224r1: IDerObjectIdentifier; static; inline;
    class function GetSecP384r1: IDerObjectIdentifier; static; inline;
    class function GetSecP521r1: IDerObjectIdentifier; static; inline;
    class function GetSecT409k1: IDerObjectIdentifier; static; inline;
    class function GetSecT409r1: IDerObjectIdentifier; static; inline;
    class function GetSecT571k1: IDerObjectIdentifier; static; inline;
    class function GetSecT571r1: IDerObjectIdentifier; static; inline;
    class function GetSecP192r1: IDerObjectIdentifier; static; inline;
    class function GetSecP256r1: IDerObjectIdentifier; static; inline;
    class function GetSecgScheme: IDerObjectIdentifier; static; inline;
    class function GetDhSinglePassStdDHSha224KdfScheme: IDerObjectIdentifier; static; inline;
    class function GetDhSinglePassStdDHSha256KdfScheme: IDerObjectIdentifier; static; inline;
    class function GetDhSinglePassStdDHSha384KdfScheme: IDerObjectIdentifier; static; inline;
    class function GetDhSinglePassStdDHSha512KdfScheme: IDerObjectIdentifier; static; inline;
    class function GetDhSinglePassCofactorDHSha224KdfScheme: IDerObjectIdentifier; static; inline;
    class function GetDhSinglePassCofactorDHSha256KdfScheme: IDerObjectIdentifier; static; inline;
    class function GetDhSinglePassCofactorDHSha384KdfScheme: IDerObjectIdentifier; static; inline;
    class function GetDhSinglePassCofactorDHSha512KdfScheme: IDerObjectIdentifier; static; inline;
    class function GetMqvSinglePassSha224KdfScheme: IDerObjectIdentifier; static; inline;
    class function GetMqvSinglePassSha256KdfScheme: IDerObjectIdentifier; static; inline;
    class function GetMqvSinglePassSha384KdfScheme: IDerObjectIdentifier; static; inline;
    class function GetMqvSinglePassSha512KdfScheme: IDerObjectIdentifier; static; inline;
    class function GetMqvFullSha224KdfScheme: IDerObjectIdentifier; static; inline;
    class function GetMqvFullSha256KdfScheme: IDerObjectIdentifier; static; inline;
    class function GetMqvFullSha384KdfScheme: IDerObjectIdentifier; static; inline;
    class function GetMqvFullSha512KdfScheme: IDerObjectIdentifier; static; inline;

    class constructor Create;
  public
    class property EllipticCurve: IDerObjectIdentifier read GetEllipticCurve;
    class property SecT163k1: IDerObjectIdentifier read GetSecT163k1;
    class property SecT163r1: IDerObjectIdentifier read GetSecT163r1;
    class property SecT239k1: IDerObjectIdentifier read GetSecT239k1;
    class property SecT113r1: IDerObjectIdentifier read GetSecT113r1;
    class property SecT113r2: IDerObjectIdentifier read GetSecT113r2;
    class property SecP112r1: IDerObjectIdentifier read GetSecP112r1;
    class property SecP112r2: IDerObjectIdentifier read GetSecP112r2;
    class property SecP160r1: IDerObjectIdentifier read GetSecP160r1;
    class property SecP160k1: IDerObjectIdentifier read GetSecP160k1;
    class property SecP256k1: IDerObjectIdentifier read GetSecP256k1;
    class property SecT163r2: IDerObjectIdentifier read GetSecT163r2;
    class property SecT283k1: IDerObjectIdentifier read GetSecT283k1;
    class property SecT283r1: IDerObjectIdentifier read GetSecT283r1;
    class property SecT131r1: IDerObjectIdentifier read GetSecT131r1;
    class property SecT131r2: IDerObjectIdentifier read GetSecT131r2;
    class property SecT193r1: IDerObjectIdentifier read GetSecT193r1;
    class property SecT193r2: IDerObjectIdentifier read GetSecT193r2;
    class property SecT233k1: IDerObjectIdentifier read GetSecT233k1;
    class property SecT233r1: IDerObjectIdentifier read GetSecT233r1;
    class property SecP128r1: IDerObjectIdentifier read GetSecP128r1;
    class property SecP128r2: IDerObjectIdentifier read GetSecP128r2;
    class property SecP160r2: IDerObjectIdentifier read GetSecP160r2;
    class property SecP192k1: IDerObjectIdentifier read GetSecP192k1;
    class property SecP224k1: IDerObjectIdentifier read GetSecP224k1;
    class property SecP224r1: IDerObjectIdentifier read GetSecP224r1;
    class property SecP384r1: IDerObjectIdentifier read GetSecP384r1;
    class property SecP521r1: IDerObjectIdentifier read GetSecP521r1;
    class property SecT409k1: IDerObjectIdentifier read GetSecT409k1;
    class property SecT409r1: IDerObjectIdentifier read GetSecT409r1;
    class property SecT571k1: IDerObjectIdentifier read GetSecT571k1;
    class property SecT571r1: IDerObjectIdentifier read GetSecT571r1;
    class property SecP192r1: IDerObjectIdentifier read GetSecP192r1;
    class property SecP256r1: IDerObjectIdentifier read GetSecP256r1;
    class property SecgScheme: IDerObjectIdentifier read GetSecgScheme;
    class property DhSinglePassStdDHSha224KdfScheme: IDerObjectIdentifier read GetDhSinglePassStdDHSha224KdfScheme;
    class property DhSinglePassStdDHSha256KdfScheme: IDerObjectIdentifier read GetDhSinglePassStdDHSha256KdfScheme;
    class property DhSinglePassStdDHSha384KdfScheme: IDerObjectIdentifier read GetDhSinglePassStdDHSha384KdfScheme;
    class property DhSinglePassStdDHSha512KdfScheme: IDerObjectIdentifier read GetDhSinglePassStdDHSha512KdfScheme;
    class property DhSinglePassCofactorDHSha224KdfScheme: IDerObjectIdentifier read GetDhSinglePassCofactorDHSha224KdfScheme;
    class property DhSinglePassCofactorDHSha256KdfScheme: IDerObjectIdentifier read GetDhSinglePassCofactorDHSha256KdfScheme;
    class property DhSinglePassCofactorDHSha384KdfScheme: IDerObjectIdentifier read GetDhSinglePassCofactorDHSha384KdfScheme;
    class property DhSinglePassCofactorDHSha512KdfScheme: IDerObjectIdentifier read GetDhSinglePassCofactorDHSha512KdfScheme;
    class property MqvSinglePassSha224KdfScheme: IDerObjectIdentifier read GetMqvSinglePassSha224KdfScheme;
    class property MqvSinglePassSha256KdfScheme: IDerObjectIdentifier read GetMqvSinglePassSha256KdfScheme;
    class property MqvSinglePassSha384KdfScheme: IDerObjectIdentifier read GetMqvSinglePassSha384KdfScheme;
    class property MqvSinglePassSha512KdfScheme: IDerObjectIdentifier read GetMqvSinglePassSha512KdfScheme;
    class property MqvFullSha224KdfScheme: IDerObjectIdentifier read GetMqvFullSha224KdfScheme;
    class property MqvFullSha256KdfScheme: IDerObjectIdentifier read GetMqvFullSha256KdfScheme;
    class property MqvFullSha384KdfScheme: IDerObjectIdentifier read GetMqvFullSha384KdfScheme;
    class property MqvFullSha512KdfScheme: IDerObjectIdentifier read GetMqvFullSha512KdfScheme;

    class procedure Boot; static;
  end;

implementation

{ TSecObjectIdentifiers }

class constructor TSecObjectIdentifiers.Create;
begin
  Boot;
end;

class procedure TSecObjectIdentifiers.Boot;
begin
  if not FIsBooted then
  begin
    TX9ObjectIdentifiers.Boot;

    FEllipticCurve := TDerObjectIdentifier.Create('1.3.132.0');
    FSecT163k1 := FEllipticCurve.Branch('1');
    FSecT163r1 := FEllipticCurve.Branch('2');
    FSecT239k1 := FEllipticCurve.Branch('3');
    FSecT113r1 := FEllipticCurve.Branch('4');
    FSecT113r2 := FEllipticCurve.Branch('5');
    FSecP112r1 := FEllipticCurve.Branch('6');
    FSecP112r2 := FEllipticCurve.Branch('7');
    FSecP160r1 := FEllipticCurve.Branch('8');
    FSecP160k1 := FEllipticCurve.Branch('9');
    FSecP256k1 := FEllipticCurve.Branch('10');
    FSecT163r2 := FEllipticCurve.Branch('15');
    FSecT283k1 := FEllipticCurve.Branch('16');
    FSecT283r1 := FEllipticCurve.Branch('17');
    FSecT131r1 := FEllipticCurve.Branch('22');
    FSecT131r2 := FEllipticCurve.Branch('23');
    FSecT193r1 := FEllipticCurve.Branch('24');
    FSecT193r2 := FEllipticCurve.Branch('25');
    FSecT233k1 := FEllipticCurve.Branch('26');
    FSecT233r1 := FEllipticCurve.Branch('27');
    FSecP128r1 := FEllipticCurve.Branch('28');
    FSecP128r2 := FEllipticCurve.Branch('29');
    FSecP160r2 := FEllipticCurve.Branch('30');
    FSecP192k1 := FEllipticCurve.Branch('31');
    FSecP224k1 := FEllipticCurve.Branch('32');
    FSecP224r1 := FEllipticCurve.Branch('33');
    FSecP384r1 := FEllipticCurve.Branch('34');
    FSecP521r1 := FEllipticCurve.Branch('35');
    FSecT409k1 := FEllipticCurve.Branch('36');
    FSecT409r1 := FEllipticCurve.Branch('37');
    FSecT571k1 := FEllipticCurve.Branch('38');
    FSecT571r1 := FEllipticCurve.Branch('39');

    FSecP192r1 := TX9ObjectIdentifiers.Prime192v1;
    FSecP256r1 := TX9ObjectIdentifiers.Prime256v1;

    FSecgScheme := TDerObjectIdentifier.Create('1.3.132.1');
    FDhSinglePassStdDHSha224KdfScheme := FSecgScheme.Branch('11.0');
    FDhSinglePassStdDHSha256KdfScheme := FSecgScheme.Branch('11.1');
    FDhSinglePassStdDHSha384KdfScheme := FSecgScheme.Branch('11.2');
    FDhSinglePassStdDHSha512KdfScheme := FSecgScheme.Branch('11.3');
    FDhSinglePassCofactorDHSha224KdfScheme := FSecgScheme.Branch('14.0');
    FDhSinglePassCofactorDHSha256KdfScheme := FSecgScheme.Branch('14.1');
    FDhSinglePassCofactorDHSha384KdfScheme := FSecgScheme.Branch('14.2');
    FDhSinglePassCofactorDHSha512KdfScheme := FSecgScheme.Branch('14.3');
    FMqvSinglePassSha224KdfScheme := FSecgScheme.Branch('15.0');
    FMqvSinglePassSha256KdfScheme := FSecgScheme.Branch('15.1');
    FMqvSinglePassSha384KdfScheme := FSecgScheme.Branch('15.2');
    FMqvSinglePassSha512KdfScheme := FSecgScheme.Branch('15.3');
    FMqvFullSha224KdfScheme := FSecgScheme.Branch('16.0');
    FMqvFullSha256KdfScheme := FSecgScheme.Branch('16.1');
    FMqvFullSha384KdfScheme := FSecgScheme.Branch('16.2');
    FMqvFullSha512KdfScheme := FSecgScheme.Branch('16.3');

    FIsBooted := True;
  end;
end;

class function TSecObjectIdentifiers.GetDhSinglePassCofactorDHSha224KdfScheme: IDerObjectIdentifier;
begin
  Result := FDhSinglePassCofactorDHSha224KdfScheme;
end;

class function TSecObjectIdentifiers.GetDhSinglePassCofactorDHSha256KdfScheme: IDerObjectIdentifier;
begin
  Result := FDhSinglePassCofactorDHSha256KdfScheme;
end;

class function TSecObjectIdentifiers.GetDhSinglePassCofactorDHSha384KdfScheme: IDerObjectIdentifier;
begin
  Result := FDhSinglePassCofactorDHSha384KdfScheme;
end;

class function TSecObjectIdentifiers.GetDhSinglePassCofactorDHSha512KdfScheme: IDerObjectIdentifier;
begin
  Result := FDhSinglePassCofactorDHSha512KdfScheme;
end;

class function TSecObjectIdentifiers.GetDhSinglePassStdDHSha224KdfScheme: IDerObjectIdentifier;
begin
  Result := FDhSinglePassStdDHSha224KdfScheme;
end;

class function TSecObjectIdentifiers.GetDhSinglePassStdDHSha256KdfScheme: IDerObjectIdentifier;
begin
  Result := FDhSinglePassStdDHSha256KdfScheme;
end;

class function TSecObjectIdentifiers.GetDhSinglePassStdDHSha384KdfScheme: IDerObjectIdentifier;
begin
  Result := FDhSinglePassStdDHSha384KdfScheme;
end;

class function TSecObjectIdentifiers.GetDhSinglePassStdDHSha512KdfScheme: IDerObjectIdentifier;
begin
  Result := FDhSinglePassStdDHSha512KdfScheme;
end;

class function TSecObjectIdentifiers.GetEllipticCurve: IDerObjectIdentifier;
begin
  Result := FEllipticCurve;
end;

class function TSecObjectIdentifiers.GetMqvFullSha224KdfScheme: IDerObjectIdentifier;
begin
  Result := FMqvFullSha224KdfScheme;
end;

class function TSecObjectIdentifiers.GetMqvFullSha256KdfScheme: IDerObjectIdentifier;
begin
  Result := FMqvFullSha256KdfScheme;
end;

class function TSecObjectIdentifiers.GetMqvFullSha384KdfScheme: IDerObjectIdentifier;
begin
  Result := FMqvFullSha384KdfScheme;
end;

class function TSecObjectIdentifiers.GetMqvFullSha512KdfScheme: IDerObjectIdentifier;
begin
  Result := FMqvFullSha512KdfScheme;
end;

class function TSecObjectIdentifiers.GetMqvSinglePassSha224KdfScheme: IDerObjectIdentifier;
begin
  Result := FMqvSinglePassSha224KdfScheme;
end;

class function TSecObjectIdentifiers.GetMqvSinglePassSha256KdfScheme: IDerObjectIdentifier;
begin
  Result := FMqvSinglePassSha256KdfScheme;
end;

class function TSecObjectIdentifiers.GetMqvSinglePassSha384KdfScheme: IDerObjectIdentifier;
begin
  Result := FMqvSinglePassSha384KdfScheme;
end;

class function TSecObjectIdentifiers.GetMqvSinglePassSha512KdfScheme: IDerObjectIdentifier;
begin
  Result := FMqvSinglePassSha512KdfScheme;
end;

class function TSecObjectIdentifiers.GetSecgScheme: IDerObjectIdentifier;
begin
  Result := FSecgScheme;
end;

class function TSecObjectIdentifiers.GetSecP112r1: IDerObjectIdentifier;
begin
  Result := FSecP112r1;
end;

class function TSecObjectIdentifiers.GetSecP112r2: IDerObjectIdentifier;
begin
  Result := FSecP112r2;
end;

class function TSecObjectIdentifiers.GetSecP128r1: IDerObjectIdentifier;
begin
  Result := FSecP128r1;
end;

class function TSecObjectIdentifiers.GetSecP128r2: IDerObjectIdentifier;
begin
  Result := FSecP128r2;
end;

class function TSecObjectIdentifiers.GetSecP160k1: IDerObjectIdentifier;
begin
  Result := FSecP160k1;
end;

class function TSecObjectIdentifiers.GetSecP160r1: IDerObjectIdentifier;
begin
  Result := FSecP160r1;
end;

class function TSecObjectIdentifiers.GetSecP160r2: IDerObjectIdentifier;
begin
  Result := FSecP160r2;
end;

class function TSecObjectIdentifiers.GetSecP192k1: IDerObjectIdentifier;
begin
  Result := FSecP192k1;
end;

class function TSecObjectIdentifiers.GetSecP192r1: IDerObjectIdentifier;
begin
  Result := FSecP192r1;
end;

class function TSecObjectIdentifiers.GetSecP224k1: IDerObjectIdentifier;
begin
  Result := FSecP224k1;
end;

class function TSecObjectIdentifiers.GetSecP224r1: IDerObjectIdentifier;
begin
  Result := FSecP224r1;
end;

class function TSecObjectIdentifiers.GetSecP256k1: IDerObjectIdentifier;
begin
  Result := FSecP256k1;
end;

class function TSecObjectIdentifiers.GetSecP256r1: IDerObjectIdentifier;
begin
  Result := FSecP256r1;
end;

class function TSecObjectIdentifiers.GetSecP384r1: IDerObjectIdentifier;
begin
  Result := FSecP384r1;
end;

class function TSecObjectIdentifiers.GetSecP521r1: IDerObjectIdentifier;
begin
  Result := FSecP521r1;
end;

class function TSecObjectIdentifiers.GetSecT113r1: IDerObjectIdentifier;
begin
  Result := FSecT113r1;
end;

class function TSecObjectIdentifiers.GetSecT113r2: IDerObjectIdentifier;
begin
  Result := FSecT113r2;
end;

class function TSecObjectIdentifiers.GetSecT131r1: IDerObjectIdentifier;
begin
  Result := FSecT131r1;
end;

class function TSecObjectIdentifiers.GetSecT131r2: IDerObjectIdentifier;
begin
  Result := FSecT131r2;
end;

class function TSecObjectIdentifiers.GetSecT163k1: IDerObjectIdentifier;
begin
  Result := FSecT163k1;
end;

class function TSecObjectIdentifiers.GetSecT163r1: IDerObjectIdentifier;
begin
  Result := FSecT163r1;
end;

class function TSecObjectIdentifiers.GetSecT163r2: IDerObjectIdentifier;
begin
  Result := FSecT163r2;
end;

class function TSecObjectIdentifiers.GetSecT193r1: IDerObjectIdentifier;
begin
  Result := FSecT193r1;
end;

class function TSecObjectIdentifiers.GetSecT193r2: IDerObjectIdentifier;
begin
  Result := FSecT193r2;
end;

class function TSecObjectIdentifiers.GetSecT233k1: IDerObjectIdentifier;
begin
  Result := FSecT233k1;
end;

class function TSecObjectIdentifiers.GetSecT233r1: IDerObjectIdentifier;
begin
  Result := FSecT233r1;
end;

class function TSecObjectIdentifiers.GetSecT239k1: IDerObjectIdentifier;
begin
  Result := FSecT239k1;
end;

class function TSecObjectIdentifiers.GetSecT283k1: IDerObjectIdentifier;
begin
  Result := FSecT283k1;
end;

class function TSecObjectIdentifiers.GetSecT283r1: IDerObjectIdentifier;
begin
  Result := FSecT283r1;
end;

class function TSecObjectIdentifiers.GetSecT409k1: IDerObjectIdentifier;
begin
  Result := FSecT409k1;
end;

class function TSecObjectIdentifiers.GetSecT409r1: IDerObjectIdentifier;
begin
  Result := FSecT409r1;
end;

class function TSecObjectIdentifiers.GetSecT571k1: IDerObjectIdentifier;
begin
  Result := FSecT571k1;
end;

class function TSecObjectIdentifiers.GetSecT571r1: IDerObjectIdentifier;
begin
  Result := FSecT571r1;
end;

end.
