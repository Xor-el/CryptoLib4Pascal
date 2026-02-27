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

unit ClpRosstandartObjectIdentifiers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsn1Objects,
  ClpIAsn1Objects;

type
  TRosstandartObjectIdentifiers = class abstract(TObject)
  strict private
    class var
      FIsBooted: Boolean;
      FRosstandart, FIdTc26, FIdTc26Gost3411_12_256, FIdTc26Gost3411_12_512,
      FIdTc26HmacGost3411_12_256, FIdTc26HmacGost3411_12_512,
      FIdTc26Gost3410_12_256, FIdTc26Gost3410_12_512,
      FIdTc26SignwithdigestGost3410_12_256, FIdTc26SignwithdigestGost3410_12_512,
      FIdTc26Agreement, FIdTc26AgreementGost3410_12_256, FIdTc26AgreementGost3410_12_512,
      FIdTc26Gost3410_12_256ParamSet, FIdTc26Gost3410_12_256ParamSetA,
      FIdTc26Gost3410_12_256ParamSetB, FIdTc26Gost3410_12_256ParamSetC,
      FIdTc26Gost3410_12_256ParamSetD, FIdTc26Gost3410_12_512ParamSet,
      FIdTc26Gost3410_12_512ParamSetA, FIdTc26Gost3410_12_512ParamSetB,
      FIdTc26Gost3410_12_512ParamSetC, FIdTc26Gost28147ParamZ: IDerObjectIdentifier;

    class function GetRosstandart: IDerObjectIdentifier; static; inline;
    class function GetIdTc26: IDerObjectIdentifier; static; inline;
    class function GetIdTc26Gost3411_12_256: IDerObjectIdentifier; static; inline;
    class function GetIdTc26Gost3411_12_512: IDerObjectIdentifier; static; inline;
    class function GetIdTc26HmacGost3411_12_256: IDerObjectIdentifier; static; inline;
    class function GetIdTc26HmacGost3411_12_512: IDerObjectIdentifier; static; inline;
    class function GetIdTc26Gost3410_12_256: IDerObjectIdentifier; static; inline;
    class function GetIdTc26Gost3410_12_512: IDerObjectIdentifier; static; inline;
    class function GetIdTc26SignwithdigestGost3410_12_256: IDerObjectIdentifier; static; inline;
    class function GetIdTc26SignwithdigestGost3410_12_512: IDerObjectIdentifier; static; inline;
    class function GetIdTc26Agreement: IDerObjectIdentifier; static; inline;
    class function GetIdTc26AgreementGost3410_12_256: IDerObjectIdentifier; static; inline;
    class function GetIdTc26AgreementGost3410_12_512: IDerObjectIdentifier; static; inline;
    class function GetIdTc26Gost3410_12_256ParamSet: IDerObjectIdentifier; static; inline;
    class function GetIdTc26Gost3410_12_256ParamSetA: IDerObjectIdentifier; static; inline;
    class function GetIdTc26Gost3410_12_256ParamSetB: IDerObjectIdentifier; static; inline;
    class function GetIdTc26Gost3410_12_256ParamSetC: IDerObjectIdentifier; static; inline;
    class function GetIdTc26Gost3410_12_256ParamSetD: IDerObjectIdentifier; static; inline;
    class function GetIdTc26Gost3410_12_512ParamSet: IDerObjectIdentifier; static; inline;
    class function GetIdTc26Gost3410_12_512ParamSetA: IDerObjectIdentifier; static; inline;
    class function GetIdTc26Gost3410_12_512ParamSetB: IDerObjectIdentifier; static; inline;
    class function GetIdTc26Gost3410_12_512ParamSetC: IDerObjectIdentifier; static; inline;
    class function GetIdTc26Gost28147ParamZ: IDerObjectIdentifier; static; inline;

    class constructor Create;
  public
    class property Rosstandart: IDerObjectIdentifier read GetRosstandart;
    class property IdTc26: IDerObjectIdentifier read GetIdTc26;
    class property IdTc26Gost3411_12_256: IDerObjectIdentifier read GetIdTc26Gost3411_12_256;
    class property IdTc26Gost3411_12_512: IDerObjectIdentifier read GetIdTc26Gost3411_12_512;
    class property IdTc26HmacGost3411_12_256: IDerObjectIdentifier read GetIdTc26HmacGost3411_12_256;
    class property IdTc26HmacGost3411_12_512: IDerObjectIdentifier read GetIdTc26HmacGost3411_12_512;
    class property IdTc26Gost3410_12_256: IDerObjectIdentifier read GetIdTc26Gost3410_12_256;
    class property IdTc26Gost3410_12_512: IDerObjectIdentifier read GetIdTc26Gost3410_12_512;
    class property IdTc26SignwithdigestGost3410_12_256: IDerObjectIdentifier read GetIdTc26SignwithdigestGost3410_12_256;
    class property IdTc26SignwithdigestGost3410_12_512: IDerObjectIdentifier read GetIdTc26SignwithdigestGost3410_12_512;
    class property IdTc26Agreement: IDerObjectIdentifier read GetIdTc26Agreement;
    class property IdTc26AgreementGost3410_12_256: IDerObjectIdentifier read GetIdTc26AgreementGost3410_12_256;
    class property IdTc26AgreementGost3410_12_512: IDerObjectIdentifier read GetIdTc26AgreementGost3410_12_512;
    class property IdTc26Gost3410_12_256ParamSet: IDerObjectIdentifier read GetIdTc26Gost3410_12_256ParamSet;
    class property IdTc26Gost3410_12_256ParamSetA: IDerObjectIdentifier read GetIdTc26Gost3410_12_256ParamSetA;
    class property IdTc26Gost3410_12_256ParamSetB: IDerObjectIdentifier read GetIdTc26Gost3410_12_256ParamSetB;
    class property IdTc26Gost3410_12_256ParamSetC: IDerObjectIdentifier read GetIdTc26Gost3410_12_256ParamSetC;
    class property IdTc26Gost3410_12_256ParamSetD: IDerObjectIdentifier read GetIdTc26Gost3410_12_256ParamSetD;
    class property IdTc26Gost3410_12_512ParamSet: IDerObjectIdentifier read GetIdTc26Gost3410_12_512ParamSet;
    class property IdTc26Gost3410_12_512ParamSetA: IDerObjectIdentifier read GetIdTc26Gost3410_12_512ParamSetA;
    class property IdTc26Gost3410_12_512ParamSetB: IDerObjectIdentifier read GetIdTc26Gost3410_12_512ParamSetB;
    class property IdTc26Gost3410_12_512ParamSetC: IDerObjectIdentifier read GetIdTc26Gost3410_12_512ParamSetC;
    class property IdTc26Gost28147ParamZ: IDerObjectIdentifier read GetIdTc26Gost28147ParamZ;

    class procedure Boot; static;
  end;

implementation

{ TRosstandartObjectIdentifiers }

class constructor TRosstandartObjectIdentifiers.Create;
begin
  Boot;
end;

class procedure TRosstandartObjectIdentifiers.Boot;
begin
  if not FIsBooted then
  begin
    FRosstandart := TDerObjectIdentifier.Create('1.2.643.7');
    FIdTc26 := FRosstandart.Branch('1');
    FIdTc26Gost3411_12_256 := FIdTc26.Branch('1.2.2');
    FIdTc26Gost3411_12_512 := FIdTc26.Branch('1.2.3');
    FIdTc26HmacGost3411_12_256 := FIdTc26.Branch('1.4.1');
    FIdTc26HmacGost3411_12_512 := FIdTc26.Branch('1.4.2');
    FIdTc26Gost3410_12_256 := FIdTc26.Branch('1.1.1');
    FIdTc26Gost3410_12_512 := FIdTc26.Branch('1.1.2');
    FIdTc26SignwithdigestGost3410_12_256 := FIdTc26.Branch('1.3.2');
    FIdTc26SignwithdigestGost3410_12_512 := FIdTc26.Branch('1.3.3');
    FIdTc26Agreement := FIdTc26.Branch('1.6');
    FIdTc26AgreementGost3410_12_256 := FIdTc26Agreement.Branch('1');
    FIdTc26AgreementGost3410_12_512 := FIdTc26Agreement.Branch('2');
    FIdTc26Gost3410_12_256ParamSet := FIdTc26.Branch('2.1.1');
    FIdTc26Gost3410_12_256ParamSetA := FIdTc26Gost3410_12_256ParamSet.Branch('1');
    FIdTc26Gost3410_12_256ParamSetB := FIdTc26Gost3410_12_256ParamSet.Branch('2');
    FIdTc26Gost3410_12_256ParamSetC := FIdTc26Gost3410_12_256ParamSet.Branch('3');
    FIdTc26Gost3410_12_256ParamSetD := FIdTc26Gost3410_12_256ParamSet.Branch('4');
    FIdTc26Gost3410_12_512ParamSet := FIdTc26.Branch('2.1.2');
    FIdTc26Gost3410_12_512ParamSetA := FIdTc26Gost3410_12_512ParamSet.Branch('1');
    FIdTc26Gost3410_12_512ParamSetB := FIdTc26Gost3410_12_512ParamSet.Branch('2');
    FIdTc26Gost3410_12_512ParamSetC := FIdTc26Gost3410_12_512ParamSet.Branch('3');
    FIdTc26Gost28147ParamZ := FIdTc26.Branch('2.5.1.1');

    FIsBooted := True;
  end;
end;

class function TRosstandartObjectIdentifiers.GetIdTc26: IDerObjectIdentifier;
begin
  Result := FIdTc26;
end;

class function TRosstandartObjectIdentifiers.GetIdTc26Agreement: IDerObjectIdentifier;
begin
  Result := FIdTc26Agreement;
end;

class function TRosstandartObjectIdentifiers.GetIdTc26AgreementGost3410_12_256: IDerObjectIdentifier;
begin
  Result := FIdTc26AgreementGost3410_12_256;
end;

class function TRosstandartObjectIdentifiers.GetIdTc26AgreementGost3410_12_512: IDerObjectIdentifier;
begin
  Result := FIdTc26AgreementGost3410_12_512;
end;

class function TRosstandartObjectIdentifiers.GetIdTc26Gost28147ParamZ: IDerObjectIdentifier;
begin
  Result := FIdTc26Gost28147ParamZ;
end;

class function TRosstandartObjectIdentifiers.GetIdTc26Gost3410_12_256: IDerObjectIdentifier;
begin
  Result := FIdTc26Gost3410_12_256;
end;

class function TRosstandartObjectIdentifiers.GetIdTc26Gost3410_12_256ParamSet: IDerObjectIdentifier;
begin
  Result := FIdTc26Gost3410_12_256ParamSet;
end;

class function TRosstandartObjectIdentifiers.GetIdTc26Gost3410_12_256ParamSetA: IDerObjectIdentifier;
begin
  Result := FIdTc26Gost3410_12_256ParamSetA;
end;

class function TRosstandartObjectIdentifiers.GetIdTc26Gost3410_12_256ParamSetB: IDerObjectIdentifier;
begin
  Result := FIdTc26Gost3410_12_256ParamSetB;
end;

class function TRosstandartObjectIdentifiers.GetIdTc26Gost3410_12_256ParamSetC: IDerObjectIdentifier;
begin
  Result := FIdTc26Gost3410_12_256ParamSetC;
end;

class function TRosstandartObjectIdentifiers.GetIdTc26Gost3410_12_256ParamSetD: IDerObjectIdentifier;
begin
  Result := FIdTc26Gost3410_12_256ParamSetD;
end;

class function TRosstandartObjectIdentifiers.GetIdTc26Gost3410_12_512: IDerObjectIdentifier;
begin
  Result := FIdTc26Gost3410_12_512;
end;

class function TRosstandartObjectIdentifiers.GetIdTc26Gost3410_12_512ParamSet: IDerObjectIdentifier;
begin
  Result := FIdTc26Gost3410_12_512ParamSet;
end;

class function TRosstandartObjectIdentifiers.GetIdTc26Gost3410_12_512ParamSetA: IDerObjectIdentifier;
begin
  Result := FIdTc26Gost3410_12_512ParamSetA;
end;

class function TRosstandartObjectIdentifiers.GetIdTc26Gost3410_12_512ParamSetB: IDerObjectIdentifier;
begin
  Result := FIdTc26Gost3410_12_512ParamSetB;
end;

class function TRosstandartObjectIdentifiers.GetIdTc26Gost3410_12_512ParamSetC: IDerObjectIdentifier;
begin
  Result := FIdTc26Gost3410_12_512ParamSetC;
end;

class function TRosstandartObjectIdentifiers.GetIdTc26Gost3411_12_256: IDerObjectIdentifier;
begin
  Result := FIdTc26Gost3411_12_256;
end;

class function TRosstandartObjectIdentifiers.GetIdTc26Gost3411_12_512: IDerObjectIdentifier;
begin
  Result := FIdTc26Gost3411_12_512;
end;

class function TRosstandartObjectIdentifiers.GetIdTc26HmacGost3411_12_256: IDerObjectIdentifier;
begin
  Result := FIdTc26HmacGost3411_12_256;
end;

class function TRosstandartObjectIdentifiers.GetIdTc26HmacGost3411_12_512: IDerObjectIdentifier;
begin
  Result := FIdTc26HmacGost3411_12_512;
end;

class function TRosstandartObjectIdentifiers.GetIdTc26SignwithdigestGost3410_12_256: IDerObjectIdentifier;
begin
  Result := FIdTc26SignwithdigestGost3410_12_256;
end;

class function TRosstandartObjectIdentifiers.GetIdTc26SignwithdigestGost3410_12_512: IDerObjectIdentifier;
begin
  Result := FIdTc26SignwithdigestGost3410_12_512;
end;

class function TRosstandartObjectIdentifiers.GetRosstandart: IDerObjectIdentifier;
begin
  Result := FRosstandart;
end;

end.
