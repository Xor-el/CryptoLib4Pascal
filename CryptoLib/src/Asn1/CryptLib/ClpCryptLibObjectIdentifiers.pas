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

unit ClpCryptLibObjectIdentifiers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsn1Objects,
  ClpIAsn1Objects;

type
  TCryptLibObjectIdentifiers = class abstract(TObject)
  strict private
    class var
      FIsBooted: Boolean;
      FCryptlib, FEcc, FCurvey25519: IDerObjectIdentifier;

    class function GetCryptlib: IDerObjectIdentifier; static; inline;
    class function GetEcc: IDerObjectIdentifier; static; inline;
    class function GetCurvey25519: IDerObjectIdentifier; static; inline;

    class constructor Create;
  public
    class property Cryptlib: IDerObjectIdentifier read GetCryptlib;
    class property Ecc: IDerObjectIdentifier read GetEcc;
    class property Curvey25519: IDerObjectIdentifier read GetCurvey25519;

    class procedure Boot; static;
  end;

implementation

{ TCryptLibObjectIdentifiers }

class constructor TCryptLibObjectIdentifiers.Create;
begin
  Boot;
end;

class procedure TCryptLibObjectIdentifiers.Boot;
begin
  if not FIsBooted then
  begin
    FCryptlib := TDerObjectIdentifier.Create('1.3.6.1.4.1.3029');
    FEcc := FCryptlib.Branch('1.5');
    FCurvey25519 := FEcc.Branch('1');

    FIsBooted := True;
  end;
end;

class function TCryptLibObjectIdentifiers.GetCryptlib: IDerObjectIdentifier;
begin
  Result := FCryptlib;
end;

class function TCryptLibObjectIdentifiers.GetCurvey25519: IDerObjectIdentifier;
begin
  Result := FCurvey25519;
end;

class function TCryptLibObjectIdentifiers.GetEcc: IDerObjectIdentifier;
begin
  Result := FEcc;
end;

end.
