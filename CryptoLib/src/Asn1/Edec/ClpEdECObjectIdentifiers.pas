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

unit ClpEdECObjectIdentifiers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsn1Objects,
  ClpIAsn1Objects;

type
  /// <summary>Edwards Elliptic Curve Object Identifiers (RFC 8410)</summary>
  TEdECObjectIdentifiers = class abstract(TObject)
  strict private
    class var
      FIsBooted: Boolean;
      FIdEdwardsCurveAlgs, FIdX25519, FIdX448, FIdEd25519, FIdEd448: IDerObjectIdentifier;

    class function GetIdEdwardsCurveAlgs: IDerObjectIdentifier; static; inline;
    class function GetIdX25519: IDerObjectIdentifier; static; inline;
    class function GetIdX448: IDerObjectIdentifier; static; inline;
    class function GetIdEd25519: IDerObjectIdentifier; static; inline;
    class function GetIdEd448: IDerObjectIdentifier; static; inline;

    class constructor Create;
  public
    class property IdEdwardsCurveAlgs: IDerObjectIdentifier read GetIdEdwardsCurveAlgs;
    class property IdX25519: IDerObjectIdentifier read GetIdX25519;
    class property IdX448: IDerObjectIdentifier read GetIdX448;
    class property IdEd25519: IDerObjectIdentifier read GetIdEd25519;
    class property IdEd448: IDerObjectIdentifier read GetIdEd448;

    class procedure Boot; static;
  end;

implementation

{ TEdECObjectIdentifiers }

class constructor TEdECObjectIdentifiers.Create;
begin
  Boot;
end;

class procedure TEdECObjectIdentifiers.Boot;
begin
  if not FIsBooted then
  begin
    FIdEdwardsCurveAlgs := TDerObjectIdentifier.Create('1.3.101');
    FIdX25519 := FIdEdwardsCurveAlgs.Branch('110');
    FIdX448 := FIdEdwardsCurveAlgs.Branch('111');
    FIdEd25519 := FIdEdwardsCurveAlgs.Branch('112');
    FIdEd448 := FIdEdwardsCurveAlgs.Branch('113');

    FIsBooted := True;
  end;
end;

class function TEdECObjectIdentifiers.GetIdEd448: IDerObjectIdentifier;
begin
  Result := FIdEd448;
end;

class function TEdECObjectIdentifiers.GetIdEd25519: IDerObjectIdentifier;
begin
  Result := FIdEd25519;
end;

class function TEdECObjectIdentifiers.GetIdEdwardsCurveAlgs: IDerObjectIdentifier;
begin
  Result := FIdEdwardsCurveAlgs;
end;

class function TEdECObjectIdentifiers.GetIdX25519: IDerObjectIdentifier;
begin
  Result := FIdX25519;
end;

class function TEdECObjectIdentifiers.GetIdX448: IDerObjectIdentifier;
begin
  Result := FIdX448;
end;

end.
