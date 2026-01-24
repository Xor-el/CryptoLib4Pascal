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

unit ClpEacObjectIdentifiers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsn1Objects,
  ClpBsiObjectIdentifiers,
  ClpIAsn1Objects;

type
  TEacObjectIdentifiers = class abstract(TObject)
  strict private
    class var
      FIsBooted: Boolean;
      FBsiDe, FIdPK, FIdPKDH, FIdPKECDH, FIdCA, FIdCADH, FIdCADH3DesCbcCbc,
      FIdCAECDH, FIdCAECDH3DesCbcCbc, FIdTA, FIdTARsa, FIdTARsaV1_5Sha1,
      FIdTARsaV1_5Sha256, FIdTARsaPssSha1, FIdTARsaPssSha256, FIdTAEcdsa,
      FIdTAEcdsaSha1, FIdTAEcdsaSha224, FIdTAEcdsaSha256, FIdTAEcdsaSha384,
      FIdTAEcdsaSha512: IDerObjectIdentifier;

    class function GetBsiDe: IDerObjectIdentifier; static; inline;
    class function GetIdPK: IDerObjectIdentifier; static; inline;
    class function GetIdPKDH: IDerObjectIdentifier; static; inline;
    class function GetIdPKECDH: IDerObjectIdentifier; static; inline;
    class function GetIdCA: IDerObjectIdentifier; static; inline;
    class function GetIdCADH: IDerObjectIdentifier; static; inline;
    class function GetIdCADH3DesCbcCbc: IDerObjectIdentifier; static; inline;
    class function GetIdCAECDH: IDerObjectIdentifier; static; inline;
    class function GetIdCAECDH3DesCbcCbc: IDerObjectIdentifier; static; inline;
    class function GetIdTA: IDerObjectIdentifier; static; inline;
    class function GetIdTARsa: IDerObjectIdentifier; static; inline;
    class function GetIdTARsaV1_5Sha1: IDerObjectIdentifier; static; inline;
    class function GetIdTARsaV1_5Sha256: IDerObjectIdentifier; static; inline;
    class function GetIdTARsaPssSha1: IDerObjectIdentifier; static; inline;
    class function GetIdTARsaPssSha256: IDerObjectIdentifier; static; inline;
    class function GetIdTAEcdsa: IDerObjectIdentifier; static; inline;
    class function GetIdTAEcdsaSha1: IDerObjectIdentifier; static; inline;
    class function GetIdTAEcdsaSha224: IDerObjectIdentifier; static; inline;
    class function GetIdTAEcdsaSha256: IDerObjectIdentifier; static; inline;
    class function GetIdTAEcdsaSha384: IDerObjectIdentifier; static; inline;
    class function GetIdTAEcdsaSha512: IDerObjectIdentifier; static; inline;

    class constructor Create;
  public
    /// <summary>bsi-de OBJECT IDENTIFIER ::= { itu-t(0) identified-organization(4) etsi(0) reserved(127) etsi-identified-organization(0) 7 }</summary>
    class property BsiDe: IDerObjectIdentifier read GetBsiDe;
    /// <summary>id-PK ::= { bsi-de protocols(2) smartcard(2) 1 }</summary>
    class property IdPK: IDerObjectIdentifier read GetIdPK;
    class property IdPKDH: IDerObjectIdentifier read GetIdPKDH;
    class property IdPKECDH: IDerObjectIdentifier read GetIdPKECDH;
    /// <summary>id-CA ::= { bsi-de protocols(2) smartcard(2) 3 }</summary>
    class property IdCA: IDerObjectIdentifier read GetIdCA;
    class property IdCADH: IDerObjectIdentifier read GetIdCADH;
    class property IdCADH3DesCbcCbc: IDerObjectIdentifier read GetIdCADH3DesCbcCbc;
    class property IdCAECDH: IDerObjectIdentifier read GetIdCAECDH;
    class property IdCAECDH3DesCbcCbc: IDerObjectIdentifier read GetIdCAECDH3DesCbcCbc;
    /// <summary>id-TA ::= { bsi-de protocols(2) smartcard(2) 2 }</summary>
    class property IdTA: IDerObjectIdentifier read GetIdTA;
    class property IdTARsa: IDerObjectIdentifier read GetIdTARsa;
    class property IdTARsaV1_5Sha1: IDerObjectIdentifier read GetIdTARsaV1_5Sha1;
    class property IdTARsaV1_5Sha256: IDerObjectIdentifier read GetIdTARsaV1_5Sha256;
    class property IdTARsaPssSha1: IDerObjectIdentifier read GetIdTARsaPssSha1;
    class property IdTARsaPssSha256: IDerObjectIdentifier read GetIdTARsaPssSha256;
    class property IdTAEcdsa: IDerObjectIdentifier read GetIdTAEcdsa;
    class property IdTAEcdsaSha1: IDerObjectIdentifier read GetIdTAEcdsaSha1;
    class property IdTAEcdsaSha224: IDerObjectIdentifier read GetIdTAEcdsaSha224;
    class property IdTAEcdsaSha256: IDerObjectIdentifier read GetIdTAEcdsaSha256;
    class property IdTAEcdsaSha384: IDerObjectIdentifier read GetIdTAEcdsaSha384;
    class property IdTAEcdsaSha512: IDerObjectIdentifier read GetIdTAEcdsaSha512;

    class procedure Boot; static;
  end;

implementation

{ TEacObjectIdentifiers }

class constructor TEacObjectIdentifiers.Create;
begin
  Boot;
end;

class procedure TEacObjectIdentifiers.Boot;
begin
  if not FIsBooted then
  begin
    TBsiObjectIdentifiers.Boot;
    FBsiDe := TBsiObjectIdentifiers.BsiDe;
    FIdPK := FBsiDe.Branch('2.2.1');
    FIdPKDH := FIdPK.Branch('1');
    FIdPKECDH := FIdPK.Branch('2');
    FIdCA := FBsiDe.Branch('2.2.3');
    FIdCADH := FIdCA.Branch('1');
    FIdCADH3DesCbcCbc := FIdCADH.Branch('1');
    FIdCAECDH := FIdCA.Branch('2');
    FIdCAECDH3DesCbcCbc := FIdCAECDH.Branch('1');
    FIdTA := FBsiDe.Branch('2.2.2');
    FIdTARsa := FIdTA.Branch('1');
    FIdTARsaV1_5Sha1 := FIdTARsa.Branch('1');
    FIdTARsaV1_5Sha256 := FIdTARsa.Branch('2');
    FIdTARsaPssSha1 := FIdTARsa.Branch('3');
    FIdTARsaPssSha256 := FIdTARsa.Branch('4');
    FIdTAEcdsa := FIdTA.Branch('2');
    FIdTAEcdsaSha1 := FIdTAEcdsa.Branch('1');
    FIdTAEcdsaSha224 := FIdTAEcdsa.Branch('2');
    FIdTAEcdsaSha256 := FIdTAEcdsa.Branch('3');
    FIdTAEcdsaSha384 := FIdTAEcdsa.Branch('4');
    FIdTAEcdsaSha512 := FIdTAEcdsa.Branch('5');

    FIsBooted := True;
  end;
end;

class function TEacObjectIdentifiers.GetBsiDe: IDerObjectIdentifier;
begin
  Result := FBsiDe;
end;

class function TEacObjectIdentifiers.GetIdCA: IDerObjectIdentifier;
begin
  Result := FIdCA;
end;

class function TEacObjectIdentifiers.GetIdCADH: IDerObjectIdentifier;
begin
  Result := FIdCADH;
end;

class function TEacObjectIdentifiers.GetIdCADH3DesCbcCbc: IDerObjectIdentifier;
begin
  Result := FIdCADH3DesCbcCbc;
end;

class function TEacObjectIdentifiers.GetIdCAECDH: IDerObjectIdentifier;
begin
  Result := FIdCAECDH;
end;

class function TEacObjectIdentifiers.GetIdCAECDH3DesCbcCbc: IDerObjectIdentifier;
begin
  Result := FIdCAECDH3DesCbcCbc;
end;

class function TEacObjectIdentifiers.GetIdPK: IDerObjectIdentifier;
begin
  Result := FIdPK;
end;

class function TEacObjectIdentifiers.GetIdPKDH: IDerObjectIdentifier;
begin
  Result := FIdPKDH;
end;

class function TEacObjectIdentifiers.GetIdPKECDH: IDerObjectIdentifier;
begin
  Result := FIdPKECDH;
end;

class function TEacObjectIdentifiers.GetIdTA: IDerObjectIdentifier;
begin
  Result := FIdTA;
end;

class function TEacObjectIdentifiers.GetIdTAEcdsa: IDerObjectIdentifier;
begin
  Result := FIdTAEcdsa;
end;

class function TEacObjectIdentifiers.GetIdTAEcdsaSha1: IDerObjectIdentifier;
begin
  Result := FIdTAEcdsaSha1;
end;

class function TEacObjectIdentifiers.GetIdTAEcdsaSha224: IDerObjectIdentifier;
begin
  Result := FIdTAEcdsaSha224;
end;

class function TEacObjectIdentifiers.GetIdTAEcdsaSha256: IDerObjectIdentifier;
begin
  Result := FIdTAEcdsaSha256;
end;

class function TEacObjectIdentifiers.GetIdTAEcdsaSha384: IDerObjectIdentifier;
begin
  Result := FIdTAEcdsaSha384;
end;

class function TEacObjectIdentifiers.GetIdTAEcdsaSha512: IDerObjectIdentifier;
begin
  Result := FIdTAEcdsaSha512;
end;

class function TEacObjectIdentifiers.GetIdTARsa: IDerObjectIdentifier;
begin
  Result := FIdTARsa;
end;

class function TEacObjectIdentifiers.GetIdTARsaPssSha1: IDerObjectIdentifier;
begin
  Result := FIdTARsaPssSha1;
end;

class function TEacObjectIdentifiers.GetIdTARsaPssSha256: IDerObjectIdentifier;
begin
  Result := FIdTARsaPssSha256;
end;

class function TEacObjectIdentifiers.GetIdTARsaV1_5Sha1: IDerObjectIdentifier;
begin
  Result := FIdTARsaV1_5Sha1;
end;

class function TEacObjectIdentifiers.GetIdTARsaV1_5Sha256: IDerObjectIdentifier;
begin
  Result := FIdTARsaV1_5Sha256;
end;

end.
