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

unit ClpCryptoProObjectIdentifiers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsn1Objects,
  ClpIAsn1Objects;

type
  /// <summary>GOST Algorithms OBJECT IDENTIFIERS : { iso(1) member-body(2) ru(643) rans(2) cryptopro(2)}</summary>
  TCryptoProObjectIdentifiers = class abstract(TObject)
  strict private
    class var
      FIsBooted: Boolean;
      FGostId, FGostR3411, FGostR3411Hmac, FIdGost28147_89NoneKeyWrap,
      FIdGost28147_89CryptoProKeyWrap, FGostR28147Gcfb,
      FIdGost28147_89CryptoProTestParamSet, FIdGost28147_89CryptoProAParamSet,
      FIdGost28147_89CryptoProBParamSet, FIdGost28147_89CryptoProCParamSet,
      FIdGost28147_89CryptoProDParamSet, FGostR3410x94, FGostR3410x2001,
      FGostR3411x94WithGostR3410x94, FGostR3411x94WithGostR3410x2001,
      FGostR3411x94CryptoProParamSet, FGostR3410x94CryptoProA,
      FGostR3410x94CryptoProB, FGostR3410x94CryptoProC, FGostR3410x94CryptoProD,
      FGostR3410x94CryptoProXchA, FGostR3410x94CryptoProXchB,
      FGostR3410x94CryptoProXchC, FGostR3410x2001CryptoProA,
      FGostR3410x2001CryptoProB, FGostR3410x2001CryptoProC,
      FGostR3410x2001CryptoProXchA, FGostR3410x2001CryptoProXchB,
      FGostR3410x2001CryptoProESDH, FGostR3410x2001DH: IDerObjectIdentifier;

    class function GetGostId: IDerObjectIdentifier; static; inline;
    class function GetGostR3411: IDerObjectIdentifier; static; inline;
    class function GetGostR3411Hmac: IDerObjectIdentifier; static; inline;
    class function GetIdGost28147_89NoneKeyWrap: IDerObjectIdentifier; static; inline;
    class function GetIdGost28147_89CryptoProKeyWrap: IDerObjectIdentifier; static; inline;
    class function GetGostR28147Gcfb: IDerObjectIdentifier; static; inline;
    class function GetIdGost28147_89CryptoProTestParamSet: IDerObjectIdentifier; static; inline;
    class function GetIdGost28147_89CryptoProAParamSet: IDerObjectIdentifier; static; inline;
    class function GetIdGost28147_89CryptoProBParamSet: IDerObjectIdentifier; static; inline;
    class function GetIdGost28147_89CryptoProCParamSet: IDerObjectIdentifier; static; inline;
    class function GetIdGost28147_89CryptoProDParamSet: IDerObjectIdentifier; static; inline;
    class function GetGostR3410x94: IDerObjectIdentifier; static; inline;
    class function GetGostR3410x2001: IDerObjectIdentifier; static; inline;
    class function GetGostR3411x94WithGostR3410x94: IDerObjectIdentifier; static; inline;
    class function GetGostR3411x94WithGostR3410x2001: IDerObjectIdentifier; static; inline;
    class function GetGostR3411x94CryptoProParamSet: IDerObjectIdentifier; static; inline;
    class function GetGostR3410x94CryptoProA: IDerObjectIdentifier; static; inline;
    class function GetGostR3410x94CryptoProB: IDerObjectIdentifier; static; inline;
    class function GetGostR3410x94CryptoProC: IDerObjectIdentifier; static; inline;
    class function GetGostR3410x94CryptoProD: IDerObjectIdentifier; static; inline;
    class function GetGostR3410x94CryptoProXchA: IDerObjectIdentifier; static; inline;
    class function GetGostR3410x94CryptoProXchB: IDerObjectIdentifier; static; inline;
    class function GetGostR3410x94CryptoProXchC: IDerObjectIdentifier; static; inline;
    class function GetGostR3410x2001CryptoProA: IDerObjectIdentifier; static; inline;
    class function GetGostR3410x2001CryptoProB: IDerObjectIdentifier; static; inline;
    class function GetGostR3410x2001CryptoProC: IDerObjectIdentifier; static; inline;
    class function GetGostR3410x2001CryptoProXchA: IDerObjectIdentifier; static; inline;
    class function GetGostR3410x2001CryptoProXchB: IDerObjectIdentifier; static; inline;
    class function GetGostR3410x2001CryptoProESDH: IDerObjectIdentifier; static; inline;
    class function GetGostR3410x2001DH: IDerObjectIdentifier; static; inline;

    class constructor Create;
  public
    class property GostId: IDerObjectIdentifier read GetGostId;
    class property GostR3411: IDerObjectIdentifier read GetGostR3411;
    class property GostR3411Hmac: IDerObjectIdentifier read GetGostR3411Hmac;
    class property IdGost28147_89NoneKeyWrap: IDerObjectIdentifier read GetIdGost28147_89NoneKeyWrap;
    class property IdGost28147_89CryptoProKeyWrap: IDerObjectIdentifier read GetIdGost28147_89CryptoProKeyWrap;
    class property GostR28147Gcfb: IDerObjectIdentifier read GetGostR28147Gcfb;
    class property IdGost28147_89CryptoProTestParamSet: IDerObjectIdentifier read GetIdGost28147_89CryptoProTestParamSet;
    class property IdGost28147_89CryptoProAParamSet: IDerObjectIdentifier read GetIdGost28147_89CryptoProAParamSet;
    class property IdGost28147_89CryptoProBParamSet: IDerObjectIdentifier read GetIdGost28147_89CryptoProBParamSet;
    class property IdGost28147_89CryptoProCParamSet: IDerObjectIdentifier read GetIdGost28147_89CryptoProCParamSet;
    class property IdGost28147_89CryptoProDParamSet: IDerObjectIdentifier read GetIdGost28147_89CryptoProDParamSet;
    class property GostR3410x94: IDerObjectIdentifier read GetGostR3410x94;
    class property GostR3410x2001: IDerObjectIdentifier read GetGostR3410x2001;
    class property GostR3411x94WithGostR3410x94: IDerObjectIdentifier read GetGostR3411x94WithGostR3410x94;
    class property GostR3411x94WithGostR3410x2001: IDerObjectIdentifier read GetGostR3411x94WithGostR3410x2001;
    class property GostR3411x94CryptoProParamSet: IDerObjectIdentifier read GetGostR3411x94CryptoProParamSet;
    class property GostR3410x94CryptoProA: IDerObjectIdentifier read GetGostR3410x94CryptoProA;
    class property GostR3410x94CryptoProB: IDerObjectIdentifier read GetGostR3410x94CryptoProB;
    class property GostR3410x94CryptoProC: IDerObjectIdentifier read GetGostR3410x94CryptoProC;
    class property GostR3410x94CryptoProD: IDerObjectIdentifier read GetGostR3410x94CryptoProD;
    class property GostR3410x94CryptoProXchA: IDerObjectIdentifier read GetGostR3410x94CryptoProXchA;
    class property GostR3410x94CryptoProXchB: IDerObjectIdentifier read GetGostR3410x94CryptoProXchB;
    class property GostR3410x94CryptoProXchC: IDerObjectIdentifier read GetGostR3410x94CryptoProXchC;
    class property GostR3410x2001CryptoProA: IDerObjectIdentifier read GetGostR3410x2001CryptoProA;
    class property GostR3410x2001CryptoProB: IDerObjectIdentifier read GetGostR3410x2001CryptoProB;
    class property GostR3410x2001CryptoProC: IDerObjectIdentifier read GetGostR3410x2001CryptoProC;
    class property GostR3410x2001CryptoProXchA: IDerObjectIdentifier read GetGostR3410x2001CryptoProXchA;
    class property GostR3410x2001CryptoProXchB: IDerObjectIdentifier read GetGostR3410x2001CryptoProXchB;
    class property GostR3410x2001CryptoProESDH: IDerObjectIdentifier read GetGostR3410x2001CryptoProESDH;
    class property GostR3410x2001DH: IDerObjectIdentifier read GetGostR3410x2001DH;

    class procedure Boot; static;
  end;

implementation

{ TCryptoProObjectIdentifiers }

class constructor TCryptoProObjectIdentifiers.Create;
begin
  Boot;
end;

class procedure TCryptoProObjectIdentifiers.Boot;
begin
  if not FIsBooted then
  begin
    FGostId := TDerObjectIdentifier.Create('1.2.643.2.2');
    FGostR3411 := FGostId.Branch('9');
    FGostR3411Hmac := FGostId.Branch('10');
    FIdGost28147_89NoneKeyWrap := FGostId.Branch('13.0');
    FIdGost28147_89CryptoProKeyWrap := FGostId.Branch('13.1');
    FGostR28147Gcfb := FGostId.Branch('21');
    FIdGost28147_89CryptoProTestParamSet := FGostId.Branch('31.0');
    FIdGost28147_89CryptoProAParamSet := FGostId.Branch('31.1');
    FIdGost28147_89CryptoProBParamSet := FGostId.Branch('31.2');
    FIdGost28147_89CryptoProCParamSet := FGostId.Branch('31.3');
    FIdGost28147_89CryptoProDParamSet := FGostId.Branch('31.4');
    FGostR3410x94 := FGostId.Branch('20');
    FGostR3410x2001 := FGostId.Branch('19');
    FGostR3411x94WithGostR3410x94 := FGostId.Branch('4');
    FGostR3411x94WithGostR3410x2001 := FGostId.Branch('3');
    FGostR3411x94CryptoProParamSet := FGostId.Branch('30.1');
    FGostR3410x94CryptoProA := FGostId.Branch('32.2');
    FGostR3410x94CryptoProB := FGostId.Branch('32.3');
    FGostR3410x94CryptoProC := FGostId.Branch('32.4');
    FGostR3410x94CryptoProD := FGostId.Branch('32.5');
    FGostR3410x94CryptoProXchA := FGostId.Branch('33.1');
    FGostR3410x94CryptoProXchB := FGostId.Branch('33.2');
    FGostR3410x94CryptoProXchC := FGostId.Branch('33.3');
    FGostR3410x2001CryptoProA := FGostId.Branch('35.1');
    FGostR3410x2001CryptoProB := FGostId.Branch('35.2');
    FGostR3410x2001CryptoProC := FGostId.Branch('35.3');
    FGostR3410x2001CryptoProXchA := FGostId.Branch('36.0');
    FGostR3410x2001CryptoProXchB := FGostId.Branch('36.1');
    FGostR3410x2001CryptoProESDH := FGostId.Branch('96');
    FGostR3410x2001DH := FGostId.Branch('98');

    FIsBooted := True;
  end;
end;

class function TCryptoProObjectIdentifiers.GetGostId: IDerObjectIdentifier;
begin
  Result := FGostId;
end;

class function TCryptoProObjectIdentifiers.GetGostR3411: IDerObjectIdentifier;
begin
  Result := FGostR3411;
end;

class function TCryptoProObjectIdentifiers.GetGostR3411Hmac: IDerObjectIdentifier;
begin
  Result := FGostR3411Hmac;
end;

class function TCryptoProObjectIdentifiers.GetIdGost28147_89NoneKeyWrap: IDerObjectIdentifier;
begin
  Result := FIdGost28147_89NoneKeyWrap;
end;

class function TCryptoProObjectIdentifiers.GetIdGost28147_89CryptoProKeyWrap: IDerObjectIdentifier;
begin
  Result := FIdGost28147_89CryptoProKeyWrap;
end;

class function TCryptoProObjectIdentifiers.GetGostR28147Gcfb: IDerObjectIdentifier;
begin
  Result := FGostR28147Gcfb;
end;

class function TCryptoProObjectIdentifiers.GetIdGost28147_89CryptoProTestParamSet: IDerObjectIdentifier;
begin
  Result := FIdGost28147_89CryptoProTestParamSet;
end;

class function TCryptoProObjectIdentifiers.GetIdGost28147_89CryptoProAParamSet: IDerObjectIdentifier;
begin
  Result := FIdGost28147_89CryptoProAParamSet;
end;

class function TCryptoProObjectIdentifiers.GetIdGost28147_89CryptoProBParamSet: IDerObjectIdentifier;
begin
  Result := FIdGost28147_89CryptoProBParamSet;
end;

class function TCryptoProObjectIdentifiers.GetIdGost28147_89CryptoProCParamSet: IDerObjectIdentifier;
begin
  Result := FIdGost28147_89CryptoProCParamSet;
end;

class function TCryptoProObjectIdentifiers.GetIdGost28147_89CryptoProDParamSet: IDerObjectIdentifier;
begin
  Result := FIdGost28147_89CryptoProDParamSet;
end;

class function TCryptoProObjectIdentifiers.GetGostR3410x94: IDerObjectIdentifier;
begin
  Result := FGostR3410x94;
end;

class function TCryptoProObjectIdentifiers.GetGostR3410x2001: IDerObjectIdentifier;
begin
  Result := FGostR3410x2001;
end;

class function TCryptoProObjectIdentifiers.GetGostR3411x94WithGostR3410x94: IDerObjectIdentifier;
begin
  Result := FGostR3411x94WithGostR3410x94;
end;

class function TCryptoProObjectIdentifiers.GetGostR3411x94WithGostR3410x2001: IDerObjectIdentifier;
begin
  Result := FGostR3411x94WithGostR3410x2001;
end;

class function TCryptoProObjectIdentifiers.GetGostR3411x94CryptoProParamSet: IDerObjectIdentifier;
begin
  Result := FGostR3411x94CryptoProParamSet;
end;

class function TCryptoProObjectIdentifiers.GetGostR3410x94CryptoProA: IDerObjectIdentifier;
begin
  Result := FGostR3410x94CryptoProA;
end;

class function TCryptoProObjectIdentifiers.GetGostR3410x94CryptoProB: IDerObjectIdentifier;
begin
  Result := FGostR3410x94CryptoProB;
end;

class function TCryptoProObjectIdentifiers.GetGostR3410x94CryptoProC: IDerObjectIdentifier;
begin
  Result := FGostR3410x94CryptoProC;
end;

class function TCryptoProObjectIdentifiers.GetGostR3410x94CryptoProD: IDerObjectIdentifier;
begin
  Result := FGostR3410x94CryptoProD;
end;

class function TCryptoProObjectIdentifiers.GetGostR3410x94CryptoProXchA: IDerObjectIdentifier;
begin
  Result := FGostR3410x94CryptoProXchA;
end;

class function TCryptoProObjectIdentifiers.GetGostR3410x94CryptoProXchB: IDerObjectIdentifier;
begin
  Result := FGostR3410x94CryptoProXchB;
end;

class function TCryptoProObjectIdentifiers.GetGostR3410x94CryptoProXchC: IDerObjectIdentifier;
begin
  Result := FGostR3410x94CryptoProXchC;
end;

class function TCryptoProObjectIdentifiers.GetGostR3410x2001CryptoProA: IDerObjectIdentifier;
begin
  Result := FGostR3410x2001CryptoProA;
end;

class function TCryptoProObjectIdentifiers.GetGostR3410x2001CryptoProB: IDerObjectIdentifier;
begin
  Result := FGostR3410x2001CryptoProB;
end;

class function TCryptoProObjectIdentifiers.GetGostR3410x2001CryptoProC: IDerObjectIdentifier;
begin
  Result := FGostR3410x2001CryptoProC;
end;

class function TCryptoProObjectIdentifiers.GetGostR3410x2001CryptoProXchA: IDerObjectIdentifier;
begin
  Result := FGostR3410x2001CryptoProXchA;
end;

class function TCryptoProObjectIdentifiers.GetGostR3410x2001CryptoProXchB: IDerObjectIdentifier;
begin
  Result := FGostR3410x2001CryptoProXchB;
end;

class function TCryptoProObjectIdentifiers.GetGostR3410x2001CryptoProESDH: IDerObjectIdentifier;
begin
  Result := FGostR3410x2001CryptoProESDH;
end;

class function TCryptoProObjectIdentifiers.GetGostR3410x2001DH: IDerObjectIdentifier;
begin
  Result := FGostR3410x2001DH;
end;

end.
