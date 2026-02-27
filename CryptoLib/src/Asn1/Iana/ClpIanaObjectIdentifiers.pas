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

unit ClpIanaObjectIdentifiers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsn1Objects,
  ClpIAsn1Objects;

type
  /// <summary>{ iso(1) identifier-organization(3) dod(6) internet(1) } == IETF defined things</summary>
  TIanaObjectIdentifiers = class abstract(TObject)
  strict private
    class var
      FIsBooted: Boolean;
      FInternet, FDirectory, FMgmt, FExperimental, FClsPrivate, FSecurity,
      FSNMPv2, FMail, FSecurityMechanisms, FSecurityNametypes, FPkix, FIpsec,
      FIsakmpOakley, FHmacMD5, FHmacSha1, FHmacTiger, FHmacRipeMD160: IDerObjectIdentifier;

    class function GetInternet: IDerObjectIdentifier; static; inline;
    class function GetDirectory: IDerObjectIdentifier; static; inline;
    class function GetMgmt: IDerObjectIdentifier; static; inline;
    class function GetExperimental: IDerObjectIdentifier; static; inline;
    class function GetClsPrivate: IDerObjectIdentifier; static; inline;
    class function GetSecurity: IDerObjectIdentifier; static; inline;
    class function GetSNMPv2: IDerObjectIdentifier; static; inline;
    class function GetMail: IDerObjectIdentifier; static; inline;
    class function GetSecurityMechanisms: IDerObjectIdentifier; static; inline;
    class function GetSecurityNametypes: IDerObjectIdentifier; static; inline;
    class function GetPkix: IDerObjectIdentifier; static; inline;
    class function GetIpsec: IDerObjectIdentifier; static; inline;
    class function GetIsakmpOakley: IDerObjectIdentifier; static; inline;
    class function GetHmacMD5: IDerObjectIdentifier; static; inline;
    class function GetHmacSha1: IDerObjectIdentifier; static; inline;
    class function GetHmacTiger: IDerObjectIdentifier; static; inline;
    class function GetHmacRipeMD160: IDerObjectIdentifier; static; inline;

    class constructor Create;
  public
    class property Internet: IDerObjectIdentifier read GetInternet;
    class property Directory: IDerObjectIdentifier read GetDirectory;
    class property Mgmt: IDerObjectIdentifier read GetMgmt;
    class property &Experimental: IDerObjectIdentifier read GetExperimental;
    class property ClsPrivate: IDerObjectIdentifier read GetClsPrivate;
    class property Security: IDerObjectIdentifier read GetSecurity;
    class property SNMPv2: IDerObjectIdentifier read GetSNMPv2;
    class property Mail: IDerObjectIdentifier read GetMail;
    class property SecurityMechanisms: IDerObjectIdentifier read GetSecurityMechanisms;
    class property SecurityNametypes: IDerObjectIdentifier read GetSecurityNametypes;
    class property Pkix: IDerObjectIdentifier read GetPkix;
    class property Ipsec: IDerObjectIdentifier read GetIpsec;
    class property IsakmpOakley: IDerObjectIdentifier read GetIsakmpOakley;
    class property HmacMD5: IDerObjectIdentifier read GetHmacMD5;
    class property HmacSha1: IDerObjectIdentifier read GetHmacSha1;
    class property HmacTiger: IDerObjectIdentifier read GetHmacTiger;
    class property HmacRipeMD160: IDerObjectIdentifier read GetHmacRipeMD160;

    class procedure Boot; static;
  end;

implementation

{ TIanaObjectIdentifiers }

class constructor TIanaObjectIdentifiers.Create;
begin
  Boot;
end;

class procedure TIanaObjectIdentifiers.Boot;
begin
  if not FIsBooted then
  begin
    FInternet := TDerObjectIdentifier.Create('1.3.6.1');
    FDirectory := FInternet.Branch('1');
    FMgmt := FInternet.Branch('2');
    FExperimental := FInternet.Branch('3');
    FClsPrivate := FInternet.Branch('4');
    FSecurity := FInternet.Branch('5');
    FSNMPv2 := FInternet.Branch('6');
    FMail := FInternet.Branch('7');
    FSecurityMechanisms := FSecurity.Branch('5');
    FSecurityNametypes := FSecurity.Branch('6');
    FPkix := FSecurityMechanisms.Branch('7');
    FIpsec := FSecurityMechanisms.Branch('8');
    FIsakmpOakley := FIpsec.Branch('1');
    FHmacMD5 := FIsakmpOakley.Branch('1');
    FHmacSha1 := FIsakmpOakley.Branch('2');
    FHmacTiger := FIsakmpOakley.Branch('3');
    FHmacRipeMD160 := FIsakmpOakley.Branch('4');

    FIsBooted := True;
  end;
end;

class function TIanaObjectIdentifiers.GetClsPrivate: IDerObjectIdentifier;
begin
  Result := FClsPrivate;
end;

class function TIanaObjectIdentifiers.GetDirectory: IDerObjectIdentifier;
begin
  Result := FDirectory;
end;

class function TIanaObjectIdentifiers.GetExperimental: IDerObjectIdentifier;
begin
  Result := FExperimental;
end;

class function TIanaObjectIdentifiers.GetHmacMD5: IDerObjectIdentifier;
begin
  Result := FHmacMD5;
end;

class function TIanaObjectIdentifiers.GetHmacRipeMD160: IDerObjectIdentifier;
begin
  Result := FHmacRipeMD160;
end;

class function TIanaObjectIdentifiers.GetHmacSha1: IDerObjectIdentifier;
begin
  Result := FHmacSha1;
end;

class function TIanaObjectIdentifiers.GetHmacTiger: IDerObjectIdentifier;
begin
  Result := FHmacTiger;
end;

class function TIanaObjectIdentifiers.GetInternet: IDerObjectIdentifier;
begin
  Result := FInternet;
end;

class function TIanaObjectIdentifiers.GetIpsec: IDerObjectIdentifier;
begin
  Result := FIpsec;
end;

class function TIanaObjectIdentifiers.GetIsakmpOakley: IDerObjectIdentifier;
begin
  Result := FIsakmpOakley;
end;

class function TIanaObjectIdentifiers.GetMail: IDerObjectIdentifier;
begin
  Result := FMail;
end;

class function TIanaObjectIdentifiers.GetMgmt: IDerObjectIdentifier;
begin
  Result := FMgmt;
end;

class function TIanaObjectIdentifiers.GetPkix: IDerObjectIdentifier;
begin
  Result := FPkix;
end;

class function TIanaObjectIdentifiers.GetSecurity: IDerObjectIdentifier;
begin
  Result := FSecurity;
end;

class function TIanaObjectIdentifiers.GetSecurityMechanisms: IDerObjectIdentifier;
begin
  Result := FSecurityMechanisms;
end;

class function TIanaObjectIdentifiers.GetSecurityNametypes: IDerObjectIdentifier;
begin
  Result := FSecurityNametypes;
end;

class function TIanaObjectIdentifiers.GetSNMPv2: IDerObjectIdentifier;
begin
  Result := FSNMPv2;
end;

end.
