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
      FInternet, FDirectory, FMgmt, FExperimental, FClsPrivate, FSecurity,
      FSNMPv2, FMail, FSecurityMechanisms, FSecurityNametypes, FPkix, FIpsec,
      FIsakmpOakley, FHmacMD5, FHmacSha1, FHmacTiger, FHmacRipeMD160,
      FIdAlg, FIdRsassaPssShake128, FIdRsassaPssShake256, FIdEcdsaWithShake128,
      FIdEcdsaWithShake256, FIdAlgUnsigned: IDerObjectIdentifier;

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
    class function GetIdAlg: IDerObjectIdentifier; static; inline;
    class function GetIdRsassaPssShake128: IDerObjectIdentifier; static; inline;
    class function GetIdRsassaPssShake256: IDerObjectIdentifier; static; inline;
    class function GetIdEcdsaWithShake128: IDerObjectIdentifier; static; inline;
    class function GetIdEcdsaWithShake256: IDerObjectIdentifier; static; inline;
    class function GetIdAlgUnsigned: IDerObjectIdentifier; static; inline;

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
    /// <summary>id-alg: 1.3.6.1.5.5.7.6</summary>
    class property IdAlg: IDerObjectIdentifier read GetIdAlg;
    /// <summary>id-RSASSA-PSS-SHAKE128</summary>
    class property IdRsassaPssShake128: IDerObjectIdentifier read GetIdRsassaPssShake128;
    /// <summary>id-RSASSA-PSS-SHAKE256</summary>
    class property IdRsassaPssShake256: IDerObjectIdentifier read GetIdRsassaPssShake256;
    /// <summary>id-ecdsa-with-shake128</summary>
    class property IdEcdsaWithShake128: IDerObjectIdentifier read GetIdEcdsaWithShake128;
    /// <summary>id-ecdsa-with-shake256</summary>
    class property IdEcdsaWithShake256: IDerObjectIdentifier read GetIdEcdsaWithShake256;
    /// <summary>id-alg-unsigned</summary>
    class property IdAlgUnsigned: IDerObjectIdentifier read GetIdAlgUnsigned;
  end;

implementation

{ TIanaObjectIdentifiers }

class constructor TIanaObjectIdentifiers.Create;
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
  FIdAlg := FPkix.Branch('6');
  FIdRsassaPssShake128 := FIdAlg.Branch('30');
  FIdRsassaPssShake256 := FIdAlg.Branch('31');
  FIdEcdsaWithShake128 := FIdAlg.Branch('32');
  FIdEcdsaWithShake256 := FIdAlg.Branch('33');
  FIdAlgUnsigned := FIdAlg.Branch('36');
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

class function TIanaObjectIdentifiers.GetIdAlg: IDerObjectIdentifier;
begin
  Result := FIdAlg;
end;

class function TIanaObjectIdentifiers.GetIdAlgUnsigned: IDerObjectIdentifier;
begin
  Result := FIdAlgUnsigned;
end;

class function TIanaObjectIdentifiers.GetIdEcdsaWithShake128: IDerObjectIdentifier;
begin
  Result := FIdEcdsaWithShake128;
end;

class function TIanaObjectIdentifiers.GetIdEcdsaWithShake256: IDerObjectIdentifier;
begin
  Result := FIdEcdsaWithShake256;
end;

class function TIanaObjectIdentifiers.GetIdRsassaPssShake128: IDerObjectIdentifier;
begin
  Result := FIdRsassaPssShake128;
end;

class function TIanaObjectIdentifiers.GetIdRsassaPssShake256: IDerObjectIdentifier;
begin
  Result := FIdRsassaPssShake256;
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
