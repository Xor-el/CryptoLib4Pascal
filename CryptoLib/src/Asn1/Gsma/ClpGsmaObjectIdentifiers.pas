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

unit ClpGsmaObjectIdentifiers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsn1Objects,
  ClpIAsn1Objects;

type
  /// <summary>{ joint-iso-itu-t(2) international-organizations(23) gsma(146) } == GSMA defined things</summary>
  TGsmaObjectIdentifiers = class abstract(TObject)
  strict private
    class var
      FIdGsma, FIdRsp, FIdRspCertObjects, FIdRspRole, FIdRspRoleCi, FIdRspRoleEuicc,
      FIdRspRoleEum: IDerObjectIdentifier;

    class function GetIdGsma: IDerObjectIdentifier; static; inline;
    class function GetIdRsp: IDerObjectIdentifier; static; inline;
    class function GetIdRspCertObjects: IDerObjectIdentifier; static; inline;
    class function GetIdRspRole: IDerObjectIdentifier; static; inline;
    class function GetIdRspRoleCi: IDerObjectIdentifier; static; inline;
    class function GetIdRspRoleEuicc: IDerObjectIdentifier; static; inline;
    class function GetIdRspRoleEum: IDerObjectIdentifier; static; inline;

    class constructor Create;
  public
    /// <summary>id-gsma: 2.23.146</summary>
    class property IdGsma: IDerObjectIdentifier read GetIdGsma;
    /// <summary>id-rsp: 2.23.146.1</summary>
    class property IdRsp: IDerObjectIdentifier read GetIdRsp;
    /// <summary>id-rsp-cert-objects: 2.23.146.1.2</summary>
    class property IdRspCertObjects: IDerObjectIdentifier read GetIdRspCertObjects;
    /// <summary>id-rspRole: 2.23.146.1.2.1</summary>
    class property IdRspRole: IDerObjectIdentifier read GetIdRspRole;
    /// <summary>id-rspRole-ci: the SGP.22 certificate issuer role</summary>
    class property IdRspRoleCi: IDerObjectIdentifier read GetIdRspRoleCi;
    /// <summary>id-rspRole-euicc: the SGP.22 eUICC role</summary>
    class property IdRspRoleEuicc: IDerObjectIdentifier read GetIdRspRoleEuicc;
    /// <summary>id-rspRole-eum: the SGP.22 eUICC manufacturer role</summary>
    class property IdRspRoleEum: IDerObjectIdentifier read GetIdRspRoleEum;
  end;

implementation

{ TGsmaObjectIdentifiers }

class constructor TGsmaObjectIdentifiers.Create;
begin
  FIdGsma := TDerObjectIdentifier.Create('2.23.146');
  FIdRsp := FIdGsma.Branch('1');
  FIdRspCertObjects := FIdRsp.Branch('2');
  FIdRspRole := FIdRspCertObjects.Branch('1');
  FIdRspRoleCi := FIdRspRole.Branch('0');
  FIdRspRoleEuicc := FIdRspRole.Branch('1');
  FIdRspRoleEum := FIdRspRole.Branch('2');
end;

class function TGsmaObjectIdentifiers.GetIdGsma: IDerObjectIdentifier;
begin
  Result := FIdGsma;
end;

class function TGsmaObjectIdentifiers.GetIdRsp: IDerObjectIdentifier;
begin
  Result := FIdRsp;
end;

class function TGsmaObjectIdentifiers.GetIdRspCertObjects: IDerObjectIdentifier;
begin
  Result := FIdRspCertObjects;
end;

class function TGsmaObjectIdentifiers.GetIdRspRole: IDerObjectIdentifier;
begin
  Result := FIdRspRole;
end;

class function TGsmaObjectIdentifiers.GetIdRspRoleCi: IDerObjectIdentifier;
begin
  Result := FIdRspRoleCi;
end;

class function TGsmaObjectIdentifiers.GetIdRspRoleEuicc: IDerObjectIdentifier;
begin
  Result := FIdRspRoleEuicc;
end;

class function TGsmaObjectIdentifiers.GetIdRspRoleEum: IDerObjectIdentifier;
begin
  Result := FIdRspRoleEum;
end;

end.
