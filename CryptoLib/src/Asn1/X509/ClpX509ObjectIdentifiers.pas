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

unit ClpX509ObjectIdentifiers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsn1Objects,
  ClpIAsn1Objects;

type
  /// <summary>
  /// X.509 Object Identifiers
  /// </summary>
  TX509ObjectIdentifiers = class abstract(TObject)

  strict private
  const
    // base id
    AttributeType: String = '2.5.4';

  class var
    FAttributeType: IDerObjectIdentifier;
    FCommonName: IDerObjectIdentifier;
    FCountryName: IDerObjectIdentifier;
    FLocalityName: IDerObjectIdentifier;
    FStateOrProvinceName: IDerObjectIdentifier;
    FOrganization: IDerObjectIdentifier;
    FOrganizationalUnitName: IDerObjectIdentifier;
    FIdAtTelephoneNumber: IDerObjectIdentifier;
    FIdAtName: IDerObjectIdentifier;
    FIdAtOrganizationIdentifier: IDerObjectIdentifier;
    FIdSha1: IDerObjectIdentifier;
    FRipeMD160: IDerObjectIdentifier;
    FRipeMD160WithRsaEncryption: IDerObjectIdentifier;
    FIdEARsa: IDerObjectIdentifier;
    FIdPkix: IDerObjectIdentifier;
    FIdPE: IDerObjectIdentifier;
    FPkixAlgorithms: IDerObjectIdentifier;
    FIdRsassaPssShake128: IDerObjectIdentifier;
    FIdRsassaPssShake256: IDerObjectIdentifier;
    FIdEcdsaWithShake128: IDerObjectIdentifier;
    FIdEcdsaWithShake256: IDerObjectIdentifier;
    FIdPda: IDerObjectIdentifier;
    FIdAD: IDerObjectIdentifier;
    FIdADOcsp: IDerObjectIdentifier;
    FIdADCAIssuers: IDerObjectIdentifier;
    FIdCe: IDerObjectIdentifier;

    class function GetAttributeType: IDerObjectIdentifier; static; inline;
    class function GetCommonName: IDerObjectIdentifier; static; inline;
    class function GetCountryName: IDerObjectIdentifier; static; inline;
    class function GetLocalityName: IDerObjectIdentifier; static; inline;
    class function GetStateOrProvinceName: IDerObjectIdentifier; static; inline;
    class function GetOrganization: IDerObjectIdentifier; static; inline;
    class function GetOrganizationalUnitName: IDerObjectIdentifier; static; inline;
    class function GetIdAtTelephoneNumber: IDerObjectIdentifier; static; inline;
    class function GetIdAtName: IDerObjectIdentifier; static; inline;
    class function GetIdAtOrganizationIdentifier: IDerObjectIdentifier; static; inline;
    class function GetIdSha1: IDerObjectIdentifier; static; inline;
    class function GetRipeMD160: IDerObjectIdentifier; static; inline;
    class function GetRipeMD160WithRsaEncryption: IDerObjectIdentifier; static; inline;
    class function GetIdEARsa: IDerObjectIdentifier; static; inline;
    class function GetIdPkix: IDerObjectIdentifier; static; inline;
    class function GetIdPE: IDerObjectIdentifier; static; inline;
    class function GetPkixAlgorithms: IDerObjectIdentifier; static; inline;
    class function GetIdRsassaPssShake128: IDerObjectIdentifier; static; inline;
    class function GetIdRsassaPssShake256: IDerObjectIdentifier; static; inline;
    class function GetIdEcdsaWithShake128: IDerObjectIdentifier; static; inline;
    class function GetIdEcdsaWithShake256: IDerObjectIdentifier; static; inline;
    class function GetIdPda: IDerObjectIdentifier; static; inline;
    class function GetIdAD: IDerObjectIdentifier; static; inline;
    class function GetIdADOcsp: IDerObjectIdentifier; static; inline;
    class function GetIdADCAIssuers: IDerObjectIdentifier; static; inline;
    class function GetIdCe: IDerObjectIdentifier; static; inline;

    class procedure Boot(); static;
    class constructor X509ObjectIdentifiers();

  public
    // Attribute types
    class property AttributeTypeOid: IDerObjectIdentifier read GetAttributeType;
    class property CommonName: IDerObjectIdentifier read GetCommonName;
    class property CountryName: IDerObjectIdentifier read GetCountryName;
    class property LocalityName: IDerObjectIdentifier read GetLocalityName;
    class property StateOrProvinceName: IDerObjectIdentifier read GetStateOrProvinceName;
    class property Organization: IDerObjectIdentifier read GetOrganization;
    class property OrganizationalUnitName: IDerObjectIdentifier read GetOrganizationalUnitName;
    class property IdAtTelephoneNumber: IDerObjectIdentifier read GetIdAtTelephoneNumber;
    class property IdAtName: IDerObjectIdentifier read GetIdAtName;
    class property IdAtOrganizationIdentifier: IDerObjectIdentifier read GetIdAtOrganizationIdentifier;

    // Hash algorithms
    class property IdSha1: IDerObjectIdentifier read GetIdSha1;
    class property RipeMD160: IDerObjectIdentifier read GetRipeMD160;
    class property RipeMD160WithRsaEncryption: IDerObjectIdentifier read GetRipeMD160WithRsaEncryption;

    // Encryption
    class property IdEARsa: IDerObjectIdentifier read GetIdEARsa;

    // PKIX
    class property IdPkix: IDerObjectIdentifier read GetIdPkix;
    class property IdPE: IDerObjectIdentifier read GetIdPE;
    class property PkixAlgorithms: IDerObjectIdentifier read GetPkixAlgorithms;
    class property IdRsassaPssShake128: IDerObjectIdentifier read GetIdRsassaPssShake128;
    class property IdRsassaPssShake256: IDerObjectIdentifier read GetIdRsassaPssShake256;
    class property IdEcdsaWithShake128: IDerObjectIdentifier read GetIdEcdsaWithShake128;
    class property IdEcdsaWithShake256: IDerObjectIdentifier read GetIdEcdsaWithShake256;
    class property IdPda: IDerObjectIdentifier read GetIdPda;

    // Authority Information Access
    class property IdAD: IDerObjectIdentifier read GetIdAD;
    class property IdADOcsp: IDerObjectIdentifier read GetIdADOcsp;
    class property IdADCAIssuers: IDerObjectIdentifier read GetIdADCAIssuers;
    class property OcspAccessMethod: IDerObjectIdentifier read GetIdADOcsp;
    class property CrlAccessMethod: IDerObjectIdentifier read GetIdADCAIssuers;

    // Certificate Extensions
    class property IdCe: IDerObjectIdentifier read GetIdCe;

  end;

implementation

{ TX509ObjectIdentifiers }

class procedure TX509ObjectIdentifiers.Boot;
begin
  // Base attribute type
  FAttributeType := TDerObjectIdentifier.Create(AttributeType);

  // Attribute types
  FCommonName := FAttributeType.Branch('3');
  FCountryName := FAttributeType.Branch('6');
  FLocalityName := FAttributeType.Branch('7');
  FStateOrProvinceName := FAttributeType.Branch('8');
  FOrganization := FAttributeType.Branch('10');
  FOrganizationalUnitName := FAttributeType.Branch('11');
  FIdAtTelephoneNumber := FAttributeType.Branch('20');
  FIdAtName := FAttributeType.Branch('41');
  FIdAtOrganizationIdentifier := FAttributeType.Branch('97');

  // SHA-1: 1.3.14.3.2.26
  FIdSha1 := TDerObjectIdentifier.Create('1.3.14.3.2.26');

  // RIPEMD-160: 1.3.36.3.2.1
  FRipeMD160 := TDerObjectIdentifier.Create('1.3.36.3.2.1');

  // RIPEMD-160 with RSA: 1.3.36.3.3.1.2
  FRipeMD160WithRsaEncryption := TDerObjectIdentifier.Create('1.3.36.3.3.1.2');

  // EA RSA: 2.5.8.1.1
  FIdEARsa := TDerObjectIdentifier.Create('2.5.8.1.1');

  // PKIX: 1.3.6.1.5.5.7
  FIdPkix := TDerObjectIdentifier.Create('1.3.6.1.5.5.7');
  FIdPE := FIdPkix.Branch('1');
  FPkixAlgorithms := FIdPkix.Branch('6');
  FIdRsassaPssShake128 := FPkixAlgorithms.Branch('30');
  FIdRsassaPssShake256 := FPkixAlgorithms.Branch('31');
  FIdEcdsaWithShake128 := FPkixAlgorithms.Branch('32');
  FIdEcdsaWithShake256 := FPkixAlgorithms.Branch('33');
  FIdPda := FIdPkix.Branch('9');

  // Authority Information Access
  FIdAD := FIdPkix.Branch('48');
  FIdADOcsp := FIdAD.Branch('1');
  FIdADCAIssuers := FIdAD.Branch('2');

  // Certificate Extensions: 2.5.29
  FIdCe := TDerObjectIdentifier.Create('2.5.29');
end;

class constructor TX509ObjectIdentifiers.X509ObjectIdentifiers;
begin
  TX509ObjectIdentifiers.Boot();
end;

class function TX509ObjectIdentifiers.GetAttributeType: IDerObjectIdentifier;
begin
  Result := FAttributeType;
end;

class function TX509ObjectIdentifiers.GetCommonName: IDerObjectIdentifier;
begin
  Result := FCommonName;
end;

class function TX509ObjectIdentifiers.GetCountryName: IDerObjectIdentifier;
begin
  Result := FCountryName;
end;

class function TX509ObjectIdentifiers.GetLocalityName: IDerObjectIdentifier;
begin
  Result := FLocalityName;
end;

class function TX509ObjectIdentifiers.GetStateOrProvinceName: IDerObjectIdentifier;
begin
  Result := FStateOrProvinceName;
end;

class function TX509ObjectIdentifiers.GetOrganization: IDerObjectIdentifier;
begin
  Result := FOrganization;
end;

class function TX509ObjectIdentifiers.GetOrganizationalUnitName: IDerObjectIdentifier;
begin
  Result := FOrganizationalUnitName;
end;

class function TX509ObjectIdentifiers.GetIdAtTelephoneNumber: IDerObjectIdentifier;
begin
  Result := FIdAtTelephoneNumber;
end;

class function TX509ObjectIdentifiers.GetIdAtName: IDerObjectIdentifier;
begin
  Result := FIdAtName;
end;

class function TX509ObjectIdentifiers.GetIdAtOrganizationIdentifier: IDerObjectIdentifier;
begin
  Result := FIdAtOrganizationIdentifier;
end;

class function TX509ObjectIdentifiers.GetIdSha1: IDerObjectIdentifier;
begin
  Result := FIdSha1;
end;

class function TX509ObjectIdentifiers.GetRipeMD160: IDerObjectIdentifier;
begin
  Result := FRipeMD160;
end;

class function TX509ObjectIdentifiers.GetRipeMD160WithRsaEncryption: IDerObjectIdentifier;
begin
  Result := FRipeMD160WithRsaEncryption;
end;

class function TX509ObjectIdentifiers.GetIdEARsa: IDerObjectIdentifier;
begin
  Result := FIdEARsa;
end;

class function TX509ObjectIdentifiers.GetIdPkix: IDerObjectIdentifier;
begin
  Result := FIdPkix;
end;

class function TX509ObjectIdentifiers.GetIdPE: IDerObjectIdentifier;
begin
  Result := FIdPE;
end;

class function TX509ObjectIdentifiers.GetPkixAlgorithms: IDerObjectIdentifier;
begin
  Result := FPkixAlgorithms;
end;

class function TX509ObjectIdentifiers.GetIdRsassaPssShake128: IDerObjectIdentifier;
begin
  Result := FIdRsassaPssShake128;
end;

class function TX509ObjectIdentifiers.GetIdRsassaPssShake256: IDerObjectIdentifier;
begin
  Result := FIdRsassaPssShake256;
end;

class function TX509ObjectIdentifiers.GetIdEcdsaWithShake128: IDerObjectIdentifier;
begin
  Result := FIdEcdsaWithShake128;
end;

class function TX509ObjectIdentifiers.GetIdEcdsaWithShake256: IDerObjectIdentifier;
begin
  Result := FIdEcdsaWithShake256;
end;

class function TX509ObjectIdentifiers.GetIdPda: IDerObjectIdentifier;
begin
  Result := FIdPda;
end;

class function TX509ObjectIdentifiers.GetIdAD: IDerObjectIdentifier;
begin
  Result := FIdAD;
end;

class function TX509ObjectIdentifiers.GetIdADOcsp: IDerObjectIdentifier;
begin
  Result := FIdADOcsp;
end;

class function TX509ObjectIdentifiers.GetIdADCAIssuers: IDerObjectIdentifier;
begin
  Result := FIdADCAIssuers;
end;

class function TX509ObjectIdentifiers.GetIdCe: IDerObjectIdentifier;
begin
  Result := FIdCe;
end;

end.
