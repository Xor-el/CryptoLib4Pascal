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

unit ClpX509NameBuilder;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpAsn1Comparers,
  ClpIX509NameBuilder,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIAsn1Objects,
  ClpCryptoLibTypes;

resourcestring
  SUnknownOid = 'Unknown Oid';

type
  /// <summary>
  /// Builder class for creating X509Name objects with method chaining.
  /// </summary>
  TX509NameBuilder = class sealed(TInterfacedObject, IX509NameBuilder)

  strict private
  var
    FOrdering: TList<IDerObjectIdentifier>;
    FValues: TList<String>;

    function GetOidByName(const AName: String): IDerObjectIdentifier;

  public
    /// <summary>
    /// Create a new builder instance.
    /// </summary>
    constructor Create;
    destructor Destroy; override;

    /// <summary>
    /// Add an RDN (Relative Distinguished Name) by OID and value.
    /// </summary>
    function AddRdn(const AOid: IDerObjectIdentifier; const AValue: String): IX509NameBuilder; overload;

    /// <summary>
    /// Add an RDN by standard name (e.g., "C", "O", "CN") and value.
    /// </summary>
    function AddRdn(const AName: String; const AValue: String): IX509NameBuilder; overload;

    /// <summary>
    /// Add Country attribute.
    /// </summary>
    function AddCountry(const AValue: String): IX509NameBuilder;

    /// <summary>
    /// Add Organization attribute.
    /// </summary>
    function AddOrganization(const AValue: String): IX509NameBuilder;

    /// <summary>
    /// Add Organizational Unit attribute.
    /// </summary>
    function AddOrganizationalUnit(const AValue: String): IX509NameBuilder;

    /// <summary>
    /// Add Locality attribute.
    /// </summary>
    function AddLocality(const AValue: String): IX509NameBuilder;

    /// <summary>
    /// Add State attribute.
    /// </summary>
    function AddState(const AValue: String): IX509NameBuilder;

    /// <summary>
    /// Add Common Name attribute.
    /// </summary>
    function AddCommonName(const AValue: String): IX509NameBuilder;

    /// <summary>
    /// Add Email Address attribute.
    /// </summary>
    function AddEmailAddress(const AValue: String): IX509NameBuilder;

    /// <summary>
    /// Reset the builder, clearing all added RDNs so it can be reused.
    /// </summary>
    function Reset(): IX509NameBuilder;

    /// <summary>
    /// Build and return the X509Name object.
    /// </summary>
    function Build(): IX509Name;

  end;

implementation

{ TX509NameBuilder }

constructor TX509NameBuilder.Create;
begin
  inherited Create();
  FOrdering := TList<IDerObjectIdentifier>.Create(TAsn1Comparers.OidComparer);
  FValues := TList<String>.Create();
end;

destructor TX509NameBuilder.Destroy;
begin
  FOrdering.Free;
  FValues.Free;
  inherited Destroy;
end;

function TX509NameBuilder.AddCountry(const AValue: String): IX509NameBuilder;
begin
  Result := AddRdn(TX509Name.C, AValue);
end;

function TX509NameBuilder.AddCommonName(const AValue: String): IX509NameBuilder;
begin
  Result := AddRdn(TX509Name.CN, AValue);
end;

function TX509NameBuilder.AddEmailAddress(const AValue: String): IX509NameBuilder;
begin
  Result := AddRdn(TX509Name.EmailAddress, AValue);
end;

function TX509NameBuilder.AddLocality(const AValue: String): IX509NameBuilder;
begin
  Result := AddRdn(TX509Name.L, AValue);
end;

function TX509NameBuilder.AddOrganization(const AValue: String): IX509NameBuilder;
begin
  Result := AddRdn(TX509Name.O, AValue);
end;

function TX509NameBuilder.AddOrganizationalUnit(const AValue: String): IX509NameBuilder;
begin
  Result := AddRdn(TX509Name.OU, AValue);
end;

function TX509NameBuilder.AddRdn(const AOid: IDerObjectIdentifier;
  const AValue: String): IX509NameBuilder;
var
  LIdx: Int32;
begin
  if AOid = nil then
    raise EArgumentNilCryptoLibException.Create('oid');
  if AValue = '' then
    raise EArgumentCryptoLibException.Create('value cannot be empty');

  LIdx := FOrdering.IndexOf(AOid);
  if LIdx >= 0 then
    FValues[LIdx] := AValue
  else
  begin
    FOrdering.Add(AOid);
    FValues.Add(AValue);
  end;
  Result := Self;
end;

function TX509NameBuilder.AddRdn(const AName: String; const AValue: String): IX509NameBuilder;
var
  LOid: IDerObjectIdentifier;
begin
  LOid := GetOidByName(AName);
  if LOid = nil then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SUnknownOid, [AName]);
  end;
  Result := AddRdn(LOid, AValue);
end;

function TX509NameBuilder.AddState(const AValue: String): IX509NameBuilder;
begin
  Result := AddRdn(TX509Name.ST, AValue);
end;

function TX509NameBuilder.Reset(): IX509NameBuilder;
begin
  FOrdering.Clear();
  FValues.Clear();
  Result := Self;
end;

function TX509NameBuilder.Build(): IX509Name;
begin
  if FOrdering.Count = 0 then
  begin
    raise EArgumentCryptoLibException.Create('X509Name must have at least one RDN');
  end;
  Result := TX509Name.Create(FOrdering, FValues);
end;

function TX509NameBuilder.GetOidByName(const AName: String): IDerObjectIdentifier;
begin
  Result := nil;

  // Check standard OIDs using case-insensitive comparison
  if SameText(AName, 'C') or SameText(AName, 'Country') then
    Result := TX509Name.C
  else if SameText(AName, 'O') or SameText(AName, 'Organization') then
    Result := TX509Name.O
  else if SameText(AName, 'OU') or SameText(AName, 'OrganizationalUnit') then
    Result := TX509Name.OU
  else if SameText(AName, 'L') or SameText(AName, 'Locality') then
    Result := TX509Name.L
  else if SameText(AName, 'ST') or SameText(AName, 'State') or SameText(AName, 'SP') or
    SameText(AName, 'StateProvince') then
    Result := TX509Name.ST
  else if SameText(AName, 'CN') or SameText(AName, 'CommonName') then
    Result := TX509Name.CN
  else if SameText(AName, 'E') or SameText(AName, 'Email') or SameText(AName, 'EmailAddress') then
    Result := TX509Name.EmailAddress
  else if SameText(AName, 'Street') then
    Result := TX509Name.Street
  else if SameText(AName, 'SerialNumber') then
    Result := TX509Name.SerialNumber
  else if SameText(AName, 'Surname') then
    Result := TX509Name.Surname
  else if SameText(AName, 'GivenName') then
    Result := TX509Name.GivenName
  else if SameText(AName, 'Initials') then
    Result := TX509Name.Initials
  else if SameText(AName, 'Generation') then
    Result := TX509Name.Generation
  else if SameText(AName, 'UniqueIdentifier') or SameText(AName, 'UID') then
    Result := TX509Name.UniqueIdentifier
  else if SameText(AName, 'Description') then
    Result := TX509Name.Description
  else if SameText(AName, 'BusinessCategory') then
    Result := TX509Name.BusinessCategory
  else if SameText(AName, 'PostalCode') then
    Result := TX509Name.PostalCode
  else if SameText(AName, 'DnQualifier') then
    Result := TX509Name.DnQualifier
  else if SameText(AName, 'Pseudonym') then
    Result := TX509Name.Pseudonym
  else if SameText(AName, 'Role') then
    Result := TX509Name.Role
  else if SameText(AName, 'DateOfBirth') then
    Result := TX509Name.DateOfBirth
  else if SameText(AName, 'PlaceOfBirth') then
    Result := TX509Name.PlaceOfBirth
  else if SameText(AName, 'Gender') then
    Result := TX509Name.Gender
  else if SameText(AName, 'CountryOfCitizenship') then
    Result := TX509Name.CountryOfCitizenship
  else if SameText(AName, 'CountryOfResidence') then
    Result := TX509Name.CountryOfResidence
  else if SameText(AName, 'NameAtBirth') then
    Result := TX509Name.NameAtBirth
  else if SameText(AName, 'PostalAddress') then
    Result := TX509Name.PostalAddress
  else if SameText(AName, 'DmdName') then
    Result := TX509Name.DmdName
  else if SameText(AName, 'TelephoneNumber') then
    Result := TX509Name.TelephoneNumber
  else if SameText(AName, 'OrganizationIdentifier') then
    Result := TX509Name.OrganizationIdentifier
  else if SameText(AName, 'Name') then
    Result := TX509Name.Name
  else if SameText(AName, 'DC') or SameText(AName, 'DomainComponent') then
    Result := TX509Name.DC;
end;

end.

