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

unit ClpX500Name;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIX500Name,
  ClpCryptoLibTypes;

resourcestring
  SInvalidX500Name = 'Invalid X500Name: %s';

type
  /// <summary>
  /// X.500 Object Identifiers for Distinguished Name attributes
  /// </summary>
  TX500NameOids = class abstract(TObject)
  strict private
  const
    // Base OID for X.500 attribute types: 2.5.4
    X500AttrBase: String = '2.5.4';
    // PKCS#9 base: 1.2.840.113549.1.9
    Pkcs9Base: String = '1.2.840.113549.1.9';

  class var
    FIsBooted: Boolean;
    FCommonName, FOrganization, FOrganizationalUnit, FCountry, FState,
      FLocality, FSerialNumber, FEmailAddress: IDerObjectIdentifier;

    class function GetCommonName: IDerObjectIdentifier; static; inline;
    class function GetOrganization: IDerObjectIdentifier; static; inline;
    class function GetOrganizationalUnit: IDerObjectIdentifier; static; inline;
    class function GetCountry: IDerObjectIdentifier; static; inline;
    class function GetState: IDerObjectIdentifier; static; inline;
    class function GetLocality: IDerObjectIdentifier; static; inline;
    class function GetSerialNumber: IDerObjectIdentifier; static; inline;
    class function GetEmailAddress: IDerObjectIdentifier; static; inline;

    class constructor X500NameOids();

  public
    /// <summary>Common Name (CN) - 2.5.4.3</summary>
    class property CommonName: IDerObjectIdentifier read GetCommonName;
    /// <summary>Organization (O) - 2.5.4.10</summary>
    class property Organization: IDerObjectIdentifier read GetOrganization;
    /// <summary>Organizational Unit (OU) - 2.5.4.11</summary>
    class property OrganizationalUnit: IDerObjectIdentifier read GetOrganizationalUnit;
    /// <summary>Country (C) - 2.5.4.6</summary>
    class property Country: IDerObjectIdentifier read GetCountry;
    /// <summary>State/Province (ST) - 2.5.4.8</summary>
    class property State: IDerObjectIdentifier read GetState;
    /// <summary>Locality (L) - 2.5.4.7</summary>
    class property Locality: IDerObjectIdentifier read GetLocality;
    /// <summary>Serial Number - 2.5.4.5</summary>
    class property SerialNumber: IDerObjectIdentifier read GetSerialNumber;
    /// <summary>Email Address - 1.2.840.113549.1.9.1</summary>
    class property EmailAddress: IDerObjectIdentifier read GetEmailAddress;

    class procedure Boot(); static;
  end;

type
  /// <summary>
  /// X.500 Distinguished Name
  /// Name ::= SEQUENCE OF RelativeDistinguishedName
  /// RDN ::= SET OF AttributeTypeAndValue
  /// AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }
  /// </summary>
  TX500Name = class(TAsn1Encodable, IX500Name)

  strict private
  var
    FSeq: IAsn1Sequence;

    constructor Create(const seq: IAsn1Sequence); overload;

  public
    constructor Create(const rdnSequence: TList<IAsn1Encodable>); overload;

    function ToAsn1Object(): IAsn1Object; override;

    class function GetInstance(obj: TObject): IX500Name; overload; static;
    class function GetInstance(const obj: IAsn1TaggedObject;
      explicitly: Boolean): IX500Name; overload; static;
  end;

type
  /// <summary>
  /// Builder for X.500 Distinguished Names
  /// </summary>
  TX500NameBuilder = class(TInterfacedObject, IX500NameBuilder)
  strict private
  var
    FRdns: TList<IAsn1Encodable>;

    function CreateRdn(const oid: IDerObjectIdentifier;
      const value: string): IAsn1Encodable;

  public
    constructor Create();
    destructor Destroy(); override;

    function AddRdn(const oid: IDerObjectIdentifier; const value: string): IX500NameBuilder;
    function AddCommonName(const value: string): IX500NameBuilder;
    function AddOrganization(const value: string): IX500NameBuilder;
    function AddOrganizationalUnit(const value: string): IX500NameBuilder;
    function AddCountry(const value: string): IX500NameBuilder;
    function AddState(const value: string): IX500NameBuilder;
    function AddLocality(const value: string): IX500NameBuilder;
    function AddEmailAddress(const value: string): IX500NameBuilder;
    function Build: IX500Name;
  end;

implementation

{ TX500NameOids }

class procedure TX500NameOids.Boot;
begin
  if not FIsBooted then
  begin
    FCommonName := TDerObjectIdentifier.Create(X500AttrBase + '.3');
    FOrganization := TDerObjectIdentifier.Create(X500AttrBase + '.10');
    FOrganizationalUnit := TDerObjectIdentifier.Create(X500AttrBase + '.11');
    FCountry := TDerObjectIdentifier.Create(X500AttrBase + '.6');
    FState := TDerObjectIdentifier.Create(X500AttrBase + '.8');
    FLocality := TDerObjectIdentifier.Create(X500AttrBase + '.7');
    FSerialNumber := TDerObjectIdentifier.Create(X500AttrBase + '.5');
    FEmailAddress := TDerObjectIdentifier.Create(Pkcs9Base + '.1');

    FIsBooted := True;
  end;
end;

class function TX500NameOids.GetCommonName: IDerObjectIdentifier;
begin
  Result := FCommonName;
end;

class function TX500NameOids.GetOrganization: IDerObjectIdentifier;
begin
  Result := FOrganization;
end;

class function TX500NameOids.GetOrganizationalUnit: IDerObjectIdentifier;
begin
  Result := FOrganizationalUnit;
end;

class function TX500NameOids.GetCountry: IDerObjectIdentifier;
begin
  Result := FCountry;
end;

class function TX500NameOids.GetState: IDerObjectIdentifier;
begin
  Result := FState;
end;

class function TX500NameOids.GetLocality: IDerObjectIdentifier;
begin
  Result := FLocality;
end;

class function TX500NameOids.GetSerialNumber: IDerObjectIdentifier;
begin
  Result := FSerialNumber;
end;

class function TX500NameOids.GetEmailAddress: IDerObjectIdentifier;
begin
  Result := FEmailAddress;
end;

class constructor TX500NameOids.X500NameOids;
begin
  TX500NameOids.Boot;
end;

{ TX500Name }

constructor TX500Name.Create(const seq: IAsn1Sequence);
begin
  inherited Create();
  FSeq := seq;
end;

constructor TX500Name.Create(const rdnSequence: TList<IAsn1Encodable>);
var
  arr: TCryptoLibGenericArray<IAsn1Encodable>;
  i: Integer;
begin
  inherited Create();
  System.SetLength(arr, rdnSequence.Count);
  for i := 0 to rdnSequence.Count - 1 do
  begin
    arr[i] := rdnSequence[i];
  end;
  FSeq := TDerSequence.Create(arr);
end;

class function TX500Name.GetInstance(obj: TObject): IX500Name;
begin
  if (obj = nil) or (obj is TX500Name) then
  begin
    Result := obj as TX500Name;
    Exit;
  end;

  if obj is TAsn1Sequence then
  begin
    Result := TX500Name.Create(obj as TAsn1Sequence);
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SInvalidX500Name,
    [obj.ToString]);
end;

class function TX500Name.GetInstance(const obj: IAsn1TaggedObject;
  explicitly: Boolean): IX500Name;
begin
  Result := GetInstance(TAsn1Sequence.GetInstance(obj, explicitly) as TAsn1Sequence);
end;

function TX500Name.ToAsn1Object: IAsn1Object;
begin
  Result := FSeq;
end;

{ TX500NameBuilder }

constructor TX500NameBuilder.Create;
begin
  inherited Create();
  FRdns := TList<IAsn1Encodable>.Create;
end;

destructor TX500NameBuilder.Destroy;
begin
  FRdns.Free;
  inherited Destroy();
end;

function TX500NameBuilder.CreateRdn(const oid: IDerObjectIdentifier;
  const value: string): IAsn1Encodable;
var
  seqV, setV: IAsn1EncodableVector;
  rdnValue: IDerUtf8String;
  attrTypeAndValue: IDerSequence;
begin
  // Create the UTF8 string value
  rdnValue := TDerUtf8String.Create(value);

  // AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }
  seqV := TAsn1EncodableVector.Create();
  seqV.Add(oid);
  seqV.Add(rdnValue);
  attrTypeAndValue := TDerSequence.FromVector(seqV);

  // RDN ::= SET OF AttributeTypeAndValue
  setV := TAsn1EncodableVector.Create();
  setV.Add(attrTypeAndValue);
  Result := TDerSet.FromVector(setV, False);
end;

function TX500NameBuilder.AddRdn(const oid: IDerObjectIdentifier;
  const value: string): IX500NameBuilder;
begin
  FRdns.Add(CreateRdn(oid, value));
  Result := Self;
end;

function TX500NameBuilder.AddCommonName(const value: string): IX500NameBuilder;
begin
  Result := AddRdn(TX500NameOids.CommonName, value);
end;

function TX500NameBuilder.AddOrganization(const value: string): IX500NameBuilder;
begin
  Result := AddRdn(TX500NameOids.Organization, value);
end;

function TX500NameBuilder.AddOrganizationalUnit(const value: string): IX500NameBuilder;
begin
  Result := AddRdn(TX500NameOids.OrganizationalUnit, value);
end;

function TX500NameBuilder.AddCountry(const value: string): IX500NameBuilder;
begin
  Result := AddRdn(TX500NameOids.Country, value);
end;

function TX500NameBuilder.AddState(const value: string): IX500NameBuilder;
begin
  Result := AddRdn(TX500NameOids.State, value);
end;

function TX500NameBuilder.AddLocality(const value: string): IX500NameBuilder;
begin
  Result := AddRdn(TX500NameOids.Locality, value);
end;

function TX500NameBuilder.AddEmailAddress(const value: string): IX500NameBuilder;
begin
  Result := AddRdn(TX500NameOids.EmailAddress, value);
end;

function TX500NameBuilder.Build: IX500Name;
begin
  Result := TX500Name.Create(FRdns);
end;

end.
