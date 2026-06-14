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

unit ClpPkcs12Entry;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Generics.Collections,
  ClpIAsn1Core,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIPkcs12Entry,
  ClpPkcsObjectIdentifiers,
  ClpCollectionUtilities,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Base class for PKCS#12 bag entries (private keys and certificates) carrying optional
  /// PKCS#9 bag attributes such as friendly name and local key identifier.
  /// </summary>
  TPkcs12Entry = class abstract(TInterfacedObject, IPkcs12Entry)
  strict private
  var
    FAttributes: TDictionary<IDerObjectIdentifier, IAsn1Encodable>;
    FOwnsAttributes: Boolean;

  strict protected
    /// <summary>
    /// Gets the bag attribute value for the given object identifier, or <c>nil</c> if absent.
    /// </summary>
    /// <param name="AOid">The bag attribute OID.</param>
    function GetItem(const AOid: IDerObjectIdentifier): IAsn1Encodable;
    /// <summary>Gets the object identifiers of all bag attributes on this entry.</summary>
    function GetBagAttributeKeys: TCryptoLibGenericArray<IDerObjectIdentifier>;
    /// <summary>
    /// Returns <c>true</c> if this entry has a PKCS#9 friendly name attribute.
    /// </summary>
    function GetHasFriendlyName: Boolean;
    /// <summary>
    /// Sets or replaces the PKCS#9 friendly name bag attribute on this entry.
    /// </summary>
    /// <param name="AName">The friendly name to store.</param>
    procedure SetFriendlyName(const AName: String);
    /// <summary>
    /// Attempts to retrieve a bag attribute by OID.
    /// </summary>
    /// <param name="AOid">The bag attribute OID.</param>
    /// <param name="AAttribute">The attribute value, if present.</param>
    /// <returns><c>true</c> if the attribute was found.</returns>
    function TryGetAttribute(const AOid: IDerObjectIdentifier;
      out AAttribute: IAsn1Encodable): Boolean;

  public
    constructor Create(const AAttributes: TDictionary<IDerObjectIdentifier, IAsn1Encodable>;
      AOwnsAttributes: Boolean = False);
    destructor Destroy; override;
    property HasFriendlyName: Boolean read GetHasFriendlyName;
  end;

implementation

{ TPkcs12Entry }

constructor TPkcs12Entry.Create(const AAttributes: TDictionary<IDerObjectIdentifier, IAsn1Encodable>;
  AOwnsAttributes: Boolean);
begin
  inherited Create();
  FAttributes := AAttributes;
  FOwnsAttributes := AOwnsAttributes;
end;

destructor TPkcs12Entry.Destroy;
begin
  if FOwnsAttributes and (FAttributes <> nil) then
    FAttributes.Free;
  FAttributes := nil;
  inherited Destroy;
end;

function TPkcs12Entry.GetItem(const AOid: IDerObjectIdentifier): IAsn1Encodable;
begin
  Result := TCollectionUtilities.GetValueOrNull<IDerObjectIdentifier, IAsn1Encodable>(FAttributes, AOid);
end;

function TPkcs12Entry.GetBagAttributeKeys: TCryptoLibGenericArray<IDerObjectIdentifier>;
begin
  Result := TCollectionUtilities.Keys<IDerObjectIdentifier, IAsn1Encodable>(FAttributes);
end;

function TPkcs12Entry.GetHasFriendlyName: Boolean;
begin
  Result := FAttributes.ContainsKey(TPkcsObjectIdentifiers.Pkcs9AtFriendlyName);
end;

procedure TPkcs12Entry.SetFriendlyName(const AName: String);
var
  LEnc: IAsn1Encodable;
  LBmp: IDerBmpString;
begin
  LBmp := TDerBmpString.Create(AName);
  LEnc := LBmp;
  FAttributes.AddOrSetValue(TPkcsObjectIdentifiers.Pkcs9AtFriendlyName, LEnc);
end;

function TPkcs12Entry.TryGetAttribute(const AOid: IDerObjectIdentifier;
  out AAttribute: IAsn1Encodable): Boolean;
begin
  Result := FAttributes.TryGetValue(AOid, AAttribute);
end;

end.
