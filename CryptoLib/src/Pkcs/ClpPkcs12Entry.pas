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
  /// Abstract base for PKCS#12 bag entries with attributes.
  /// </summary>
  TPkcs12Entry = class abstract(TInterfacedObject, IPkcs12Entry)
  strict private
  var
    FAttributes: TDictionary<IDerObjectIdentifier, IAsn1Encodable>;
    FOwnsAttributes: Boolean;

  strict protected
    function GetItem(const AOid: IDerObjectIdentifier): IAsn1Encodable;
    function GetBagAttributeKeys: TCryptoLibGenericArray<IDerObjectIdentifier>;
    function GetHasFriendlyName: Boolean;
    procedure SetFriendlyName(const AName: String);
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
