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

unit ClpAsymmetricKeyEntry;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Generics.Collections,
  ClpAsn1Comparers,
  ClpIAsn1Core,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIPkcs12Entry,
  ClpIAsymmetricKeyEntry,
  ClpIAsymmetricKeyParameter,
  ClpPkcs12Entry,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// PKCS#12 asymmetric key bag entry.
  /// </summary>
  TAsymmetricKeyEntry = class(TPkcs12Entry, IAsymmetricKeyEntry)
  strict private
  var
    FKey: IAsymmetricKeyParameter;

  strict protected
    function GetKey: IAsymmetricKeyParameter;

  public
    constructor Create(const AKey: IAsymmetricKeyParameter); overload;
    constructor Create(const AKey: IAsymmetricKeyParameter;
      const AAttributes: TDictionary<IDerObjectIdentifier, IAsn1Encodable>); overload;

    function Equals(const AOther: IAsymmetricKeyEntry): Boolean; reintroduce;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI} override;

    property Key: IAsymmetricKeyParameter read GetKey;
  end;

implementation

{ TAsymmetricKeyEntry }

constructor TAsymmetricKeyEntry.Create(const AKey: IAsymmetricKeyParameter);
var
  LAttributes: TDictionary<IDerObjectIdentifier, IAsn1Encodable>;
begin
  LAttributes := TDictionary<IDerObjectIdentifier, IAsn1Encodable>.Create(TAsn1Comparers.OidEqualityComparer);
  inherited Create(LAttributes, True);
  if AKey = nil then
    raise EArgumentNilCryptoLibException.Create('key');
  FKey := AKey;
end;

constructor TAsymmetricKeyEntry.Create(const AKey: IAsymmetricKeyParameter;
  const AAttributes: TDictionary<IDerObjectIdentifier, IAsn1Encodable>);
begin
  inherited Create(AAttributes, True);
  if AKey = nil then
    raise EArgumentNilCryptoLibException.Create('key');
  FKey := AKey;
end;

function TAsymmetricKeyEntry.GetKey: IAsymmetricKeyParameter;
begin
  Result := FKey;
end;

function TAsymmetricKeyEntry.Equals(const AOther: IAsymmetricKeyEntry): Boolean;
begin
  if AOther = nil then
  begin
    Result := False;
    Exit;
  end;

  Result := FKey.Equals(AOther.Key);
end;

function TAsymmetricKeyEntry.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
begin
  Result := not FKey.GetHashCode();
end;

end.
