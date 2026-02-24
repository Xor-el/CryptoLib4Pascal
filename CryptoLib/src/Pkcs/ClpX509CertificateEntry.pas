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

unit ClpX509CertificateEntry;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Generics.Collections,
  ClpAsn1Comparers,
  ClpIAsn1Core,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIPkcs12Entry,
  ClpIX509CertificateEntry,
  ClpIX509Certificate,
  ClpPkcs12Entry,
  ClpX509Certificate,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// PKCS#12 certificate bag entry.
  /// </summary>
  TX509CertificateEntry = class(TPkcs12Entry, IX509CertificateEntry)
  strict private
  var
    FCertificate: IX509Certificate;

  strict protected
    function GetCertificate: IX509Certificate;

  public
    constructor Create(const ACert: IX509Certificate); overload;
    constructor Create(const ACert: IX509Certificate;
      const AAttributes: TDictionary<IDerObjectIdentifier, IAsn1Encodable>); overload;

    function Equals(const AOther: IX509CertificateEntry): Boolean; reintroduce;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI} override;

    property Certificate: IX509Certificate read GetCertificate;
  end;

implementation

{ TX509CertificateEntry }

constructor TX509CertificateEntry.Create(const ACert: IX509Certificate);
var
  LAttributes: TDictionary<IDerObjectIdentifier, IAsn1Encodable>;
begin
  LAttributes := TDictionary<IDerObjectIdentifier, IAsn1Encodable>.Create(TAsn1Comparers.OidEqualityComparer);
  inherited Create(LAttributes, True);
  if ACert = nil then
    raise EArgumentNilCryptoLibException.Create('cert');
  FCertificate := ACert;
end;

constructor TX509CertificateEntry.Create(const ACert: IX509Certificate;
  const AAttributes: TDictionary<IDerObjectIdentifier, IAsn1Encodable>);
begin
  inherited Create(AAttributes, False);
  if ACert = nil then
    raise EArgumentNilCryptoLibException.Create('cert');
  FCertificate := ACert;
end;

function TX509CertificateEntry.GetCertificate: IX509Certificate;
begin
  Result := FCertificate;
end;

function TX509CertificateEntry.Equals(const AOther: IX509CertificateEntry): Boolean;
begin
  if AOther = nil then
  begin
    Result := False;
    Exit;
  end;

  Result := FCertificate.Equals(AOther.Certificate);
end;

function TX509CertificateEntry.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
begin
  Result := not FCertificate.GetHashCode();
end;

end.
