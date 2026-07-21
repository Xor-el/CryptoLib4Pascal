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

unit PkitsVectors;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Generics.Collections,
  ClpIX509Certificate,
  ClpX509CertificateParser,
  ClpIX509Crl,
  ClpX509CrlParser,
  ClpX509Asn1Objects,
  ClpIAsn1Objects,
  ClpAsn1Core,
  ClpIPkixTypes,
  ClpTrustAnchor,
  ClpCryptoLibTypes,
  CryptoLibTestResourceLoader;

type
  /// <summary>
  /// Loads the NIST PKITS certificate and CRL corpus by name from Data/Cert/Pkits.
  /// </summary>
  /// <remarks>
  /// The corpus is addressed by file name rather than through a manifest - there are hundreds of
  /// files and the suites name them directly. <see cref="IsAvailable" /> lets a suite skip cleanly
  /// when the corpus has not been placed in Data/.
  /// </remarks>
  TPkitsVectors = class sealed(TObject)
  strict private
    class var
      FCertCache: TDictionary<string, IX509Certificate>;
      FCrlCache: TDictionary<string, IX509Crl>;

    class function CertPath(const AName: string): string; static;
    class function CrlPath(const AName: string): string; static;
  public
    class constructor Create;
    class destructor Destroy;

    /// <summary>True when the corpus is present, so a suite can skip instead of failing.</summary>
    class function IsAvailable: Boolean; static;
    class function GetCertificate(const AName: string): IX509Certificate; static;
    class function GetCrl(const AName: string): IX509Crl; static;
    /// <summary>The named certificate as a trust anchor, carrying its name constraints if present.</summary>
    class function GetTrustAnchor(const AName: string): ITrustAnchor; static;
  end;

implementation

{ TPkitsVectors }

class constructor TPkitsVectors.Create;
begin
  FCertCache := TDictionary<string, IX509Certificate>.Create();
  FCrlCache := TDictionary<string, IX509Crl>.Create();
end;

class destructor TPkitsVectors.Destroy;
begin
  FCertCache.Free;
  FCrlCache.Free;
end;

class function TPkitsVectors.CertPath(const AName: string): string;
begin
  Result := 'Cert/Pkits/Certs/' + AName + '.crt';
end;

class function TPkitsVectors.CrlPath(const AName: string): string;
begin
  Result := 'Cert/Pkits/Crls/' + AName + '.crl';
end;

class function TPkitsVectors.IsAvailable: Boolean;
begin
  Result := TCryptoLibTestResourceLoader.Instance.ResourceExists
    (CertPath('TrustAnchorRootCertificate'));
end;

class function TPkitsVectors.GetCertificate(const AName: string): IX509Certificate;
var
  LParser: TX509CertificateParser;
begin
  if FCertCache.TryGetValue(AName, Result) then
    Exit;

  LParser := TX509CertificateParser.Create();
  try
    Result := LParser.ReadCertificate(TCryptoLibTestResourceLoader.Instance.LoadAsBytes(CertPath(AName)));
  finally
    LParser.Free;
  end;
  FCertCache.AddOrSetValue(AName, Result);
end;

class function TPkitsVectors.GetCrl(const AName: string): IX509Crl;
var
  LParser: TX509CrlParser;
begin
  if FCrlCache.TryGetValue(AName, Result) then
    Exit;

  LParser := TX509CrlParser.Create();
  try
    Result := LParser.ReadCrl(TCryptoLibTestResourceLoader.Instance.LoadAsBytes(CrlPath(AName)));
  finally
    LParser.Free;
  end;
  FCrlCache.AddOrSetValue(AName, Result);
end;

class function TPkitsVectors.GetTrustAnchor(const AName: string): ITrustAnchor;
var
  LCert: IX509Certificate;
  LExtensionValue: IAsn1OctetString;
  LNameConstraints: TCryptoLibByteArray;
begin
  LCert := GetCertificate(AName);

  LNameConstraints := nil;
  LExtensionValue := LCert.GetExtensionValue(TX509Extensions.NameConstraints);
  if LExtensionValue <> nil then
    // round-trip through the parser so a BER-encoded extension value reaches the anchor as DER
    LNameConstraints := TNameConstraints.GetInstance(LExtensionValue.GetOctets())
      .GetEncoded(TAsn1Encodable.Der);

  Result := TTrustAnchor.Create(LCert, LNameConstraints);
end;

end.
