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

unit ClpOcspObjectIdentifiers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpX509ObjectIdentifiers,
  ClpIAsn1Objects;

type
  /// <summary>OCSP object identifiers rooted at id-pkix-ocsp (RFC 6960 sec. 4.4).</summary>
  TOcspObjectIdentifiers = class abstract(TObject)
  strict private
    class var
      FPkixOcsp, FPkixOcspBasic, FPkixOcspNonce, FPkixOcspCrl, FPkixOcspResponse,
      FPkixOcspNocheck, FPkixOcspArchiveCutoff, FPkixOcspServiceLocator,
      FPkixPcspPrefSigSlgs, FPkixPcspExtendedRevoke: IDerObjectIdentifier;

    class function GetPkixOcsp: IDerObjectIdentifier; static; inline;
    class function GetPkixOcspBasic: IDerObjectIdentifier; static; inline;
    class function GetPkixOcspNonce: IDerObjectIdentifier; static; inline;
    class function GetPkixOcspCrl: IDerObjectIdentifier; static; inline;
    class function GetPkixOcspResponse: IDerObjectIdentifier; static; inline;
    class function GetPkixOcspNocheck: IDerObjectIdentifier; static; inline;
    class function GetPkixOcspArchiveCutoff: IDerObjectIdentifier; static; inline;
    class function GetPkixOcspServiceLocator: IDerObjectIdentifier; static; inline;
    class function GetPkixPcspPrefSigSlgs: IDerObjectIdentifier; static; inline;
    class function GetPkixPcspExtendedRevoke: IDerObjectIdentifier; static; inline;

    class constructor Create;
  public
    /// <summary>id-pkix-ocsp: 1.3.6.1.5.5.7.48.1</summary>
    class property PkixOcsp: IDerObjectIdentifier read GetPkixOcsp;
    /// <summary>id-pkix-ocsp-basic: 1.3.6.1.5.5.7.48.1.1</summary>
    class property PkixOcspBasic: IDerObjectIdentifier read GetPkixOcspBasic;
    /// <summary>id-pkix-ocsp-nonce: 1.3.6.1.5.5.7.48.1.2</summary>
    class property PkixOcspNonce: IDerObjectIdentifier read GetPkixOcspNonce;
    /// <summary>id-pkix-ocsp-crl: 1.3.6.1.5.5.7.48.1.3</summary>
    class property PkixOcspCrl: IDerObjectIdentifier read GetPkixOcspCrl;
    /// <summary>id-pkix-ocsp-response: 1.3.6.1.5.5.7.48.1.4</summary>
    class property PkixOcspResponse: IDerObjectIdentifier read GetPkixOcspResponse;
    /// <summary>id-pkix-ocsp-nocheck: 1.3.6.1.5.5.7.48.1.5</summary>
    class property PkixOcspNocheck: IDerObjectIdentifier read GetPkixOcspNocheck;
    /// <summary>id-pkix-ocsp-archive-cutoff: 1.3.6.1.5.5.7.48.1.6</summary>
    class property PkixOcspArchiveCutoff: IDerObjectIdentifier read GetPkixOcspArchiveCutoff;
    /// <summary>id-pkix-ocsp-service-locator: 1.3.6.1.5.5.7.48.1.7</summary>
    class property PkixOcspServiceLocator: IDerObjectIdentifier read GetPkixOcspServiceLocator;
    /// <summary>id-pkix-ocsp-pref-sig-algs: 1.3.6.1.5.5.7.48.1.8</summary>
    class property PkixPcspPrefSigSlgs: IDerObjectIdentifier read GetPkixPcspPrefSigSlgs;
    /// <summary>id-pkix-ocsp-extended-revoke: 1.3.6.1.5.5.7.48.1.9</summary>
    class property PkixPcspExtendedRevoke: IDerObjectIdentifier read GetPkixPcspExtendedRevoke;
  end;

implementation

{ TOcspObjectIdentifiers }

class constructor TOcspObjectIdentifiers.Create;
begin
  FPkixOcsp := TX509ObjectIdentifiers.IdADOcsp;
  FPkixOcspBasic := FPkixOcsp.Branch('1');
  FPkixOcspNonce := FPkixOcsp.Branch('2');
  FPkixOcspCrl := FPkixOcsp.Branch('3');
  FPkixOcspResponse := FPkixOcsp.Branch('4');
  FPkixOcspNocheck := FPkixOcsp.Branch('5');
  FPkixOcspArchiveCutoff := FPkixOcsp.Branch('6');
  FPkixOcspServiceLocator := FPkixOcsp.Branch('7');
  FPkixPcspPrefSigSlgs := FPkixOcsp.Branch('8');
  FPkixPcspExtendedRevoke := FPkixOcsp.Branch('9');
end;

class function TOcspObjectIdentifiers.GetPkixOcsp: IDerObjectIdentifier;
begin
  Result := FPkixOcsp;
end;

class function TOcspObjectIdentifiers.GetPkixOcspBasic: IDerObjectIdentifier;
begin
  Result := FPkixOcspBasic;
end;

class function TOcspObjectIdentifiers.GetPkixOcspNonce: IDerObjectIdentifier;
begin
  Result := FPkixOcspNonce;
end;

class function TOcspObjectIdentifiers.GetPkixOcspCrl: IDerObjectIdentifier;
begin
  Result := FPkixOcspCrl;
end;

class function TOcspObjectIdentifiers.GetPkixOcspResponse: IDerObjectIdentifier;
begin
  Result := FPkixOcspResponse;
end;

class function TOcspObjectIdentifiers.GetPkixOcspNocheck: IDerObjectIdentifier;
begin
  Result := FPkixOcspNocheck;
end;

class function TOcspObjectIdentifiers.GetPkixOcspArchiveCutoff: IDerObjectIdentifier;
begin
  Result := FPkixOcspArchiveCutoff;
end;

class function TOcspObjectIdentifiers.GetPkixOcspServiceLocator: IDerObjectIdentifier;
begin
  Result := FPkixOcspServiceLocator;
end;

class function TOcspObjectIdentifiers.GetPkixPcspPrefSigSlgs: IDerObjectIdentifier;
begin
  Result := FPkixPcspPrefSigSlgs;
end;

class function TOcspObjectIdentifiers.GetPkixPcspExtendedRevoke: IDerObjectIdentifier;
begin
  Result := FPkixPcspExtendedRevoke;
end;

end.
