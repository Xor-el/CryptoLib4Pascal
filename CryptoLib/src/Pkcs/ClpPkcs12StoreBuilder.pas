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

unit ClpPkcs12StoreBuilder;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  //ClpPkcsObjectIdentifiers,
  ClpNistObjectIdentifiers,
  ClpIPkcs12StoreBuilder,
  ClpIPkcs12Store,
  ClpPkcs12Store,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Builder for Pkcs12Store with configurable algorithms and options.
  /// </summary>
  TPkcs12StoreBuilder = class sealed(TInterfacedObject, IPkcs12StoreBuilder)
  strict private
    FCertAlgorithm: IDerObjectIdentifier;
    FCertPrfAlgorithm: IDerObjectIdentifier;
    FKeyAlgorithm: IDerObjectIdentifier;
    FKeyPrfAlgorithm: IDerObjectIdentifier;
    FUseDerEncoding: Boolean;
    FReverseCertificates: Boolean;
    FOverwriteFriendlyName: Boolean;
    FEnableOracleTrustedKeyUsage: Boolean;
  public
    constructor Create;
    function Build: IPkcs12Store;
    function SetCertAlgorithm(const ACertAlgorithm: IDerObjectIdentifier): IPkcs12StoreBuilder; overload;
    function SetCertAlgorithm(const ACertAlgorithm, ACertPrfAlgorithm: IDerObjectIdentifier): IPkcs12StoreBuilder; overload;
    /// <summary>
    /// Whether to include Oracle's TrustedKeyUsage attribute in CertBag attributes. Defaults to <c>true</c>.
    /// </summary>
    /// <remarks>The OID 2.16.840.1.113894.746875.1.1 is used for this attribute.</remarks>
    /// <param name="AEnableOracleTrustedKeyUsage"></param>
    /// <returns></returns>
    function SetEnableOracleTrustedKeyUsage(AEnableOracleTrustedKeyUsage: Boolean): IPkcs12StoreBuilder;
    function SetKeyAlgorithm(const AKeyAlgorithm: IDerObjectIdentifier): IPkcs12StoreBuilder; overload;
    function SetKeyAlgorithm(const AKeyAlgorithm, AKeyPrfAlgorithm: IDerObjectIdentifier): IPkcs12StoreBuilder; overload;
    function SetOverwriteFriendlyName(AOverwriteFriendlyName: Boolean): IPkcs12StoreBuilder;
    function SetReverseCertificates(AReverseCertificates: Boolean): IPkcs12StoreBuilder;
    function SetUseDerEncoding(AUseDerEncoding: Boolean): IPkcs12StoreBuilder;
  end;

implementation

{ TPkcs12StoreBuilder }

constructor TPkcs12StoreBuilder.Create;
begin
  inherited Create;
  FCertAlgorithm := TNistObjectIdentifiers.IdAes256Cbc;//TPkcsObjectIdentifiers.PbewithShaAnd40BitRC2Cbc;
  FCertPrfAlgorithm := nil;
  FKeyAlgorithm := TNistObjectIdentifiers.IdAes256Cbc;//TPkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc;
  FKeyPrfAlgorithm := nil;
  FUseDerEncoding := False;
  FReverseCertificates := False;
  FOverwriteFriendlyName := True;
  FEnableOracleTrustedKeyUsage := True;
end;

function TPkcs12StoreBuilder.Build: IPkcs12Store;
begin
  Result := TPkcs12Store.Create(FCertAlgorithm, FCertPrfAlgorithm, FKeyAlgorithm, FKeyPrfAlgorithm,
    FUseDerEncoding, FReverseCertificates, FOverwriteFriendlyName, FEnableOracleTrustedKeyUsage);
end;

function TPkcs12StoreBuilder.SetCertAlgorithm(const ACertAlgorithm: IDerObjectIdentifier): IPkcs12StoreBuilder;
begin
  FCertAlgorithm := ACertAlgorithm;
  FCertPrfAlgorithm := nil;
  Result := Self;
end;

function TPkcs12StoreBuilder.SetCertAlgorithm(const ACertAlgorithm, ACertPrfAlgorithm: IDerObjectIdentifier): IPkcs12StoreBuilder;
begin
  FCertAlgorithm := ACertAlgorithm;
  FCertPrfAlgorithm := ACertPrfAlgorithm;
  Result := Self;
end;

function TPkcs12StoreBuilder.SetEnableOracleTrustedKeyUsage(AEnableOracleTrustedKeyUsage: Boolean): IPkcs12StoreBuilder;
begin
  FEnableOracleTrustedKeyUsage := AEnableOracleTrustedKeyUsage;
  Result := Self;
end;

function TPkcs12StoreBuilder.SetKeyAlgorithm(const AKeyAlgorithm: IDerObjectIdentifier): IPkcs12StoreBuilder;
begin
  FKeyAlgorithm := AKeyAlgorithm;
  FKeyPrfAlgorithm := nil;
  Result := Self;
end;

function TPkcs12StoreBuilder.SetKeyAlgorithm(const AKeyAlgorithm, AKeyPrfAlgorithm: IDerObjectIdentifier): IPkcs12StoreBuilder;
begin
  FKeyAlgorithm := AKeyAlgorithm;
  FKeyPrfAlgorithm := AKeyPrfAlgorithm;
  Result := Self;
end;

function TPkcs12StoreBuilder.SetOverwriteFriendlyName(AOverwriteFriendlyName: Boolean): IPkcs12StoreBuilder;
begin
  FOverwriteFriendlyName := AOverwriteFriendlyName;
  Result := Self;
end;

function TPkcs12StoreBuilder.SetReverseCertificates(AReverseCertificates: Boolean): IPkcs12StoreBuilder;
begin
  FReverseCertificates := AReverseCertificates;
  Result := Self;
end;

function TPkcs12StoreBuilder.SetUseDerEncoding(AUseDerEncoding: Boolean): IPkcs12StoreBuilder;
begin
  FUseDerEncoding := AUseDerEncoding;
  Result := Self;
end;

end.
