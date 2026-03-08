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
  ClpNistObjectIdentifiers,
  ClpPkcsObjectIdentifiers,
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
    FMacDigestAlgorithm: IDerObjectIdentifier;
    FUseDerEncoding: Boolean;
    FReverseCertificates: Boolean;
    FOverwriteFriendlyName: Boolean;
    FEnableOracleTrustedKeyUsage: Boolean;
    FKeyIterations: Int32;
    FCertIterations: Int32;
    FMacIterations: Int32;
    FKeySaltSize: Int32;
    FCertSaltSize: Int32;
    FMacSaltSize: Int32;
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
    function SetMacDigestAlgorithm(const AMacDigestAlgorithm: IDerObjectIdentifier): IPkcs12StoreBuilder;
    function SetOverwriteFriendlyName(AOverwriteFriendlyName: Boolean): IPkcs12StoreBuilder;
    function SetReverseCertificates(AReverseCertificates: Boolean): IPkcs12StoreBuilder;
    function SetUseDerEncoding(AUseDerEncoding: Boolean): IPkcs12StoreBuilder;
    function SetKeyIterationCount(AIterations: Int32): IPkcs12StoreBuilder;
    function SetCertIterationCount(AIterations: Int32): IPkcs12StoreBuilder;
    function SetMacIterationCount(AIterations: Int32): IPkcs12StoreBuilder;
    function SetKeySaltSize(ASaltSize: Int32): IPkcs12StoreBuilder;
    function SetCertSaltSize(ASaltSize: Int32): IPkcs12StoreBuilder;
    function SetMacSaltSize(ASaltSize: Int32): IPkcs12StoreBuilder;
  end;

implementation

{ TPkcs12StoreBuilder }

constructor TPkcs12StoreBuilder.Create;
begin
  inherited Create;
  FCertAlgorithm := TNistObjectIdentifiers.IdAes256Cbc;
  FCertPrfAlgorithm := nil;
  FKeyAlgorithm := TNistObjectIdentifiers.IdAes256Cbc;
  FKeyPrfAlgorithm := nil;
  FMacDigestAlgorithm := nil;
  FUseDerEncoding := False;
  FReverseCertificates := False;
  FOverwriteFriendlyName := True;
  FEnableOracleTrustedKeyUsage := True;
  FKeyIterations := TPkcs12Store.DefaultIterations;
  FCertIterations := TPkcs12Store.DefaultIterations;
  FMacIterations := TPkcs12Store.DefaultIterations;
  FKeySaltSize := TPkcs12Store.DefaultSaltSize;
  FCertSaltSize := TPkcs12Store.DefaultSaltSize;
  FMacSaltSize := TPkcs12Store.DefaultSaltSize;
end;

function TPkcs12StoreBuilder.Build: IPkcs12Store;
begin
  Result := TPkcs12Store.Create(FCertAlgorithm, FCertPrfAlgorithm, FKeyAlgorithm, FKeyPrfAlgorithm, FMacDigestAlgorithm,
    FUseDerEncoding, FReverseCertificates, FOverwriteFriendlyName, FEnableOracleTrustedKeyUsage,
    FKeyIterations, FCertIterations, FMacIterations, FKeySaltSize, FCertSaltSize, FMacSaltSize);
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

function TPkcs12StoreBuilder.SetMacDigestAlgorithm(const AMacDigestAlgorithm: IDerObjectIdentifier): IPkcs12StoreBuilder;
begin
  FMacDigestAlgorithm := AMacDigestAlgorithm;
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

function TPkcs12StoreBuilder.SetKeyIterationCount(AIterations: Int32): IPkcs12StoreBuilder;
begin
  FKeyIterations := AIterations;
  Result := Self;
end;

function TPkcs12StoreBuilder.SetCertIterationCount(AIterations: Int32): IPkcs12StoreBuilder;
begin
  FCertIterations := AIterations;
  Result := Self;
end;

function TPkcs12StoreBuilder.SetMacIterationCount(AIterations: Int32): IPkcs12StoreBuilder;
begin
  FMacIterations := AIterations;
  Result := Self;
end;

function TPkcs12StoreBuilder.SetKeySaltSize(ASaltSize: Int32): IPkcs12StoreBuilder;
begin
  FKeySaltSize := ASaltSize;
  Result := Self;
end;

function TPkcs12StoreBuilder.SetCertSaltSize(ASaltSize: Int32): IPkcs12StoreBuilder;
begin
  FCertSaltSize := ASaltSize;
  Result := Self;
end;

function TPkcs12StoreBuilder.SetMacSaltSize(ASaltSize: Int32): IPkcs12StoreBuilder;
begin
  FMacSaltSize := ASaltSize;
  Result := Self;
end;

end.
