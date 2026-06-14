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
  /// Fluent builder for <see cref="TPkcs12Store"/> instances, configuring PBE algorithms and
  /// encoding options used when saving PKCS#12 files (RFC 7292).
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
    /// <summary>Creates a builder with library-default PBE algorithms and options.</summary>
    constructor Create;
    /// <summary>
    /// Builds a new <see cref="TPkcs12Store"/> using the configured algorithms and options.
    /// </summary>
    /// <returns>A new, empty PKCS#12 store.</returns>
    function Build: IPkcs12Store;
    /// <summary>
    /// Sets the PBE algorithm used to encrypt certificate bags when saving (PKCS#12 scheme 1).
    /// </summary>
    /// <param name="ACertAlgorithm">The certificate encryption algorithm OID.</param>
    /// <returns>This builder instance.</returns>
    function SetCertAlgorithm(const ACertAlgorithm: IDerObjectIdentifier): IPkcs12StoreBuilder; overload;
    /// <summary>
    /// Sets the PBES2 algorithm and PRF used to encrypt certificate bags when saving (PKCS#12 scheme 2).
    /// </summary>
    /// <param name="ACertAlgorithm">The certificate encryption algorithm OID.</param>
    /// <param name="ACertPrfAlgorithm">The PRF algorithm OID.</param>
    /// <returns>This builder instance.</returns>
    function SetCertAlgorithm(const ACertAlgorithm, ACertPrfAlgorithm: IDerObjectIdentifier): IPkcs12StoreBuilder; overload;
    /// <summary>
    /// Whether to include Oracle's TrustedKeyUsage attribute in CertBag attributes. Defaults to <c>true</c>.
    /// </summary>
    /// <remarks>The OID 2.16.840.1.113894.746875.1.1 is used for this attribute.</remarks>
    /// <param name="AEnableOracleTrustedKeyUsage"><c>true</c> to emit the attribute when saving.</param>
    /// <returns>This builder instance.</returns>
    function SetEnableOracleTrustedKeyUsage(AEnableOracleTrustedKeyUsage: Boolean): IPkcs12StoreBuilder;
    /// <summary>
    /// Sets the PBE algorithm used to encrypt private-key bags when saving (PKCS#12 scheme 1).
    /// </summary>
    /// <param name="AKeyAlgorithm">The key encryption algorithm OID.</param>
    /// <returns>This builder instance.</returns>
    function SetKeyAlgorithm(const AKeyAlgorithm: IDerObjectIdentifier): IPkcs12StoreBuilder; overload;
    /// <summary>
    /// Sets the PBES2 algorithm and PRF used to encrypt private-key bags when saving (PKCS#12 scheme 2).
    /// </summary>
    /// <param name="AKeyAlgorithm">The key encryption algorithm OID.</param>
    /// <param name="AKeyPrfAlgorithm">The PRF algorithm OID.</param>
    /// <returns>This builder instance.</returns>
    function SetKeyAlgorithm(const AKeyAlgorithm, AKeyPrfAlgorithm: IDerObjectIdentifier): IPkcs12StoreBuilder; overload;
    /// <summary>
    /// Sets the digest algorithm OID used for the PKCS#12 integrity MAC when saving.
    /// </summary>
    /// <param name="AMacDigestAlgorithm">The MAC digest algorithm OID, or <c>nil</c> for the library default.</param>
    /// <returns>This builder instance.</returns>
    function SetMacDigestAlgorithm(const AMacDigestAlgorithm: IDerObjectIdentifier): IPkcs12StoreBuilder;
    /// <summary>
    /// Controls whether <see cref="TPkcs12Store.SetFriendlyName"/> may replace an existing friendly name.
    /// Defaults to <c>true</c>.
    /// </summary>
    /// <param name="AOverwriteFriendlyName"><c>true</c> to allow overwriting friendly names.</param>
    /// <returns>This builder instance.</returns>
    function SetOverwriteFriendlyName(AOverwriteFriendlyName: Boolean): IPkcs12StoreBuilder;
    /// <summary>
    /// When <c>true</c>, certificate and key bags are written in reverse insertion order when saving.
    /// </summary>
    /// <param name="AReverseCertificates"><c>true</c> to reverse bag order on save.</param>
    /// <returns>This builder instance.</returns>
    function SetReverseCertificates(AReverseCertificates: Boolean): IPkcs12StoreBuilder;
    /// <summary>
    /// When <c>true</c>, saved PKCS#12 structures use DER encoding instead of BER for inner content.
    /// </summary>
    /// <param name="AUseDerEncoding"><c>true</c> for definite-length DER encoding.</param>
    /// <returns>This builder instance.</returns>
    function SetUseDerEncoding(AUseDerEncoding: Boolean): IPkcs12StoreBuilder;
    /// <summary>
    /// Sets the PBE iteration count used when encrypting private-key bags on save.
    /// </summary>
    /// <param name="AIterations">The iteration count (defaults to <see cref="TPkcs12Store.DefaultIterations"/>).</param>
    /// <returns>This builder instance.</returns>
    function SetKeyIterationCount(AIterations: Int32): IPkcs12StoreBuilder;
    /// <summary>
    /// Sets the PBE iteration count used when encrypting certificate bags on save.
    /// </summary>
    /// <param name="AIterations">The iteration count (defaults to <see cref="TPkcs12Store.DefaultIterations"/>).</param>
    /// <returns>This builder instance.</returns>
    function SetCertIterationCount(AIterations: Int32): IPkcs12StoreBuilder;
    /// <summary>
    /// Sets the iteration count used when computing the PKCS#12 integrity MAC on save.
    /// </summary>
    /// <param name="AIterations">The iteration count (defaults to <see cref="TPkcs12Store.DefaultIterations"/>).</param>
    /// <returns>This builder instance.</returns>
    function SetMacIterationCount(AIterations: Int32): IPkcs12StoreBuilder;
    /// <summary>
    /// Sets the salt size in bytes used when encrypting private-key bags on save.
    /// </summary>
    /// <param name="ASaltSize">The salt size in bytes (defaults to <see cref="TPkcs12Store.DefaultSaltSize"/>).</param>
    /// <returns>This builder instance.</returns>
    function SetKeySaltSize(ASaltSize: Int32): IPkcs12StoreBuilder;
    /// <summary>
    /// Sets the salt size in bytes used when encrypting certificate bags on save.
    /// </summary>
    /// <param name="ASaltSize">The salt size in bytes (defaults to <see cref="TPkcs12Store.DefaultSaltSize"/>).</param>
    /// <returns>This builder instance.</returns>
    function SetCertSaltSize(ASaltSize: Int32): IPkcs12StoreBuilder;
    /// <summary>
    /// Sets the salt size in bytes used when computing the PKCS#12 integrity MAC on save.
    /// </summary>
    /// <param name="ASaltSize">The salt size in bytes (defaults to <see cref="TPkcs12Store.DefaultSaltSize"/>).</param>
    /// <returns>This builder instance.</returns>
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
