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

unit ClpIPkcs12StoreBuilder;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIPkcs12Store,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Fluent builder for <see cref="IPkcs12Store"/> instances, configuring PBE algorithms and
  /// encoding options used when saving PKCS#12 files (RFC 7292).
  /// </summary>
  IPkcs12StoreBuilder = interface(IInterface)
    ['{8E7F2D1C-9B4A-4E5F-8C3D-0A1B2C3D4E5F}']

    /// <summary>
    /// Builds a new <see cref="IPkcs12Store"/> using the configured algorithms and options.
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
    /// Controls whether <see cref="IPkcs12Store.SetFriendlyName"/> may replace an existing friendly name.
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
    /// <param name="AIterations">The iteration count.</param>
    /// <returns>This builder instance.</returns>
    function SetKeyIterationCount(AIterations: Int32): IPkcs12StoreBuilder;
    /// <summary>
    /// Sets the PBE iteration count used when encrypting certificate bags on save.
    /// </summary>
    /// <param name="AIterations">The iteration count.</param>
    /// <returns>This builder instance.</returns>
    function SetCertIterationCount(AIterations: Int32): IPkcs12StoreBuilder;
    /// <summary>
    /// Sets the iteration count used when computing the PKCS#12 integrity MAC on save.
    /// </summary>
    /// <param name="AIterations">The iteration count.</param>
    /// <returns>This builder instance.</returns>
    function SetMacIterationCount(AIterations: Int32): IPkcs12StoreBuilder;
    /// <summary>
    /// Sets the salt size in bytes used when encrypting private-key bags on save.
    /// </summary>
    /// <param name="ASaltSize">The salt size in bytes.</param>
    /// <returns>This builder instance.</returns>
    function SetKeySaltSize(ASaltSize: Int32): IPkcs12StoreBuilder;
    /// <summary>
    /// Sets the salt size in bytes used when encrypting certificate bags on save.
    /// </summary>
    /// <param name="ASaltSize">The salt size in bytes.</param>
    /// <returns>This builder instance.</returns>
    function SetCertSaltSize(ASaltSize: Int32): IPkcs12StoreBuilder;
    /// <summary>
    /// Sets the salt size in bytes used when computing the PKCS#12 integrity MAC on save.
    /// </summary>
    /// <param name="ASaltSize">The salt size in bytes.</param>
    /// <returns>This builder instance.</returns>
    function SetMacSaltSize(ASaltSize: Int32): IPkcs12StoreBuilder;
  end;

implementation

end.
