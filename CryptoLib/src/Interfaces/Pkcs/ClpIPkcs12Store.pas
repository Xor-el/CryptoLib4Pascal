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

unit ClpIPkcs12Store;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  TypInfo,
  ClpIX509Certificate,
  ClpIX509CertificateEntry,
  ClpIAsymmetricKeyEntry,
  ClpISecureRandom,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// In-memory PKCS#12 keystore (PFX) as defined in RFC 7292. Loads and saves password-protected bags of
  /// private keys and X.509 certificates. Create instances via <see cref="IPkcs12StoreBuilder"/>.
  /// </summary>
  IPkcs12Store = interface(IInterface)
    ['{2D3E4F5A-6B7C-8D9E-0F1A-2B3C4D5E6F7A}']

    /// <summary>
    /// Loads a PKCS#12 file from a stream, populating this store with keys and certificates.
    /// </summary>
    /// <param name="AInput">The stream containing the PKCS#12 PFX structure.</param>
    /// <param name="APassword">
    /// The password used to verify the MAC and decrypt shrouded key bags, or <c>nil</c> if none is required.
    /// </param>
    /// <exception cref="EArgumentNilCryptoLibException">
    /// <paramref name="AInput"/> is <c>nil</c>.
    /// </exception>
    /// <exception cref="EIOCryptoLibException">
    /// The MAC verification failed, a password was supplied when none is required (unless
    /// <c>TCryptoLibConfig.Pkcs12.IgnoreUselessPassword</c> is <c>true</c>), or bag attributes conflict.
    /// </exception>
    procedure Load(const AInput: TStream; const APassword: TCryptoLibCharArray);
    /// <summary>
    /// Returns the private-key entry for the given alias, or <c>nil</c> if not present.
    /// </summary>
    /// <param name="AAlias">The entry alias (friendly name or local key id hex string).</param>
    /// <exception cref="EArgumentNilCryptoLibException"><paramref name="AAlias"/> is empty.</exception>
    function GetKey(const AAlias: String): IAsymmetricKeyEntry;
    /// <summary>
    /// Returns <c>true</c> if the alias refers to a certificate-only entry (no private key).
    /// </summary>
    /// <param name="AAlias">The entry alias.</param>
    /// <exception cref="EArgumentNilCryptoLibException"><paramref name="AAlias"/> is empty.</exception>
    function IsCertificateEntry(const AAlias: String): Boolean;
    /// <summary>
    /// Returns <c>true</c> if the alias refers to a private-key entry.
    /// </summary>
    /// <param name="AAlias">The entry alias.</param>
    /// <exception cref="EArgumentNilCryptoLibException"><paramref name="AAlias"/> is empty.</exception>
    function IsKeyEntry(const AAlias: String): Boolean;
    /// <summary>Gets all aliases in this store (union of certificate and key aliases).</summary>
    function GetAliases: TCryptoLibStringArray;
    /// <summary>
    /// Returns <c>true</c> if an entry exists under the given alias.
    /// </summary>
    /// <param name="AAlias">The entry alias.</param>
    /// <exception cref="EArgumentNilCryptoLibException"><paramref name="AAlias"/> is empty.</exception>
    function ContainsAlias(const AAlias: String): Boolean;
    /// <summary>
    /// Returns the certificate entry for the alias — either a certificate-only entry or the end-entity
    /// certificate associated with a private-key alias.
    /// </summary>
    /// <param name="AAlias">The entry alias.</param>
    /// <returns>The certificate entry, or <c>nil</c> if not found.</returns>
    /// <exception cref="EArgumentNilCryptoLibException"><paramref name="AAlias"/> is empty.</exception>
    function GetCertificate(const AAlias: String): IX509CertificateEntry;
    /// <summary>
    /// Finds the alias of the first entry whose certificate equals <paramref name="ACert"/>.
    /// </summary>
    /// <param name="ACert">The certificate to search for.</param>
    /// <returns>The alias, or an empty string if not found.</returns>
    /// <exception cref="EArgumentNilCryptoLibException"><paramref name="ACert"/> is <c>nil</c>.</exception>
    function GetCertificateAlias(const ACert: IX509Certificate): String;
    /// <summary>
    /// Builds the certificate chain for a private-key alias by following Authority Key Identifier
    /// or issuer/subject matching.
    /// </summary>
    /// <param name="AAlias">The private-key alias.</param>
    /// <returns>The chain from end entity to root, or <c>nil</c> if the alias is not a key entry.</returns>
    /// <exception cref="EArgumentNilCryptoLibException"><paramref name="AAlias"/> is empty.</exception>
    function GetCertificateChain(const AAlias: String): TCryptoLibGenericArray<IX509CertificateEntry>;
    /// <summary>
    /// Adds or replaces a certificate-only entry under the given alias.
    /// </summary>
    /// <param name="AAlias">The entry alias.</param>
    /// <param name="ACertEntry">The certificate entry to store.</param>
    /// <exception cref="EArgumentNilCryptoLibException">
    /// <paramref name="AAlias"/> is empty or <paramref name="ACertEntry"/> is <c>nil</c>.
    /// </exception>
    /// <exception cref="EArgumentCryptoLibException">
    /// A private-key entry already exists under <paramref name="AAlias"/>.
    /// </exception>
    procedure SetCertificateEntry(const AAlias: String; const ACertEntry: IX509CertificateEntry);
    /// <summary>
    /// Renames an entry by updating its PKCS#9 friendly name and re-keying internal maps.
    /// </summary>
    /// <param name="AAlias">The current alias.</param>
    /// <param name="ANewFriendlyName">The new friendly name.</param>
    /// <exception cref="EArgumentNilCryptoLibException">
    /// <paramref name="AAlias"/> is empty or <paramref name="ANewFriendlyName"/> is empty.
    /// </exception>
    procedure SetFriendlyName(const AAlias: String; const ANewFriendlyName: String);
    /// <summary>
    /// Adds or replaces a private-key entry and optional certificate chain under the given alias.
    /// </summary>
    /// <param name="AAlias">The entry alias.</param>
    /// <param name="AKeyEntry">The private-key entry.</param>
    /// <param name="AChain">
    /// The certificate chain for the key (required when <paramref name="AKeyEntry"/> holds a private key).
    /// </param>
    /// <exception cref="EArgumentNilCryptoLibException">
    /// <paramref name="AAlias"/> is empty or <paramref name="AKeyEntry"/> is <c>nil</c>.
    /// </exception>
    /// <exception cref="EArgumentCryptoLibException">
    /// A private key was supplied without a certificate chain.
    /// </exception>
    procedure SetKeyEntry(const AAlias: String; const AKeyEntry: IAsymmetricKeyEntry;
      const AChain: TCryptoLibGenericArray<IX509CertificateEntry>);
    /// <summary>Removes the entry (certificate and/or key) for the given alias.</summary>
    /// <param name="AAlias">The entry alias.</param>
    /// <exception cref="EArgumentNilCryptoLibException"><paramref name="AAlias"/> is empty.</exception>
    procedure DeleteEntry(const AAlias: String);
    /// <summary>
    /// Returns <c>true</c> if the alias refers to an entry assignable to <paramref name="AEntryType"/>.
    /// </summary>
    /// <param name="AAlias">The entry alias.</param>
    /// <param name="AEntryType"><see cref="IX509CertificateEntry"/> or <see cref="IAsymmetricKeyEntry"/>.</param>
    function IsEntryOfType(const AAlias: String; AEntryType: PTypeInfo): Boolean;
    /// <summary>Gets the number of distinct aliases in this store.</summary>
    function GetCount: Int32;
    /// <summary>
    /// Writes this store as a PKCS#12 PFX structure to a stream.
    /// </summary>
    /// <param name="AStream">The output stream.</param>
    /// <param name="APassword">
    /// The password used to encrypt shrouded key bags and the integrity MAC, or <c>nil</c> for unencrypted keys.
    /// </param>
    /// <param name="ARandom">Randomness source for salts and IVs.</param>
    /// <exception cref="EArgumentNilCryptoLibException">
    /// <paramref name="AStream"/> or <paramref name="ARandom"/> is <c>nil</c>.
    /// </exception>
    procedure Save(const AStream: TStream; const APassword: TCryptoLibCharArray; const ARandom: ISecureRandom);

    property Count: Int32 read GetCount;
    property Aliases: TCryptoLibStringArray read GetAliases;
  end;

implementation

end.
