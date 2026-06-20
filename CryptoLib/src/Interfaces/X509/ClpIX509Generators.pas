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

unit ClpIX509Generators;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpBigInteger,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpIX509Extension,
  ClpIX509Attribute,
  ClpIX509V2AttributeCertificate,
  ClpIAttributeCertificateHolder,
  ClpIAttributeCertificateIssuer,
  ClpIAsymmetricKeyParameter,
  ClpISignatureFactory,
  ClpIX509Certificate,
  ClpIX509Crl;

type
  /// <summary>
  /// Generator for X.509 version 1 certificates as defined in RFC 5280.
  /// Builds the TBSCertificate structure and signs the result via
  /// <see cref="Generate"/>.
  /// </summary>
  IX509V1CertificateGenerator = interface
    ['{8B7E875E-C0AE-4CB6-9F89-C86D1EA230BE}']
    procedure Reset;
    /// <summary>Set the certificate serial number.</summary>
    /// <remarks>
    /// Make serial numbers long; if you have no serial number policy make sure the number is at least
    /// 16 bytes of secure random data. You will be surprised how ugly a serial number collision can get.
    /// </remarks>
    procedure SetSerialNumber(const ASerialNumber: TBigInteger);
    procedure SetIssuerDN(const AIssuer: IX509Name);
    /// <summary>Sets the certificate validity period from a pre-built <see cref="IValidity"/> structure.</summary>
    procedure SetValidity(const AValidity: IValidity);
    procedure SetNotBefore(const ADate: TDateTime);
    procedure SetNotAfter(const ADate: TDateTime);
    procedure SetNotBeforeUtc(const AUtcDate: TDateTime);
    procedure SetNotAfterUtc(const AUtcDate: TDateTime);
    procedure SetSubjectDN(const ASubject: IX509Name);
    /// <summary>Set the public key that this certificate identifies.</summary>
    procedure SetPublicKey(const APublicKey: IAsymmetricKeyParameter);
    function Generate(const ASignatureFactory: ISignatureFactory): IX509Certificate;
    function GetSignatureAlgNames: TCryptoLibStringArray;
  end;

  /// <summary>
  /// Generator for X.509 version 3 certificates as defined in RFC 5280.
  /// Builds the TBSCertificate structure, optional v3 extensions, and signs via
  /// <see cref="Generate"/>.
  /// </summary>
  IX509V3CertificateGenerator = interface
    ['{0B5BDF63-032B-4348-BBD1-30E75BA32731}']
    procedure Reset;
    /// <summary>Set the certificate serial number.</summary>
    /// <remarks>
    /// Make serial numbers long; if you have no serial number policy make sure the number is at least
    /// 16 bytes of secure random data. You will be surprised how ugly a serial number collision can get.
    /// </remarks>
    /// <param name="ASerialNumber">The serial number.</param>
    /// <exception cref="EArgumentNilCryptoLibException"><paramref name="ASerialNumber"/> is <c>nil</c>.</exception>
    /// <exception cref="EArgumentCryptoLibException"><paramref name="ASerialNumber"/> is not a positive integer.</exception>
    procedure SetSerialNumber(const ASerialNumber: IDerInteger); overload;
    /// <summary>Set the certificate serial number.</summary>
    /// <remarks>
    /// Make serial numbers long; if you have no serial number policy make sure the number is at least
    /// 16 bytes of secure random data. You will be surprised how ugly a serial number collision can get.
    /// </remarks>
    /// <param name="ASerialNumber">The serial number.</param>
    /// <exception cref="EArgumentCryptoLibException"><paramref name="ASerialNumber"/> is not a positive integer.</exception>
    procedure SetSerialNumber(const ASerialNumber: TBigInteger); overload;
    procedure SetIssuerDN(const AIssuer: IX509Name);
    /// <summary>Sets the certificate validity period from a pre-built <see cref="IValidity"/> structure.</summary>
    procedure SetValidity(const AValidity: IValidity);
    procedure SetNotBefore(const ADate: TDateTime);
    procedure SetNotAfter(const ADate: TDateTime);
    procedure SetNotBeforeUtc(const AUtcDate: TDateTime);
    procedure SetNotAfterUtc(const AUtcDate: TDateTime);
    procedure SetSubjectDN(const ASubject: IX509Name);
    procedure SetPublicKey(const APublicKey: IAsymmetricKeyParameter);
    procedure SetSubjectPublicKeyInfo(const APubKeyInfo: ISubjectPublicKeyInfo);
    procedure SetSubjectUniqueID(const AUniqueID: TCryptoLibBooleanArray);
    procedure SetIssuerUniqueID(const AUniqueID: TCryptoLibBooleanArray);
    procedure AddExtension(const AOid: String; ACritical: Boolean;
      const AExtValue: IAsn1Encodable); overload;
    procedure AddExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtValue: IAsn1Encodable); overload;
    procedure AddExtension(const AOid: String; ACritical: Boolean;
      const AExtValue: IAsn1Convertible); overload;
    procedure AddExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtValue: IAsn1Convertible); overload;
    procedure AddExtension(const AOid: String; ACritical: Boolean;
      const AExtValue: TCryptoLibByteArray); overload;
    procedure AddExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtValue: TCryptoLibByteArray); overload;
    procedure AddExtension(const AOid: IDerObjectIdentifier;
      const AX509Extension: IX509Extension); overload;
    /// <summary>Adds a parsed ASN.1 extension to this certificate.</summary>
    procedure AddExtension(const AExtension: IExtension); overload;
    /// <summary>Adds all extensions from an <see cref="IX509Extensions"/> collection.</summary>
    procedure AddExtensions(const AExtensions: IX509Extensions); overload;
    /// <summary>Adds all extensions from an <see cref="IExtensions"/> collection.</summary>
    procedure AddExtensions(const AExtensions: IExtensions); overload;
    /// <summary>Copies an extension value from another certificate.</summary>
    procedure CopyAndAddExtension(const AOid: IDerObjectIdentifier;
      ACritical: Boolean; const ACert: IX509Certificate);
    function Generate(const ASignatureFactory: ISignatureFactory): IX509Certificate; overload;
    function Generate(const ASignatureFactory: ISignatureFactory; AIsCritical: Boolean;
      const AAltSignatureFactory: ISignatureFactory): IX509Certificate; overload;
    function GetSignatureAlgNames: TCryptoLibStringArray;
  end;

  /// <summary>
  /// Interface for X.509 V2 Attribute Certificate generator.
  /// </summary>
  IX509V2AttributeCertificateGenerator = interface
    ['{A5B6C7D8-E9F0-1234-5678-9ABCDEF01234}']
    procedure Reset;
    procedure SetHolder(const AHolder: IAttributeCertificateHolder);
    procedure SetIssuer(const AIssuer: IAttributeCertificateIssuer);
    procedure SetSerialNumber(const ASerialNumber: TBigInteger);
    procedure SetNotBefore(const ADate: TDateTime);
    procedure SetNotAfter(const ADate: TDateTime);
    procedure SetNotBeforeUtc(const AUtcDate: TDateTime);
    procedure SetNotAfterUtc(const AUtcDate: TDateTime);
    procedure AddAttribute(const AAttribute: IX509Attribute);
    procedure SetIssuerUniqueID(const AIui: TCryptoLibBooleanArray);
    procedure AddExtension(const AOid: String; ACritical: Boolean;
      const AExtensionValue: IAsn1Encodable); overload;
    procedure AddExtension(const AOid: String; ACritical: Boolean;
      const AExtensionValue: TCryptoLibByteArray); overload;
    function Generate(const ASignatureFactory: ISignatureFactory): IX509V2AttributeCertificate;
    function GetSignatureAlgNames: TCryptoLibStringArray;
  end;

  /// <summary>
  /// Generator for X.509 version 2 certificate revocation lists (CRLs) as defined in RFC 5280.
  /// Builds the TBSCertList structure, optional CRL extensions, and signs via
  /// <see cref="Generate"/>.
  /// </summary>
  IX509V2CrlGenerator = interface
    ['{B6C7D8E9-F0A1-2345-6789-ABCDEF012345}']
    procedure Reset;
    procedure SetIssuerDN(const AIssuer: IX509Name);
    procedure SetThisUpdate(const ADate: TDateTime);
    procedure SetNextUpdate(const ADate: TDateTime);
    procedure SetThisUpdateUtc(const AUtcDate: TDateTime);
    procedure SetNextUpdateUtc(const AUtcDate: TDateTime);
    procedure AddCrlEntry(const AUserCertificate: TBigInteger; const ARevocationDate: TDateTime; AReason: Int32); overload;
    procedure AddCrlEntry(const AUserCertificate: TBigInteger; const ARevocationDate: TDateTime; AReason: Int32;
      const AInvalidityDate: TDateTime); overload;
    procedure AddCrlEntry(const AUserCertificate: TBigInteger; const ARevocationDate: TDateTime;
      const AExtensions: IX509Extensions); overload;
    procedure AddCrlEntryUtc(const AUserCertificate: TBigInteger; const ARevocationDateUtc: TDateTime; AReason: Int32); overload;
    procedure AddCrlEntryUtc(const AUserCertificate: TBigInteger; const ARevocationDateUtc: TDateTime; AReason: Int32;
      const AInvalidityDateUtc: TDateTime); overload;
    procedure AddCrlEntryUtc(const AUserCertificate: TBigInteger; const ARevocationDateUtc: TDateTime;
      const AExtensions: IX509Extensions); overload;
    procedure AddCrl(const AOther: IX509Crl);
    procedure AddExtension(const AOid: String; ACritical: Boolean;
      const AExtensionValue: IAsn1Encodable); overload;
    procedure AddExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtensionValue: IAsn1Encodable); overload;
    procedure AddExtension(const AOid: String; ACritical: Boolean;
      const AExtensionValue: TCryptoLibByteArray); overload;
    procedure AddExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtensionValue: TCryptoLibByteArray); overload;
    function Generate(const ASignatureFactory: ISignatureFactory): IX509Crl; overload;
    function Generate(const ASignatureFactory: ISignatureFactory; AIsCritical: Boolean;
      const AAltSignatureFactory: ISignatureFactory): IX509Crl; overload;
    function GetSignatureAlgNames: TCryptoLibStringArray;
  end;

implementation

end.

