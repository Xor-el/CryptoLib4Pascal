{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIPkcs10CertificationRequestBuilder;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpIX509Asn1Objects,
  ClpIPkcsAsn1Objects,
  ClpIPkcs10CertificationRequest,
  ClpIAsymmetricCipherKeyPair,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Fluent builder for PKCS#10 Certification Requests (CSRs).
  /// Wraps the boilerplate of creating extensions, attributes, and calling
  /// TPkcs10CertificationRequest constructors.
  /// </summary>
  IPkcs10CertificationRequestBuilder = interface(IInterface)
    ['{0E5C1612-BEFE-4A4D-AD68-C134254411CE}']

    /// <summary>
    /// Set the subject distinguished name for the CSR. Required.
    /// </summary>
    function SetSubject(const ASubject: IX509Name): IPkcs10CertificationRequestBuilder;

    /// <summary>
    /// Set the key pair (public key for the CSR, private key for signing). Required.
    /// </summary>
    function SetKeyPair(const AKeyPair: IAsymmetricCipherKeyPair): IPkcs10CertificationRequestBuilder;

    /// <summary>
    /// Set the signature algorithm name (e.g. 'SHA256withRSA', 'SHA256withECDSA'). Required.
    /// </summary>
    function SetSignatureAlgorithm(const AAlgorithm: String): IPkcs10CertificationRequestBuilder;

    /// <summary>
    /// Add a single arbitrary X509 extension by OID and ASN.1 value.
    /// </summary>
    function AddExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AValue: IAsn1Encodable): IPkcs10CertificationRequestBuilder; overload;

    /// <summary>
    /// Add a single arbitrary X509 extension by OID and raw DER-encoded bytes.
    /// </summary>
    function AddExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtValue: TCryptoLibByteArray): IPkcs10CertificationRequestBuilder; overload;

    /// <summary>
    /// Bulk-add all extensions from a pre-built IX509Extensions object.
    /// </summary>
    function AddExtensions(const AExtensions: IX509Extensions): IPkcs10CertificationRequestBuilder;

    /// <summary>
    /// Add a BasicConstraints extension.
    /// </summary>
    function AddBasicConstraints(ACritical: Boolean; AIsCA: Boolean): IPkcs10CertificationRequestBuilder; overload;

    /// <summary>
    /// Add a BasicConstraints extension with a path length constraint (implies CA=True).
    /// </summary>
    function AddBasicConstraints(ACritical: Boolean; APathLenConstraint: Int32): IPkcs10CertificationRequestBuilder; overload;

    /// <summary>
    /// Add a KeyUsage extension.
    /// </summary>
    function AddKeyUsage(ACritical: Boolean; AUsage: Int32): IPkcs10CertificationRequestBuilder;

    /// <summary>
    /// Add a SubjectAlternativeName extension.
    /// </summary>
    function AddSubjectAlternativeName(ACritical: Boolean;
      const ANames: IGeneralNames): IPkcs10CertificationRequestBuilder;

    /// <summary>
    /// Add an ExtendedKeyUsage extension from an array of key purpose OIDs.
    /// </summary>
    function AddExtendedKeyUsage(ACritical: Boolean;
      const AUsages: TCryptoLibGenericArray<IDerObjectIdentifier>): IPkcs10CertificationRequestBuilder;

    /// <summary>
    /// Add a SubjectKeyIdentifier extension computed from the public key.
    /// SetKeyPair must be called before this method.
    /// </summary>
    function AddSubjectKeyIdentifier(ACritical: Boolean): IPkcs10CertificationRequestBuilder;

    /// <summary>
    /// Add a raw PKCS attribute (for non-extension attributes).
    /// </summary>
    function AddAttribute(const AAttribute: IAttributePkcs): IPkcs10CertificationRequestBuilder;

    /// <summary>
    /// Reset the builder to its initial state, clearing subject, key pair,
    /// signature algorithm, extensions and attributes so it can be reused.
    /// </summary>
    function Reset: IPkcs10CertificationRequestBuilder;

    /// <summary>
    /// Build and return the signed PKCS#10 Certification Request.
    /// Subject, KeyPair, and SignatureAlgorithm must all be set before calling Build.
    /// </summary>
    function Build: IPkcs10CertificationRequest;

  end;

implementation

end.
