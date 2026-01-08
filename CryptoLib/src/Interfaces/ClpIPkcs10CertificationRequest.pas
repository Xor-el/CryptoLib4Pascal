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

unit ClpIPkcs10CertificationRequest;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIAlgorithmIdentifier,
  ClpISubjectPublicKeyInfo,
  ClpIX500Name,
  ClpIAsymmetricKeyParameter,
  ClpCryptoLibTypes;

type
  // Forward declaration
  IPkcs10CertificationRequest = interface;

  /// <summary>
  /// Interface for PKCS#10 CertificationRequestInfo (to-be-signed portion)
  /// </summary>
  IPkcs10CertificationRequestInfo = interface(IAsn1Encodable)
    ['{C1C8160E-D066-4E12-BE4B-D598AA1B9C87}']
    function GetVersion: IDerInteger;
    function GetSubject: IX500Name;
    function GetSubjectPublicKeyInfo: ISubjectPublicKeyInfo;

    property Version: IDerInteger read GetVersion;
    property Subject: IX500Name read GetSubject;
    property SubjectPublicKeyInfo: ISubjectPublicKeyInfo read GetSubjectPublicKeyInfo;
  end;

  /// <summary>
  /// Interface for complete PKCS#10 CertificationRequest
  /// </summary>
  IPkcs10CertificationRequest = interface(IAsn1Encodable)
    ['{12920416-C1BF-4B2E-8F67-598FB16D1C30}']
    function GetCertificationRequestInfo: IPkcs10CertificationRequestInfo;
    function GetSignatureAlgorithm: IAlgorithmIdentifier;
    function GetSignature: IDerBitString;

    function GetEncoded(): TCryptoLibByteArray; overload;
    function GetPemEncoded: string;

    property CertificationRequestInfo: IPkcs10CertificationRequestInfo read GetCertificationRequestInfo;
    property SignatureAlgorithm: IAlgorithmIdentifier read GetSignatureAlgorithm;
    property Signature: IDerBitString read GetSignature;
  end;

  /// <summary>
  /// Base interface for PKCS#10 Certification Request Builders.
  /// </summary>
  IPkcs10CertificationRequestBuilder = interface(IInterface)
    ['{848CE226-C322-4CC7-A4F5-FD45BC4BE714}']
    /// <summary>
    /// Set the subject distinguished name for the CSR.
    /// </summary>
    function SetSubject(const subject: IX500Name): IPkcs10CertificationRequestBuilder;

    /// <summary>
    /// Set the public key. The builder implementation validates the key type.
    /// </summary>
    function SetPublicKey(const publicKey: IAsymmetricKeyParameter): IPkcs10CertificationRequestBuilder;

    /// <summary>
    /// Build the CSR using the provided private key.
    /// The builder determines the correct signature algorithm based on key type.
    /// </summary>
    function Build(const privateKey: IAsymmetricKeyParameter): IPkcs10CertificationRequest;

    /// <summary>
    /// Add an X.509 extension to the CSR.
    /// </summary>
    function AddExtension(const oid: IDerObjectIdentifier; critical: Boolean;
      const value: IAsn1Encodable): IPkcs10CertificationRequestBuilder;

    /// <summary>
    /// Add Subject Key Identifier extension (computed from public key).
    /// Must be called after SetPublicKey.
    /// </summary>
    function AddSubjectKeyIdentifier: IPkcs10CertificationRequestBuilder;
  end;

implementation

end.
