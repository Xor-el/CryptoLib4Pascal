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

unit ClpIX509Certificate;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Rtti,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpIX509Extension,
  ClpIAsymmetricKeyParameter,
  ClpIVerifierFactoryProvider,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Interface for X509Certificate.
  /// </summary>
  IX509Certificate = interface(IX509Extension)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}']

    function GetCertificateStructure: IX509CertificateStructure;
    function IsValidNow: Boolean;
    function IsValid(const ATime: TDateTime): Boolean;
    procedure CheckValidity(); overload;
    procedure CheckValidity(const ATime: TDateTime); overload;

    function GetVersion: Int32;
    function GetSerialNumber: TBigInteger;
    function GetIssuerDN: IX509Name;
    function GetSubjectDN: IX509Name;
    function GetNotBefore: TDateTime;
    function GetNotAfter: TDateTime;
    function GetTbsCertificate: ITbsCertificateStructure;
    function GetTbsCertificateEncoded: TCryptoLibByteArray;
    function GetSignature: TCryptoLibByteArray;
    function GetSigAlgName: String;
    function GetSigAlgOid: String;
    function GetSigAlgParams: TCryptoLibByteArray;
    function GetSignatureAlgorithm: IAlgorithmIdentifier;
    function GetIssuerUniqueID: IDerBitString;
    function GetSubjectUniqueID: IDerBitString;
    function GetKeyUsage: TCryptoLibBooleanArray;
    function GetExtendedKeyUsage: TCryptoLibGenericArray<IDerObjectIdentifier>;
    function GetBasicConstraints: Int32;
    function GetIssuerAlternativeNameExtension: IGeneralNames;
    function GetSubjectAlternativeNameExtension: IGeneralNames;
    function GetIssuerAlternativeNames: TCryptoLibGenericArray<TCryptoLibGenericArray<TValue>>;
    function GetSubjectAlternativeNames: TCryptoLibGenericArray<TCryptoLibGenericArray<TValue>>;
    function GetSubjectPublicKeyInfo: ISubjectPublicKeyInfo;
    function GetPublicKey: IAsymmetricKeyParameter;
    function GetEncoded: TCryptoLibByteArray;

    function IsSignatureValid(const AKey: IAsymmetricKeyParameter): Boolean; overload;
    function IsSignatureValid(const AVerifierProvider: IVerifierFactoryProvider): Boolean; overload;
    function IsAlternativeSignatureValid(const APublicKey: IAsymmetricKeyParameter): Boolean; overload;
    function IsAlternativeSignatureValid(const AVerifierProvider: IVerifierFactoryProvider): Boolean; overload;

    procedure Verify(const AKey: IAsymmetricKeyParameter); overload;
    procedure Verify(const AVerifierProvider: IVerifierFactoryProvider); overload;
    procedure VerifyAltSignature(const AVerifierProvider: IVerifierFactoryProvider);

    property CertificateStructure: IX509CertificateStructure read GetCertificateStructure;
    property Version: Int32 read GetVersion;
    property SerialNumber: TBigInteger read GetSerialNumber;
    property IssuerDN: IX509Name read GetIssuerDN;
    property SubjectDN: IX509Name read GetSubjectDN;
    property NotBefore: TDateTime read GetNotBefore;
    property NotAfter: TDateTime read GetNotAfter;
    property TbsCertificate: ITbsCertificateStructure read GetTbsCertificate;
    property SignatureAlgorithm: IAlgorithmIdentifier read GetSignatureAlgorithm;
    property SigAlgName: String read GetSigAlgName;
    property SubjectPublicKeyInfo: ISubjectPublicKeyInfo read GetSubjectPublicKeyInfo;
  end;

implementation

end.
