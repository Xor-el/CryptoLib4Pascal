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

unit ClpIX509Crl;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIX509Asn1Objects,
  ClpIX509CrlEntry,
  ClpIX509Certificate,
  ClpIAsymmetricKeyParameter,
  ClpIVerifierFactoryProvider,
  ClpNullable,
  ClpCryptoLibTypes,
  ClpBigInteger;

type
  IX509Crl = interface(IInterface)
    ['{D3E4F5A6-B7C8-9012-DEF0-345678901234}']

    function GetCertificateList: ICertificateList;
    function GetVersion: Int32;
    function GetIssuerDN: IX509Name;
    function GetThisUpdate: TDateTime;
    function GetNextUpdate: TNullable<TDateTime>;
    function GetRevokedCertificate(const ASerialNumber: TBigInteger): IX509CrlEntry;
    function GetRevokedCertificates: TCryptoLibGenericArray<IX509CrlEntry>;
    function GetTbsCertList: TCryptoLibByteArray;
    function GetSignature: TCryptoLibByteArray;
    function GetSigAlgName: String;
    function GetSigAlgOid: String;
    function GetSigAlgParams: TCryptoLibByteArray;
    function GetSignatureAlgorithm: IAlgorithmIdentifier;
    function GetEncoded: TCryptoLibByteArray;

    function IsSignatureValid(const AKey: IAsymmetricKeyParameter): Boolean; overload;
    function IsSignatureValid(const AVerifierProvider: IVerifierFactoryProvider): Boolean; overload;
    function IsAlternativeSignatureValid(const AVerifierProvider: IVerifierFactoryProvider): Boolean;
    procedure Verify(const AKey: IAsymmetricKeyParameter); overload;
    procedure Verify(const AVerifierProvider: IVerifierFactoryProvider); overload;
    procedure VerifyAltSignature(const AVerifierProvider: IVerifierFactoryProvider);

    function IsRevoked(const ACert: IX509Certificate): Boolean;
    function Equals(const AOther: TObject): Boolean;
    function GetHashCode: Int32;
    function ToString: String;

    property CertificateList: ICertificateList read GetCertificateList;
    property Version: Int32 read GetVersion;
    property IssuerDN: IX509Name read GetIssuerDN;
    property ThisUpdate: TDateTime read GetThisUpdate;
    property NextUpdate: TNullable<TDateTime> read GetNextUpdate;
    property SigAlgName: String read GetSigAlgName;
    property SigAlgOid: String read GetSigAlgOid;
    property SignatureAlgorithm: IAlgorithmIdentifier read GetSignatureAlgorithm;
  end;

implementation

end.
