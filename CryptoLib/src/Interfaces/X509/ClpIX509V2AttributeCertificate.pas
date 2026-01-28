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

unit ClpIX509V2AttributeCertificate;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIAsn1Core,
  ClpIX509Asn1Objects,
  ClpIX509Extension,
  ClpIAsymmetricKeyParameter,
  ClpIVerifierFactoryProvider,
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpIX509Attribute,
  ClpIAttributeCertificateHolder,
  ClpIAttributeCertificateIssuer;

type
  /// <summary>
  /// An implementation of a version 2 X.509 Attribute Certificate.
  /// </summary>
  IX509V2AttributeCertificate = interface(IX509Extension)
    ['{E4F5A6B7-C8D9-0123-EF01-456789ABCDEF}']

    function GetAttributeCertificate: IAttributeCertificate;
    function GetVersion: Int32;
    function GetSerialNumber: TBigInteger;
    function GetHolder: IAttributeCertificateHolder;
    function GetIssuer: IAttributeCertificateIssuer;
    function GetNotBefore: TDateTime;
    function GetNotAfter: TDateTime;

    function GetIssuerUniqueID: TCryptoLibBooleanArray;
    function IsValidNow: Boolean;
    function IsValid(const ADate: TDateTime): Boolean;
    procedure CheckValidity; overload;
    procedure CheckValidity(const ADate: TDateTime); overload;

    function GetSignatureAlgorithm: IAlgorithmIdentifier;
    function GetSignature: TCryptoLibByteArray;

    function IsSignatureValid(const AKey: IAsymmetricKeyParameter): Boolean; overload;
    function IsSignatureValid(const AVerifierProvider: IVerifierFactoryProvider): Boolean; overload;
    procedure Verify(const AKey: IAsymmetricKeyParameter); overload;
    procedure Verify(const AVerifierProvider: IVerifierFactoryProvider); overload;

    function GetEncoded: TCryptoLibByteArray;
    function GetAttributes: TCryptoLibGenericArray<IX509Attribute>; overload;
    function GetAttributes(const AOid: String): TCryptoLibGenericArray<IX509Attribute>; overload;
    function Equals(const AOther: IX509V2AttributeCertificate): Boolean;

    property AttributeCertificate: IAttributeCertificate read GetAttributeCertificate;
    property Version: Int32 read GetVersion;
    property SerialNumber: TBigInteger read GetSerialNumber;
    property Holder: IAttributeCertificateHolder read GetHolder;
    property Issuer: IAttributeCertificateIssuer read GetIssuer;
    property NotBefore: TDateTime read GetNotBefore;
    property NotAfter: TDateTime read GetNotAfter;
    property SignatureAlgorithm: IAlgorithmIdentifier read GetSignatureAlgorithm;
  end;

implementation

end.

