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

unit ClpIX509Generators;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
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
  ClpIX509Certificate;

type
  IX509V1CertificateGenerator = interface
    ['{C2D3E4F5-A6B7-8901-CDEF-234567890123}']
    procedure Reset;
    procedure SetSerialNumber(const ASerialNumber: TBigInteger);
    procedure SetIssuerDN(const AIssuer: IX509Name);
    procedure SetValidity(const AValidity: IValidity);
    procedure SetNotBefore(const ADate: TDateTime);
    procedure SetNotAfter(const ADate: TDateTime);
    procedure SetSubjectDN(const ASubject: IX509Name);
    procedure SetPublicKey(const APublicKey: IAsymmetricKeyParameter);
    function Generate(const ASignatureFactory: ISignatureFactory): IX509Certificate;
    function GetSignatureAlgNames: TCryptoLibStringArray;
  end;

  IX509V3CertificateGenerator = interface
    ['{D3E4F5A6-B7C8-9012-DEF0-345678901234}']
    procedure Reset;
    procedure SetSerialNumber(const ASerialNumber: TBigInteger);
    procedure SetIssuerDN(const AIssuer: IX509Name);
    procedure SetValidity(const AValidity: IValidity);
    procedure SetNotBefore(const ADate: TDateTime);
    procedure SetNotAfter(const ADate: TDateTime);
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
    procedure AddExtensions(const AExtensions: IX509Extensions);
    procedure CopyAndAddExtension(const AOid: IDerObjectIdentifier;
      ACritical: Boolean; const ACert: IX509Certificate);
    function Generate(const ASignatureFactory: ISignatureFactory): IX509Certificate;
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
    procedure AddAttribute(const AAttribute: IX509Attribute);
    procedure SetIssuerUniqueID(const AIui: TCryptoLibBooleanArray);
    procedure AddExtension(const AOid: String; ACritical: Boolean;
      const AExtensionValue: IAsn1Encodable); overload;
    procedure AddExtension(const AOid: String; ACritical: Boolean;
      const AExtensionValue: TCryptoLibByteArray); overload;
    function Generate(const ASignatureFactory: ISignatureFactory): IX509V2AttributeCertificate;
    function GetSignatureAlgNames: TCryptoLibStringArray;
  end;

implementation

end.

