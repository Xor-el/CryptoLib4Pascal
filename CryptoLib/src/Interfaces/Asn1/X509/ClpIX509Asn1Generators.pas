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

unit ClpIX509Asn1Generators;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpIX509Asn1Objects,
  ClpIX509Extension,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Interface for V1 TbsCertificate structure generator.
  /// </summary>
  IV1TbsCertificateGenerator = interface
    ['{26EA3114-5B47-49BE-9CD9-58E7A4E5C927}']
    procedure SetSerialNumber(const ASerialNumber: IDerInteger);
    procedure SetSignature(const ASignature: IAlgorithmIdentifier);
    procedure SetIssuer(const AIssuer: IX509Name);
    procedure SetValidity(const AValidity: IValidity);
    procedure SetStartDate(const AStartDate: ITime); overload;
    procedure SetStartDate(const AStartDate: IAsn1UtcTime); overload;
    procedure SetEndDate(const AEndDate: ITime); overload;
    procedure SetEndDate(const AEndDate: IAsn1UtcTime); overload;
    procedure SetSubject(const ASubject: IX509Name);
    procedure SetSubjectPublicKeyInfo(const APubKeyInfo: ISubjectPublicKeyInfo);
    function GenerateTbsCertificate: ITbsCertificateStructure;
  end;

  /// <summary>
  /// Interface for V3 TbsCertificate structure generator.
  /// </summary>
  IV3TbsCertificateGenerator = interface
    ['{B0863857-D467-4983-9BDA-A78DAA8D6784}']
    procedure SetSerialNumber(const ASerialNumber: IDerInteger);
    procedure SetSignature(const ASignature: IAlgorithmIdentifier);
    procedure SetIssuer(const AIssuer: IX509Name);
    procedure SetValidity(const AValidity: IValidity);
    procedure SetStartDate(const AStartDate: ITime); overload;
    procedure SetStartDate(const AStartDate: IAsn1UtcTime); overload;
    procedure SetEndDate(const AEndDate: ITime); overload;
    procedure SetEndDate(const AEndDate: IAsn1UtcTime); overload;
    procedure SetSubject(const ASubject: IX509Name);
    procedure SetSubjectPublicKeyInfo(const APubKeyInfo: ISubjectPublicKeyInfo);
    procedure SetIssuerUniqueID(const AUniqueID: IDerBitString);
    procedure SetSubjectUniqueID(const AUniqueID: IDerBitString);
    procedure SetExtensions(const AExtensions: IX509Extensions);
    function GeneratePreTbsCertificate: IAsn1Sequence;
    function GenerateTbsCertificate: ITbsCertificateStructure;
  end;

  /// <summary>
  /// Interface for V2 AttributeCertificateInfo generator.
  /// </summary>
  IV2AttributeCertificateInfoGenerator = interface
    ['{50F936AE-95F8-4716-898E-7E01D0CBCE9A}']
    procedure SetHolder(const AHolder: IHolder);
    procedure AddAttribute(const AOid: String; const AValue: IAsn1Encodable); overload;
    procedure AddAttribute(const AAttribute: IAttributeX509); overload;
    procedure SetSerialNumber(const ASerialNumber: IDerInteger);
    procedure SetSignature(const ASignature: IAlgorithmIdentifier);
    procedure SetIssuer(const AIssuer: IAttCertIssuer);
    procedure SetStartDate(const AStartDate: IAsn1GeneralizedTime);
    procedure SetEndDate(const AEndDate: IAsn1GeneralizedTime);
    procedure SetIssuerUniqueID(const AIssuerUniqueID: IDerBitString);
    procedure SetExtensions(const AExtensions: IX509Extensions);
    function GenerateAttributeCertificateInfo: IAttributeCertificateInfo;
  end;

  /// <summary>
  /// Interface for V2 TbsCertList structure generator.
  /// </summary>
  IV2TbsCertListGenerator = interface
    ['{AC77BA87-29B9-4BE8-A61F-E44F9A0B2FB6}']
    procedure SetSignature(const ASignature: IAlgorithmIdentifier);
    procedure SetIssuer(const AIssuer: IX509Name);
    procedure SetThisUpdate(const AThisUpdate: IAsn1UtcTime); overload;
    procedure SetThisUpdate(const AThisUpdate: ITime); overload;
    procedure SetNextUpdate(const ANextUpdate: IAsn1UtcTime); overload;
    procedure SetNextUpdate(const ANextUpdate: ITime); overload;
    procedure AddCrlEntry(const ACrlEntry: IAsn1Sequence); overload;
    procedure AddCrlEntry(const AUserCertificate: IDerInteger; const ARevocationDate: IAsn1UtcTime; AReason: Int32); overload;
    procedure AddCrlEntry(const AUserCertificate: IDerInteger; const ARevocationDate: ITime; AReason: Int32); overload;
    procedure AddCrlEntry(const AUserCertificate: IDerInteger; const ARevocationDate: ITime; AReason: Int32;
      const AInvalidityDate: IAsn1GeneralizedTime); overload;
    procedure AddCrlEntry(const AUserCertificate: IDerInteger; const ARevocationDate: ITime;
      const AExtensions: IX509Extensions); overload;
    procedure SetExtensions(const AExtensions: IX509Extensions);
    function GeneratePreTbsCertList: IAsn1Sequence;
    function GenerateTbsCertList: ITbsCertificateList;
  end;

  /// <summary>
  /// Interface for X509ExtensionsGenerator.
  /// </summary>
  IX509ExtensionsGenerator = interface
    ['{F2A3B4C5-D6E7-8901-FABC-0123456789DE}']

    procedure AddExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtValue: IAsn1Convertible); overload;
    procedure AddExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtValue: IAsn1Encodable); overload;
    procedure AddExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtValue: TCryptoLibByteArray); overload;
    procedure AddExtension(const AOid: IDerObjectIdentifier;
      const AX509Extension: IX509Extension); overload;
    procedure AddExtensions(const AExtensions: IX509Extensions);
    function Generate: IX509Extensions;
    function GetExtension(const AOid: IDerObjectIdentifier): IX509Extension;
    function HasExtension(const AOid: IDerObjectIdentifier): Boolean;
    function IsEmpty: Boolean;
    procedure RemoveExtension(const AOid: IDerObjectIdentifier);
    procedure ReplaceExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtValue: IAsn1Convertible); overload;
    procedure ReplaceExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtValue: IAsn1Encodable); overload;
    procedure ReplaceExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtValue: TCryptoLibByteArray); overload;
    procedure ReplaceExtension(const AOid: IDerObjectIdentifier;
      const AX509Extension: IX509Extension); overload;
    procedure Reset;
  end;

implementation

end.
