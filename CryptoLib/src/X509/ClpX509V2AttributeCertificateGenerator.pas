{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpX509V2AttributeCertificateGenerator;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpX509Attribute,
  ClpX509V2AttributeCertificate,
  ClpAttributeCertificateHolder,
  ClpAttributeCertificateIssuer,
  ClpV2AttributeCertificateInfoGenerator,
  ClpX509ExtensionsGenerator,
  ClpIX509ExtensionsGenerator,
  ClpISignatureFactory,
  ClpRfc5280Asn1Utilities,
  ClpX509Utilities,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
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

  /// <summary>
  /// Class to produce an X.509 Version 2 AttributeCertificate.
  /// </summary>
  TX509V2AttributeCertificateGenerator = class(TInterfacedObject,
    IX509V2AttributeCertificateGenerator)

  strict private
    FExtGenerator: IX509ExtensionsGenerator;
    FACInfoGen: IV2AttributeCertificateInfoGenerator;

  public
    constructor Create;
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

{ TX509V2AttributeCertificateGenerator }

constructor TX509V2AttributeCertificateGenerator.Create;
begin
  inherited Create;
  FExtGenerator := TX509ExtensionsGenerator.Create;
  FACInfoGen := TV2AttributeCertificateInfoGenerator.Create;
end;

procedure TX509V2AttributeCertificateGenerator.Reset;
begin
  FExtGenerator.Reset;
  FACInfoGen := TV2AttributeCertificateInfoGenerator.Create;
end;

procedure TX509V2AttributeCertificateGenerator.SetHolder(const AHolder
  : IAttributeCertificateHolder);
begin
  FACInfoGen.SetHolder(AHolder.GetHolder);
end;

procedure TX509V2AttributeCertificateGenerator.SetIssuer(const AIssuer
  : IAttributeCertificateIssuer);
begin
  FACInfoGen.SetIssuer(AIssuer.GetAttCertIssuer);
end;

procedure TX509V2AttributeCertificateGenerator.SetSerialNumber(const ASerialNumber
  : TBigInteger);
begin
  FACInfoGen.SetSerialNumber(TDerInteger.Create(ASerialNumber));
end;

procedure TX509V2AttributeCertificateGenerator.SetNotBefore(const ADate: TDateTime);
begin
  FACInfoGen.SetStartDate(TRfc5280Asn1Utilities.CreateGeneralizedTime(ADate));
end;

procedure TX509V2AttributeCertificateGenerator.SetNotAfter(const ADate: TDateTime);
begin
  FACInfoGen.SetEndDate(TRfc5280Asn1Utilities.CreateGeneralizedTime(ADate));
end;

procedure TX509V2AttributeCertificateGenerator.AddAttribute(const AAttribute
  : IX509Attribute);
begin
  FACInfoGen.AddAttribute(TAttributeX509.GetInstance(AAttribute.ToAsn1Object));
end;

procedure TX509V2AttributeCertificateGenerator.SetIssuerUniqueID(const AIui
  : TCryptoLibBooleanArray);
begin
  FACInfoGen.SetIssuerUniqueID(TX509Utilities.BooleanToBitString(AIui));
end;

procedure TX509V2AttributeCertificateGenerator.AddExtension(const AOid: String;
  ACritical: Boolean; const AExtensionValue: IAsn1Encodable);
begin
  FExtGenerator.AddExtension(TDerObjectIdentifier.Create(AOid), ACritical,
    AExtensionValue);
end;

procedure TX509V2AttributeCertificateGenerator.AddExtension(const AOid: String;
  ACritical: Boolean; const AExtensionValue: TCryptoLibByteArray);
begin
  FExtGenerator.AddExtension(TDerObjectIdentifier.Create(AOid), ACritical,
    AExtensionValue);
end;

function TX509V2AttributeCertificateGenerator.Generate(const ASignatureFactory
  : ISignatureFactory): IX509V2AttributeCertificate;
var
  LSigAlgID: IAlgorithmIdentifier;
  LAcInfo: IAttributeCertificateInfo;
  LSignature: IDerBitString;
  LAc: IAttributeCertificate;
begin
  LSigAlgID := ASignatureFactory.AlgorithmDetails;
  FACInfoGen.SetSignature(LSigAlgID);

  if not FExtGenerator.IsEmpty then
    FACInfoGen.SetExtensions(FExtGenerator.Generate);

  LAcInfo := FACInfoGen.GenerateAttributeCertificateInfo;
  LSignature := TX509Utilities.GenerateSignature(ASignatureFactory, LAcInfo);
  LAc := TAttributeCertificate.Create(LAcInfo, LSigAlgID, LSignature);
  Result := TX509V2AttributeCertificate.Create(LAc);
end;

function TX509V2AttributeCertificateGenerator.GetSignatureAlgNames
  : TCryptoLibStringArray;
begin
  Result := TX509Utilities.GetAlgNames;
end;

end.
