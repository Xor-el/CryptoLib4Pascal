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

unit ClpX509Generators;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIAsn1Core,
  ClpIX509Certificate,
  ClpX509Certificate,
  ClpIX509Crl,
  ClpX509Crl,
  ClpIX509CrlEntry,
  ClpIX509Extension,
  ClpIAsymmetricKeyParameter,
  ClpISignatureFactory,
  ClpSubjectPublicKeyInfoFactory,
  ClpX509Utilities,
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpDeltaCertificateTool,
  ClpIX509Attribute,
  ClpIX509V2AttributeCertificate,
  ClpIAttributeCertificateHolder,
  ClpIAttributeCertificateIssuer,
  ClpX509V2AttributeCertificate,
  ClpRfc5280Asn1Utilities,
  ClpIX509Generators,
  ClpIX509Asn1Generators,
  ClpX509Asn1Generators;

type
  TX509V1CertificateGenerator = class(TInterfacedObject, IX509V1CertificateGenerator)
  strict private
    FTbsGen: IV1TbsCertificateGenerator;
  public
    constructor Create;
    procedure Reset;
    procedure SetSerialNumber(const ASerialNumber: TBigInteger);
    procedure SetIssuerDN(const AIssuer: IX509Name);
    procedure SetValidity(const AValidity: IValidity);
    procedure SetNotBefore(const ADate: TDateTime);
    procedure SetNotAfter(const ADate: TDateTime);
    procedure SetNotBeforeUtc(const AUtcDate: TDateTime);
    procedure SetNotAfterUtc(const AUtcDate: TDateTime);
    procedure SetSubjectDN(const ASubject: IX509Name);
    procedure SetPublicKey(const APublicKey: IAsymmetricKeyParameter);
    function Generate(const ASignatureFactory: ISignatureFactory): IX509Certificate;
    function GetSignatureAlgNames: TCryptoLibStringArray;
  end;

  TX509V3CertificateGenerator = class(TInterfacedObject, IX509V3CertificateGenerator)
  strict private
    FExtGenerator: IX509ExtensionsGenerator;
    FTbsGen: IV3TbsCertificateGenerator;

    procedure ImplInitFromTemplate(const ATemplate: IX509CertificateStructure);
  public
    constructor Create; overload;
    constructor Create(const ATemplate: IX509Certificate); overload;
    constructor Create(const ATemplate: IX509CertificateStructure); overload;

    procedure Reset;
    procedure SetSerialNumber(const ASerialNumber: TBigInteger);
    procedure SetIssuerDN(const AIssuer: IX509Name);
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
    procedure AddExtensions(const AExtensions: IX509Extensions);
    procedure CopyAndAddExtension(const AOid: IDerObjectIdentifier;
      ACritical: Boolean; const ACert: IX509Certificate);
    function Generate(const ASignatureFactory: ISignatureFactory): IX509Certificate;
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
  /// Class to produce an X.509 Version 2 CRL.
  /// </summary>
  TX509V2CrlGenerator = class(TInterfacedObject, IX509V2CrlGenerator)
  strict private
    FExtGenerator: IX509ExtensionsGenerator;
    FTbsGen: IV2TbsCertListGenerator;

    procedure ImplInitFromTemplate(const ATemplate: ICertificateList);
  public
    constructor Create; overload;
    constructor Create(const ATemplate: IX509Crl); overload;
    constructor Create(const ATemplate: ICertificateList); overload;

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

{ TX509V1CertificateGenerator }

constructor TX509V1CertificateGenerator.Create;
begin
  inherited Create;
  FTbsGen := TV1TbsCertificateGenerator.Create;
end;

procedure TX509V1CertificateGenerator.Reset;
begin
  FTbsGen := TV1TbsCertificateGenerator.Create;
end;

procedure TX509V1CertificateGenerator.SetSerialNumber(const ASerialNumber: TBigInteger);
begin
  if ASerialNumber.SignValue <= 0 then
    raise EArgumentCryptoLibException.Create('serial number must be a positive integer');
  FTbsGen.SetSerialNumber(TDerInteger.Create(ASerialNumber));
end;

procedure TX509V1CertificateGenerator.SetIssuerDN(const AIssuer: IX509Name);
begin
  FTbsGen.SetIssuer(AIssuer);
end;

procedure TX509V1CertificateGenerator.SetValidity(const AValidity: IValidity);
begin
  FTbsGen.SetValidity(AValidity);
end;

procedure TX509V1CertificateGenerator.SetNotBefore(const ADate: TDateTime);
begin
  FTbsGen.SetStartDate(TTime.Create(ADate) as ITime);
end;

procedure TX509V1CertificateGenerator.SetNotAfter(const ADate: TDateTime);
begin
  FTbsGen.SetEndDate(TTime.Create(ADate) as ITime);
end;

procedure TX509V1CertificateGenerator.SetNotBeforeUtc(const AUtcDate: TDateTime);
begin
  FTbsGen.SetStartDate(TTime.CreateUtc(AUtcDate) as ITime);
end;

procedure TX509V1CertificateGenerator.SetNotAfterUtc(const AUtcDate: TDateTime);
begin
  FTbsGen.SetEndDate(TTime.CreateUtc(AUtcDate) as ITime);
end;

procedure TX509V1CertificateGenerator.SetSubjectDN(const ASubject: IX509Name);
begin
  FTbsGen.SetSubject(ASubject);
end;

procedure TX509V1CertificateGenerator.SetPublicKey(const APublicKey: IAsymmetricKeyParameter);
begin
  try
    FTbsGen.SetSubjectPublicKeyInfo(
      TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(APublicKey));
  except
    on E: Exception do
      raise EArgumentCryptoLibException.Create('unable to process key - ' + E.ToString);
  end;
end;

function TX509V1CertificateGenerator.Generate(const ASignatureFactory: ISignatureFactory): IX509Certificate;
var
  LSigAlgID: IAlgorithmIdentifier;
  LTbs: ITbsCertificateStructure;
  LSignature: IDerBitString;
  LStruct: IX509CertificateStructure;
begin
  LSigAlgID := ASignatureFactory.AlgorithmDetails;
  FTbsGen.SetSignature(LSigAlgID);
  LTbs := FTbsGen.GenerateTbsCertificate;
  LSignature := TX509Utilities.GenerateSignature(ASignatureFactory, LTbs);
  LStruct := TX509CertificateStructure.Create(LTbs, LSigAlgID, LSignature);
  Result := TX509Certificate.Create(LStruct);
end;

function TX509V1CertificateGenerator.GetSignatureAlgNames: TCryptoLibStringArray;
begin
  Result := TX509Utilities.GetAlgNames;
end;

{ TX509V3CertificateGenerator }

procedure TX509V3CertificateGenerator.ImplInitFromTemplate(const ATemplate: IX509CertificateStructure);
var
  LExtensions: IX509Extensions;
  LOid: IDerObjectIdentifier;
  LExt: IX509Extension;
begin
  FTbsGen.SetSerialNumber(ATemplate.SerialNumber);
  FTbsGen.SetIssuer(ATemplate.Issuer);
  FTbsGen.SetValidity(ATemplate.Validity);
  FTbsGen.SetSubject(ATemplate.Subject);
  FTbsGen.SetSubjectPublicKeyInfo(ATemplate.SubjectPublicKeyInfo);

  LExtensions := ATemplate.Extensions;
  if LExtensions <> nil then
    for LOid in LExtensions.ExtensionOids do
    begin
      if TX509Extensions.SubjectAltPublicKeyInfo.Equals(LOid) or
         TX509Extensions.AltSignatureAlgorithm.Equals(LOid) or
         TX509Extensions.AltSignatureValue.Equals(LOid) then
        Continue;
      LExt := LExtensions.GetExtension(LOid);
      FExtGenerator.AddExtension(LOid, LExt.IsCritical, LExt.Value.GetOctets());
    end;
end;

constructor TX509V3CertificateGenerator.Create;
begin
  inherited Create;
  FExtGenerator := TX509ExtensionsGenerator.Create;
  FTbsGen := TV3TbsCertificateGenerator.Create;
end;

constructor TX509V3CertificateGenerator.Create(const ATemplate: IX509Certificate);
begin
  Create;
  ImplInitFromTemplate(ATemplate.CertificateStructure);
end;

constructor TX509V3CertificateGenerator.Create(const ATemplate: IX509CertificateStructure);
begin
  Create;
  ImplInitFromTemplate(ATemplate);
end;

procedure TX509V3CertificateGenerator.Reset;
begin
  FExtGenerator := TX509ExtensionsGenerator.Create;
  FTbsGen := TV3TbsCertificateGenerator.Create;
end;

procedure TX509V3CertificateGenerator.SetSerialNumber(const ASerialNumber: TBigInteger);
begin
  if ASerialNumber.SignValue <= 0 then
    raise EArgumentCryptoLibException.Create('serial number must be a positive integer');
  FTbsGen.SetSerialNumber(TDerInteger.Create(ASerialNumber) as IDerInteger);
end;

procedure TX509V3CertificateGenerator.SetIssuerDN(const AIssuer: IX509Name);
begin
  FTbsGen.SetIssuer(AIssuer);
end;

procedure TX509V3CertificateGenerator.SetValidity(const AValidity: IValidity);
begin
  FTbsGen.SetValidity(AValidity);
end;

procedure TX509V3CertificateGenerator.SetNotBefore(const ADate: TDateTime);
begin
  FTbsGen.SetStartDate(TTime.Create(ADate) as ITime);
end;

procedure TX509V3CertificateGenerator.SetNotAfter(const ADate: TDateTime);
begin
  FTbsGen.SetEndDate(TTime.Create(ADate) as ITime);
end;

procedure TX509V3CertificateGenerator.SetNotBeforeUtc(const AUtcDate: TDateTime);
begin
  FTbsGen.SetStartDate(TTime.CreateUtc(AUtcDate) as ITime);
end;

procedure TX509V3CertificateGenerator.SetNotAfterUtc(const AUtcDate: TDateTime);
begin
  FTbsGen.SetEndDate(TTime.CreateUtc(AUtcDate) as ITime);
end;

procedure TX509V3CertificateGenerator.SetSubjectDN(const ASubject: IX509Name);
begin
  FTbsGen.SetSubject(ASubject);
end;

procedure TX509V3CertificateGenerator.SetPublicKey(const APublicKey: IAsymmetricKeyParameter);
begin
  FTbsGen.SetSubjectPublicKeyInfo(
    TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(APublicKey) as ISubjectPublicKeyInfo);
end;

procedure TX509V3CertificateGenerator.SetSubjectPublicKeyInfo(const APubKeyInfo: ISubjectPublicKeyInfo);
begin
  FTbsGen.SetSubjectPublicKeyInfo(APubKeyInfo);
end;

procedure TX509V3CertificateGenerator.SetSubjectUniqueID(const AUniqueID: TCryptoLibBooleanArray);
begin
  FTbsGen.SetSubjectUniqueID(TX509Utilities.BooleanToBitString(AUniqueID));
end;

procedure TX509V3CertificateGenerator.SetIssuerUniqueID(const AUniqueID: TCryptoLibBooleanArray);
begin
  FTbsGen.SetIssuerUniqueID(TX509Utilities.BooleanToBitString(AUniqueID));
end;

procedure TX509V3CertificateGenerator.AddExtension(const AOid: String;
  ACritical: Boolean; const AExtValue: IAsn1Encodable);
begin
  AddExtension(TDerObjectIdentifier.Create(AOid) as IDerObjectIdentifier, ACritical, AExtValue);
end;

procedure TX509V3CertificateGenerator.AddExtension(const AOid: IDerObjectIdentifier;
  ACritical: Boolean; const AExtValue: IAsn1Encodable);
begin
  FExtGenerator.AddExtension(AOid, ACritical, AExtValue);
end;

procedure TX509V3CertificateGenerator.AddExtension(const AOid: String;
  ACritical: Boolean; const AExtValue: IAsn1Convertible);
begin
  AddExtension(TDerObjectIdentifier.Create(AOid) as IDerObjectIdentifier, ACritical, AExtValue);
end;

procedure TX509V3CertificateGenerator.AddExtension(const AOid: IDerObjectIdentifier;
  ACritical: Boolean; const AExtValue: IAsn1Convertible);
begin
  FExtGenerator.AddExtension(AOid, ACritical, AExtValue);
end;

procedure TX509V3CertificateGenerator.AddExtension(const AOid: String;
  ACritical: Boolean; const AExtValue: TCryptoLibByteArray);
begin
  AddExtension(TDerObjectIdentifier.Create(AOid) as IDerObjectIdentifier, ACritical, AExtValue);
end;

procedure TX509V3CertificateGenerator.AddExtension(const AOid: IDerObjectIdentifier;
  ACritical: Boolean; const AExtValue: TCryptoLibByteArray);
begin
  FExtGenerator.AddExtension(AOid, ACritical, AExtValue);
end;

procedure TX509V3CertificateGenerator.AddExtension(const AOid: IDerObjectIdentifier;
  const AX509Extension: IX509Extension);
begin
  FExtGenerator.AddExtension(AOid, AX509Extension);
end;

procedure TX509V3CertificateGenerator.AddExtensions(const AExtensions: IX509Extensions);
begin
  FExtGenerator.AddExtensions(AExtensions);
end;

procedure TX509V3CertificateGenerator.CopyAndAddExtension(const AOid: IDerObjectIdentifier;
  ACritical: Boolean; const ACert: IX509Certificate);
var
  LExt: IX509Extension;
begin
  LExt := ACert.CertificateStructure.Extensions.GetExtension(AOid);
  if LExt = nil then
    raise EArgumentCryptoLibException.CreateFmt('extension %s not present', [AOid.Id]);
  try
    FExtGenerator.AddExtension(AOid, LExt);
  except
    on E: Exception do
      raise EArgumentCryptoLibException.CreateFmt('extension %s: %s', [AOid.Id, E.Message]);
  end;
end;

function TX509V3CertificateGenerator.Generate(const ASignatureFactory: ISignatureFactory): IX509Certificate;
var
  LSigAlgID: IAlgorithmIdentifier;
  LDeltaExt: IX509Extension;
  LDescriptor: IDeltaCertificateDescriptor;
  LTbs: ITbsCertificateStructure;
  LSignature: IDerBitString;
  LStruct: IX509CertificateStructure;
begin
  LSigAlgID := ASignatureFactory.AlgorithmDetails;
  FTbsGen.SetSignature(LSigAlgID);

  if not FExtGenerator.IsEmpty then
  begin
    LDeltaExt := FExtGenerator.GetExtension(TX509Extensions.DraftDeltaCertificateDescriptor);
    if LDeltaExt <> nil then
    begin
      LDescriptor := TDeltaCertificateTool.TrimDeltaCertificateDescriptor(
        TDeltaCertificateDescriptor.GetInstance(LDeltaExt.GetParsedValue),
        FTbsGen.GenerateTbsCertificate,
        FExtGenerator.Generate);
      FExtGenerator.ReplaceExtension(TX509Extensions.DraftDeltaCertificateDescriptor,
        LDeltaExt.IsCritical, LDescriptor);
    end;

    FTbsGen.SetExtensions(FExtGenerator.Generate);
  end;

  LTbs := FTbsGen.GenerateTbsCertificate;
  LSignature := TX509Utilities.GenerateSignature(ASignatureFactory, LTbs);
  LStruct := TX509CertificateStructure.Create(LTbs, LSigAlgID, LSignature);
  Result := TX509Certificate.Create(LStruct);
end;

function TX509V3CertificateGenerator.GetSignatureAlgNames: TCryptoLibStringArray;
begin
  Result := TX509Utilities.GetAlgNames;
end;

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

procedure TX509V2AttributeCertificateGenerator.SetHolder(const AHolder: IAttributeCertificateHolder);
begin
  FACInfoGen.SetHolder(AHolder.GetHolder);
end;

procedure TX509V2AttributeCertificateGenerator.SetIssuer(const AIssuer: IAttributeCertificateIssuer);
begin
  FACInfoGen.SetIssuer(AIssuer.GetAttCertIssuer);
end;

procedure TX509V2AttributeCertificateGenerator.SetSerialNumber(const ASerialNumber: TBigInteger);
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

procedure TX509V2AttributeCertificateGenerator.SetNotBeforeUtc(const AUtcDate: TDateTime);
begin
  FACInfoGen.SetStartDate(TRfc5280Asn1Utilities.CreateGeneralizedTime(AUtcDate));
end;

procedure TX509V2AttributeCertificateGenerator.SetNotAfterUtc(const AUtcDate: TDateTime);
begin
  FACInfoGen.SetEndDate(TRfc5280Asn1Utilities.CreateGeneralizedTime(AUtcDate));
end;

procedure TX509V2AttributeCertificateGenerator.AddAttribute(const AAttribute: IX509Attribute);
begin
  FACInfoGen.AddAttribute(TAttributeX509.GetInstance(AAttribute.ToAsn1Object));
end;

procedure TX509V2AttributeCertificateGenerator.SetIssuerUniqueID(const AIui: TCryptoLibBooleanArray);
begin
  FACInfoGen.SetIssuerUniqueID(TX509Utilities.BooleanToBitString(AIui));
end;

procedure TX509V2AttributeCertificateGenerator.AddExtension(const AOid: String;
  ACritical: Boolean; const AExtensionValue: IAsn1Encodable);
begin
  FExtGenerator.AddExtension(TDerObjectIdentifier.Create(AOid), ACritical, AExtensionValue);
end;

procedure TX509V2AttributeCertificateGenerator.AddExtension(const AOid: String;
  ACritical: Boolean; const AExtensionValue: TCryptoLibByteArray);
begin
  FExtGenerator.AddExtension(TDerObjectIdentifier.Create(AOid), ACritical, AExtensionValue);
end;

function TX509V2AttributeCertificateGenerator.Generate(
  const ASignatureFactory: ISignatureFactory): IX509V2AttributeCertificate;
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

function TX509V2AttributeCertificateGenerator.GetSignatureAlgNames: TCryptoLibStringArray;
begin
  Result := TX509Utilities.GetAlgNames;
end;

{ TX509V2CrlGenerator }

procedure TX509V2CrlGenerator.ImplInitFromTemplate(const ATemplate: ICertificateList);
var
  LExtensions: IX509Extensions;
  LOid: IDerObjectIdentifier;
  LExt: IX509Extension;
  LCrl: IX509Crl;
begin
  FTbsGen.SetIssuer(ATemplate.TbsCertList.Issuer);
  FTbsGen.SetThisUpdate(ATemplate.TbsCertList.ThisUpdate);
  FTbsGen.SetNextUpdate(ATemplate.TbsCertList.NextUpdate);

  LCrl := TX509Crl.Create(ATemplate);
  AddCrl(LCrl);

  LExtensions := ATemplate.TbsCertList.Extensions;
  if LExtensions <> nil then
    for LOid in LExtensions.ExtensionOids do
    begin
      if TX509Extensions.AltSignatureAlgorithm.Equals(LOid) or
         TX509Extensions.AltSignatureValue.Equals(LOid) then
        Continue;
      LExt := LExtensions.GetExtension(LOid);
      FExtGenerator.AddExtension(LOid, LExt.IsCritical, LExt.Value.GetOctets());
    end;
end;

constructor TX509V2CrlGenerator.Create;
begin
  inherited Create;
  FExtGenerator := TX509ExtensionsGenerator.Create;
  FTbsGen := TV2TbsCertListGenerator.Create;
end;

constructor TX509V2CrlGenerator.Create(const ATemplate: IX509Crl);
begin
  Create;
  ImplInitFromTemplate(ATemplate.CertificateList);
end;

constructor TX509V2CrlGenerator.Create(const ATemplate: ICertificateList);
begin
  Create;
  ImplInitFromTemplate(ATemplate);
end;

procedure TX509V2CrlGenerator.Reset;
begin
  FTbsGen := TV2TbsCertListGenerator.Create;
  FExtGenerator.Reset;
end;

procedure TX509V2CrlGenerator.SetIssuerDN(const AIssuer: IX509Name);
begin
  FTbsGen.SetIssuer(AIssuer);
end;

procedure TX509V2CrlGenerator.SetThisUpdate(const ADate: TDateTime);
begin
  FTbsGen.SetThisUpdate(TTime.Create(ADate) as ITime);
end;

procedure TX509V2CrlGenerator.SetNextUpdate(const ADate: TDateTime);
begin
  FTbsGen.SetNextUpdate(TTime.Create(ADate) as ITime);
end;

procedure TX509V2CrlGenerator.SetThisUpdateUtc(const AUtcDate: TDateTime);
begin
  FTbsGen.SetThisUpdate(TTime.CreateUtc(AUtcDate) as ITime);
end;

procedure TX509V2CrlGenerator.SetNextUpdateUtc(const AUtcDate: TDateTime);
begin
  FTbsGen.SetNextUpdate(TTime.CreateUtc(AUtcDate) as ITime);
end;

procedure TX509V2CrlGenerator.AddCrlEntry(const AUserCertificate: TBigInteger;
  const ARevocationDate: TDateTime; AReason: Int32);
begin
  FTbsGen.AddCrlEntry(TDerInteger.Create(AUserCertificate), TTime.Create(ARevocationDate) as ITime, AReason);
end;

procedure TX509V2CrlGenerator.AddCrlEntry(const AUserCertificate: TBigInteger;
  const ARevocationDate: TDateTime; AReason: Int32; const AInvalidityDate: TDateTime);
begin
  FTbsGen.AddCrlEntry(TDerInteger.Create(AUserCertificate), TTime.Create(ARevocationDate) as ITime, AReason,
    TRfc5280Asn1Utilities.CreateGeneralizedTime(AInvalidityDate));
end;

procedure TX509V2CrlGenerator.AddCrlEntry(const AUserCertificate: TBigInteger;
  const ARevocationDate: TDateTime; const AExtensions: IX509Extensions);
begin
  FTbsGen.AddCrlEntry(TDerInteger.Create(AUserCertificate), TTime.Create(ARevocationDate) as ITime, AExtensions);
end;

procedure TX509V2CrlGenerator.AddCrlEntryUtc(const AUserCertificate: TBigInteger;
  const ARevocationDateUtc: TDateTime; AReason: Int32);
begin
  FTbsGen.AddCrlEntry(TDerInteger.Create(AUserCertificate), TTime.CreateUtc(ARevocationDateUtc) as ITime, AReason);
end;

procedure TX509V2CrlGenerator.AddCrlEntryUtc(const AUserCertificate: TBigInteger;
  const ARevocationDateUtc: TDateTime; AReason: Int32; const AInvalidityDateUtc: TDateTime);
begin
  FTbsGen.AddCrlEntry(TDerInteger.Create(AUserCertificate), TTime.CreateUtc(ARevocationDateUtc) as ITime, AReason,
    TRfc5280Asn1Utilities.CreateGeneralizedTime(AInvalidityDateUtc));
end;

procedure TX509V2CrlGenerator.AddCrlEntryUtc(const AUserCertificate: TBigInteger;
  const ARevocationDateUtc: TDateTime; const AExtensions: IX509Extensions);
begin
  FTbsGen.AddCrlEntry(TDerInteger.Create(AUserCertificate), TTime.CreateUtc(ARevocationDateUtc) as ITime, AExtensions);
end;

procedure TX509V2CrlGenerator.AddCrl(const AOther: IX509Crl);
var
  LRevocations: TCryptoLibGenericArray<IX509CrlEntry>;
  LEntry: IX509CrlEntry;
begin
  if AOther = nil then
    raise EArgumentNilCryptoLibException.Create('AOther');

  LRevocations := AOther.GetRevokedCertificates;
  if LRevocations <> nil then
    for LEntry in LRevocations do
      FTbsGen.AddCrlEntry(TAsn1Sequence.GetInstance(LEntry.CrlEntry.ToAsn1Object));
end;

procedure TX509V2CrlGenerator.AddExtension(const AOid: String; ACritical: Boolean;
  const AExtensionValue: IAsn1Encodable);
begin
  FExtGenerator.AddExtension(TDerObjectIdentifier.Create(AOid) as IDerObjectIdentifier, ACritical, AExtensionValue);
end;

procedure TX509V2CrlGenerator.AddExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
  const AExtensionValue: IAsn1Encodable);
begin
  FExtGenerator.AddExtension(AOid, ACritical, AExtensionValue);
end;

procedure TX509V2CrlGenerator.AddExtension(const AOid: String; ACritical: Boolean;
  const AExtensionValue: TCryptoLibByteArray);
begin
  FExtGenerator.AddExtension(TDerObjectIdentifier.Create(AOid) as IDerObjectIdentifier, ACritical,
    TDerOctetString.FromContents(AExtensionValue));
end;

procedure TX509V2CrlGenerator.AddExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
  const AExtensionValue: TCryptoLibByteArray);
begin
  FExtGenerator.AddExtension(AOid, ACritical, TDerOctetString.FromContents(AExtensionValue));
end;

function TX509V2CrlGenerator.Generate(const ASignatureFactory: ISignatureFactory): IX509Crl;
var
  LSigAlgID: IAlgorithmIdentifier;
  LTbsCertList: ITbsCertificateList;
  LSignature: IDerBitString;
  LCertList: ICertificateList;
begin
  LSigAlgID := ASignatureFactory.AlgorithmDetails;
  FTbsGen.SetSignature(LSigAlgID);

  if not FExtGenerator.IsEmpty then
    FTbsGen.SetExtensions(FExtGenerator.Generate);

  LTbsCertList := FTbsGen.GenerateTbsCertList;
  LSignature := TX509Utilities.GenerateSignature(ASignatureFactory, LTbsCertList);
  LCertList := TCertificateList.GetInstance(TDerSequence.Create([LTbsCertList, LSigAlgID, LSignature]) as IDerSequence);
  Result := TX509Crl.Create(LCertList);
end;

function TX509V2CrlGenerator.Generate(const ASignatureFactory: ISignatureFactory; AIsCritical: Boolean;
  const AAltSignatureFactory: ISignatureFactory): IX509Crl;
var
  LAltSigAlgID: IAlgorithmIdentifier;
  LAltSignature: IDerBitString;
begin
  FTbsGen.SetSignature(nil);
  LAltSigAlgID := AAltSignatureFactory.AlgorithmDetails;
  FExtGenerator.AddExtension(TX509Extensions.AltSignatureAlgorithm, AIsCritical, LAltSigAlgID);
  FTbsGen.SetExtensions(FExtGenerator.Generate);
  LAltSignature := TX509Utilities.GenerateSignature(AAltSignatureFactory, FTbsGen.GeneratePreTbsCertList);
  FExtGenerator.AddExtension(TX509Extensions.AltSignatureValue, AIsCritical, LAltSignature);
  Result := Generate(ASignatureFactory);
end;

function TX509V2CrlGenerator.GetSignatureAlgNames: TCryptoLibStringArray;
begin
  Result := TX509Utilities.GetAlgNames;
end;

end.

