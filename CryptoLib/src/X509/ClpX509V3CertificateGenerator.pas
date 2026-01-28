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

unit ClpX509V3CertificateGenerator;

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
  ClpIX509Extension,
  ClpIX509ExtensionsGenerator,
  ClpX509ExtensionsGenerator,
  ClpIAsymmetricKeyParameter,
  ClpISignatureFactory,
  ClpV3TbsCertificateGenerator,
  ClpSubjectPublicKeyInfoFactory,
  ClpX509Utilities,
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpDeltaCertificateTool;

type
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

implementation

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

end.
