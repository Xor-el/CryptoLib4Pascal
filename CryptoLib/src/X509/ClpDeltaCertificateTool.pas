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

unit ClpDeltaCertificateTool;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpIX509Certificate,
  ClpIX509Extension,
  ClpX509Asn1Objects,
  ClpX509ExtensionsGenerator,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Tool for the extension in draft-bonnell-lamps-chameleon-certs.
  /// </summary>
  TDeltaCertificateTool = class sealed

  strict private
    class function ExtractDeltaExtensions(const ADescriptorExtensions,
      ABaseExtensions: IX509Extensions): IX509Extensions; static;

  public
    /// <summary>
    /// Create a deltaCertificateDescriptor extension from a delta certificate structure.
    /// </summary>
    class function CreateDeltaCertificateExtension(ACritical: Boolean;
      const ADeltaCert: IX509CertificateStructure): IX509Extension; overload; static;
    /// <summary>
    /// Create a deltaCertificateDescriptor extension from a delta certificate.
    /// </summary>
    class function CreateDeltaCertificateExtension(ACritical: Boolean;
      const ADeltaCert: IX509Certificate): IX509Extension; overload; static;

    /// <summary>
    /// Extract the delta certificate from the base TBS certificate's DCD extension.
    /// </summary>
    class function ExtractDeltaCertificate(const ABaseTbs: ITbsCertificateStructure): IX509CertificateStructure; overload; static;
    /// <summary>
    /// Extract the delta certificate from the base certificate's DCD extension.
    /// </summary>
    class function ExtractDeltaCertificate(const ABaseCert: IX509Certificate): IX509Certificate; overload; static;

    /// <summary>
    /// Trim the descriptor per draft: drop fields equal to the base TBS and
    /// extensions that match the base; exclude DCD OID from the result.
    /// </summary>
    class function TrimDeltaCertificateDescriptor(const ADescriptor: IDeltaCertificateDescriptor;
      const ATbsCertificate: ITbsCertificateStructure;
      const ATbsExtensions: IX509Extensions): IDeltaCertificateDescriptor; static;

  end;

implementation

uses
  ClpAsn1Objects,
  ClpX509Extension,
  ClpX509Certificate;

{ TDeltaCertificateTool }

class function TDeltaCertificateTool.ExtractDeltaExtensions(const ADescriptorExtensions,
  ABaseExtensions: IX509Extensions): IX509Extensions;
var
  LExtGen: TX509ExtensionsGenerator;
  LOid: IDerObjectIdentifier;
begin
  LExtGen := TX509ExtensionsGenerator.Create;
  try
    for LOid in ABaseExtensions.ExtensionOids do
    begin
      if not TX509Extensions.DraftDeltaCertificateDescriptor.Equals(LOid) then
        LExtGen.AddExtension(LOid, ABaseExtensions.GetExtension(LOid));
    end;
    if ADescriptorExtensions <> nil then
    begin
      for LOid in ADescriptorExtensions.ExtensionOids do
        LExtGen.ReplaceExtension(LOid, ADescriptorExtensions.GetExtension(LOid));
    end;
    if LExtGen.IsEmpty then
      Result := nil
    else
      Result := LExtGen.Generate;
  finally
    LExtGen.Free;
  end;
end;

class function TDeltaCertificateTool.CreateDeltaCertificateExtension(ACritical: Boolean;
  const ADeltaCert: IX509CertificateStructure): IX509Extension;
var
  LDescriptor: IDeltaCertificateDescriptor;
  LEnc: TCryptoLibByteArray;
  LOctet: IAsn1OctetString;
begin
  LDescriptor := TDeltaCertificateDescriptor.Create(ADeltaCert.SerialNumber,
    ADeltaCert.SignatureAlgorithm, ADeltaCert.Issuer, ADeltaCert.Validity,
    ADeltaCert.Subject, ADeltaCert.SubjectPublicKeyInfo, ADeltaCert.Extensions,
    ADeltaCert.Signature);
  LEnc := (LDescriptor as IAsn1Encodable).GetEncoded(TAsn1Encodable.Der);
  LOctet := TDerOctetString.FromContents(LEnc);
  Result := TX509Extension.Create(ACritical, LOctet);
end;

class function TDeltaCertificateTool.CreateDeltaCertificateExtension(ACritical: Boolean;
  const ADeltaCert: IX509Certificate): IX509Extension;
begin
  Result := CreateDeltaCertificateExtension(ACritical, ADeltaCert.CertificateStructure);
end;

class function TDeltaCertificateTool.ExtractDeltaCertificate(
  const ABaseTbs: ITbsCertificateStructure): IX509CertificateStructure;
var
  LBaseExtensions: IX509Extensions;
  LDcdExt: IX509Extension;
  LDescriptor: IDeltaCertificateDescriptor;
  LVersion: IDerInteger;
  LSerialNumber: IDerInteger;
  LSignature: IAlgorithmIdentifier;
  LIssuer: IX509Name;
  LValidity: IValidity;
  LSubject: IX509Name;
  LSubjectPublicKeyInfo: ISubjectPublicKeyInfo;
  LExtensions: IX509Extensions;
  LTbs: ITbsCertificateStructure;
begin
  LBaseExtensions := ABaseTbs.Extensions;
  if LBaseExtensions = nil then
    raise EInvalidOperationCryptoLibException.Create('no extensions in base TBS certificate');
  LDcdExt := LBaseExtensions.GetExtension(TX509Extensions.DraftDeltaCertificateDescriptor);
  if LDcdExt = nil then
    raise EInvalidOperationCryptoLibException.Create('no deltaCertificateDescriptor present');
  LDescriptor := TDeltaCertificateDescriptor.GetInstance(LDcdExt.GetParsedValue as IAsn1Convertible);
  LVersion := ABaseTbs.VersionNumber;
  LSerialNumber := LDescriptor.SerialNumber;
  LSignature := LDescriptor.Signature;
  if LSignature = nil then
    LSignature := ABaseTbs.Signature;
  LIssuer := LDescriptor.Issuer;
  if LIssuer = nil then
    LIssuer := ABaseTbs.Issuer;
  LValidity := LDescriptor.Validity;
  if LValidity = nil then
    LValidity := ABaseTbs.Validity;
  LSubject := LDescriptor.Subject;
  if LSubject = nil then
    LSubject := ABaseTbs.Subject;
  LSubjectPublicKeyInfo := LDescriptor.SubjectPublicKeyInfo;
  LExtensions := ExtractDeltaExtensions(LDescriptor.Extensions, LBaseExtensions);
  LTbs := TTbsCertificateStructure.Create(LVersion, LSerialNumber, LSignature, LIssuer,
    LValidity, LSubject, LSubjectPublicKeyInfo, nil, nil, LExtensions);
  Result := TX509CertificateStructure.Create(LTbs, LSignature, LDescriptor.SignatureValue);
end;

class function TDeltaCertificateTool.ExtractDeltaCertificate(
  const ABaseCert: IX509Certificate): IX509Certificate;
begin
  Result := TX509Certificate.Create(ExtractDeltaCertificate(ABaseCert.TbsCertificate));
end;

class function TDeltaCertificateTool.TrimDeltaCertificateDescriptor(
  const ADescriptor: IDeltaCertificateDescriptor;
  const ATbsCertificate: ITbsCertificateStructure;
  const ATbsExtensions: IX509Extensions): IDeltaCertificateDescriptor;
var
  LSerialNumber: IDerInteger;
  LSignature: IAlgorithmIdentifier;
  LIssuer: IX509Name;
  LValidity: IValidity;
  LSubject: IX509Name;
  LSubjectPublicKeyInfo: ISubjectPublicKeyInfo;
  LExtensions: IX509Extensions;
  LSignatureValue: IDerBitString;
  LGenerator: TX509ExtensionsGenerator;
  LOid: IDerObjectIdentifier;
  LDeltaExt, LBaseExt: IX509Extension;
begin
  LSerialNumber := ADescriptor.SerialNumber;

  LSignature := ADescriptor.Signature;
  if (LSignature <> nil) and LSignature.Equals(ATbsCertificate.Signature) then
    LSignature := nil;

  LIssuer := ADescriptor.Issuer;
  if (LIssuer <> nil) and LIssuer.Equals(ATbsCertificate.Issuer) then
    LIssuer := nil;

  LValidity := ADescriptor.Validity;
  if (LValidity <> nil) and LValidity.Equals(ATbsCertificate.Validity) then
    LValidity := nil;

  LSubject := ADescriptor.Subject;
  if (LSubject <> nil) and LSubject.Equals(ATbsCertificate.Subject) then
    LSubject := nil;

  LSubjectPublicKeyInfo := ADescriptor.SubjectPublicKeyInfo;

  LExtensions := ADescriptor.Extensions;
  if LExtensions <> nil then
  begin
    LGenerator := TX509ExtensionsGenerator.Create();
    try
      for LOid in ATbsExtensions.ExtensionOids do
      begin
        if TX509Extensions.DraftDeltaCertificateDescriptor.Equals(LOid) then
          Continue;

        LDeltaExt := LExtensions.GetExtension(LOid);
        LBaseExt := ATbsExtensions.GetExtension(LOid);
        if (LDeltaExt <> nil) and (LBaseExt <> nil) and
           ((LDeltaExt.IsCritical <> LBaseExt.IsCritical) or
            (not (LDeltaExt.Value as IAsn1Encodable).Equals(LBaseExt.Value))) then
          LGenerator.AddExtension(LOid, LDeltaExt);
      end;

      if LGenerator.IsEmpty then
        LExtensions := nil
      else
        LExtensions := LGenerator.Generate;
    finally
      LGenerator.Free;
    end;
  end;

  LSignatureValue := ADescriptor.SignatureValue;

  Result := TDeltaCertificateDescriptor.Create(LSerialNumber, LSignature, LIssuer,
    LValidity, LSubject, LSubjectPublicKeyInfo, LExtensions, LSignatureValue);
end;

end.
