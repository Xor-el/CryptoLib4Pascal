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

unit ClpPkcs10CertificationRequestBuilder;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Generics.Collections,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpAsn1Core,
  ClpIPkcsAsn1Objects,
  ClpPkcsAsn1Objects,
  ClpPkcsObjectIdentifiers,
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpIX509Asn1Generators,
  ClpX509Asn1Generators,
  ClpX509ExtensionUtilities,
  ClpSubjectPublicKeyInfoFactory,
  ClpAsn1SignatureFactory,
  ClpISignatureFactory,
  ClpPkcs10CertificationRequest,
  ClpIPkcs10CertificationRequest,
  ClpIPkcs10CertificationRequestBuilder,
  ClpIAsymmetricCipherKeyPair,
  ClpCryptoLibTypes;

resourcestring
  SSubjectNotSet = 'Subject must be set before calling Build';
  SKeyPairNotSet = 'KeyPair must be set before calling Build';
  SSignatureAlgorithmNotSet = 'SignatureAlgorithm must be set before calling Build';
  SKeyPairRequiredForSKI = 'KeyPair must be set before calling AddSubjectKeyIdentifier';

type
  /// <summary>
  /// Fluent builder for PKCS#10 Certification Requests (CSRs).
  /// </summary>
  TPkcs10CertificationRequestBuilder = class(TInterfacedObject, IPkcs10CertificationRequestBuilder)

  strict private
  var
    FSubject: IX509Name;
    FKeyPair: IAsymmetricCipherKeyPair;
    FSignatureAlgorithm: String;
    FExtGen: IX509ExtensionsGenerator;
    FAttributes: TList<IAttributePkcs>;

  public
    constructor Create;
    destructor Destroy; override;

    function SetSubject(const ASubject: IX509Name): IPkcs10CertificationRequestBuilder;
    function SetKeyPair(const AKeyPair: IAsymmetricCipherKeyPair): IPkcs10CertificationRequestBuilder;
    function SetSignatureAlgorithm(const AAlgorithm: String): IPkcs10CertificationRequestBuilder;

    function AddExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AValue: IAsn1Encodable): IPkcs10CertificationRequestBuilder; overload;
    function AddExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtValue: TCryptoLibByteArray): IPkcs10CertificationRequestBuilder; overload;
    function AddExtensions(const AExtensions: IX509Extensions): IPkcs10CertificationRequestBuilder;

    function AddBasicConstraints(ACritical: Boolean; AIsCA: Boolean): IPkcs10CertificationRequestBuilder; overload;
    function AddBasicConstraints(ACritical: Boolean; APathLenConstraint: Int32): IPkcs10CertificationRequestBuilder; overload;
    function AddKeyUsage(ACritical: Boolean; AUsage: Int32): IPkcs10CertificationRequestBuilder;
    function AddSubjectAlternativeName(ACritical: Boolean;
      const ANames: IGeneralNames): IPkcs10CertificationRequestBuilder;
    function AddExtendedKeyUsage(ACritical: Boolean;
      const AUsages: TCryptoLibGenericArray<IDerObjectIdentifier>): IPkcs10CertificationRequestBuilder;
    function AddSubjectKeyIdentifier(ACritical: Boolean): IPkcs10CertificationRequestBuilder;

    function AddAttribute(const AAttribute: IAttributePkcs): IPkcs10CertificationRequestBuilder;

    function Reset: IPkcs10CertificationRequestBuilder;
    function Build: IPkcs10CertificationRequest;

  end;

implementation

{ TPkcs10CertificationRequestBuilder }

constructor TPkcs10CertificationRequestBuilder.Create;
begin
  inherited Create;
  FExtGen := TX509ExtensionsGenerator.Create();
  FAttributes := TList<IAttributePkcs>.Create;
end;

destructor TPkcs10CertificationRequestBuilder.Destroy;
begin
  FAttributes.Free;
  inherited Destroy;
end;

function TPkcs10CertificationRequestBuilder.SetSubject(const ASubject: IX509Name): IPkcs10CertificationRequestBuilder;
begin
  FSubject := ASubject;
  Result := Self;
end;

function TPkcs10CertificationRequestBuilder.SetKeyPair(const AKeyPair: IAsymmetricCipherKeyPair): IPkcs10CertificationRequestBuilder;
begin
  FKeyPair := AKeyPair;
  Result := Self;
end;

function TPkcs10CertificationRequestBuilder.SetSignatureAlgorithm(const AAlgorithm: String): IPkcs10CertificationRequestBuilder;
begin
  FSignatureAlgorithm := AAlgorithm;
  Result := Self;
end;

function TPkcs10CertificationRequestBuilder.AddExtension(const AOid: IDerObjectIdentifier;
  ACritical: Boolean; const AValue: IAsn1Encodable): IPkcs10CertificationRequestBuilder;
begin
  FExtGen.AddExtension(AOid, ACritical, AValue);
  Result := Self;
end;

function TPkcs10CertificationRequestBuilder.AddExtension(const AOid: IDerObjectIdentifier;
  ACritical: Boolean; const AExtValue: TCryptoLibByteArray): IPkcs10CertificationRequestBuilder;
begin
  FExtGen.AddExtension(AOid, ACritical, AExtValue);
  Result := Self;
end;

function TPkcs10CertificationRequestBuilder.AddExtensions(const AExtensions: IX509Extensions): IPkcs10CertificationRequestBuilder;
begin
  FExtGen.AddExtensions(AExtensions);
  Result := Self;
end;

function TPkcs10CertificationRequestBuilder.AddBasicConstraints(ACritical: Boolean;
  AIsCA: Boolean): IPkcs10CertificationRequestBuilder;
begin
  FExtGen.AddExtension(TX509Extensions.BasicConstraints, ACritical, TBasicConstraints.Create(AIsCA) as IBasicConstraints);
  Result := Self;
end;

function TPkcs10CertificationRequestBuilder.AddBasicConstraints(ACritical: Boolean;
  APathLenConstraint: Int32): IPkcs10CertificationRequestBuilder;
begin
  FExtGen.AddExtension(TX509Extensions.BasicConstraints, ACritical, TBasicConstraints.Create(APathLenConstraint) as IBasicConstraints);
  Result := Self;
end;

function TPkcs10CertificationRequestBuilder.AddKeyUsage(ACritical: Boolean;
  AUsage: Int32): IPkcs10CertificationRequestBuilder;
begin
  FExtGen.AddExtension(TX509Extensions.KeyUsage, ACritical, TKeyUsage.Create(AUsage) as IKeyUsage);
  Result := Self;
end;

function TPkcs10CertificationRequestBuilder.AddSubjectAlternativeName(ACritical: Boolean;
  const ANames: IGeneralNames): IPkcs10CertificationRequestBuilder;
begin
  FExtGen.AddExtension(TX509Extensions.SubjectAlternativeName, ACritical, ANames);
  Result := Self;
end;

function TPkcs10CertificationRequestBuilder.AddExtendedKeyUsage(ACritical: Boolean;
  const AUsages: TCryptoLibGenericArray<IDerObjectIdentifier>): IPkcs10CertificationRequestBuilder;
begin
  FExtGen.AddExtension(TX509Extensions.ExtendedKeyUsage, ACritical, TExtendedKeyUsage.Create(AUsages) as IExtendedKeyUsage);
  Result := Self;
end;

function TPkcs10CertificationRequestBuilder.AddSubjectKeyIdentifier(ACritical: Boolean): IPkcs10CertificationRequestBuilder;
var
  LSpki: ISubjectPublicKeyInfo;
begin
  if FKeyPair = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SKeyPairRequiredForSKI);
  LSpki := TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(FKeyPair.Public);
  FExtGen.AddExtension(TX509Extensions.SubjectKeyIdentifier, ACritical,
    TX509ExtensionUtilities.CreateSubjectKeyIdentifier(LSpki));
  Result := Self;
end;

function TPkcs10CertificationRequestBuilder.AddAttribute(const AAttribute: IAttributePkcs): IPkcs10CertificationRequestBuilder;
begin
  FAttributes.Add(AAttribute);
  Result := Self;
end;

function TPkcs10CertificationRequestBuilder.Reset: IPkcs10CertificationRequestBuilder;
begin
  FSubject := nil;
  FKeyPair := nil;
  FSignatureAlgorithm := '';
  FExtGen.Reset;
  FAttributes.Clear;
  Result := Self;
end;

function TPkcs10CertificationRequestBuilder.Build: IPkcs10CertificationRequest;
var
  LSignatureFactory: ISignatureFactory;
  LAttrVec: IAsn1EncodableVector;
  LExtAttr: IAttributePkcs;
  LAttributes: IAsn1Set;
  LItem: IAttributePkcs;
begin
  if FSubject = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SSubjectNotSet);
  if FKeyPair = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SKeyPairNotSet);
  if FSignatureAlgorithm = '' then
    raise EInvalidOperationCryptoLibException.CreateRes(@SSignatureAlgorithmNotSet);

  LAttrVec := TAsn1EncodableVector.Create;

  if not FExtGen.IsEmpty then
  begin
    LExtAttr := TAttributePkcs.Create(TPkcsObjectIdentifiers.Pkcs9AtExtensionRequest,
      TDerSet.Create(FExtGen.Generate()) as IDerSet);
    LAttrVec.Add(LExtAttr);
  end;

  for LItem in FAttributes do
    LAttrVec.Add(LItem);

  if LAttrVec.Count > 0 then
    LAttributes := TDerSet.Create(LAttrVec)
  else
    LAttributes := nil;

  LSignatureFactory := TAsn1SignatureFactory.Create(FSignatureAlgorithm, FKeyPair.Private, nil);
  Result := TPkcs10CertificationRequest.Create(LSignatureFactory, FSubject, FKeyPair.Public, LAttributes);
end;

end.
