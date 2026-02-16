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

unit ClpOpenSslMiscPemGenerator;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Rtti,
  ClpIPemObject,
  ClpPemObject,
  ClpIAsymmetricKeyParameter,
  ClpPrivateKeyInfoFactory,
  ClpSubjectPublicKeyInfoFactory,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIDsaParameters,
  ClpIPkcsAsn1Objects,
  ClpPkcsObjectIdentifiers,
  ClpX9ObjectIdentifiers,
  ClpOiwObjectIdentifiers,
  ClpIX509Asn1Objects,
  ClpX509DsaAsn1Objects,
  ClpIX509DsaAsn1Objects,
  ClpAsn1Core,
  ClpIAsymmetricCipherKeyPair,
  ClpIX509Certificate,
  ClpIX509Crl,
  ClpIX509V2AttributeCertificate,
  ClpIPkcs10CertificationRequest,
  ClpICmsAsn1Objects,
  ClpX509Certificate,
  ClpX509Crl,
  ClpX509V2AttributeCertificate,
  ClpPkcs10CertificationRequest,
  ClpCmsAsn1Objects,
  ClpPkcsAsn1Objects,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// PEM generator for the original set of PEM objects used in OpenSSL.
  /// </summary>
  TOpenSslMiscPemGenerator = class sealed(TInterfacedObject, IPemObjectGenerator)
  strict private
    FObj: TValue;

    class function CreatePemObject(const AObj: TValue): IPemObject; static;
    class function EncodePrivateKey(const AAkp: IAsymmetricKeyParameter;
      out AKeyType: String): TCryptoLibByteArray; static;
    class function EncodePrivateKeyInfo(const AInfo: IPrivateKeyInfo;
      out AKeyType: String): TCryptoLibByteArray; static;
    class function EncodePublicKey(const AAkp: IAsymmetricKeyParameter;
      out AKeyType: String): TCryptoLibByteArray; static;
    class function EncodePublicKeyInfo(const AInfo: ISubjectPublicKeyInfo;
      out AKeyType: String): TCryptoLibByteArray; static;
  public
    constructor Create(const AObj: TValue);
    function Generate(): IPemObject;
  end;

implementation

{ TOpenSslMiscPemGenerator }

constructor TOpenSslMiscPemGenerator.Create(const AObj: TValue);
begin
  inherited Create();
  FObj := AObj;
end;

function TOpenSslMiscPemGenerator.Generate: IPemObject;
begin
  try
    Result := CreatePemObject(FObj);
  except
    on E: Exception do
      raise EPemGenerationCryptoLibException.Create('encoding exception');
  end;
end;

class function TOpenSslMiscPemGenerator.CreatePemObject(const AObj: TValue): IPemObject;
var
  LKp: IAsymmetricCipherKeyPair;
  LPemObj: IPemObject;
  LPemGen: IPemObjectGenerator;
  LCert: IX509Certificate;
  LCrl: IX509Crl;
  LAkp: IAsymmetricKeyParameter;
  LPrivInfo: IPrivateKeyInfo;
  LPubInfo: ISubjectPublicKeyInfo;
  LAttrCert: IX509V2AttributeCertificate;
  LCertReq: IPkcs10CertificationRequest;
  LCmsContent: ICmsContentInfo;
  LPkcsContent: IPkcsContentInfo;
  LType: String;
  LEncoding: TCryptoLibByteArray;
begin
  if AObj.IsEmpty then
    raise EArgumentNilCryptoLibException.Create('obj');

  // Key pair -> recurse with private key
  if AObj.TryAsType<IAsymmetricCipherKeyPair>(LKp) then
    Exit(CreatePemObject(TValue.From<IAsymmetricKeyParameter>(LKp.Private)));

  // PEM object identity
  if AObj.TryAsType<IPemObject>(LPemObj) then
    Exit(LPemObj);

  // PEM object generator
  if AObj.TryAsType<IPemObjectGenerator>(LPemGen) then
    Exit(LPemGen.Generate());

  // X509 Certificate
  if AObj.TryAsType<IX509Certificate>(LCert) then
  begin
    try
      LEncoding := LCert.GetEncoded();
    except
      on E: Exception do
        raise EPemGenerationCryptoLibException.Create('Cannot Encode object: ' + E.Message);
    end;
    Exit(TPemObject.Create('CERTIFICATE', LEncoding));
  end;

  // X509 CRL
  if AObj.TryAsType<IX509Crl>(LCrl) then
  begin
    try
      LEncoding := LCrl.GetEncoded();
    except
      on E: Exception do
        raise EPemGenerationCryptoLibException.Create('Cannot Encode object: ' + E.Message);
    end;
    Exit(TPemObject.Create('X509 CRL', LEncoding));
  end;

  // Asymmetric key (private or public)
  if AObj.TryAsType<IAsymmetricKeyParameter>(LAkp) then
  begin
    if LAkp.IsPrivate then
      LEncoding := EncodePrivateKey(LAkp, LType)
    else
      LEncoding := EncodePublicKey(LAkp, LType);
    Exit(TPemObject.Create(LType, LEncoding));
  end;

  // PrivateKeyInfo
  if AObj.TryAsType<IPrivateKeyInfo>(LPrivInfo) then
  begin
    LEncoding := EncodePrivateKeyInfo(LPrivInfo, LType);
    Exit(TPemObject.Create(LType, LEncoding));
  end;

  // SubjectPublicKeyInfo
  if AObj.TryAsType<ISubjectPublicKeyInfo>(LPubInfo) then
  begin
    LEncoding := EncodePublicKeyInfo(LPubInfo, LType);
    Exit(TPemObject.Create(LType, LEncoding));
  end;

  // X509V2 Attribute Certificate
  if AObj.TryAsType<IX509V2AttributeCertificate>(LAttrCert) then
    Exit(TPemObject.Create('ATTRIBUTE CERTIFICATE', LAttrCert.GetEncoded()));

  // PKCS#10 Certification Request
  if AObj.TryAsType<IPkcs10CertificationRequest>(LCertReq) then
    Exit(TPemObject.Create('CERTIFICATE REQUEST', LCertReq.GetEncoded()));

  // CMS ContentInfo
  if AObj.TryAsType<ICmsContentInfo>(LCmsContent) then
    Exit(TPemObject.Create('PKCS7', LCmsContent.GetEncoded()));

  // PKCS ContentInfo
  if AObj.TryAsType<IPkcsContentInfo>(LPkcsContent) then
    Exit(TPemObject.Create('PKCS7', LPkcsContent.GetEncoded()));

  raise EPemGenerationCryptoLibException.Create('Object type not supported');
end;

class function TOpenSslMiscPemGenerator.EncodePrivateKey(const AAkp: IAsymmetricKeyParameter;
  out AKeyType: String): TCryptoLibByteArray;
var
  LInfo: IPrivateKeyInfo;
begin
  LInfo := TPrivateKeyInfoFactory.CreatePrivateKeyInfo(AAkp);
  Result := EncodePrivateKeyInfo(LInfo, AKeyType);
end;

class function TOpenSslMiscPemGenerator.EncodePrivateKeyInfo(const AInfo: IPrivateKeyInfo;
  out AKeyType: String): TCryptoLibByteArray;
var
  LAlgID: IAlgorithmIdentifier;
  LAlgOid: IDerObjectIdentifier;
  LDsaP: IDsaParameter;
  LX: TBigInteger;
  LY: TBigInteger;
  LSeq: IAsn1Sequence;
begin
  LAlgID := AInfo.PrivateKeyAlgorithm;
  LAlgOid := LAlgID.Algorithm;

  if LAlgOid.Equals(TPkcsObjectIdentifiers.RsaEncryption) then
  begin
    AKeyType := 'RSA PRIVATE KEY';
    Result := AInfo.ParsePrivateKey().GetEncoded();
    Exit;
  end;

  if LAlgOid.Equals(TX9ObjectIdentifiers.IdECPublicKey) then
  begin
    AKeyType := 'EC PRIVATE KEY';
    Result := AInfo.ParsePrivateKey().GetEncoded();
    Exit;
  end;

  if LAlgOid.Equals(TX9ObjectIdentifiers.IdDsa) or LAlgOid.Equals(TOiwObjectIdentifiers.DsaWithSha1) then
  begin
    AKeyType := 'DSA PRIVATE KEY';
    LDsaP := TDsaParameter.GetInstance(LAlgID.Parameters);
    LX := TDerInteger.GetInstance(AInfo.ParsePrivateKey()).Value;
    LY := LDsaP.G.ModPow(LX, LDsaP.P);
    LSeq := TDerSequence.Create([
      TDerInteger.Zero,
      TDerInteger.Create(LDsaP.P) as IDerInteger,
      TDerInteger.Create(LDsaP.Q) as IDerInteger,
      TDerInteger.Create(LDsaP.G) as IDerInteger,
      TDerInteger.Create(LY) as IDerInteger,
      TDerInteger.Create(LX) as IDerInteger
    ]);
    Result := LSeq.GetEncoded();
    Exit;
  end;

  AKeyType := 'PRIVATE KEY';
  Result := AInfo.GetEncoded();
end;

class function TOpenSslMiscPemGenerator.EncodePublicKey(const AAkp: IAsymmetricKeyParameter;
  out AKeyType: String): TCryptoLibByteArray;
var
  LInfo: ISubjectPublicKeyInfo;
begin
  LInfo := TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(AAkp);
  Result := EncodePublicKeyInfo(LInfo, AKeyType);
end;

class function TOpenSslMiscPemGenerator.EncodePublicKeyInfo(const AInfo: ISubjectPublicKeyInfo;
  out AKeyType: String): TCryptoLibByteArray;
begin
  AKeyType := 'PUBLIC KEY';
  Result := AInfo.GetEncoded();
end;

end.
