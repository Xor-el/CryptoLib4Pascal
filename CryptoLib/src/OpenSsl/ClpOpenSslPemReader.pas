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

unit ClpOpenSslPemReader;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Classes,
  Generics.Collections,
  Rtti,
  ClpIPemHeader,
  ClpIPemObject,
  ClpPemReader,
  ClpIOpenSslPemReader,
  ClpIAsymmetricKeyParameter,
  ClpIAsymmetricCipherKeyPair,
  ClpIX509Certificate,
  ClpIX509Crl,
  ClpIX509V2AttributeCertificate,
  ClpIPkcs10CertificationRequest,
  ClpICmsAsn1Objects,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpPublicKeyFactory,
  ClpPrivateKeyFactory,
  ClpAsymmetricCipherKeyPair,
  ClpX509Certificate,
  ClpX509Crl,
  ClpX509V2AttributeCertificate,
  ClpPkcs10CertificationRequest,
  ClpCmsAsn1Objects,
  ClpX509RsaAsn1Objects,
  ClpIX509RsaAsn1Objects,
  ClpPkcsRsaAsn1Objects,
  ClpIPkcsRsaAsn1Objects,
  ClpPkcsAsn1Objects,
  ClpIPkcsAsn1Objects,
  ClpSecECAsn1Objects,
  ClpISecECAsn1Objects,
  ClpX9ECAsn1Objects,
  ClpIX9ECAsn1Objects,
  ClpX509Asn1Objects,
  ClpRsaParameters,
  ClpDsaParameters,
  ClpIDsaParameters,
  ClpX9ObjectIdentifiers,
  ClpECGenerators,
  ClpIECParameters,
  ClpIX509Asn1Objects,
  ClpStringUtilities,
  ClpCollectionUtilities,
  ClpEncoders,
  ClpIOpenSslPasswordFinder,
  ClpOpenSslPemUtilities,
  ClpCryptoLibTypes;

resourcestring
  SUnrecognisedObject = 'unrecognised object: %s';
  SProblemParsingCert = 'problem parsing cert: %s';
  SProblemParsingPkcs7 = 'problem parsing PKCS7 object: %s';
  SMalformedSequenceRsa = 'malformed sequence in RSA private key';
  SMalformedSequenceDsa = 'malformed sequence in DSA private key';
  SProblemCreatingPrivateKey = 'problem creating %s private key: %s';
  SUnknownKeyType = 'Unknown key type: %s';
  SEncryptedPrivateKeyNotSupported = 'Encrypted private key is not supported';
  SNoPasswordFinderSpecified = 'No password finder specified, but a password is required';
  SPasswordIsNull = 'Password is null, but a password is required';
  SMissingDekInfo = 'missing DEK-info';
  SProblemExtractingECParams = 'exception extracting EC named curve: %s';

type
  /// <summary>
  /// Reader for OpenSSL PEM encoded streams containing X509 certificates,
  /// PKCS#8 encoded keys and PKCS#7/CMS objects. Returns typed values as TValue.
  /// Encrypted private keys (Proc-Type 4,ENCRYPTED with DEK-Info) supported when
  /// IOpenSslPasswordFinder is provided.
  /// </summary>
  TOpenSslPemReader = class(TPemReader, IOpenSslPemReader)
  strict private
    FPasswordFinder: IOpenSslPasswordFinder;
    function ReadRsaPublicKey(const APemObject: IPemObject): IAsymmetricKeyParameter;
    function ReadPublicKey(const APemObject: IPemObject): IAsymmetricKeyParameter;
    function ReadCertificate(const APemObject: IPemObject): IX509Certificate;
    function ReadCrl(const APemObject: IPemObject): IX509Crl;
    function ReadCertificateRequest(const APemObject: IPemObject): IPkcs10CertificationRequest;
    function ReadAttributeCertificate(const APemObject: IPemObject): IX509V2AttributeCertificate;
    function ReadPkcs7(const APemObject: IPemObject): ICmsContentInfo;
    function ReadPrivateKey(const APemObject: IPemObject): TValue;
    function ReadECParameters(const APemObject: IPemObject): TValue;
  public
    constructor Create(const AReader: TStream); overload;
    constructor Create(const AReader: TStream; const APasswordFinder: IOpenSslPasswordFinder); overload;
    function ReadObject(): TValue;
  end;

implementation

{ TOpenSslPemReader }

constructor TOpenSslPemReader.Create(const AReader: TStream);
begin
  Create(AReader, nil);
end;

constructor TOpenSslPemReader.Create(const AReader: TStream; const APasswordFinder: IOpenSslPasswordFinder);
begin
  inherited Create(AReader);
  FPasswordFinder := APasswordFinder;
end;

function TOpenSslPemReader.ReadObject(): TValue;
var
  LObj: IPemObject;
  LType: String;
begin
  LObj := ReadPemObject();
  if LObj = nil then
  begin
    Result := TValue.Empty;
    Exit;
  end;

  LType := LObj.&Type;

  if TStringUtilities.EndsWith(LType, 'PRIVATE KEY') then
  begin
    Result := ReadPrivateKey(LObj);
    Exit;
  end;

  if LType = 'PUBLIC KEY' then
  begin
    Result := TValue.From<IAsymmetricKeyParameter>(ReadPublicKey(LObj));
    Exit;
  end;

  if LType = 'RSA PUBLIC KEY' then
  begin
    Result := TValue.From<IAsymmetricKeyParameter>(ReadRsaPublicKey(LObj));
    Exit;
  end;

  if (LType = 'CERTIFICATE REQUEST') or (LType = 'NEW CERTIFICATE REQUEST') then
  begin
    Result := TValue.From<IPkcs10CertificationRequest>(ReadCertificateRequest(LObj));
    Exit;
  end;

  if (LType = 'CERTIFICATE') or (LType = 'X509 CERTIFICATE') then
  begin
    Result := TValue.From<IX509Certificate>(ReadCertificate(LObj));
    Exit;
  end;

  if (LType = 'PKCS7') or (LType = 'CMS') then
  begin
    Result := TValue.From<ICmsContentInfo>(ReadPkcs7(LObj));
    Exit;
  end;

  if LType = 'X509 CRL' then
  begin
    Result := TValue.From<IX509Crl>(ReadCrl(LObj));
    Exit;
  end;

  if LType = 'ATTRIBUTE CERTIFICATE' then
  begin
    Result := TValue.From<IX509V2AttributeCertificate>(ReadAttributeCertificate(LObj));
    Exit;
  end;

  if LType = 'EC PARAMETERS' then
  begin
    Result := ReadECParameters(LObj);
    Exit;
  end;

  raise EIOCryptoLibException.CreateResFmt(@SUnrecognisedObject, [LType]);
end;

function TOpenSslPemReader.ReadECParameters(const APemObject: IPemObject): TValue;
var
  LAsn1Obj: IAsn1Object;
  LOid: IDerObjectIdentifier;
  LSeq: IAsn1Sequence;
begin
  try
    LAsn1Obj := TAsn1Object.FromByteArray(APemObject.Content);

    if Supports(LAsn1Obj, IDerObjectIdentifier, LOid) then
    begin
      Result := TValue.From<IDerObjectIdentifier>(LOid);
      Exit;
    end;

    if Supports(LAsn1Obj, IAsn1Sequence, LSeq) then
    begin
      Result := TValue.From<IX9ECParameters>(TX9ECParameters.GetInstance(LSeq));
      Exit;
    end;

    Result := TValue.Empty;
  except
    on EIOCryptoLibException do
      raise;
    on E: Exception do
      raise EPemGenerationCryptoLibException.CreateResFmt(@SProblemExtractingECParams, [E.Message]);
  end;
end;

function TOpenSslPemReader.ReadRsaPublicKey(const APemObject: IPemObject): IAsymmetricKeyParameter;
var
  LRsaPublicKey: IRsaPublicKeyStructure;
begin
  LRsaPublicKey := TRsaPublicKeyStructure.GetInstance(APemObject.Content);
  Result := TRsaKeyParameters.Create(False, LRsaPublicKey.Modulus, LRsaPublicKey.PublicExponent);
end;

function TOpenSslPemReader.ReadPublicKey(const APemObject: IPemObject): IAsymmetricKeyParameter;
begin
  Result := TPublicKeyFactory.CreateKey(APemObject.Content);
end;

function TOpenSslPemReader.ReadCertificate(const APemObject: IPemObject): IX509Certificate;
begin
  try
    Result := TX509Certificate.Create(APemObject.Content);
  except
    on E: Exception do
      raise EPemGenerationCryptoLibException.CreateResFmt(@SProblemParsingCert, [E.Message]);
  end;
end;

function TOpenSslPemReader.ReadCrl(const APemObject: IPemObject): IX509Crl;
begin
  try
    Result := TX509Crl.Create(APemObject.Content);
  except
    on E: Exception do
      raise EPemGenerationCryptoLibException.CreateResFmt(@SProblemParsingCert, [E.Message]);
  end;
end;

function TOpenSslPemReader.ReadCertificateRequest(const APemObject: IPemObject): IPkcs10CertificationRequest;
begin
  try
    Result := TPkcs10CertificationRequest.Create(APemObject.Content);
  except
    on E: Exception do
      raise EPemGenerationCryptoLibException.CreateResFmt(@SProblemParsingCert, [E.Message]);
  end;
end;

function TOpenSslPemReader.ReadAttributeCertificate(const APemObject: IPemObject): IX509V2AttributeCertificate;
begin
  Result := TX509V2AttributeCertificate.Create(APemObject.Content);
end;

function TOpenSslPemReader.ReadPkcs7(const APemObject: IPemObject): ICmsContentInfo;
begin
  try
    Result := TCmsContentInfo.GetInstance(APemObject.Content);
  except
    on E: Exception do
      raise EPemGenerationCryptoLibException.CreateResFmt(@SProblemParsingPkcs7, [E.Message]);
  end;
end;

function TOpenSslPemReader.ReadPrivateKey(const APemObject: IPemObject): TValue;
var
  LType: String;
  LKeyBytes: TCryptoLibByteArray;
  LFields: TDictionary<String, String>;
  LProcType: String;
  LHeader: IPemHeader;
  I: Int32;
  LSeq: IAsn1Sequence;
  LRsa: IRsaPrivateKeyStructure;
  LPubSpec, LPrivSpec: IAsymmetricKeyParameter;
  LP, LQ, LG, LY, LX: IDerInteger;
  LDsaParams: IDsaParameters;
  LPKey: IECPrivateKeyStructure;
  LAlgId: IAlgorithmIdentifier;
  LPrivInfo: IPrivateKeyInfo;
  LPubKey: IDerBitString;
  LPubInfo: ISubjectPublicKeyInfo;
  LECPriv: IECPrivateKeyParameters;
  LPasswordChars: TCryptoLibCharArray;
  LDekInfo: String;
  LTokens: TCryptoLibStringArray;
  LDekAlgName: String;
  LIV: TCryptoLibByteArray;
begin
  if not TStringUtilities.EndsWith(APemObject.&Type, 'PRIVATE KEY') then
    raise EArgumentCryptoLibException.Create('Expected type ending with PRIVATE KEY');

  LType := TStringUtilities.Trim(TStringUtilities.Substring(APemObject.&Type, 1,
    Length(APemObject.&Type) - Length('PRIVATE KEY')));
  LKeyBytes := APemObject.Content;

  LFields := TDictionary<String, String>.Create();
  try
    for I := 0 to Length(APemObject.Headers) - 1 do
    begin
      LHeader := APemObject.Headers[I];
      LFields.AddOrSetValue(LHeader.Name, LHeader.Value);
    end;

    LProcType := TCollectionUtilities.GetValueOrNull<String, String>(LFields, 'Proc-Type');
    if LProcType = '4,ENCRYPTED' then
    begin
      if FPasswordFinder = nil then
        raise EArgumentCryptoLibException.Create(SNoPasswordFinderSpecified);

      LPasswordChars := FPasswordFinder.GetPassword();
      if (LPasswordChars = nil) then
        raise EArgumentCryptoLibException.Create(SPasswordIsNull);

      if not LFields.TryGetValue('DEK-Info', LDekInfo) then
        raise EPemCryptoLibException.Create(SMissingDekInfo);

      LTokens := TStringUtilities.SplitString(LDekInfo, ',');
      if System.Length(LTokens) < 2 then
        raise EPemCryptoLibException.Create(SMissingDekInfo);

      LDekAlgName := TStringUtilities.Trim(LTokens[0]);
      LIV := THexEncoder.Decode(TStringUtilities.Trim(LTokens[1]));

      LKeyBytes := TOpenSslPemUtilities.Crypt(False, LKeyBytes, LPasswordChars, LDekAlgName, LIV);
    end;

    try
      LSeq := TAsn1Sequence.GetInstance(LKeyBytes);

      if LType = 'RSA' then
      begin
        if LSeq.Count <> 9 then
          raise EPemCryptoLibException.Create(SMalformedSequenceRsa);

        LRsa := TRsaPrivateKeyStructure.GetInstance(LSeq);

        LPubSpec := TRsaKeyParameters.Create(False, LRsa.Modulus, LRsa.PublicExponent);
        LPrivSpec := TRsaPrivateCrtKeyParameters.Create(
          LRsa.Modulus, LRsa.PublicExponent, LRsa.PrivateExponent,
          LRsa.Prime1, LRsa.Prime2, LRsa.Exponent1, LRsa.Exponent2,
          LRsa.Coefficient);

        Result := TValue.From<IAsymmetricCipherKeyPair>(
          TAsymmetricCipherKeyPair.Create(LPubSpec, LPrivSpec) as IAsymmetricCipherKeyPair);
        Exit;
      end;

      if LType = 'DSA' then
      begin
        if LSeq.Count <> 6 then
          raise EPemCryptoLibException.Create(SMalformedSequenceDsa);

        LP := TDerInteger.GetInstance(LSeq[1]);
        LQ := TDerInteger.GetInstance(LSeq[2]);
        LG := TDerInteger.GetInstance(LSeq[3]);
        LY := TDerInteger.GetInstance(LSeq[4]);
        LX := TDerInteger.GetInstance(LSeq[5]);

        LDsaParams := TDsaParameters.Create(LP.Value, LQ.Value, LG.Value);

        LPrivSpec := TDsaPrivateKeyParameters.Create(LX.Value, LDsaParams);
        LPubSpec := TDsaPublicKeyParameters.Create(LY.Value, LDsaParams);

        Result := TValue.From<IAsymmetricCipherKeyPair>(
          TAsymmetricCipherKeyPair.Create(LPubSpec, LPrivSpec) as IAsymmetricCipherKeyPair);
        Exit;
      end;

      if LType = 'EC' then
      begin
        LPKey := TECPrivateKeyStructure.GetInstance(LSeq);
        LAlgId := TAlgorithmIdentifier.Create(TX9ObjectIdentifiers.IdECPublicKey, LPKey.Parameters);

        LPrivInfo := TPrivateKeyInfo.Create(LAlgId, LPKey.ToAsn1Object());
        LPrivSpec := TPrivateKeyFactory.CreateKey(LPrivInfo);

        LPubKey := LPKey.PublicKey;
        if LPubKey <> nil then
        begin
          LPubInfo := TSubjectPublicKeyInfo.Create(LAlgId, LPubKey);
          LPubSpec := TPublicKeyFactory.CreateKey(LPubInfo);
        end
        else
        begin
          if not Supports(LPrivSpec, IECPrivateKeyParameters, LECPriv) then
            raise EPemGenerationCryptoLibException.Create('EC private key expected');
          LPubSpec := TECKeyPairGenerator.GetCorrespondingPublicKey(LECPriv);
        end;

        Result := TValue.From<IAsymmetricCipherKeyPair>(
          TAsymmetricCipherKeyPair.Create(LPubSpec, LPrivSpec) as IAsymmetricCipherKeyPair);
        Exit;
      end;

      if LType = 'ENCRYPTED' then
      begin
        if FPasswordFinder = nil then
          raise EArgumentCryptoLibException.Create(SNoPasswordFinderSpecified);
        LPasswordChars := FPasswordFinder.GetPassword();
        if LPasswordChars = nil then
          raise EArgumentCryptoLibException.Create(SPasswordIsNull);
        Result := TValue.From<IAsymmetricKeyParameter>(
          TPrivateKeyFactory.DecryptKey(LPasswordChars, TEncryptedPrivateKeyInfo.GetInstance(LSeq)));
        Exit;
      end;

      if LType = '' then
      begin
        Result := TValue.From<IAsymmetricKeyParameter>(
          TPrivateKeyFactory.CreateKey(TPrivateKeyInfo.GetInstance(LSeq)));
        Exit;
      end;

      raise EArgumentCryptoLibException.CreateResFmt(@SUnknownKeyType, [LType]);
    except
      on EIOCryptoLibException do
        raise;
      on E: Exception do
        raise EPemCryptoLibException.CreateResFmt(@SProblemCreatingPrivateKey, [LType, E.Message]);
    end;
  finally
    LFields.Free;
  end;
end;

end.
