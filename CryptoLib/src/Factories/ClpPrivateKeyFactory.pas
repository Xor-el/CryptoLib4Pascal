{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpPrivateKeyFactory;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIPkcsAsn1Objects,
  ClpIPkcsRsaAsn1Objects,
  ClpIAsymmetricKeyParameter,
  ClpRsaParameters,
  ClpDsaParameters,
  ClpECParameters,
  ClpDHParameters,
  ClpIDHParameters,
  ClpIPkcsDHAsn1Objects,
  ClpPkcsDHAsn1Objects,
  ClpEd25519Parameters,
  ClpEd448Parameters,
  ClpX25519Parameters,
  ClpX448Parameters,
  ClpMlDsaParameters,
  ClpMlKemParameters,
  ClpIMlDsaParameters,
  ClpIMlKemParameters,
  ClpMlKemEngine,
  ClpArrayUtilities,
  ClpPkcsObjectIdentifiers,
  ClpX509ObjectIdentifiers,
  ClpX9ObjectIdentifiers,
  ClpEdECObjectIdentifiers,
  ClpGnuObjectIdentifiers,
  ClpCryptLibObjectIdentifiers,
  ClpIX9ECAsn1Objects,
  ClpX9ECAsn1Objects,
  ClpPkcsAsn1Objects,
  ClpPkcsRsaAsn1Objects,
  ClpIDsaParameters,
  ClpIECParameters,
  ClpIX509Asn1Objects,
  ClpIX509DsaAsn1Objects,
  ClpX509DsaAsn1Objects,
  ClpSecECAsn1Objects,
  ClpISecECAsn1Objects,
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpPrivateKeyInfoFactory;

resourcestring
  SKeyTypeWithOidNotSupported = 'key type with OID %s not yet supported';
  SInvalidMlDsaPrivateKey = 'invalid %s private key';
  SInconsistentMlDsaPrivateKey = 'inconsistent %s private key';
  SInvalidMlKemPrivateKey = 'invalid %s private key';
  SInconsistentMlKemPrivateKey = 'inconsistent %s private key';

type
  /// <summary>
  /// Factory for creating private key parameters from PrivateKeyInfo.
  /// </summary>
  TPrivateKeyFactory = class sealed(TObject)
  strict private
    class function ParseMlDsaPrivateKey(const AParameters: IMlDsaParameters;
      const APrivateKey: IAsn1OctetString): IMlDsaPrivateKeyParameters; static;
    class function ParseMlKemPrivateKey(const AParameters: IMlKemParameters;
      const APrivateKey: IAsn1OctetString): IMlKemPrivateKeyParameters; static;
  public
    class function CreateKey(const APrivateKeyInfoData: TCryptoLibByteArray): IAsymmetricKeyParameter; overload; static;
    class function CreateKey(const AInStr: TStream): IAsymmetricKeyParameter; overload; static;
    class function CreateKey(const AKeyInfo: IPrivateKeyInfo): IAsymmetricKeyParameter; overload; static;

    /// <summary>
    /// Decrypt encrypted private key info using the given password.
    /// </summary>
    class function DecryptKey(const APassPhrase: TCryptoLibCharArray;
      const AEncInfo: IEncryptedPrivateKeyInfo): IAsymmetricKeyParameter; overload; static;
    /// <summary>
    /// Decrypt encoded EncryptedPrivateKeyInfo using the given password.
    /// </summary>
    class function DecryptKey(const APassPhrase: TCryptoLibCharArray;
      const AEncryptedPrivateKeyInfoData: TCryptoLibByteArray): IAsymmetricKeyParameter; overload; static;

    /// <summary>
    /// Decrypt encoded Stream using the given password.
    /// </summary>
    class function DecryptKey(const APassPhrase: TCryptoLibCharArray;
      const AEncryptedPrivateKeyInfoStream: TStream): IAsymmetricKeyParameter; overload; static;
  end;

implementation

{ TPrivateKeyFactory }

class function TPrivateKeyFactory.ParseMlDsaPrivateKey(const AParameters: IMlDsaParameters;
  const APrivateKey: IAsn1OctetString): IMlDsaPrivateKeyParameters;
var
  LLength: Int32;
  LAsn1Object: IAsn1Object;
  LTagged: IAsn1TaggedObject;
  LSequence: IAsn1Sequence;
  LOct: IAsn1OctetString;
  LSeed, LEncoding, LFromSeedEncoding: TCryptoLibByteArray;
  LFromSeed: IMlDsaPrivateKeyParameters;
begin
  LLength := APrivateKey.GetOctetsLength();
  if LLength = AParameters.ParameterSet.SeedLength then
    Exit(TMlDsaPrivateKeyParameters.FromSeed(AParameters, APrivateKey.GetOctets()));
  if LLength = AParameters.ParameterSet.PrivateKeyLength then
    Exit(TMlDsaPrivateKeyParameters.FromEncoding(AParameters, APrivateKey.GetOctets()));
  try
    LAsn1Object := TAsn1Object.FromByteArray(APrivateKey.GetOctets());
    if Supports(LAsn1Object, IAsn1TaggedObject, LTagged) then
    begin
      if LTagged.HasContextTag(0) then
      begin
        LSeed := TAsn1OctetString.GetTagged(LTagged, False).GetOctets();
        Exit(TMlDsaPrivateKeyParameters.FromSeed(AParameters, LSeed));
      end;
    end
    else if Supports(LAsn1Object, IAsn1OctetString, LOct) then
    begin
      LEncoding := LOct.GetOctets();
      Exit(TMlDsaPrivateKeyParameters.FromEncoding(AParameters, LEncoding));
    end
    else if Supports(LAsn1Object, IAsn1Sequence, LSequence) then
    begin
      if LSequence.Count = 2 then
      begin
        LSeed := TAsn1OctetString.GetInstance(LSequence[0]).GetOctets();
        LEncoding := TAsn1OctetString.GetInstance(LSequence[1]).GetOctets();
        LFromSeed := TMlDsaPrivateKeyParameters.FromSeed(AParameters, LSeed, TMlDsaPrivateKeyFormat.SeedAndEncoding);
        LFromSeedEncoding := LFromSeed.GetEncoded();
        if not TArrayUtilities.FixedTimeEquals(LFromSeedEncoding, LEncoding) then
          raise EArgumentCryptoLibException.CreateResFmt(@SInconsistentMlDsaPrivateKey, [AParameters.Name]);
        Exit(LFromSeed);
      end;
    end;
  except
    on E: EArgumentCryptoLibException do
      raise;
  end;
  raise EArgumentCryptoLibException.CreateResFmt(@SInvalidMlDsaPrivateKey, [AParameters.Name]);
end;

class function TPrivateKeyFactory.ParseMlKemPrivateKey(const AParameters: IMlKemParameters;
  const APrivateKey: IAsn1OctetString): IMlKemPrivateKeyParameters;
var
  LLength: Int32;
  LAsn1Object: IAsn1Object;
  LTagged: IAsn1TaggedObject;
  LSequence: IAsn1Sequence;
  LOct: IAsn1OctetString;
  LSeed, LEncoding, LFromSeedEncoding: TCryptoLibByteArray;
  LFromSeed: IMlKemPrivateKeyParameters;
begin
  LLength := APrivateKey.GetOctetsLength();
  if LLength = TMlKemEngine.SeedBytes then
    Exit(TMlKemPrivateKeyParameters.FromSeed(AParameters, APrivateKey.GetOctets()));
  if LLength = AParameters.ParameterSet.Engine.SecretKeyBytes then
    Exit(TMlKemPrivateKeyParameters.FromEncoding(AParameters, APrivateKey.GetOctets()));
  try
    LAsn1Object := TAsn1Object.FromByteArray(APrivateKey.GetOctets());
    if Supports(LAsn1Object, IAsn1TaggedObject, LTagged) then
    begin
      if LTagged.HasContextTag(0) then
      begin
        LSeed := TAsn1OctetString.GetTagged(LTagged, False).GetOctets();
        Exit(TMlKemPrivateKeyParameters.FromSeed(AParameters, LSeed));
      end;
    end
    else if Supports(LAsn1Object, IAsn1OctetString, LOct) then
    begin
      LEncoding := LOct.GetOctets();
      Exit(TMlKemPrivateKeyParameters.FromEncoding(AParameters, LEncoding));
    end
    else if Supports(LAsn1Object, IAsn1Sequence, LSequence) then
    begin
      if LSequence.Count = 2 then
      begin
        LSeed := TAsn1OctetString.GetInstance(LSequence[0]).GetOctets();
        LEncoding := TAsn1OctetString.GetInstance(LSequence[1]).GetOctets();
        LFromSeed := TMlKemPrivateKeyParameters.FromSeed(AParameters, LSeed, TMlKemPrivateKeyFormat.SeedAndEncoding);
        LFromSeedEncoding := LFromSeed.GetEncoded();
        if not TArrayUtilities.FixedTimeEquals(LFromSeedEncoding, LEncoding) then
          raise EArgumentCryptoLibException.CreateResFmt(@SInconsistentMlKemPrivateKey, [AParameters.Name]);
        Exit(LFromSeed);
      end;
    end;
  except
    on E: EArgumentCryptoLibException do
      raise;
  end;
  raise EArgumentCryptoLibException.CreateResFmt(@SInvalidMlKemPrivateKey, [AParameters.Name]);
end;

class function TPrivateKeyFactory.CreateKey(const APrivateKeyInfoData: TCryptoLibByteArray): IAsymmetricKeyParameter;
var
  LAsn1Obj: IAsn1Object;
begin
  LAsn1Obj := TAsn1Object.FromByteArray(APrivateKeyInfoData);
  Result := CreateKey(TPrivateKeyInfo.GetInstance(LAsn1Obj));
end;

class function TPrivateKeyFactory.CreateKey(const AInStr: TStream): IAsymmetricKeyParameter;
var
  LAsn1Obj: IAsn1Object;
begin
  LAsn1Obj := TAsn1Object.FromStream(AInStr);
  Result := CreateKey(TPrivateKeyInfo.GetInstance(LAsn1Obj));
end;

class function TPrivateKeyFactory.DecryptKey(const APassPhrase: TCryptoLibCharArray;
  const AEncInfo: IEncryptedPrivateKeyInfo): IAsymmetricKeyParameter;
begin
  Result := CreateKey(TPrivateKeyInfoFactory.CreatePrivateKeyInfo(APassPhrase, False, AEncInfo));
end;

class function TPrivateKeyFactory.DecryptKey(const APassPhrase: TCryptoLibCharArray;
  const AEncryptedPrivateKeyInfoData: TCryptoLibByteArray): IAsymmetricKeyParameter;
var
  LEncInfo: IEncryptedPrivateKeyInfo;
begin
  LEncInfo := TEncryptedPrivateKeyInfo.GetInstance(AEncryptedPrivateKeyInfoData);
  Result := DecryptKey(APassPhrase, LEncInfo);
end;

class function TPrivateKeyFactory.DecryptKey(const APassPhrase: TCryptoLibCharArray;
  const AEncryptedPrivateKeyInfoStream: TStream): IAsymmetricKeyParameter;
var
  LEncInfo: IEncryptedPrivateKeyInfo;
begin
  LEncInfo := TEncryptedPrivateKeyInfo.GetInstance(TAsn1Object.FromStream(AEncryptedPrivateKeyInfoStream));
  Result := DecryptKey(APassPhrase, LEncInfo);
end;

class function TPrivateKeyFactory.CreateKey(const AKeyInfo: IPrivateKeyInfo): IAsymmetricKeyParameter;
var
  LAlgID: IAlgorithmIdentifier;
  LAlgOid: IDerObjectIdentifier;
  LRsaKeyStructure: IRsaPrivateKeyStructure;
  LDsaX: IDerInteger;
  LDsaParams: IDsaParameters;
  LDsaPara: IDsaParameter;
  LX962Params: IX962Parameters;
  LECParams: IECDomainParameters;
  LECPrivateKeyObj: IAsn1Object;
  LECPrivateKeySeq: IECPrivateKeyStructure;
  LDHPara: IDHParameter;
  LDerInteger: IDerInteger;
  LLVal: Int32;
  LDHParams: IDHParameters;
  LRawKey: TCryptoLibByteArray;
  LMlDsaParameters: IMlDsaParameters;
  LMlKemParameters: IMlKemParameters;
begin
  if AKeyInfo = nil then
  begin
    Result := nil;
    Exit;
  end;

  LAlgID := AKeyInfo.PrivateKeyAlgorithm;
  LAlgOid := LAlgID.Algorithm;

  // RSA keys
  if LAlgOid.Equals(TPkcsObjectIdentifiers.RsaEncryption) or
    LAlgOid.Equals(TX509ObjectIdentifiers.IdEARsa) or
    LAlgOid.Equals(TPkcsObjectIdentifiers.IdRsassaPss) or
    LAlgOid.Equals(TPkcsObjectIdentifiers.IdRsaesOaep) then
  begin
    LRsaKeyStructure := TRsaPrivateKeyStructure.GetInstance(AKeyInfo.ParsePrivateKey());
    Result := TRsaPrivateCrtKeyParameters.Create(
      LRsaKeyStructure.Modulus,
      LRsaKeyStructure.PublicExponent,
      LRsaKeyStructure.PrivateExponent,
      LRsaKeyStructure.Prime1,
      LRsaKeyStructure.Prime2,
      LRsaKeyStructure.Exponent1,
      LRsaKeyStructure.Exponent2,
      LRsaKeyStructure.Coefficient);
    Exit;
  end;

  // DSA keys
  if LAlgOid.Equals(TX9ObjectIdentifiers.IdDsa) then
  begin
    LDsaX := TDerInteger.GetInstance(AKeyInfo.ParsePrivateKey());
    if LAlgID.Parameters <> nil then
    begin
      LDsaPara := TDsaParameter.GetInstance(LAlgID.Parameters.ToAsn1Object());
      LDsaParams := TDsaParameters.Create(LDsaPara.P, LDsaPara.Q, LDsaPara.G);
    end
    else
    begin
      LDsaParams := nil;
    end;
    Result := TDsaPrivateKeyParameters.Create(LDsaX.Value, LDsaParams);
    Exit;
  end;

  // EC keys
  if LAlgOid.Equals(TX9ObjectIdentifiers.IdECPublicKey) then
  begin
    // TODO: Consistency checks in case parameters and/or public key are specified at both the
    // PrivateKeyInfo and ECPrivateKey levels?
    LECPrivateKeyObj := AKeyInfo.ParsePrivateKey();
    LECPrivateKeySeq := TECPrivateKeyStructure.GetInstance(LECPrivateKeyObj);
    LX962Params := TX962Parameters.GetInstance(LAlgID.Parameters);
    LECParams := TECDomainParameters.FromX962Parameters(LX962Params);
    Result := TECPrivateKeyParameters.Create('EC', LECPrivateKeySeq.GetKey(), LECParams);
    Exit;
  end;

  // DH keys
  if LAlgOid.Equals(TPkcsObjectIdentifiers.DhKeyAgreement) then
  begin
    LDHPara := TDHParameter.GetInstance(LAlgID.Parameters);
    LDerInteger := TDerInteger.GetInstance(AKeyInfo.ParsePrivateKey());
    if LDHPara.L <> nil then
      LLVal := LDHPara.L.Value.Int32Value
    else
      LLVal := 0;
    LDHParams := TDHParameters.Create(LDHPara.P, LDHPara.G,
      TBigInteger.GetDefault, LLVal);
    Result := TDHPrivateKeyParameters.Create(LDerInteger.Value, LDHParams, LAlgOid);
    Exit;
  end;

  // Ed25519 keys
  if LAlgOid.Equals(TEdECObjectIdentifiers.IdEd25519) or
    LAlgOid.Equals(TGnuObjectIdentifiers.Ed25519) then
  begin
    LRawKey := TAsn1OctetString.GetInstance(AKeyInfo.ParsePrivateKey()).GetOctets();
    Result := TEd25519PrivateKeyParameters.Create(LRawKey);
    Exit;
  end;

  // X25519 keys
  if LAlgOid.Equals(TEdECObjectIdentifiers.IdX25519) or
    LAlgOid.Equals(TCryptLibObjectIdentifiers.Curvey25519) then
  begin
    if TX25519PrivateKeyParameters.KeySize = AKeyInfo.PrivateKeyLength then
      LRawKey := AKeyInfo.PrivateKey.GetOctets()
    else
      LRawKey := TAsn1OctetString.GetInstance(AKeyInfo.ParsePrivateKey()).GetOctets();
    Result := TX25519PrivateKeyParameters.Create(LRawKey);
    Exit;
  end;

  // Ed448 keys
  if LAlgOid.Equals(TEdECObjectIdentifiers.IdEd448) then
  begin
    LRawKey := TAsn1OctetString.GetInstance(AKeyInfo.ParsePrivateKey()).GetOctets();
    Result := TEd448PrivateKeyParameters.Create(LRawKey);
    Exit;
  end;

  // X448 keys
  if LAlgOid.Equals(TEdECObjectIdentifiers.IdX448) then
  begin
    if TX448PrivateKeyParameters.KeySize = AKeyInfo.PrivateKeyLength then
      LRawKey := AKeyInfo.PrivateKey.GetOctets()
    else
      LRawKey := TAsn1OctetString.GetInstance(AKeyInfo.ParsePrivateKey()).GetOctets();
    Result := TX448PrivateKeyParameters.Create(LRawKey);
    Exit;
  end;

  LMlDsaParameters := TMlDsaParameters.GetByOid(LAlgOid);
  if LMlDsaParameters <> nil then
  begin
    Result := ParseMlDsaPrivateKey(LMlDsaParameters, AKeyInfo.PrivateKey);
    Exit;
  end;

  LMlKemParameters := TMlKemParameters.GetByOid(LAlgOid);
  if LMlKemParameters <> nil then
  begin
    Result := ParseMlKemPrivateKey(LMlKemParameters, AKeyInfo.PrivateKey);
    Exit;
  end;

  raise ENotSupportedCryptoLibException.CreateResFmt(@SKeyTypeWithOidNotSupported, [LAlgOid.Id]);
end;

end.
