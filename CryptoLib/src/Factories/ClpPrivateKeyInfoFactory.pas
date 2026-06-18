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

unit ClpPrivateKeyInfoFactory;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Rtti,
  ClpValueHelper,
  ClpAsn1Objects,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpIAsymmetricKeyParameter,
  ClpIRsaParameters,
  ClpIDsaParameters,
  ClpIECParameters,
  ClpIDHParameters,
  ClpICipherParameters,
  ClpIEd25519Parameters,
  ClpIEd448Parameters,
  ClpIX25519Parameters,
  ClpIX448Parameters,
  ClpIMlDsaParameters,
  ClpIMlKemParameters,
  ClpMlDsaParameters,
  ClpMlKemParameters,
  ClpPkcsObjectIdentifiers,
  ClpX9ObjectIdentifiers,
  ClpEdECObjectIdentifiers,
  ClpIPkcsAsn1Objects,
  ClpIPkcsDHAsn1Objects,
  ClpPkcsAsn1Objects,
  ClpPkcsDHAsn1Objects,
  ClpPkcsRsaAsn1Objects,
  ClpIPkcsRsaAsn1Objects,
  ClpSecECAsn1Objects,
  ClpIX509DsaAsn1Objects,
  ClpX509DsaAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIX9ECAsn1Objects,
  ClpISecECAsn1Objects,
  ClpECGenerators,
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpIBufferedCipher,
  ClpPbeUtilities;

resourcestring
  SEncryptedKeyInfoNil = 'encrypted key info cannot be nil';
  SEncryptedPrivateKeyInfoHasNoEncryptionAlgorithm = 'EncryptedPrivateKeyInfo has no encryption algorithm';
  SPrivateKeyNil = 'private key cannot be nil';
  SPublicKeyPassedPrivateKeyExpected = 'public key passed - private key expected';
  SPrivateKeyRequiresParameters = 'private key requires parameters for %s';
  SKeyTypeNotSupportedForPrivateKeyInfo = 'key type not supported for PrivateKeyInfo (supported: RSA, DSA, EC, DH, X25519, Ed25519, X448, Ed448, ML-DSA, ML-KEM)';
  SUnknownEncryptionAlgorithm = 'unknown encryption algorithm: %s';

type
  /// <summary>
  /// A factory to produce <see cref="IPrivateKeyInfo"/> (PKCS#8) objects from asymmetric private key parameters.
  /// </summary>
  TPrivateKeyInfoFactory = class sealed(TObject)
  strict private
    class function GetMlDsaPrivateKeyAsn1(const AKey: IMlDsaPrivateKeyParameters): IAsn1Encodable; static;
    class function GetMlKemPrivateKeyAsn1(const AKey: IMlKemPrivateKeyParameters): IAsn1Encodable; static;
  public
    /// <summary>
    /// Create an <see cref="IPrivateKeyInfo"/> representation of a private key.
    /// </summary>
    /// <remarks>
    /// Example of exporting a private key to PKCS#8 bytes:
    /// <code>
    /// pkcs8Bytes := TPrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey).GetEncoded();
    /// </code>
    /// </remarks>
    /// <param name="APrivateKey">The private key parameters.</param>
    /// <returns>The <see cref="IPrivateKeyInfo"/> object.</returns>
    /// <exception cref="EArgumentNilCryptoLibException">If <paramref name="APrivateKey"/> is nil.</exception>
    /// <exception cref="EArgumentCryptoLibException">If a public key is passed instead of a private key.</exception>
    /// <exception cref="ENotSupportedCryptoLibException">If the class provided is not convertible.</exception>
    class function CreatePrivateKeyInfo(const APrivateKey: IAsymmetricKeyParameter): IPrivateKeyInfo; overload; static;
    /// <summary>
    /// Create an <see cref="IPrivateKeyInfo"/> representation of a private key with attributes.
    /// </summary>
    /// <param name="APrivateKey">The key to be encoded into the info object.</param>
    /// <param name="AAttributes">The set of attributes to be included.</param>
    /// <returns>The appropriate <see cref="IPrivateKeyInfo"/>.</returns>
    /// <exception cref="EArgumentNilCryptoLibException">If <paramref name="APrivateKey"/> is nil.</exception>
    /// <exception cref="EArgumentCryptoLibException">If a public key is passed instead of a private key.</exception>
    /// <exception cref="ENotSupportedCryptoLibException">If the class provided is not convertible.</exception>
    class function CreatePrivateKeyInfo(const APrivateKey: IAsymmetricKeyParameter;
      const AAttributes: IAsn1Set): IPrivateKeyInfo; overload; static;
    /// <summary>
    /// Create an <see cref="IPrivateKeyInfo"/> from an encrypted representation using a passphrase.
    /// </summary>
    /// <param name="APassPhrase">The password for decryption.</param>
    /// <param name="AEncInfo">The encrypted private key information.</param>
    /// <returns>A <see cref="IPrivateKeyInfo"/> object.</returns>
    /// <exception cref="EArgumentNilCryptoLibException">If <paramref name="AEncInfo"/> is nil.</exception>
    /// <exception cref="ECryptoLibException">If the encryption algorithm is unknown or decryption fails.</exception>
    class function CreatePrivateKeyInfo(const APassPhrase: TCryptoLibCharArray;
      const AEncInfo: IEncryptedPrivateKeyInfo): IPrivateKeyInfo; overload; static;
    /// <summary>
    /// Create an <see cref="IPrivateKeyInfo"/> from an encrypted representation using a passphrase.
    /// </summary>
    /// <param name="APassPhrase">The password for decryption.</param>
    /// <param name="AWrongPkcs12Zero">If true, uses a specific zero-padding for PKCS#12 PBE (for compatibility).</param>
    /// <param name="AEncInfo">The encrypted private key information.</param>
    /// <returns>A <see cref="IPrivateKeyInfo"/> object.</returns>
    /// <exception cref="EArgumentNilCryptoLibException">If <paramref name="AEncInfo"/> is nil.</exception>
    /// <exception cref="EArgumentCryptoLibException">If <paramref name="AEncInfo"/> has no encryption algorithm.</exception>
    /// <exception cref="ECryptoLibException">If the encryption algorithm is unknown or decryption fails.</exception>
    class function CreatePrivateKeyInfo(const APassPhrase: TCryptoLibCharArray;
      AWrongPkcs12Zero: Boolean; const AEncInfo: IEncryptedPrivateKeyInfo): IPrivateKeyInfo; overload; static;
  end;

implementation

{ TPrivateKeyInfoFactory }

class function TPrivateKeyInfoFactory.GetMlDsaPrivateKeyAsn1(
  const AKey: IMlDsaPrivateKeyParameters): IAsn1Encodable;
begin
  case AKey.PreferredFormat of
    TMlDsaPrivateKeyFormat.EncodingOnly:
      Result := TDerOctetString.Create(AKey.GetEncoded()) as IAsn1Encodable;
    TMlDsaPrivateKeyFormat.SeedOnly:
      Result := TDerTaggedObject.Create(False, 0,
        TDerOctetString.Create(AKey.GetSeed()) as IAsn1Encodable);
  else
    Result := TDerSequence.Create(
      TDerOctetString.Create(AKey.GetSeed()) as IAsn1Encodable,
      TDerOctetString.Create(AKey.GetEncoded()) as IAsn1Encodable);
  end;
end;

class function TPrivateKeyInfoFactory.GetMlKemPrivateKeyAsn1(
  const AKey: IMlKemPrivateKeyParameters): IAsn1Encodable;
begin
  case AKey.PreferredFormat of
    TMlKemPrivateKeyFormat.EncodingOnly:
      Result := TDerOctetString.Create(AKey.GetEncoded()) as IAsn1Encodable;
    TMlKemPrivateKeyFormat.SeedOnly:
      Result := TDerTaggedObject.Create(False, 0,
        TDerOctetString.Create(AKey.GetSeed()) as IAsn1Encodable);
  else
    Result := TDerSequence.Create(
      TDerOctetString.Create(AKey.GetSeed()) as IAsn1Encodable,
      TDerOctetString.Create(AKey.GetEncoded()) as IAsn1Encodable);
  end;
end;

class function TPrivateKeyInfoFactory.CreatePrivateKeyInfo(const APrivateKey: IAsymmetricKeyParameter): IPrivateKeyInfo;
begin
  Result := CreatePrivateKeyInfo(APrivateKey, nil);
end;

class function TPrivateKeyInfoFactory.CreatePrivateKeyInfo(const APassPhrase: TCryptoLibCharArray;
  const AEncInfo: IEncryptedPrivateKeyInfo): IPrivateKeyInfo;
begin
  Result := CreatePrivateKeyInfo(APassPhrase, False, AEncInfo);
end;

class function TPrivateKeyInfoFactory.CreatePrivateKeyInfo(const APassPhrase: TCryptoLibCharArray;
  AWrongPkcs12Zero: Boolean; const AEncInfo: IEncryptedPrivateKeyInfo): IPrivateKeyInfo;
var
  LAlgID: IAlgorithmIdentifier;
  LEngine: TValue;
  LCipher: IBufferedCipher;
  LCipherParameters: ICipherParameters;
  LKeyBytes: TCryptoLibByteArray;
begin
  if AEncInfo = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SEncryptedKeyInfoNil);
  LAlgID := AEncInfo.EncryptionAlgorithm;
  if LAlgID = nil then
    raise EArgumentCryptoLibException.CreateRes(@SEncryptedPrivateKeyInfoHasNoEncryptionAlgorithm);
  LEngine := TPbeUtilities.CreateEngine(LAlgID);
  if not (LEngine.TryGetAsType<IBufferedCipher>(LCipher)) or (LCipher = nil) then
    raise ECryptoLibException.CreateResFmt(@SUnknownEncryptionAlgorithm, [LAlgID.Algorithm.ID]);
  LCipherParameters := TPbeUtilities.GenerateCipherParameters(LAlgID, APassPhrase, AWrongPkcs12Zero);
  LCipher.Init(False, LCipherParameters);
  LKeyBytes := LCipher.DoFinal(AEncInfo.GetEncryptedDataBytes());
  Result := TPrivateKeyInfo.GetInstance(LKeyBytes);
end;

class function TPrivateKeyInfoFactory.CreatePrivateKeyInfo(const APrivateKey: IAsymmetricKeyParameter;
  const AAttributes: IAsn1Set): IPrivateKeyInfo;
var
  LAlgID: IAlgorithmIdentifier;
  LRsaKey: IRsaKeyParameters;
  LCrtKey: IRsaPrivateCrtKeyParameters;
  LKeyStruct: IRsaPrivateKeyStructure;
  LDsaKey: IDsaPrivateKeyParameters;
  LECKey: IECPrivateKeyParameters;
  LDhKey: IDHPrivateKeyParameters;
  LX25519Key: IX25519PrivateKeyParameters;
  LEd25519Key: IEd25519PrivateKeyParameters;
  LX448Key: IX448PrivateKeyParameters;
  LEd448Key: IEd448PrivateKeyParameters;
  LMlDsaKey: IMlDsaPrivateKeyParameters;
  LMlKemKey: IMlKemPrivateKeyParameters;
  LPub: IECPublicKeyParameters;
  LPubEnc: TCryptoLibByteArray;
  LDerPub: IDerBitString;
  LParams: IECDomainParameters;
  LX962: IX962Parameters;
  LOrderBitLength: Int32;
  LEC: IECPrivateKeyStructure;
  LAlgParams: IDHParameter;
  LPrivBytes: TCryptoLibByteArray;
  LPubBytes: TCryptoLibByteArray;
  LDhParams: IDHParameters;
begin
  if APrivateKey = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SPrivateKeyNil);
  if not APrivateKey.IsPrivate then
    raise EArgumentCryptoLibException.CreateRes(@SPublicKeyPassedPrivateKeyExpected);

  // RSA
  if Supports(APrivateKey, IRsaPrivateCrtKeyParameters, LCrtKey) then
  begin
    LAlgID := TAlgorithmIdentifier.Create(TPkcsObjectIdentifiers.RsaEncryption, TDerNull.Instance);
    LKeyStruct := TRsaPrivateKeyStructure.Create(
      LCrtKey.Modulus,
      LCrtKey.PublicExponent,
      LCrtKey.Exponent,
      LCrtKey.P,
      LCrtKey.Q,
      LCrtKey.DP,
      LCrtKey.DQ,
      LCrtKey.QInv);
    Result := TPrivateKeyInfo.Create(LAlgID, LKeyStruct, AAttributes);
    Exit;
  end;

  if Supports(APrivateKey, IRsaKeyParameters, LRsaKey) then
  begin
    LAlgID := TAlgorithmIdentifier.Create(TPkcsObjectIdentifiers.RsaEncryption, TDerNull.Instance);
    LKeyStruct := TRsaPrivateKeyStructure.Create(
      LRsaKey.Modulus,
      TBigInteger.Zero,
      LRsaKey.Exponent,
      TBigInteger.Zero,
      TBigInteger.Zero,
      TBigInteger.Zero,
      TBigInteger.Zero,
      TBigInteger.Zero);
    Result := TPrivateKeyInfo.Create(LAlgID, LKeyStruct, AAttributes);
    Exit;
  end;

  // DSA
  if Supports(APrivateKey, IDsaPrivateKeyParameters, LDsaKey) then
  begin
    if LDsaKey.Parameters = nil then
      raise EArgumentCryptoLibException.CreateResFmt(@SPrivateKeyRequiresParameters, ['DSA']);
    LAlgID := TAlgorithmIdentifier.Create(TX9ObjectIdentifiers.IdDsa,
      TDsaParameter.Create(LDsaKey.Parameters.P, LDsaKey.Parameters.Q, LDsaKey.Parameters.G) as IDsaParameter);
    Result := TPrivateKeyInfo.Create(LAlgID, TDerInteger.Create(LDsaKey.X) as IDerInteger, AAttributes);
    Exit;
  end;

  // EC
  if Supports(APrivateKey, IECPrivateKeyParameters, LECKey) then
  begin
    LPub := TECKeyPairGenerator.GetCorrespondingPublicKey(LECKey);
    LPubEnc := LPub.Q.GetEncoded(False);
    LDerPub := TDerBitString.Create(LPubEnc);
    LParams := LECKey.Parameters;
    if LParams = nil then
      raise EArgumentCryptoLibException.CreateResFmt(@SPrivateKeyRequiresParameters, ['EC']);
    LX962 := LParams.ToX962Parameters();
    LOrderBitLength := LParams.N.BitLength;
    LEC := TECPrivateKeyStructure.Create(LOrderBitLength, LECKey.D, LDerPub, LX962);
    LAlgID := TAlgorithmIdentifier.Create(TX9ObjectIdentifiers.IdECPublicKey, LX962);
    Result := TPrivateKeyInfo.Create(LAlgID, LEC, AAttributes);
    Exit;
  end;

  // DH
  if Supports(APrivateKey, IDHPrivateKeyParameters, LDhKey) then
  begin
    LDhParams := LDhKey.Parameters;
    if LDhParams = nil then
      raise EArgumentCryptoLibException.CreateResFmt(@SPrivateKeyRequiresParameters, ['DH']);
    LAlgParams := TDHParameter.Create(LDhParams.P, LDhParams.G, LDhParams.L);
    LAlgID := TAlgorithmIdentifier.Create(LDhKey.AlgorithmOid, LAlgParams);
    Result := TPrivateKeyInfo.Create(LAlgID, TDerInteger.Create(LDhKey.X) as IDerInteger, AAttributes);
    Exit;
  end;

  // X25519
  if Supports(APrivateKey, IX25519PrivateKeyParameters, LX25519Key) then
  begin
    LAlgID := TAlgorithmIdentifier.Create(TEdECObjectIdentifiers.IdX25519);
    LPrivBytes := LX25519Key.GetEncoded();
    LPubBytes := LX25519Key.GeneratePublicKey().GetEncoded();
    Result := TPrivateKeyInfo.Create(LAlgID, TDerOctetString.Create(LPrivBytes) as IDerOctetString, AAttributes, LPubBytes);
    Exit;
  end;

  // Ed25519
  if Supports(APrivateKey, IEd25519PrivateKeyParameters, LEd25519Key) then
  begin
    LAlgID := TAlgorithmIdentifier.Create(TEdECObjectIdentifiers.IdEd25519);
    LPrivBytes := LEd25519Key.GetEncoded();
    LPubBytes := LEd25519Key.GeneratePublicKey().GetEncoded();
    Result := TPrivateKeyInfo.Create(LAlgID, TDerOctetString.Create(LPrivBytes) as IDerOctetString, AAttributes, LPubBytes);
    Exit;
  end;

  // X448
  if Supports(APrivateKey, IX448PrivateKeyParameters, LX448Key) then
  begin
    LAlgID := TAlgorithmIdentifier.Create(TEdECObjectIdentifiers.IdX448);
    LPrivBytes := LX448Key.GetEncoded();
    LPubBytes := LX448Key.GeneratePublicKey().GetEncoded();
    Result := TPrivateKeyInfo.Create(LAlgID, TDerOctetString.Create(LPrivBytes) as IDerOctetString, AAttributes, LPubBytes);
    Exit;
  end;

  // Ed448
  if Supports(APrivateKey, IEd448PrivateKeyParameters, LEd448Key) then
  begin
    LAlgID := TAlgorithmIdentifier.Create(TEdECObjectIdentifiers.IdEd448);
    LPrivBytes := LEd448Key.GetEncoded();
    LPubBytes := LEd448Key.GeneratePublicKey().GetEncoded();
    Result := TPrivateKeyInfo.Create(LAlgID, TDerOctetString.Create(LPrivBytes) as IDerOctetString, AAttributes, LPubBytes);
    Exit;
  end;

  if Supports(APrivateKey, IMlDsaPrivateKeyParameters, LMlDsaKey) then
  begin
    LAlgID := TAlgorithmIdentifier.Create(LMlDsaKey.Parameters.Oid);
    Result := TPrivateKeyInfo.Create(LAlgID, GetMlDsaPrivateKeyAsn1(LMlDsaKey), AAttributes, nil);
    Exit;
  end;

  if Supports(APrivateKey, IMlKemPrivateKeyParameters, LMlKemKey) then
  begin
    LAlgID := TAlgorithmIdentifier.Create(LMlKemKey.Parameters.Oid);
    Result := TPrivateKeyInfo.Create(LAlgID, GetMlKemPrivateKeyAsn1(LMlKemKey), AAttributes, nil);
    Exit;
  end;

  raise ENotSupportedCryptoLibException.CreateRes(@SKeyTypeNotSupportedForPrivateKeyInfo);
end;

end.
