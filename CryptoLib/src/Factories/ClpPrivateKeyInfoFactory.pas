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

unit ClpPrivateKeyInfoFactory;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIAsymmetricKeyParameter,
  ClpIRsaParameters,
  ClpIDsaParameters,
  ClpIECParameters,
  ClpIDHParameters,
  ClpIEd25519Parameters,
  ClpIX25519Parameters,
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
  ClpX9ECAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIX9ECAsn1Objects,
  ClpISecECAsn1Objects,
  ClpECGenerators,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Factory for creating PrivateKeyInfo from asymmetric private key parameters.
  /// </summary>
  TPrivateKeyInfoFactory = class sealed(TObject)
  public
    class function CreatePrivateKeyInfo(const APrivateKey: IAsymmetricKeyParameter): IPrivateKeyInfo; overload; static;
    class function CreatePrivateKeyInfo(const APrivateKey: IAsymmetricKeyParameter;
      const AAttributes: IAsn1Set): IPrivateKeyInfo; overload; static;
  end;

implementation

{ TPrivateKeyInfoFactory }

class function TPrivateKeyInfoFactory.CreatePrivateKeyInfo(const APrivateKey: IAsymmetricKeyParameter): IPrivateKeyInfo;
begin
  Result := CreatePrivateKeyInfo(APrivateKey, nil);
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
    raise EArgumentNilCryptoLibException.Create('APrivateKey');
  if not APrivateKey.IsPrivate then
    raise EArgumentCryptoLibException.Create('Public key passed - private key expected');

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
      raise EArgumentCryptoLibException.Create('DSA private key requires parameters.');
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
      raise EArgumentCryptoLibException.Create('EC private key requires parameters.');
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
      raise EArgumentCryptoLibException.Create('DH private key requires parameters.');
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

  raise ENotSupportedCryptoLibException.Create('Key type not supported for PrivateKeyInfo (supported: RSA, DSA, EC, DH, X25519, Ed25519).');
end;

end.
