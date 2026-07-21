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

unit ClpSubjectPublicKeyInfoFactory;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIAsymmetricKeyParameter,
  ClpIRsaParameters,
  ClpIDsaParameters,
  ClpIDHParameters,
  ClpIECParameters,
  ClpIEd25519Parameters,
  ClpIEd448Parameters,
  ClpIX25519Parameters,
  ClpIX448Parameters,
  ClpIMlDsaParameters,
  ClpIMlKemParameters,
  ClpISlhDsaParameters,
  ClpMlDsaParameters,
  ClpMlKemParameters,
  ClpSlhDsaParameters,
  ClpPkcsObjectIdentifiers,
  ClpX9ObjectIdentifiers,
  ClpEdECObjectIdentifiers,
  ClpIX509Asn1Objects,
  ClpIX509RsaAsn1Objects,
  ClpIX509DsaAsn1Objects,
  ClpX509Asn1Objects,
  ClpX509RsaAsn1Objects,
  ClpX509DsaAsn1Objects,
  ClpIX9ECAsn1Objects,
  ClpIPkcsDHAsn1Objects,
  ClpPkcsDHAsn1Objects,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SPublicKeyNil = 'public key cannot be nil';
  SPrivateKeyPassedPublicKeyExpected = 'private key passed - public key expected';
  SPublicKeyRequiresParameters = 'public key requires parameters for %s';
  SKeyTypeNotSupportedForSubjectPublicKeyInfo = 'key type not supported for SubjectPublicKeyInfo';

type
  /// <summary>
  /// A factory to produce <see cref="ISubjectPublicKeyInfo"/> (an X.509 ASN.1 type used for public keys) objects from
  /// asymmetric public key parameters.
  /// </summary>
  /// <remarks>
  /// This class handles the correct encoding of the AlgorithmIdentifier for various algorithms, including mandatory
  /// parameters like the DER NULL for RSA.
  /// </remarks>
  TSubjectPublicKeyInfoFactory = class sealed(TObject)
  public
    /// <summary>
    /// Create an <see cref="ISubjectPublicKeyInfo"/> object for a given public key.
    /// </summary>
    /// <param name="APublicKey">
    /// The public key parameters (for example RSA, DSA, Diffie-Hellman, elliptic curve, or Edwards / X448 family keys
    /// exposed through <see cref="IAsymmetricKeyParameter"/>; see implementation for supported types).
    /// </param>
    /// <returns>An <see cref="ISubjectPublicKeyInfo"/> object representing the public key.</returns>
    /// <exception cref="EArgumentNilCryptoLibException">If <paramref name="APublicKey"/> is nil.</exception>
    /// <exception cref="EArgumentCryptoLibException">If a private key is passed instead of a public key, required
    /// parameters are missing, or the class provided is not convertible.</exception>
    /// <remarks>
    /// Example of exporting a public key to DER-encoded SubjectPublicKeyInfo bytes:
    /// <code>
    /// encoded := TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pub).GetEncoded(TAsn1Encodable.Der);
    /// </code>
    /// </remarks>
    class function CreateSubjectPublicKeyInfo(const APublicKey: IAsymmetricKeyParameter): ISubjectPublicKeyInfo; static;
  end;

implementation

{ TSubjectPublicKeyInfoFactory }

class function TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(const APublicKey: IAsymmetricKeyParameter): ISubjectPublicKeyInfo;
var
  LAlgID: IAlgorithmIdentifier;
  LRsaKey: IRsaKeyParameters;
  LDsaKey: IDsaPublicKeyParameters;
  LECKey: IECPublicKeyParameters;
  LDHPub: IDHPublicKeyParameters;
  LDhParams: IDHParameters;
  LAlgParams: IDHParameter;
  LEd25519Key: IEd25519PublicKeyParameters;
  LEd448Key: IEd448PublicKeyParameters;
  LX25519Key: IX25519PublicKeyParameters;
  LX448Key: IX448PublicKeyParameters;
  LMlDsaKey: IMlDsaPublicKeyParameters;
  LMlKemKey: IMlKemPublicKeyParameters;
  LSlhDsaKey: ISlhDsaPublicKeyParameters;
  LKp: IDsaParameters;
  LParams: IECDomainParameters;
  LX962: IX962Parameters;
  LPubKey: TCryptoLibByteArray;
begin
  if APublicKey = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SPublicKeyNil);
  if APublicKey.IsPrivate then
    raise EArgumentCryptoLibException.CreateRes(@SPrivateKeyPassedPublicKeyExpected);

  if Supports(APublicKey, IRsaKeyParameters, LRsaKey) then
  begin
    LAlgID := TAlgorithmIdentifier.Create(TPkcsObjectIdentifiers.RsaEncryption, TDerNull.Instance);
    Result := TSubjectPublicKeyInfo.Create(LAlgID, TRsaPublicKeyStructure.Create(LRsaKey.Modulus, LRsaKey.Exponent) as IRsaPublicKeyStructure);
    Exit;
  end;

  if Supports(APublicKey, IDsaPublicKeyParameters, LDsaKey) then
  begin
    LKp := LDsaKey.Parameters;
    if LKp = nil then
      raise EArgumentCryptoLibException.CreateResFmt(@SPublicKeyRequiresParameters, ['DSA']);
    LAlgID := TAlgorithmIdentifier.Create(TX9ObjectIdentifiers.IdDsa,
      TDsaParameter.Create(LKp.P, LKp.Q, LKp.G) as IDsaParameter);
    Result := TSubjectPublicKeyInfo.Create(LAlgID, TDerInteger.Create(LDsaKey.Y) as IDerInteger);
    Exit;
  end;

  if Supports(APublicKey, IDHPublicKeyParameters, LDHPub) then
  begin
    LDhParams := LDHPub.Parameters;
    if LDhParams = nil then
      raise EArgumentCryptoLibException.CreateResFmt(@SPublicKeyRequiresParameters, ['DH']);
    LAlgParams := TDHParameter.Create(LDhParams.P, LDhParams.G, LDhParams.L);
    LAlgID := TAlgorithmIdentifier.Create(LDHPub.AlgorithmOid, LAlgParams);
    Result := TSubjectPublicKeyInfo.Create(LAlgID, TDerInteger.Create(LDHPub.Y) as IDerInteger);
    Exit;
  end;

  if Supports(APublicKey, IECPublicKeyParameters, LECKey) then
  begin
    LParams := LECKey.Parameters;
    if LParams = nil then
      raise EArgumentCryptoLibException.CreateResFmt(@SPublicKeyRequiresParameters, ['EC']);

    LX962 := LParams.ToX962Parameters();
    LAlgID := TAlgorithmIdentifier.Create(TX9ObjectIdentifiers.IdECPublicKey, LX962);
    LPubKey := LECKey.Q.GetEncoded(False);
    Result := TSubjectPublicKeyInfo.Create(LAlgID, LPubKey);
    Exit;
  end;

  if Supports(APublicKey, IX25519PublicKeyParameters, LX25519Key) then
  begin
    LAlgID := TAlgorithmIdentifier.Create(TEdECObjectIdentifiers.IdX25519);
    Result := TSubjectPublicKeyInfo.Create(LAlgID, LX25519Key.GetEncoded());
    Exit;
  end;

  if Supports(APublicKey, IEd25519PublicKeyParameters, LEd25519Key) then
  begin
    LAlgID := TAlgorithmIdentifier.Create(TEdECObjectIdentifiers.IdEd25519);
    Result := TSubjectPublicKeyInfo.Create(LAlgID, LEd25519Key.GetEncoded());
    Exit;
  end;

  if Supports(APublicKey, IX448PublicKeyParameters, LX448Key) then
  begin
    LAlgID := TAlgorithmIdentifier.Create(TEdECObjectIdentifiers.IdX448);
    Result := TSubjectPublicKeyInfo.Create(LAlgID, LX448Key.GetEncoded());
    Exit;
  end;

  if Supports(APublicKey, IEd448PublicKeyParameters, LEd448Key) then
  begin
    LAlgID := TAlgorithmIdentifier.Create(TEdECObjectIdentifiers.IdEd448);
    Result := TSubjectPublicKeyInfo.Create(LAlgID, LEd448Key.GetEncoded());
    Exit;
  end;

  if Supports(APublicKey, IMlDsaPublicKeyParameters, LMlDsaKey) then
  begin
    LAlgID := TAlgorithmIdentifier.Create(LMlDsaKey.Parameters.Oid);
    Result := TSubjectPublicKeyInfo.Create(LAlgID, LMlDsaKey.GetEncoded());
    Exit;
  end;

  if Supports(APublicKey, IMlKemPublicKeyParameters, LMlKemKey) then
  begin
    LAlgID := TAlgorithmIdentifier.Create(LMlKemKey.Parameters.Oid);
    Result := TSubjectPublicKeyInfo.Create(LAlgID, LMlKemKey.GetEncoded());
    Exit;
  end;

  if Supports(APublicKey, ISlhDsaPublicKeyParameters, LSlhDsaKey) then
  begin
    LAlgID := TAlgorithmIdentifier.Create(LSlhDsaKey.Parameters.Oid);
    Result := TSubjectPublicKeyInfo.Create(LAlgID, LSlhDsaKey.GetEncoded());
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateRes(@SKeyTypeNotSupportedForSubjectPublicKeyInfo);
end;

end.
