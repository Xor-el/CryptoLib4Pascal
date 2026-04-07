{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

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
  ClpCryptoLibTypes;

type
  /// <summary>
  /// A factory to produce SubjectPublicKeyInfo objects from public keys.
  /// </summary>
  TSubjectPublicKeyInfoFactory = class sealed(TObject)
  public
    /// <summary>
    /// Create a SubjectPublicKeyInfo for a given public key.
    /// Supports: RsaKeyParameters, DsaPublicKeyParameters, DHPublicKeyParameters,
    /// ECPublicKeyParameters, Ed25519PublicKeyParameters, X25519PublicKeyParameters.
    /// </summary>
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
  LKp: IDsaParameters;
  LParams: IECDomainParameters;
  LX962: IX962Parameters;
  LPubKey: TCryptoLibByteArray;
begin
  if APublicKey = nil then
    raise EArgumentNilCryptoLibException.Create('APublicKey');
  if APublicKey.IsPrivate then
    raise EArgumentCryptoLibException.Create('Private key passed - public key expected.');

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
      raise EArgumentCryptoLibException.Create('DSA public key requires parameters.');
    LAlgID := TAlgorithmIdentifier.Create(TX9ObjectIdentifiers.IdDsa,
      TDsaParameter.Create(LKp.P, LKp.Q, LKp.G) as IDsaParameter);
    Result := TSubjectPublicKeyInfo.Create(LAlgID, TDerInteger.Create(LDsaKey.Y) as IDerInteger);
    Exit;
  end;

  if Supports(APublicKey, IDHPublicKeyParameters, LDHPub) then
  begin
    LDhParams := LDHPub.Parameters;
    if LDhParams = nil then
      raise EArgumentCryptoLibException.Create('DH public key requires parameters.');
    LAlgParams := TDHParameter.Create(LDhParams.P, LDhParams.G, LDhParams.L);
    LAlgID := TAlgorithmIdentifier.Create(LDHPub.AlgorithmOid, LAlgParams);
    Result := TSubjectPublicKeyInfo.Create(LAlgID, TDerInteger.Create(LDHPub.Y) as IDerInteger);
    Exit;
  end;

  if Supports(APublicKey, IECPublicKeyParameters, LECKey) then
  begin
    LParams := LECKey.Parameters;
    if LParams = nil then
      raise EArgumentCryptoLibException.Create('EC public key requires parameters.');

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

  raise EArgumentCryptoLibException.Create('Key type not supported for SubjectPublicKeyInfo.');
end;

end.
