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

unit ClpSubjectPublicKeyInfoFactory;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIAsymmetricKeyParameter,
  ClpIRsaKeyParameters,
  ClpIDsaPublicKeyParameters,
  ClpIECPublicKeyParameters,
  ClpIECDomainParameters,
  ClpIEd25519PublicKeyParameters,
  ClpIX25519PublicKeyParameters,
  ClpPkcsObjectIdentifiers,
  ClpX9ObjectIdentifiers,
  ClpEdECObjectIdentifiers,
  ClpIDsaParameters,
  ClpDsaParameter,
  ClpX9Asn1Objects,
  ClpIX9Asn1Objects,
  ClpX9ECParameters,
  ClpIX9ECParameters,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// A factory to produce SubjectPublicKeyInfo objects from public keys.
  /// </summary>
  TSubjectPublicKeyInfoFactory = class sealed(TObject)
  public
    /// <summary>
    /// Create a SubjectPublicKeyInfo for a given public key.
    /// Supports: RsaKeyParameters, DsaPublicKeyParameters, ECPublicKeyParameters,
    /// Ed25519PublicKeyParameters, X25519PublicKeyParameters.
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
  LEd25519Key: IEd25519PublicKeyParameters;
  LX25519Key: IX25519PublicKeyParameters;
  LKp: IDsaParameters;
  LParams: IECDomainParameters;
  LX9: IX9ECParameters;
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
    Result := TSubjectPublicKeyInfo.Create(LAlgID, TRsaPublicKeyStructure.Create(LRsaKey.Modulus, LRsaKey.Exponent));
    Exit;
  end;

  if Supports(APublicKey, IDsaPublicKeyParameters, LDsaKey) then
  begin
    LKp := LDsaKey.parameters;
    if LKp = nil then
      raise EArgumentCryptoLibException.Create('DSA public key requires parameters.');
    LAlgID := TAlgorithmIdentifier.Create(TX9ObjectIdentifiers.IdDsa,
      TDsaParameter.Create(LKp.p, LKp.q, LKp.g));
    Result := TSubjectPublicKeyInfo.Create(LAlgID, TDerInteger.Create(LDsaKey.y));
    Exit;
  end;

  if Supports(APublicKey, IECPublicKeyParameters, LECKey) then
  begin
    LParams := LECKey.Parameters;
    if LParams = nil then
      raise EArgumentCryptoLibException.Create('EC public key requires parameters.');
    LX9 := TX9ECParameters.Create(LParams.Curve, LParams.G, LParams.N, LParams.H, LParams.Seed);
    LX962 := TX962Parameters.Create(LX9.ToAsn1Object());
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

  raise EArgumentCryptoLibException.Create('Key type not supported for SubjectPublicKeyInfo.');
end;

end.
