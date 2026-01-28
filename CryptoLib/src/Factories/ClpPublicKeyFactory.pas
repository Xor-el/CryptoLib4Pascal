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

unit ClpPublicKeyFactory;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpIAsymmetricKeyParameter,
  ClpIRsaKeyParameters,
  ClpIDsaPublicKeyParameters,
  ClpIECPublicKeyParameters,
  ClpRsaKeyParameters,
  ClpDsaPublicKeyParameters,
  ClpECPublicKeyParameters,
  ClpDsaParameters,
  ClpECDomainParameters,
  ClpPkcsObjectIdentifiers,
  ClpX509ObjectIdentifiers,
  ClpX9ObjectIdentifiers,
  ClpOiwObjectIdentifiers,
  ClpX9Asn1Objects,
  ClpIX9Asn1Objects,
  ClpX9ECC,
  ClpX9ECParameters,
  ClpIX9ECParameters,
  ClpX509Asn1Objects,
  ClpPkcsAsn1Objects,
  ClpAsn1Objects,
  ClpECNamedCurveTable,
  ClpECNamedDomainParameters,
  ClpIECC,
  ClpIECDomainParameters,
  ClpIDsaParameters,
  ClpIDsaParameter,
  ClpDsaParameter,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Factory for creating public key parameters from SubjectPublicKeyInfo.
  /// </summary>
  TPublicKeyFactory = class sealed(TObject)

  public
    class function CreateKey(const AKeyInfoData: TCryptoLibByteArray): IAsymmetricKeyParameter; overload; static;
    class function CreateKey(const AInStr: TStream): IAsymmetricKeyParameter; overload; static;
    class function CreateKey(const AKeyInfo: ISubjectPublicKeyInfo): IAsymmetricKeyParameter; overload; static;

  end;

implementation

{ TPublicKeyFactory }

class function TPublicKeyFactory.CreateKey(const AKeyInfoData: TCryptoLibByteArray): IAsymmetricKeyParameter;
begin
  Result := CreateKey(TSubjectPublicKeyInfo.GetInstance(TAsn1Sequence.GetInstance(AKeyInfoData)));
end;

class function TPublicKeyFactory.CreateKey(const AInStr: TStream): IAsymmetricKeyParameter;
begin
  Result := CreateKey(TSubjectPublicKeyInfo.GetInstance(TAsn1Object.FromStream(AInStr)));
end;

class function TPublicKeyFactory.CreateKey(const AKeyInfo: ISubjectPublicKeyInfo): IAsymmetricKeyParameter;
var
  LAlgID: IAlgorithmIdentifier;
  LAlgOid: IDerObjectIdentifier;
  LPubKey: IRsaPublicKeyStructure;
  LDsaY: IDerInteger;
  LDsaParams: IDsaParameters;
  LDsaPara: IDsaParameter;
  LX962Params: IX962Parameters;
  LX9ECParams: IX9ECParameters;
  LECParams: IECDomainParameters;
  LQ: IECPoint;
  LPublicKeyBytes: TCryptoLibByteArray;
begin
  if AKeyInfo = nil then
  begin
    Result := nil;
    Exit;
  end;

  LAlgID := AKeyInfo.Algorithm;
  LAlgOid := LAlgID.Algorithm;

  // RSA keys
  if LAlgOid.Equals(TPkcsObjectIdentifiers.RsaEncryption) or
    LAlgOid.Equals(TX509ObjectIdentifiers.IdEARsa) or
    LAlgOid.Equals(TPkcsObjectIdentifiers.IdRsassaPss) or
    LAlgOid.Equals(TPkcsObjectIdentifiers.IdRsaesOaep) then
  begin
    LPubKey := TRsaPublicKeyStructure.GetInstance(AKeyInfo.ParsePublicKey());
    Result := TRsaKeyParameters.Create(False, LPubKey.Modulus, LPubKey.PublicExponent);
    Exit;
  end;

  // DSA keys
  if LAlgOid.Equals(TX9ObjectIdentifiers.IdDsa) or
    LAlgOid.Equals(TOiwObjectIdentifiers.DsaWithSha1) then
  begin
    LDsaY := TDerInteger.GetInstance(AKeyInfo.ParsePublicKey());
    if LAlgID.Parameters <> nil then
    begin
      LDsaPara := TDsaParameter.GetInstance(LAlgID.Parameters.ToAsn1Object() as TAsn1Object);
      LDsaParams := TDsaParameters.Create(LDsaPara.P, LDsaPara.Q, LDsaPara.G);
    end
    else
    begin
      LDsaParams := nil;
    end;
    Result := TDsaPublicKeyParameters.Create(LDsaY.Value, LDsaParams);
    Exit;
  end;

  // EC keys
  if LAlgOid.Equals(TX9ObjectIdentifiers.IdECPublicKey) then
  begin
    LX962Params := TX962Parameters.GetInstance(LAlgID.Parameters);
    LECParams := TECDomainParameters.FromX962Parameters(LX962Params);
    LPublicKeyBytes := AKeyInfo.PublicKey.GetBytes();
    LQ := LECParams.Curve.DecodePoint(LPublicKeyBytes);
    Result := TECPublicKeyParameters.Create('EC', LQ, LECParams);
    Exit;
  end;

  // TODO: Add support for other key types (DH, ElGamal, GOST, EdDSA, etc.)
  raise ENotSupportedCryptoLibException.CreateFmt('Key type with OID %s not yet supported', [LAlgOid.Id]);
end;

end.
