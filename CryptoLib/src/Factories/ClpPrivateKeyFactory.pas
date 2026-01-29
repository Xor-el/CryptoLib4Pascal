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

unit ClpPrivateKeyFactory;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  ClpIAsn1Core,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIPkcsAsn1Objects,
  ClpIX9Asn1Objects,
  ClpIAsymmetricKeyParameter,
  ClpRsaPrivateCrtKeyParameters,
  ClpDsaPrivateKeyParameters,
  ClpECPrivateKeyParameters,
  ClpDsaParameters,
  ClpECDomainParameters,
  ClpPkcsObjectIdentifiers,
  ClpX509ObjectIdentifiers,
  ClpX9ObjectIdentifiers,
  ClpX9Asn1Objects,
  ClpIX9ECParameters,
  ClpPkcsAsn1Objects,
  ClpIECDomainParameters,
  ClpIDsaParameters,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpSecAsn1Objects,
  ClpISecAsn1Objects,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Factory for creating private key parameters from PrivateKeyInfo.
  /// </summary>
  TPrivateKeyFactory = class sealed(TObject)

  public
    class function CreateKey(const APrivateKeyInfoData: TCryptoLibByteArray): IAsymmetricKeyParameter; overload; static;
    class function CreateKey(const AInStr: TStream): IAsymmetricKeyParameter; overload; static;
    class function CreateKey(const AKeyInfo: IPrivateKeyInfo): IAsymmetricKeyParameter; overload; static;

  end;

implementation

{ TPrivateKeyFactory }

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

class function TPrivateKeyFactory.CreateKey(const AKeyInfo: IPrivateKeyInfo): IAsymmetricKeyParameter;
var
  LAlgID: IAlgorithmIdentifier;
  LAlgOid: IDerObjectIdentifier;
  LRsaKeyStructure: IRsaPrivateKeyStructure;
  LDsaX: IDerInteger;
  LDsaParams: IDsaParameters;
  LDsaPara: IDsaParameter;
  LX962Params: IX962Parameters;
  LX9ECParams: IX9ECParameters;
  LECParams: IECDomainParameters;
  LECPrivateKeyObj: IAsn1Object;
  LECPrivateKeySeq: IECPrivateKeyStructure;
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
      LDsaPara := TDsaParameter.GetInstance(LAlgID.Parameters.ToAsn1Object() as TAsn1Object);
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
    LECPrivateKeyObj := AKeyInfo.ParsePrivateKey();
    LECPrivateKeySeq := TECPrivateKeyStructure.GetInstance(LECPrivateKeyObj);
    LX962Params := TX962Parameters.GetInstance(LAlgID.Parameters);
    LECParams := TECDomainParameters.FromX962Parameters(LX962Params);
    Result := TECPrivateKeyParameters.Create('EC', LECPrivateKeySeq.GetKey(), LECParams);
    Exit;
  end;

  // TODO: Add support for other key types (DH, ElGamal, GOST, EdDSA, etc.)
  raise ENotSupportedCryptoLibException.CreateFmt('Key type with OID %s not yet supported', [LAlgOid.Id]);
end;

end.
