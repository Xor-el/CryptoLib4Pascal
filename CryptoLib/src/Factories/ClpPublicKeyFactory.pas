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
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpIAsymmetricKeyParameter,
  ClpRsaParameters,
  ClpDsaParameters,
  ClpECParameters,
  ClpDHParameters,
  ClpIDHParameters,
  ClpIPkcsDHAsn1Objects,
  ClpPkcsDHAsn1Objects,
  ClpIX9DHAsn1Objects,
  ClpX9DHAsn1Objects,
  ClpEd25519Parameters,
  ClpIEd25519Parameters,
  ClpX25519Parameters,
  ClpIX25519Parameters,
  ClpPkcsObjectIdentifiers,
  ClpX509ObjectIdentifiers,
  ClpX9ObjectIdentifiers,
  ClpOiwObjectIdentifiers,
  ClpEdECObjectIdentifiers,
  ClpGnuObjectIdentifiers,
  ClpCryptLibObjectIdentifiers,
  ClpIX9ECAsn1Objects,
  ClpX9ECAsn1Objects,
  ClpAsn1Objects,
  ClpIECCommon,
  ClpIDsaParameters,
  ClpIECParameters,
  ClpIX509Asn1Objects,
  ClpIX509RsaAsn1Objects,
  ClpIX509DsaAsn1Objects,
  ClpX509Asn1Objects,
  ClpX509RsaAsn1Objects,
  ClpX509DsaAsn1Objects,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Factory for creating public key parameters from SubjectPublicKeyInfo.
  /// </summary>
  TPublicKeyFactory = class sealed(TObject)

  strict private
    class function IsPkcsDHParam(const ASeq: IAsn1Sequence): Boolean; static;
    class function ReadPkcsDHParam(const AAlgOid: IDerObjectIdentifier;
      const AY: TBigInteger; const ASeq: IAsn1Sequence): IAsymmetricKeyParameter; static;

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

class function TPublicKeyFactory.IsPkcsDHParam(const ASeq: IAsn1Sequence): Boolean;
var
  LL, LP: IDerInteger;
begin
  if ASeq.Count = 2 then
  begin
    Result := True;
    Exit;
  end;

  if ASeq.Count > 3 then
  begin
    Result := False;
    Exit;
  end;

  LL := TDerInteger.GetInstance(ASeq[2]);
  LP := TDerInteger.GetInstance(ASeq[0]);
  Result := LL.Value.CompareTo(TBigInteger.ValueOf(LP.Value.BitLength)) <= 0;
end;

class function TPublicKeyFactory.ReadPkcsDHParam(const AAlgOid: IDerObjectIdentifier;
  const AY: TBigInteger; const ASeq: IAsn1Sequence): IAsymmetricKeyParameter;
var
  LDHPara: IDHParameter;
  LLVal: Int32;
  LDHParams: IDHParameters;
begin
  LDHPara := TDHParameter.GetInstance(ASeq);
  if LDHPara.L <> nil then
    LLVal := LDHPara.L.Value.Int32Value
  else
    LLVal := 0;
  LDHParams := TDHParameters.Create(LDHPara.P, LDHPara.G,
    TBigInteger.GetDefault, LLVal);
  Result := TDHPublicKeyParameters.Create(AY, LDHParams, AAlgOid);
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
  LECParams: IECDomainParameters;
  LQ: IECPoint;
  LPublicKeyBytes: TCryptoLibByteArray;
  LSeq: IAsn1Sequence;
  LDHPublicKey: IDHPublicKey;
  LY: TBigInteger;
  LDHDomainParams: IDHDomainParameters;
  LP, LG, LBigQ, LJ: TBigInteger;
  LValidation: IDHValidationParameters;
  LDHValParms: IDHValidationParms;
  LSeed: TCryptoLibByteArray;
  LPGenCounter: TBigInteger;
  LDerY: IDerInteger;
  LRawKey: TCryptoLibByteArray;
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

  // DH keys (X9.42 DHPublicNumber)
  if LAlgOid.Equals(TX9ObjectIdentifiers.DHPublicNumber) then
  begin
    LSeq := TAsn1Sequence.GetInstance(LAlgID.Parameters.ToAsn1Object());
    LDHPublicKey := TDHPublicKey.GetInstance(AKeyInfo.ParsePublicKey());
    LY := LDHPublicKey.Y.Value;

    if IsPkcsDHParam(LSeq) then
    begin
      Result := ReadPkcsDHParam(LAlgOid, LY, LSeq);
      Exit;
    end;

    LDHDomainParams := TDHDomainParameters.GetInstance(LSeq);
    LP := LDHDomainParams.P.Value;
    LG := LDHDomainParams.G.Value;
    LBigQ := LDHDomainParams.Q.Value;

    LJ := TBigInteger.GetDefault;
    if LDHDomainParams.J <> nil then
      LJ := LDHDomainParams.J.Value;

    LValidation := nil;
    LDHValParms := LDHDomainParams.ValidationParms;
    if LDHValParms <> nil then
    begin
      LSeed := LDHValParms.Seed.GetBytes();
      LPGenCounter := LDHValParms.PGenCounter.Value;
      LValidation := TDHValidationParameters.Create(LSeed, LPGenCounter.Int32Value);
    end;

    Result := TDHPublicKeyParameters.Create(LY,
      TDHParameters.Create(LP, LG, LBigQ, LJ, LValidation));
    Exit;
  end;

  // DH keys (PKCS DhKeyAgreement)
  if LAlgOid.Equals(TPkcsObjectIdentifiers.DhKeyAgreement) then
  begin
    LSeq := TAsn1Sequence.GetInstance(LAlgID.Parameters.ToAsn1Object());
    LDerY := TDerInteger.GetInstance(AKeyInfo.ParsePublicKey());
    Result := ReadPkcsDHParam(LAlgOid, LDerY.Value, LSeq);
    Exit;
  end;

  // DSA keys
  if LAlgOid.Equals(TX9ObjectIdentifiers.IdDsa) or
    LAlgOid.Equals(TOiwObjectIdentifiers.DsaWithSha1) then
  begin
    LDsaY := TDerInteger.GetInstance(AKeyInfo.ParsePublicKey());
    if LAlgID.Parameters <> nil then
    begin
      LDsaPara := TDsaParameter.GetInstance(LAlgID.Parameters);
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

  // X25519 keys
  if LAlgOid.Equals(TEdECObjectIdentifiers.IdX25519) or
    LAlgOid.Equals(TCryptLibObjectIdentifiers.Curvey25519) then
  begin
    LRawKey := AKeyInfo.PublicKey.GetOctets();
    Result := TX25519PublicKeyParameters.Create(LRawKey);
    Exit;
  end;

  // Ed25519 keys
  if LAlgOid.Equals(TEdECObjectIdentifiers.IdEd25519) or
    LAlgOid.Equals(TGnuObjectIdentifiers.Ed25519) then
  begin
    LRawKey := AKeyInfo.PublicKey.GetOctets();
    Result := TEd25519PublicKeyParameters.Create(LRawKey);
    Exit;
  end;

  // TODO: Add support for other key types when implemented.
  raise ENotSupportedCryptoLibException.CreateFmt('Key type with OID %s not yet supported', [LAlgOid.Id]);
end;

end.
