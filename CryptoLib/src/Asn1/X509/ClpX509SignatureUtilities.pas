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

unit ClpX509SignatureUtilities;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpIAsn1Core,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpPkcsObjectIdentifiers,
  ClpIPkcsAsn1Objects,
  ClpIPkcsRsaAsn1Objects,
  ClpPkcsAsn1Objects,
  ClpPkcsRsaAsn1Objects,
  ClpX9ObjectIdentifiers,
  ClpNistObjectIdentifiers,
  ClpTeleTrusTObjectIdentifiers,
  ClpOiwObjectIdentifiers,
  ClpCryptoProObjectIdentifiers,
  ClpRosstandartObjectIdentifiers,
  ClpBsiObjectIdentifiers,
  ClpEdECObjectIdentifiers,
  ClpX509ObjectIdentifiers,
  ClpSignerUtilities,
  ClpX509Utilities,
  ClpAsn1Comparers,
  ClpCryptoLibComparers,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Internal utilities for X509 signature operations.
  /// </summary>
  TX509SignatureUtilities = class sealed(TObject)

  strict private
    class var
      FAlgorithms: TDictionary<String, IDerObjectIdentifier>;
      FExParams: TDictionary<String, IAsn1Encodable>;
      FNoParams: TDictionary<IDerObjectIdentifier, IAlgorithmIdentifier>;

    class function GetDigestName(const ADigestAlgOid: IDerObjectIdentifier): String; static;
    class procedure AddAlgorithm(const AName: String; const AOid: IDerObjectIdentifier; AIsNoParams: Boolean); static;
    class procedure AddNoParams(const AOid: IDerObjectIdentifier); static;
    class function CreatePssParams(const ADigAlgID: IAlgorithmIdentifier; ASaltSize: Int32): IRsassaPssParameters; static;
    class procedure Boot; static;
    class constructor Create;
    class destructor Destroy;

  public
    class function GetSignatureName(const ASigAlgID: IAlgorithmIdentifier): String; static;
    class function GetSigOid(const ASigName: String): IDerObjectIdentifier; static;
    class function GetSigAlgID(const AAlgorithmName: String): IAlgorithmIdentifier; static;
    class function GetSigNames: TCryptoLibStringArray; static;

  end;

implementation

{ TX509SignatureUtilities }

class constructor TX509SignatureUtilities.Create;
begin
  Boot;
end;

class destructor TX509SignatureUtilities.Destroy;
begin
  FAlgorithms.Free;
  FExParams.Free;
  FNoParams.Free;
end;

class procedure TX509SignatureUtilities.Boot;
var
  LSha1AlgId, LSha224AlgId, LSha256AlgId, LSha384AlgId, LSha512AlgId: IAlgorithmIdentifier;
begin
  FAlgorithms := TDictionary<String, IDerObjectIdentifier>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FExParams := TDictionary<String, IAsn1Encodable>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FNoParams := TDictionary<IDerObjectIdentifier, IAlgorithmIdentifier>.Create(TAsn1Comparers.OidEqualityComparer);

  // MD2 algorithms
  FAlgorithms.Add('MD2WITHRSAENCRYPTION', TPkcsObjectIdentifiers.MD2WithRsaEncryption);
  FAlgorithms.Add('MD2WITHRSA', TPkcsObjectIdentifiers.MD2WithRsaEncryption);

  // MD5 algorithms
  FAlgorithms.Add('MD5WITHRSAENCRYPTION', TPkcsObjectIdentifiers.MD5WithRsaEncryption);
  FAlgorithms.Add('MD5WITHRSA', TPkcsObjectIdentifiers.MD5WithRsaEncryption);

  // SHA1 algorithms
  FAlgorithms.Add('SHA1WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha1WithRsaEncryption);
  FAlgorithms.Add('SHA-1WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha1WithRsaEncryption);
  FAlgorithms.Add('SHA1WITHRSA', TPkcsObjectIdentifiers.Sha1WithRsaEncryption);
  FAlgorithms.Add('SHA-1WITHRSA', TPkcsObjectIdentifiers.Sha1WithRsaEncryption);

  // SHA224 algorithms
  FAlgorithms.Add('SHA224WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha224WithRsaEncryption);
  FAlgorithms.Add('SHA-224WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha224WithRsaEncryption);
  FAlgorithms.Add('SHA224WITHRSA', TPkcsObjectIdentifiers.Sha224WithRsaEncryption);
  FAlgorithms.Add('SHA-224WITHRSA', TPkcsObjectIdentifiers.Sha224WithRsaEncryption);

  // SHA256 algorithms
  FAlgorithms.Add('SHA256WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha256WithRsaEncryption);
  FAlgorithms.Add('SHA-256WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha256WithRsaEncryption);
  FAlgorithms.Add('SHA256WITHRSA', TPkcsObjectIdentifiers.Sha256WithRsaEncryption);
  FAlgorithms.Add('SHA-256WITHRSA', TPkcsObjectIdentifiers.Sha256WithRsaEncryption);

  // SHA384 algorithms
  FAlgorithms.Add('SHA384WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha384WithRsaEncryption);
  FAlgorithms.Add('SHA-384WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha384WithRsaEncryption);
  FAlgorithms.Add('SHA384WITHRSA', TPkcsObjectIdentifiers.Sha384WithRsaEncryption);
  FAlgorithms.Add('SHA-384WITHRSA', TPkcsObjectIdentifiers.Sha384WithRsaEncryption);

  // SHA512 algorithms
  FAlgorithms.Add('SHA512WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha512WithRsaEncryption);
  FAlgorithms.Add('SHA-512WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha512WithRsaEncryption);
  FAlgorithms.Add('SHA512WITHRSA', TPkcsObjectIdentifiers.Sha512WithRsaEncryption);
  FAlgorithms.Add('SHA-512WITHRSA', TPkcsObjectIdentifiers.Sha512WithRsaEncryption);

  // SHA512(224) algorithms
  FAlgorithms.Add('SHA512(224)WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
  FAlgorithms.Add('SHA-512(224)WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
  FAlgorithms.Add('SHA512(224)WITHRSA', TPkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
  FAlgorithms.Add('SHA-512(224)WITHRSA', TPkcsObjectIdentifiers.Sha512_224WithRSAEncryption);

  // SHA512(256) algorithms
  FAlgorithms.Add('SHA512(256)WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha512_256WithRSAEncryption);
  FAlgorithms.Add('SHA-512(256)WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha512_256WithRSAEncryption);
  FAlgorithms.Add('SHA512(256)WITHRSA', TPkcsObjectIdentifiers.Sha512_256WithRSAEncryption);
  FAlgorithms.Add('SHA-512(256)WITHRSA', TPkcsObjectIdentifiers.Sha512_256WithRSAEncryption);

  // SHA3-224/256/384/512 with RSA algorithms
  FAlgorithms.Add('SHA3-224WITHRSAENCRYPTION', TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224);
  FAlgorithms.Add('SHA3-256WITHRSAENCRYPTION', TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256);
  FAlgorithms.Add('SHA3-384WITHRSAENCRYPTION', TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384);
  FAlgorithms.Add('SHA3-512WITHRSAENCRYPTION', TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512);
  FAlgorithms.Add('SHA3-224WITHRSA', TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224);
  FAlgorithms.Add('SHA3-256WITHRSA', TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256);
  FAlgorithms.Add('SHA3-384WITHRSA', TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384);
  FAlgorithms.Add('SHA3-512WITHRSA', TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512);

  // RSA-PSS algorithms
  FAlgorithms.Add('SHA1WITHRSAANDMGF1', TPkcsObjectIdentifiers.IdRsassaPss);
  FAlgorithms.Add('SHA224WITHRSAANDMGF1', TPkcsObjectIdentifiers.IdRsassaPss);
  FAlgorithms.Add('SHA256WITHRSAANDMGF1', TPkcsObjectIdentifiers.IdRsassaPss);
  FAlgorithms.Add('SHA384WITHRSAANDMGF1', TPkcsObjectIdentifiers.IdRsassaPss);
  FAlgorithms.Add('SHA512WITHRSAANDMGF1', TPkcsObjectIdentifiers.IdRsassaPss);

  // RIPEMD algorithms
  FAlgorithms.Add('RIPEMD160WITHRSAENCRYPTION', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160);
  FAlgorithms.Add('RIPEMD160WITHRSA', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160);
  FAlgorithms.Add('RIPEMD128WITHRSAENCRYPTION', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128);
  FAlgorithms.Add('RIPEMD128WITHRSA', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128);
  FAlgorithms.Add('RIPEMD256WITHRSAENCRYPTION', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256);
  FAlgorithms.Add('RIPEMD256WITHRSA', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256);

  // DSA algorithms
  FAlgorithms.Add('SHA1WITHDSA', TX9ObjectIdentifiers.IdDsaWithSha1);
  FAlgorithms.Add('DSAWITHSHA1', TX9ObjectIdentifiers.IdDsaWithSha1);
  FAlgorithms.Add('SHA224WITHDSA', TNistObjectIdentifiers.DsaWithSha224);
  FAlgorithms.Add('SHA256WITHDSA', TNistObjectIdentifiers.DsaWithSha256);
  FAlgorithms.Add('SHA384WITHDSA', TNistObjectIdentifiers.DsaWithSha384);
  FAlgorithms.Add('SHA512WITHDSA', TNistObjectIdentifiers.DsaWithSha512);

  // ECDSA algorithms
  FAlgorithms.Add('SHA1WITHECDSA', TX9ObjectIdentifiers.ECDsaWithSha1);
  FAlgorithms.Add('ECDSAWITHSHA1', TX9ObjectIdentifiers.ECDsaWithSha1);
  FAlgorithms.Add('SHA224WITHECDSA', TX9ObjectIdentifiers.ECDsaWithSha224);
  FAlgorithms.Add('SHA256WITHECDSA', TX9ObjectIdentifiers.ECDsaWithSha256);
  FAlgorithms.Add('SHA384WITHECDSA', TX9ObjectIdentifiers.ECDsaWithSha384);
  FAlgorithms.Add('SHA512WITHECDSA', TX9ObjectIdentifiers.ECDsaWithSha512);

  // BSI Plain ECDSA algorithms
  FAlgorithms.Add('SHA1withPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha1);
  FAlgorithms.Add('SHA224withPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha224);
  FAlgorithms.Add('SHA256withPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha256);
  FAlgorithms.Add('SHA384withPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha384);
  FAlgorithms.Add('SHA512withPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha512);
  FAlgorithms.Add('RIPEMD160withPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainRipeMD160);

  // GOST algorithms
  FAlgorithms.Add('GOST3411WITHGOST3410', TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
  FAlgorithms.Add('GOST3411WITHGOST3410-94', TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
  FAlgorithms.Add('GOST3411WITHECGOST3410', TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
  FAlgorithms.Add('GOST3411WITHECGOST3410-2001', TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
  FAlgorithms.Add('GOST3411WITHGOST3410-2001', TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
  FAlgorithms.Add('GOST3411-2012-256WITHECGOST3410', TRosstandartObjectIdentifiers.IdTc26SignWithDigestGost3410_12_256);
  FAlgorithms.Add('GOST3411-2012-256WITHECGOST3410-2012-256', TRosstandartObjectIdentifiers.IdTc26SignWithDigestGost3410_12_256);
  FAlgorithms.Add('GOST3411-2012-512WITHECGOST3410', TRosstandartObjectIdentifiers.IdTc26SignWithDigestGost3410_12_512);
  FAlgorithms.Add('GOST3411-2012-512WITHECGOST3410-2012-512', TRosstandartObjectIdentifiers.IdTc26SignWithDigestGost3410_12_512);

  // SHAKE algorithms
  FAlgorithms.Add('SHAKE128WITHRSAPSS', TX509ObjectIdentifiers.IdRsassaPssShake128);
  FAlgorithms.Add('SHAKE256WITHRSAPSS', TX509ObjectIdentifiers.IdRsassaPssShake256);
  FAlgorithms.Add('SHAKE128WITHRSASSA-PSS', TX509ObjectIdentifiers.IdRsassaPssShake128);
  FAlgorithms.Add('SHAKE256WITHRSASSA-PSS', TX509ObjectIdentifiers.IdRsassaPssShake256);
  FAlgorithms.Add('SHAKE128WITHECDSA', TX509ObjectIdentifiers.IdEcdsaWithShake128);
  FAlgorithms.Add('SHAKE256WITHECDSA', TX509ObjectIdentifiers.IdEcdsaWithShake256);

  //
  // According to RFC 3279, the ASN.1 encoding SHALL (id-dsa-with-sha1) or MUST (ecdsa-with-SHA*) omit the parameters field.
  // The parameters field SHALL be NULL for RSA based signature algorithms.
  //

  AddNoParams(TX9ObjectIdentifiers.IdDsaWithSha1);
  AddNoParams(TOiwObjectIdentifiers.DsaWithSha1);
  AddNoParams(TNistObjectIdentifiers.DsaWithSha224);
  AddNoParams(TNistObjectIdentifiers.DsaWithSha256);
  AddNoParams(TNistObjectIdentifiers.DsaWithSha384);
  AddNoParams(TNistObjectIdentifiers.DsaWithSha512);

  AddNoParams(TX9ObjectIdentifiers.ECDsaWithSha1);
  AddNoParams(TX9ObjectIdentifiers.ECDsaWithSha224);
  AddNoParams(TX9ObjectIdentifiers.ECDsaWithSha256);
  AddNoParams(TX9ObjectIdentifiers.ECDsaWithSha384);
  AddNoParams(TX9ObjectIdentifiers.ECDsaWithSha512);

  AddNoParams(TBsiObjectIdentifiers.EcdsaPlainSha224);
  AddNoParams(TBsiObjectIdentifiers.EcdsaPlainSha256);
  AddNoParams(TBsiObjectIdentifiers.EcdsaPlainSha384);
  AddNoParams(TBsiObjectIdentifiers.EcdsaPlainSha512);

  //
  // RFC 4491
  //
  AddNoParams(TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
  AddNoParams(TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
  AddNoParams(TRosstandartObjectIdentifiers.IdTc26SignWithDigestGost3410_12_256);
  AddNoParams(TRosstandartObjectIdentifiers.IdTc26SignWithDigestGost3410_12_512);

  AddNoParams(TX509ObjectIdentifiers.IdRsassaPssShake128);
  AddNoParams(TX509ObjectIdentifiers.IdRsassaPssShake256);
  AddNoParams(TX509ObjectIdentifiers.IdEcdsaWithShake128);
  AddNoParams(TX509ObjectIdentifiers.IdEcdsaWithShake256);

  //
  // explicit params
  //
  LSha1AlgId := TAlgorithmIdentifier.Create(TOiwObjectIdentifiers.IdSha1, TDerNull.Instance);
  FExParams.Add('SHA1WITHRSAANDMGF1', CreatePssParams(LSha1AlgId, 20));

  LSha224AlgId := TAlgorithmIdentifier.Create(TNistObjectIdentifiers.IdSha224, TDerNull.Instance);
  FExParams.Add('SHA224WITHRSAANDMGF1', CreatePssParams(LSha224AlgId, 28));

  LSha256AlgId := TAlgorithmIdentifier.Create(TNistObjectIdentifiers.IdSha256, TDerNull.Instance);
  FExParams.Add('SHA256WITHRSAANDMGF1', CreatePssParams(LSha256AlgId, 32));

  LSha384AlgId := TAlgorithmIdentifier.Create(TNistObjectIdentifiers.IdSha384, TDerNull.Instance);
  FExParams.Add('SHA384WITHRSAANDMGF1', CreatePssParams(LSha384AlgId, 48));

  LSha512AlgId := TAlgorithmIdentifier.Create(TNistObjectIdentifiers.IdSha512, TDerNull.Instance);
  FExParams.Add('SHA512WITHRSAANDMGF1', CreatePssParams(LSha512AlgId, 64));

  //
  // DSA with SHA3
  //
  AddAlgorithm('SHA3-224WITHDSA', TNistObjectIdentifiers.IdDsaWithSha3_224, True);
  AddAlgorithm('SHA3-256WITHDSA', TNistObjectIdentifiers.IdDsaWithSha3_256, True);
  AddAlgorithm('SHA3-384WITHDSA', TNistObjectIdentifiers.IdDsaWithSha3_384, True);
  AddAlgorithm('SHA3-512WITHDSA', TNistObjectIdentifiers.IdDsaWithSha3_512, True);

  //
  // ECDSA with SHA3
  //
  AddAlgorithm('SHA3-224WITHECDSA', TNistObjectIdentifiers.IdECDsaWithSha3_224, True);
  AddAlgorithm('SHA3-256WITHECDSA', TNistObjectIdentifiers.IdECDsaWithSha3_256, True);
  AddAlgorithm('SHA3-384WITHECDSA', TNistObjectIdentifiers.IdECDsaWithSha3_384, True);
  AddAlgorithm('SHA3-512WITHECDSA', TNistObjectIdentifiers.IdECDsaWithSha3_512, True);

  //
  // BSI Plain ECDSA with SHA3
  //
  AddAlgorithm('SHA3-224WITHPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha3_224, True);
  AddAlgorithm('SHA3-256WITHPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha3_256, True);
  AddAlgorithm('SHA3-384WITHPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha3_384, True);
  AddAlgorithm('SHA3-512WITHPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha3_512, True);

  //
  // EdDSA
  //
  AddAlgorithm('Ed25519', TEdECObjectIdentifiers.IdEd25519, True);
  AddAlgorithm('Ed448', TEdECObjectIdentifiers.IdEd448, True);
end;

class function TX509SignatureUtilities.GetDigestName(const ADigestAlgOid: IDerObjectIdentifier): String;
begin
  if TPkcsObjectIdentifiers.MD5.Equals(ADigestAlgOid) then
    Result := 'MD5'
  else if TOiwObjectIdentifiers.IdSha1.Equals(ADigestAlgOid) then
    Result := 'SHA1'
  else if TNistObjectIdentifiers.IdSha224.Equals(ADigestAlgOid) then
    Result := 'SHA224'
  else if TNistObjectIdentifiers.IdSha256.Equals(ADigestAlgOid) then
    Result := 'SHA256'
  else if TNistObjectIdentifiers.IdSha384.Equals(ADigestAlgOid) then
    Result := 'SHA384'
  else if TNistObjectIdentifiers.IdSha512.Equals(ADigestAlgOid) then
    Result := 'SHA512'
  else if TNistObjectIdentifiers.IdSha512_224.Equals(ADigestAlgOid) then
    Result := 'SHA512(224)'
  else if TNistObjectIdentifiers.IdSha512_256.Equals(ADigestAlgOid) then
    Result := 'SHA512(256)'
  else if TTeleTrusTObjectIdentifiers.RipeMD128.Equals(ADigestAlgOid) then
    Result := 'RIPEMD128'
  else if TTeleTrusTObjectIdentifiers.RipeMD160.Equals(ADigestAlgOid) then
    Result := 'RIPEMD160'
  else if TTeleTrusTObjectIdentifiers.RipeMD256.Equals(ADigestAlgOid) then
    Result := 'RIPEMD256'
  else if TCryptoProObjectIdentifiers.GostR3411.Equals(ADigestAlgOid) then
    Result := 'GOST3411'
  else if TRosstandartObjectIdentifiers.IdTc26Gost3411_12_256.Equals(ADigestAlgOid) then
    Result := 'GOST3411-2012-256'
  else if TRosstandartObjectIdentifiers.IdTc26Gost3411_12_512.Equals(ADigestAlgOid) then
    Result := 'GOST3411-2012-512'
  else
    Result := ADigestAlgOid.Id;
end;

class function TX509SignatureUtilities.GetSignatureName(const ASigAlgID: IAlgorithmIdentifier): String;
var
  LSigAlgOid: IDerObjectIdentifier;
  LSigAlgParams: IAsn1Encodable;
  LRsassaPssParams: IRsassaPssParameters;
  LECDsaParams: IAlgorithmIdentifier;
begin
  if ASigAlgID = nil then
  begin
    Result := '';
    Exit;
  end;

  LSigAlgOid := ASigAlgID.Algorithm;
  LSigAlgParams := ASigAlgID.Parameters;

  if not TX509Utilities.IsAbsentParameters(LSigAlgParams) then
  begin
    if TPkcsObjectIdentifiers.IdRsassaPss.Equals(LSigAlgOid) then
    begin
      LRsassaPssParams := TRsassaPssParameters.GetInstance(LSigAlgParams);
      Result := GetDigestName(LRsassaPssParams.HashAlgorithm.Algorithm) + 'withRSAandMGF1';
      Exit;
    end;
    if TX9ObjectIdentifiers.ECDsaWithSha2.Equals(LSigAlgOid) then
    begin
      LECDsaParams := TAlgorithmIdentifier.GetInstance(LSigAlgParams);
      Result := GetDigestName(LECDsaParams.Algorithm) + 'withECDSA';
      Exit;
    end;
  end;

  Result := TSignerUtilities.GetEncodingName(LSigAlgOid);
  if Result = '' then
    Result := LSigAlgOid.Id;
end;

class function TX509SignatureUtilities.GetSigOid(const ASigName: String): IDerObjectIdentifier;
var
  LUpperName: String;
begin
  if ASigName = '' then
  begin
    Result := nil;
    Exit;
  end;

  LUpperName := UpperCase(ASigName);
  if not FAlgorithms.TryGetValue(LUpperName, Result) then
  begin
    // Try to parse as OID string
    try
      Result := TDerObjectIdentifier.Create(ASigName);
    except
      Result := nil;
    end;
  end;
end;

class function TX509SignatureUtilities.GetSigAlgID(const AAlgorithmName: String): IAlgorithmIdentifier;
var
  LSigOid: IDerObjectIdentifier;
  LNoParamsAlgID: IAlgorithmIdentifier;
  LExplicitParams: IAsn1Encodable;
begin
  LSigOid := GetSigOid(AAlgorithmName);

  if LSigOid = nil then
  begin
    Result := nil;
    Exit;
  end;

  // Check for no-params algorithms
  if FNoParams.TryGetValue(LSigOid, LNoParamsAlgID) then
  begin
    Result := LNoParamsAlgID;
    Exit;
  end;

  // Check for explicit parameters
  if FExParams.TryGetValue(AAlgorithmName, LExplicitParams) then
  begin
    Result := TAlgorithmIdentifier.Create(LSigOid, LExplicitParams);
    Exit;
  end;

  // Default: OID with NULL parameters
  Result := TAlgorithmIdentifier.Create(LSigOid, TDerNull.Instance);
end;

class function TX509SignatureUtilities.GetSigNames: TCryptoLibStringArray;
var
  LList: TList<String>;
  LName: String;
begin
  LList := TList<String>.Create();
  try
    for LName in FAlgorithms.Keys do
    begin
      LList.Add(LName);
    end;
    Result := LList.ToArray();
  finally
    LList.Free;
  end;
end;

class procedure TX509SignatureUtilities.AddAlgorithm(const AName: String;
  const AOid: IDerObjectIdentifier; AIsNoParams: Boolean);
begin
  FAlgorithms.Add(AName, AOid);
  if AIsNoParams then
    AddNoParams(AOid);
end;

class procedure TX509SignatureUtilities.AddNoParams(const AOid: IDerObjectIdentifier);
begin
  FNoParams.Add(AOid, TAlgorithmIdentifier.Create(AOid) as IAlgorithmIdentifier);
end;

class function TX509SignatureUtilities.CreatePssParams(const ADigAlgID: IAlgorithmIdentifier;
  ASaltSize: Int32): IRsassaPssParameters;
var
  LHashAlgId: IAlgorithmIdentifier;
  LMgfAlgId: IAlgorithmIdentifier;
  LSaltLength: IDerInteger;
begin
  LHashAlgId := ADigAlgID;
  LMgfAlgId := TAlgorithmIdentifier.Create(TPkcsObjectIdentifiers.IdMgf1, LHashAlgId);
  LSaltLength := TDerInteger.Create(ASaltSize);
  Result := TRsassaPssParameters.Create(LHashAlgId, LMgfAlgId, LSaltLength, TRsassaPssParameters.DefaultTrailerField);
end;

end.
