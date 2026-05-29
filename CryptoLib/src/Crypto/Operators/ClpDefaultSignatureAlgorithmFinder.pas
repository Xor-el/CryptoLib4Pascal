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

unit ClpDefaultSignatureAlgorithmFinder;

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
  ClpIPkcsRsaAsn1Objects,
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
  ClpEacObjectIdentifiers,
  ClpMiscObjectIdentifiers,
  ClpAsn1Comparers,
  ClpCryptoLibComparers,
  ClpISignatureAlgorithmFinder,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Default implementation of ISignatureAlgorithmFinder that maps signature names
  /// to algorithm identifiers.
  /// </summary>
  TDefaultSignatureAlgorithmFinder = class sealed(TInterfacedObject, ISignatureAlgorithmFinder)
  strict private
    class var
      FInstance: ISignatureAlgorithmFinder;
      FAlgorithms: TDictionary<String, IDerObjectIdentifier>;
      FNoParams: TDictionary<IDerObjectIdentifier, IAlgorithmIdentifier>;
      FParameters: TDictionary<String, IAsn1Encodable>;
      FPkcs15RsaEncryption: TDictionary<IDerObjectIdentifier, Byte>;
      FDigestOids: TDictionary<IDerObjectIdentifier, IDerObjectIdentifier>;
    class procedure AddAlgorithm(const AName: String; const AOid: IDerObjectIdentifier); overload; static;
    class procedure AddAlgorithm(const AName: String; const AOid: IDerObjectIdentifier;
      AIsNoParams: Boolean); overload; static;
    class procedure AddAlgorithm(const AName: String; const AOid: IDerObjectIdentifier;
      const ADigestOid: IDerObjectIdentifier; AIsNoParams: Boolean); overload; static;
    class procedure AddDigestOid(const ASignatureOid, ADigestOid: IDerObjectIdentifier); static;
    class procedure AddPkcs15RsaEncryption(const AOid: IDerObjectIdentifier); static;
    class procedure AddNoParams(const AOid: IDerObjectIdentifier); static;
    class procedure AddParameters(const AAlgorithmName: String;
      const AParameters: IAsn1Encodable); static;
    class function CreatePssParams(const ADigAlgID: IAlgorithmIdentifier;
      ASaltSize: Int32): IRsassaPssParameters; static;
    class procedure Boot; static;
    class constructor Create;
    class destructor Destroy;
  public
    class property Instance: ISignatureAlgorithmFinder read FInstance;
    function Find(const ASignatureName: String): IAlgorithmIdentifier;
  end;

implementation

{ TDefaultSignatureAlgorithmFinder }

class constructor TDefaultSignatureAlgorithmFinder.Create;
begin
  Boot;
end;

class destructor TDefaultSignatureAlgorithmFinder.Destroy;
begin
  FInstance := nil;
  FAlgorithms.Free;
  FNoParams.Free;
  FParameters.Free;
  FPkcs15RsaEncryption.Free;
  FDigestOids.Free;
end;

class procedure TDefaultSignatureAlgorithmFinder.AddAlgorithm(const AName: String;
  const AOid: IDerObjectIdentifier);
begin
  FAlgorithms.Add(AName, AOid);
end;

class procedure TDefaultSignatureAlgorithmFinder.AddAlgorithm(const AName: String;
  const AOid: IDerObjectIdentifier; AIsNoParams: Boolean);
begin
  AddAlgorithm(AName, AOid, nil, AIsNoParams);
end;

class procedure TDefaultSignatureAlgorithmFinder.AddAlgorithm(const AName: String;
  const AOid: IDerObjectIdentifier; const ADigestOid: IDerObjectIdentifier; AIsNoParams: Boolean);
begin
  if AName = '' then
    raise EArgumentNilCryptoLibException.Create('name');
  if AOid = nil then
    raise EArgumentNilCryptoLibException.Create('oid');

  AddAlgorithm(AName, AOid);

  if ADigestOid <> nil then
    AddDigestOid(AOid, ADigestOid);
  if AIsNoParams then
    AddNoParams(AOid);
end;

class procedure TDefaultSignatureAlgorithmFinder.AddDigestOid(const ASignatureOid,
  ADigestOid: IDerObjectIdentifier);
begin
  FDigestOids.Add(ASignatureOid, ADigestOid);
end;

class procedure TDefaultSignatureAlgorithmFinder.AddPkcs15RsaEncryption(
  const AOid: IDerObjectIdentifier);
begin
  if not FPkcs15RsaEncryption.ContainsKey(AOid) then
    FPkcs15RsaEncryption.Add(AOid, 0);
end;

class procedure TDefaultSignatureAlgorithmFinder.AddNoParams(const AOid: IDerObjectIdentifier);
begin
  if not FNoParams.ContainsKey(AOid) then
    FNoParams.Add(AOid, TAlgorithmIdentifier.Create(AOid) as IAlgorithmIdentifier);
end;

class procedure TDefaultSignatureAlgorithmFinder.AddParameters(const AAlgorithmName: String;
  const AParameters: IAsn1Encodable);
begin
  if AParameters = nil then
    raise EArgumentCryptoLibException.Create('use ''NoParams'' instead for absent parameters');
  FParameters.Add(AAlgorithmName, AParameters);
end;

class function TDefaultSignatureAlgorithmFinder.CreatePssParams(
  const ADigAlgID: IAlgorithmIdentifier; ASaltSize: Int32): IRsassaPssParameters;
var
  LHashAlgId: IAlgorithmIdentifier;
  LMgfAlgId: IAlgorithmIdentifier;
  LSaltLength: IDerInteger;
begin
  LHashAlgId := ADigAlgID;
  LMgfAlgId := TAlgorithmIdentifier.Create(TPkcsObjectIdentifiers.IdMgf1, LHashAlgId);
  LSaltLength := TDerInteger.Create(ASaltSize);
  Result := TRsassaPssParameters.Create(LHashAlgId, LMgfAlgId, LSaltLength,
    TRsassaPssParameters.DefaultTrailerField);
end;

class procedure TDefaultSignatureAlgorithmFinder.Boot;
var
  LSha1AlgId, LSha224AlgId, LSha256AlgId, LSha384AlgId, LSha512AlgId: IAlgorithmIdentifier;
  LSha3_224AlgId, LSha3_256AlgId, LSha3_384AlgId, LSha3_512AlgId: IAlgorithmIdentifier;
begin
  FAlgorithms := TDictionary<String, IDerObjectIdentifier>.Create(
    TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FNoParams := TDictionary<IDerObjectIdentifier, IAlgorithmIdentifier>.Create(
    TAsn1Comparers.OidEqualityComparer);
  FParameters := TDictionary<String, IAsn1Encodable>.Create(
    TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FPkcs15RsaEncryption := TDictionary<IDerObjectIdentifier, Byte>.Create(
    TAsn1Comparers.OidEqualityComparer);
  FDigestOids := TDictionary<IDerObjectIdentifier, IDerObjectIdentifier>.Create(
    TAsn1Comparers.OidEqualityComparer);

  AddAlgorithm('MD2WITHRSAENCRYPTION', TPkcsObjectIdentifiers.MD2WithRsaEncryption);
  AddAlgorithm('MD2WITHRSA', TPkcsObjectIdentifiers.MD2WithRsaEncryption);
  AddAlgorithm('MD5WITHRSAENCRYPTION', TPkcsObjectIdentifiers.MD5WithRsaEncryption);
  AddAlgorithm('MD5WITHRSA', TPkcsObjectIdentifiers.MD5WithRsaEncryption);
  AddAlgorithm('SHA1WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha1WithRsaEncryption);
  AddAlgorithm('SHA-1WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha1WithRsaEncryption);
  AddAlgorithm('SHA1WITHRSA', TPkcsObjectIdentifiers.Sha1WithRsaEncryption);
  AddAlgorithm('SHA-1WITHRSA', TPkcsObjectIdentifiers.Sha1WithRsaEncryption);
  AddAlgorithm('SHA224WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha224WithRsaEncryption);
  AddAlgorithm('SHA-224WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha224WithRsaEncryption);
  AddAlgorithm('SHA224WITHRSA', TPkcsObjectIdentifiers.Sha224WithRsaEncryption);
  AddAlgorithm('SHA-224WITHRSA', TPkcsObjectIdentifiers.Sha224WithRsaEncryption);
  AddAlgorithm('SHA256WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha256WithRsaEncryption);
  AddAlgorithm('SHA-256WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha256WithRsaEncryption);
  AddAlgorithm('SHA256WITHRSA', TPkcsObjectIdentifiers.Sha256WithRsaEncryption);
  AddAlgorithm('SHA-256WITHRSA', TPkcsObjectIdentifiers.Sha256WithRsaEncryption);
  AddAlgorithm('SHA384WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha384WithRsaEncryption);
  AddAlgorithm('SHA-384WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha384WithRsaEncryption);
  AddAlgorithm('SHA384WITHRSA', TPkcsObjectIdentifiers.Sha384WithRsaEncryption);
  AddAlgorithm('SHA-384WITHRSA', TPkcsObjectIdentifiers.Sha384WithRsaEncryption);
  AddAlgorithm('SHA512WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha512WithRsaEncryption);
  AddAlgorithm('SHA-512WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha512WithRsaEncryption);
  AddAlgorithm('SHA512WITHRSA', TPkcsObjectIdentifiers.Sha512WithRsaEncryption);
  AddAlgorithm('SHA-512WITHRSA', TPkcsObjectIdentifiers.Sha512WithRsaEncryption);
  AddAlgorithm('SHA512(224)WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
  AddAlgorithm('SHA-512(224)WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
  AddAlgorithm('SHA512(224)WITHRSA', TPkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
  AddAlgorithm('SHA-512(224)WITHRSA', TPkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
  AddAlgorithm('SHA512(256)WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha512_256WithRSAEncryption);
  AddAlgorithm('SHA-512(256)WITHRSAENCRYPTION', TPkcsObjectIdentifiers.Sha512_256WithRSAEncryption);
  AddAlgorithm('SHA512(256)WITHRSA', TPkcsObjectIdentifiers.Sha512_256WithRSAEncryption);
  AddAlgorithm('SHA-512(256)WITHRSA', TPkcsObjectIdentifiers.Sha512_256WithRSAEncryption);
  AddAlgorithm('SHA1WITHRSAANDMGF1', TPkcsObjectIdentifiers.IdRsassaPss);
  AddAlgorithm('SHA224WITHRSAANDMGF1', TPkcsObjectIdentifiers.IdRsassaPss);
  AddAlgorithm('SHA256WITHRSAANDMGF1', TPkcsObjectIdentifiers.IdRsassaPss);
  AddAlgorithm('SHA384WITHRSAANDMGF1', TPkcsObjectIdentifiers.IdRsassaPss);
  AddAlgorithm('SHA512WITHRSAANDMGF1', TPkcsObjectIdentifiers.IdRsassaPss);
  AddAlgorithm('SHA3-224WITHRSAANDMGF1', TPkcsObjectIdentifiers.IdRsassaPss);
  AddAlgorithm('SHA3-256WITHRSAANDMGF1', TPkcsObjectIdentifiers.IdRsassaPss);
  AddAlgorithm('SHA3-384WITHRSAANDMGF1', TPkcsObjectIdentifiers.IdRsassaPss);
  AddAlgorithm('SHA3-512WITHRSAANDMGF1', TPkcsObjectIdentifiers.IdRsassaPss);
  AddAlgorithm('RIPEMD160WITHRSAENCRYPTION', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160);
  AddAlgorithm('RIPEMD160WITHRSA', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160);
  AddAlgorithm('RIPEMD128WITHRSAENCRYPTION', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128);
  AddAlgorithm('RIPEMD128WITHRSA', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128);
  AddAlgorithm('RIPEMD256WITHRSAENCRYPTION', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256);
  AddAlgorithm('RIPEMD256WITHRSA', TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256);

  AddAlgorithm('SHA1WITHDSA', TX9ObjectIdentifiers.IdDsaWithSha1);
  AddAlgorithm('SHA-1WITHDSA', TX9ObjectIdentifiers.IdDsaWithSha1);
  AddAlgorithm('DSAWITHSHA1', TX9ObjectIdentifiers.IdDsaWithSha1);
  AddAlgorithm('SHA224WITHDSA', TNistObjectIdentifiers.DsaWithSha224);
  AddAlgorithm('SHA256WITHDSA', TNistObjectIdentifiers.DsaWithSha256);
  AddAlgorithm('SHA384WITHDSA', TNistObjectIdentifiers.DsaWithSha384);
  AddAlgorithm('SHA512WITHDSA', TNistObjectIdentifiers.DsaWithSha512);

  AddAlgorithm('SHA3-224WITHDSA', TNistObjectIdentifiers.IdDsaWithSha3_224);
  AddAlgorithm('SHA3-256WITHDSA', TNistObjectIdentifiers.IdDsaWithSha3_256);
  AddAlgorithm('SHA3-384WITHDSA', TNistObjectIdentifiers.IdDsaWithSha3_384);
  AddAlgorithm('SHA3-512WITHDSA', TNistObjectIdentifiers.IdDsaWithSha3_512);

  AddAlgorithm('SHA1WITHECDSA', TX9ObjectIdentifiers.ECDsaWithSha1);
  AddAlgorithm('ECDSAWITHSHA1', TX9ObjectIdentifiers.ECDsaWithSha1);
  AddAlgorithm('SHA224WITHECDSA', TX9ObjectIdentifiers.ECDsaWithSha224);
  AddAlgorithm('SHA256WITHECDSA', TX9ObjectIdentifiers.ECDsaWithSha256);
  AddAlgorithm('SHA384WITHECDSA', TX9ObjectIdentifiers.ECDsaWithSha384);
  AddAlgorithm('SHA512WITHECDSA', TX9ObjectIdentifiers.ECDsaWithSha512);

  AddAlgorithm('SHA3-224WITHECDSA', TNistObjectIdentifiers.IdECDsaWithSha3_224);
  AddAlgorithm('SHA3-256WITHECDSA', TNistObjectIdentifiers.IdECDsaWithSha3_256);
  AddAlgorithm('SHA3-384WITHECDSA', TNistObjectIdentifiers.IdECDsaWithSha3_384);
  AddAlgorithm('SHA3-512WITHECDSA', TNistObjectIdentifiers.IdECDsaWithSha3_512);

  AddAlgorithm('SHA3-224WITHRSA', TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224);
  AddAlgorithm('SHA3-256WITHRSA', TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256);
  AddAlgorithm('SHA3-384WITHRSA', TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384);
  AddAlgorithm('SHA3-512WITHRSA', TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512);
  AddAlgorithm('SHA3-224WITHRSAENCRYPTION', TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224);
  AddAlgorithm('SHA3-256WITHRSAENCRYPTION', TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256);
  AddAlgorithm('SHA3-384WITHRSAENCRYPTION', TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384);
  AddAlgorithm('SHA3-512WITHRSAENCRYPTION', TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512);

  AddAlgorithm('GOST3411WITHGOST3410', TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
  AddAlgorithm('GOST3411WITHGOST3410-94', TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
  AddAlgorithm('GOST3411WITHECGOST3410', TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
  AddAlgorithm('GOST3411WITHECGOST3410-2001', TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
  AddAlgorithm('GOST3411WITHGOST3410-2001', TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
  AddAlgorithm('GOST3411WITHECGOST3410-2012-256',
    TRosstandartObjectIdentifiers.IdTc26SignwithdigestGost3410_12_256);
  AddAlgorithm('GOST3411WITHECGOST3410-2012-512',
    TRosstandartObjectIdentifiers.IdTc26SignwithdigestGost3410_12_512);
  AddAlgorithm('GOST3411WITHGOST3410-2012-256',
    TRosstandartObjectIdentifiers.IdTc26SignwithdigestGost3410_12_256);
  AddAlgorithm('GOST3411WITHGOST3410-2012-512',
    TRosstandartObjectIdentifiers.IdTc26SignwithdigestGost3410_12_512);
  AddAlgorithm('GOST3411-2012-256WITHECGOST3410-2012-256',
    TRosstandartObjectIdentifiers.IdTc26SignwithdigestGost3410_12_256);
  AddAlgorithm('GOST3411-2012-512WITHECGOST3410-2012-512',
    TRosstandartObjectIdentifiers.IdTc26SignwithdigestGost3410_12_512);
  AddAlgorithm('GOST3411-2012-256WITHGOST3410-2012-256',
    TRosstandartObjectIdentifiers.IdTc26SignwithdigestGost3410_12_256);
  AddAlgorithm('GOST3411-2012-512WITHGOST3410-2012-512',
    TRosstandartObjectIdentifiers.IdTc26SignwithdigestGost3410_12_512);
  AddAlgorithm('GOST3411-2012-256WITHECGOST3410',
    TRosstandartObjectIdentifiers.IdTc26SignwithdigestGost3410_12_256);
  AddAlgorithm('GOST3411-2012-512WITHECGOST3410',
    TRosstandartObjectIdentifiers.IdTc26SignwithdigestGost3410_12_512);

  AddAlgorithm('SHA1WITHCVC-ECDSA', TEacObjectIdentifiers.IdTAEcdsaSha1);
  AddAlgorithm('SHA224WITHCVC-ECDSA', TEacObjectIdentifiers.IdTAEcdsaSha224);
  AddAlgorithm('SHA256WITHCVC-ECDSA', TEacObjectIdentifiers.IdTAEcdsaSha256);
  AddAlgorithm('SHA384WITHCVC-ECDSA', TEacObjectIdentifiers.IdTAEcdsaSha384);
  AddAlgorithm('SHA512WITHCVC-ECDSA', TEacObjectIdentifiers.IdTAEcdsaSha512);

  AddAlgorithm('SHA1WITHPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha1);
  AddAlgorithm('SHA224WITHPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha224);
  AddAlgorithm('SHA256WITHPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha256);
  AddAlgorithm('SHA384WITHPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha384);
  AddAlgorithm('SHA512WITHPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha512);
  AddAlgorithm('RIPEMD160WITHPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainRipeMD160);

  AddAlgorithm('SHA3-224WITHPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha3_224);
  AddAlgorithm('SHA3-256WITHPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha3_256);
  AddAlgorithm('SHA3-384WITHPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha3_384);
  AddAlgorithm('SHA3-512WITHPLAIN-ECDSA', TBsiObjectIdentifiers.EcdsaPlainSha3_512);

  AddAlgorithm('SHAKE128WITHRSAPSS', TX509ObjectIdentifiers.IdRsassaPssShake128);
  AddAlgorithm('SHAKE256WITHRSAPSS', TX509ObjectIdentifiers.IdRsassaPssShake256);
  AddAlgorithm('SHAKE128WITHRSASSA-PSS', TX509ObjectIdentifiers.IdRsassaPssShake128);
  AddAlgorithm('SHAKE256WITHRSASSA-PSS', TX509ObjectIdentifiers.IdRsassaPssShake256);
  AddAlgorithm('SHAKE128WITHECDSA', TX509ObjectIdentifiers.IdEcdsaWithShake128);
  AddAlgorithm('SHAKE256WITHECDSA', TX509ObjectIdentifiers.IdEcdsaWithShake256);

  //
  // According to RFC 3279, the ASN.1 encoding SHALL (id-dsa-with-sha1) or MUST (ecdsa-with-SHA*) omit the parameters field.
  // The parameters field SHALL be NULL for RSA based signature algorithms.
  //

  AddNoParams(TX9ObjectIdentifiers.IdDsaWithSha1);
  AddNoParams(TNistObjectIdentifiers.DsaWithSha224);
  AddNoParams(TNistObjectIdentifiers.DsaWithSha256);
  AddNoParams(TNistObjectIdentifiers.DsaWithSha384);
  AddNoParams(TNistObjectIdentifiers.DsaWithSha512);

  AddNoParams(TNistObjectIdentifiers.IdDsaWithSha3_224);
  AddNoParams(TNistObjectIdentifiers.IdDsaWithSha3_256);
  AddNoParams(TNistObjectIdentifiers.IdDsaWithSha3_384);
  AddNoParams(TNistObjectIdentifiers.IdDsaWithSha3_512);

  AddNoParams(TX9ObjectIdentifiers.ECDsaWithSha1);
  AddNoParams(TOiwObjectIdentifiers.DsaWithSha1);
  AddNoParams(TX9ObjectIdentifiers.ECDsaWithSha224);
  AddNoParams(TX9ObjectIdentifiers.ECDsaWithSha256);
  AddNoParams(TX9ObjectIdentifiers.ECDsaWithSha384);
  AddNoParams(TX9ObjectIdentifiers.ECDsaWithSha512);

  AddNoParams(TNistObjectIdentifiers.IdECDsaWithSha3_224);
  AddNoParams(TNistObjectIdentifiers.IdECDsaWithSha3_256);
  AddNoParams(TNistObjectIdentifiers.IdECDsaWithSha3_384);
  AddNoParams(TNistObjectIdentifiers.IdECDsaWithSha3_512);

  AddNoParams(TBsiObjectIdentifiers.EcdsaPlainSha1);
  AddNoParams(TBsiObjectIdentifiers.EcdsaPlainSha224);
  AddNoParams(TBsiObjectIdentifiers.EcdsaPlainSha256);
  AddNoParams(TBsiObjectIdentifiers.EcdsaPlainSha384);
  AddNoParams(TBsiObjectIdentifiers.EcdsaPlainSha512);

  AddNoParams(TBsiObjectIdentifiers.EcdsaPlainSha3_224);
  AddNoParams(TBsiObjectIdentifiers.EcdsaPlainSha3_256);
  AddNoParams(TBsiObjectIdentifiers.EcdsaPlainSha3_384);
  AddNoParams(TBsiObjectIdentifiers.EcdsaPlainSha3_512);

  //
  // RFC 4491
  //
  AddNoParams(TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
  AddNoParams(TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
  AddNoParams(TRosstandartObjectIdentifiers.IdTc26SignwithdigestGost3410_12_256);
  AddNoParams(TRosstandartObjectIdentifiers.IdTc26SignwithdigestGost3410_12_512);

  AddNoParams(TX509ObjectIdentifiers.IdRsassaPssShake128);
  AddNoParams(TX509ObjectIdentifiers.IdRsassaPssShake256);
  AddNoParams(TX509ObjectIdentifiers.IdEcdsaWithShake128);
  AddNoParams(TX509ObjectIdentifiers.IdEcdsaWithShake256);

  //
  // PKCS 1.5 encrypted algorithms
  //
  AddPkcs15RsaEncryption(TPkcsObjectIdentifiers.Sha1WithRsaEncryption);
  AddPkcs15RsaEncryption(TPkcsObjectIdentifiers.Sha224WithRsaEncryption);
  AddPkcs15RsaEncryption(TPkcsObjectIdentifiers.Sha256WithRsaEncryption);
  AddPkcs15RsaEncryption(TPkcsObjectIdentifiers.Sha384WithRsaEncryption);
  AddPkcs15RsaEncryption(TPkcsObjectIdentifiers.Sha512WithRsaEncryption);
  AddPkcs15RsaEncryption(TPkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
  AddPkcs15RsaEncryption(TPkcsObjectIdentifiers.Sha512_256WithRSAEncryption);
  AddPkcs15RsaEncryption(TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128);
  AddPkcs15RsaEncryption(TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160);
  AddPkcs15RsaEncryption(TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256);
  AddPkcs15RsaEncryption(TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224);
  AddPkcs15RsaEncryption(TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256);
  AddPkcs15RsaEncryption(TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384);
  AddPkcs15RsaEncryption(TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512);

  //
  // explicit params
  //
  LSha1AlgId := TAlgorithmIdentifier.Create(TOiwObjectIdentifiers.IdSha1, TDerNull.Instance);
  AddParameters('SHA1WITHRSAANDMGF1', CreatePssParams(LSha1AlgId, 20));

  LSha224AlgId := TAlgorithmIdentifier.Create(TNistObjectIdentifiers.IdSha224, TDerNull.Instance);
  AddParameters('SHA224WITHRSAANDMGF1', CreatePssParams(LSha224AlgId, 28));

  LSha256AlgId := TAlgorithmIdentifier.Create(TNistObjectIdentifiers.IdSha256, TDerNull.Instance);
  AddParameters('SHA256WITHRSAANDMGF1', CreatePssParams(LSha256AlgId, 32));

  LSha384AlgId := TAlgorithmIdentifier.Create(TNistObjectIdentifiers.IdSha384, TDerNull.Instance);
  AddParameters('SHA384WITHRSAANDMGF1', CreatePssParams(LSha384AlgId, 48));

  LSha512AlgId := TAlgorithmIdentifier.Create(TNistObjectIdentifiers.IdSha512, TDerNull.Instance);
  AddParameters('SHA512WITHRSAANDMGF1', CreatePssParams(LSha512AlgId, 64));

  LSha3_224AlgId := TAlgorithmIdentifier.Create(TNistObjectIdentifiers.IdSha3_224, TDerNull.Instance);
  AddParameters('SHA3-224WITHRSAANDMGF1', CreatePssParams(LSha3_224AlgId, 28));

  LSha3_256AlgId := TAlgorithmIdentifier.Create(TNistObjectIdentifiers.IdSha3_256, TDerNull.Instance);
  AddParameters('SHA3-256WITHRSAANDMGF1', CreatePssParams(LSha3_256AlgId, 32));

  LSha3_384AlgId := TAlgorithmIdentifier.Create(TNistObjectIdentifiers.IdSha3_384, TDerNull.Instance);
  AddParameters('SHA3-384WITHRSAANDMGF1', CreatePssParams(LSha3_384AlgId, 48));

  LSha3_512AlgId := TAlgorithmIdentifier.Create(TNistObjectIdentifiers.IdSha3_512, TDerNull.Instance);
  AddParameters('SHA3-512WITHRSAANDMGF1', CreatePssParams(LSha3_512AlgId, 64));

  //
  // digests
  //
  AddDigestOid(TPkcsObjectIdentifiers.Sha224WithRsaEncryption, TNistObjectIdentifiers.IdSha224);
  AddDigestOid(TPkcsObjectIdentifiers.Sha256WithRsaEncryption, TNistObjectIdentifiers.IdSha256);
  AddDigestOid(TPkcsObjectIdentifiers.Sha384WithRsaEncryption, TNistObjectIdentifiers.IdSha384);
  AddDigestOid(TPkcsObjectIdentifiers.Sha512WithRsaEncryption, TNistObjectIdentifiers.IdSha512);
  AddDigestOid(TPkcsObjectIdentifiers.Sha512_224WithRSAEncryption, TNistObjectIdentifiers.IdSha512_224);
  AddDigestOid(TPkcsObjectIdentifiers.Sha512_256WithRSAEncryption, TNistObjectIdentifiers.IdSha512_256);
  AddDigestOid(TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224, TNistObjectIdentifiers.IdSha3_224);
  AddDigestOid(TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256, TNistObjectIdentifiers.IdSha3_256);
  AddDigestOid(TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384, TNistObjectIdentifiers.IdSha3_384);
  AddDigestOid(TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512, TNistObjectIdentifiers.IdSha3_512);

  AddDigestOid(TPkcsObjectIdentifiers.MD2WithRsaEncryption, TPkcsObjectIdentifiers.MD2);
  AddDigestOid(TPkcsObjectIdentifiers.MD4WithRsaEncryption, TPkcsObjectIdentifiers.MD4);
  AddDigestOid(TPkcsObjectIdentifiers.MD5WithRsaEncryption, TPkcsObjectIdentifiers.MD5);
  AddDigestOid(TPkcsObjectIdentifiers.Sha1WithRsaEncryption, TOiwObjectIdentifiers.IdSha1);
  AddDigestOid(TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128,
    TTeleTrusTObjectIdentifiers.RipeMD128);
  AddDigestOid(TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160,
    TTeleTrusTObjectIdentifiers.RipeMD160);
  AddDigestOid(TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256,
    TTeleTrusTObjectIdentifiers.RipeMD256);
  AddDigestOid(TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94,
    TCryptoProObjectIdentifiers.GostR3411);
  AddDigestOid(TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001,
    TCryptoProObjectIdentifiers.GostR3411);
  AddDigestOid(TRosstandartObjectIdentifiers.IdTc26SignwithdigestGost3410_12_256,
    TRosstandartObjectIdentifiers.IdTc26Gost3411_12_256);
  AddDigestOid(TRosstandartObjectIdentifiers.IdTc26SignwithdigestGost3410_12_512,
    TRosstandartObjectIdentifiers.IdTc26Gost3411_12_512);

  AddDigestOid(TX9ObjectIdentifiers.IdDsaWithSha1, TOiwObjectIdentifiers.IdSha1);
  AddDigestOid(TOiwObjectIdentifiers.DsaWithSha1, TOiwObjectIdentifiers.IdSha1);
  AddDigestOid(TNistObjectIdentifiers.DsaWithSha224, TNistObjectIdentifiers.IdSha224);
  AddDigestOid(TNistObjectIdentifiers.DsaWithSha256, TNistObjectIdentifiers.IdSha256);
  AddDigestOid(TNistObjectIdentifiers.DsaWithSha384, TNistObjectIdentifiers.IdSha384);
  AddDigestOid(TNistObjectIdentifiers.DsaWithSha512, TNistObjectIdentifiers.IdSha512);

  AddDigestOid(TNistObjectIdentifiers.IdDsaWithSha3_224, TNistObjectIdentifiers.IdSha3_224);
  AddDigestOid(TNistObjectIdentifiers.IdDsaWithSha3_256, TNistObjectIdentifiers.IdSha3_256);
  AddDigestOid(TNistObjectIdentifiers.IdDsaWithSha3_384, TNistObjectIdentifiers.IdSha3_384);
  AddDigestOid(TNistObjectIdentifiers.IdDsaWithSha3_512, TNistObjectIdentifiers.IdSha3_512);

  AddDigestOid(TX9ObjectIdentifiers.ECDsaWithSha1, TOiwObjectIdentifiers.IdSha1);
  AddDigestOid(TX9ObjectIdentifiers.ECDsaWithSha224, TNistObjectIdentifiers.IdSha224);
  AddDigestOid(TX9ObjectIdentifiers.ECDsaWithSha256, TNistObjectIdentifiers.IdSha256);
  AddDigestOid(TX9ObjectIdentifiers.ECDsaWithSha384, TNistObjectIdentifiers.IdSha384);
  AddDigestOid(TX9ObjectIdentifiers.ECDsaWithSha512, TNistObjectIdentifiers.IdSha512);

  AddDigestOid(TNistObjectIdentifiers.IdECDsaWithSha3_224, TNistObjectIdentifiers.IdSha3_224);
  AddDigestOid(TNistObjectIdentifiers.IdECDsaWithSha3_256, TNistObjectIdentifiers.IdSha3_256);
  AddDigestOid(TNistObjectIdentifiers.IdECDsaWithSha3_384, TNistObjectIdentifiers.IdSha3_384);
  AddDigestOid(TNistObjectIdentifiers.IdECDsaWithSha3_512, TNistObjectIdentifiers.IdSha3_512);

  AddDigestOid(TX509ObjectIdentifiers.IdRsassaPssShake128, TNistObjectIdentifiers.IdShake128);
  AddDigestOid(TX509ObjectIdentifiers.IdRsassaPssShake256, TNistObjectIdentifiers.IdShake256);
  AddDigestOid(TX509ObjectIdentifiers.IdEcdsaWithShake128, TNistObjectIdentifiers.IdShake128);
  AddDigestOid(TX509ObjectIdentifiers.IdEcdsaWithShake256, TNistObjectIdentifiers.IdShake256);

  //
  // EdDSA
  //
  AddAlgorithm('Ed25519', TEdECObjectIdentifiers.IdEd25519, nil, True);
  AddAlgorithm('Ed448', TEdECObjectIdentifiers.IdEd448, nil, True);

  FInstance := TDefaultSignatureAlgorithmFinder.Create;
end;

function TDefaultSignatureAlgorithmFinder.Find(const ASignatureName: String): IAlgorithmIdentifier;
var
  LSigOid: IDerObjectIdentifier;
  LNoParamsAlgID: IAlgorithmIdentifier;
  LExplicitParams: IAsn1Encodable;
begin
  if not FAlgorithms.TryGetValue(ASignatureName, LSigOid) then
    raise EArgumentCryptoLibException.CreateFmt('Unknown signature name: %s', [ASignatureName]);

  if FNoParams.TryGetValue(LSigOid, LNoParamsAlgID) then
  begin
    Result := LNoParamsAlgID;
    Exit;
  end;

  if FParameters.TryGetValue(ASignatureName, LExplicitParams) then
  begin
    Result := TAlgorithmIdentifier.Create(LSigOid, LExplicitParams);
    Exit;
  end;

  Result := TAlgorithmIdentifier.Create(LSigOid, TDerNull.Instance);
end;

end.
