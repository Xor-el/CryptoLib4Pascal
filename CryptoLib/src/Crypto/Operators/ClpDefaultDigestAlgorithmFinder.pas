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

unit ClpDefaultDigestAlgorithmFinder;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Generics.Collections,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpAsn1Comparers,
  ClpCryptoLibComparers,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpPkcsRsaAsn1Objects,
  ClpIPkcsRsaAsn1Objects,
  ClpOiwObjectIdentifiers,
  ClpPkcsObjectIdentifiers,
  ClpNistObjectIdentifiers,
  ClpX9ObjectIdentifiers,
  ClpBsiObjectIdentifiers,
  ClpEacObjectIdentifiers,
  ClpTeleTrusTObjectIdentifiers,
  ClpCryptoProObjectIdentifiers,
  ClpRosstandartObjectIdentifiers,
  ClpX509ObjectIdentifiers,
  ClpEdECObjectIdentifiers,
  ClpCollectionUtilities,
  ClpIDigestAlgorithmFinder,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Default implementation of IDigestAlgorithmFinder that maps signature/digest OIDs
  /// and names to digest algorithm identifiers.
  /// </summary>
  TDefaultDigestAlgorithmFinder = class sealed(TInterfacedObject, IDigestAlgorithmFinder)
  strict private
    class var
      FInstance: IDigestAlgorithmFinder;
      FDigestOids: TDictionary<IDerObjectIdentifier, IDerObjectIdentifier>;
      FDigestNameToOids: TDictionary<String, IDerObjectIdentifier>;
      FDigestOidToAlgIDs: TDictionary<IDerObjectIdentifier, IAlgorithmIdentifier>;
    class procedure Boot; static;
    class procedure AddDigestAlgID(const AOid: IDerObjectIdentifier;
      AWithNullParams: Boolean); static;
    class constructor Create;
    class destructor Destroy;
  public
    class property Instance: IDigestAlgorithmFinder read FInstance;
    function Find(const ASignatureAlgorithm: IAlgorithmIdentifier): IAlgorithmIdentifier; overload;
    function Find(const ADigestOid: IDerObjectIdentifier): IAlgorithmIdentifier; overload;
    function Find(const ADigestName: String): IAlgorithmIdentifier; overload;
  end;

implementation

{ TDefaultDigestAlgorithmFinder }

class procedure TDefaultDigestAlgorithmFinder.AddDigestAlgID(
  const AOid: IDerObjectIdentifier; AWithNullParams: Boolean);
begin
  if AWithNullParams then
    FDigestOidToAlgIDs.Add(AOid, TAlgorithmIdentifier.Create(AOid, TDerNull.Instance) as IAlgorithmIdentifier)
  else
    FDigestOidToAlgIDs.Add(AOid, TAlgorithmIdentifier.Create(AOid) as IAlgorithmIdentifier);
end;

class constructor TDefaultDigestAlgorithmFinder.Create;
begin
  Boot;
end;

class destructor TDefaultDigestAlgorithmFinder.Destroy;
begin
  FInstance := nil;
  FDigestOids.Free;
  FDigestNameToOids.Free;
  FDigestOidToAlgIDs.Free;
end;

class procedure TDefaultDigestAlgorithmFinder.Boot;
begin
  FDigestOids := TDictionary<IDerObjectIdentifier, IDerObjectIdentifier>.Create(TAsn1Comparers.OidEqualityComparer);
  FDigestNameToOids := TDictionary<String, IDerObjectIdentifier>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FDigestOidToAlgIDs := TDictionary<IDerObjectIdentifier, IAlgorithmIdentifier>.Create(TAsn1Comparers.OidEqualityComparer);

  // Digest OID mappings (signature OID -> digest OID)
  FDigestOids.Add(TOiwObjectIdentifiers.Md4WithRsaEncryption, TPkcsObjectIdentifiers.MD4);
  FDigestOids.Add(TOiwObjectIdentifiers.Md4WithRsa, TPkcsObjectIdentifiers.MD4);
  FDigestOids.Add(TOiwObjectIdentifiers.Md5WithRsa, TPkcsObjectIdentifiers.MD5);
  FDigestOids.Add(TOiwObjectIdentifiers.Sha1WithRsa, TOiwObjectIdentifiers.IdSha1);

  FDigestOids.Add(TPkcsObjectIdentifiers.Sha224WithRsaEncryption, TNistObjectIdentifiers.IdSha224);
  FDigestOids.Add(TPkcsObjectIdentifiers.Sha256WithRsaEncryption, TNistObjectIdentifiers.IdSha256);
  FDigestOids.Add(TPkcsObjectIdentifiers.Sha384WithRsaEncryption, TNistObjectIdentifiers.IdSha384);
  FDigestOids.Add(TPkcsObjectIdentifiers.Sha512WithRsaEncryption, TNistObjectIdentifiers.IdSha512);
  FDigestOids.Add(TPkcsObjectIdentifiers.Sha512_224WithRsaEncryption, TNistObjectIdentifiers.IdSha512_224);
  FDigestOids.Add(TPkcsObjectIdentifiers.Sha512_256WithRsaEncryption, TNistObjectIdentifiers.IdSha512_256);
  FDigestOids.Add(TPkcsObjectIdentifiers.MD2WithRsaEncryption, TPkcsObjectIdentifiers.MD2);
  FDigestOids.Add(TPkcsObjectIdentifiers.MD4WithRsaEncryption, TPkcsObjectIdentifiers.MD4);
  FDigestOids.Add(TPkcsObjectIdentifiers.MD5WithRsaEncryption, TPkcsObjectIdentifiers.MD5);
  FDigestOids.Add(TPkcsObjectIdentifiers.Sha1WithRsaEncryption, TOiwObjectIdentifiers.IdSha1);

  FDigestOids.Add(TX9ObjectIdentifiers.IdDsaWithSha1, TOiwObjectIdentifiers.IdSha1);
  FDigestOids.Add(TOiwObjectIdentifiers.DsaWithSha1, TOiwObjectIdentifiers.IdSha1);
  FDigestOids.Add(TNistObjectIdentifiers.DsaWithSha224, TNistObjectIdentifiers.IdSha224);
  FDigestOids.Add(TNistObjectIdentifiers.DsaWithSha256, TNistObjectIdentifiers.IdSha256);
  FDigestOids.Add(TNistObjectIdentifiers.DsaWithSha384, TNistObjectIdentifiers.IdSha384);
  FDigestOids.Add(TNistObjectIdentifiers.DsaWithSha512, TNistObjectIdentifiers.IdSha512);

  FDigestOids.Add(TNistObjectIdentifiers.IdDsaWithSha3_224, TNistObjectIdentifiers.IdSha3_224);
  FDigestOids.Add(TNistObjectIdentifiers.IdDsaWithSha3_256, TNistObjectIdentifiers.IdSha3_256);
  FDigestOids.Add(TNistObjectIdentifiers.IdDsaWithSha3_384, TNistObjectIdentifiers.IdSha3_384);
  FDigestOids.Add(TNistObjectIdentifiers.IdDsaWithSha3_512, TNistObjectIdentifiers.IdSha3_512);

  FDigestOids.Add(TX9ObjectIdentifiers.ECDsaWithSha1, TOiwObjectIdentifiers.IdSha1);
  FDigestOids.Add(TX9ObjectIdentifiers.ECDsaWithSha224, TNistObjectIdentifiers.IdSha224);
  FDigestOids.Add(TX9ObjectIdentifiers.ECDsaWithSha256, TNistObjectIdentifiers.IdSha256);
  FDigestOids.Add(TX9ObjectIdentifiers.ECDsaWithSha384, TNistObjectIdentifiers.IdSha384);
  FDigestOids.Add(TX9ObjectIdentifiers.ECDsaWithSha512, TNistObjectIdentifiers.IdSha512);

  FDigestOids.Add(TNistObjectIdentifiers.IdECDsaWithSha3_224, TNistObjectIdentifiers.IdSha3_224);
  FDigestOids.Add(TNistObjectIdentifiers.IdECDsaWithSha3_256, TNistObjectIdentifiers.IdSha3_256);
  FDigestOids.Add(TNistObjectIdentifiers.IdECDsaWithSha3_384, TNistObjectIdentifiers.IdSha3_384);
  FDigestOids.Add(TNistObjectIdentifiers.IdECDsaWithSha3_512, TNistObjectIdentifiers.IdSha3_512);

  FDigestOids.Add(TBsiObjectIdentifiers.EcdsaPlainSha1, TOiwObjectIdentifiers.IdSha1);
  FDigestOids.Add(TBsiObjectIdentifiers.EcdsaPlainSha224, TNistObjectIdentifiers.IdSha224);
  FDigestOids.Add(TBsiObjectIdentifiers.EcdsaPlainSha256, TNistObjectIdentifiers.IdSha256);
  FDigestOids.Add(TBsiObjectIdentifiers.EcdsaPlainSha384, TNistObjectIdentifiers.IdSha384);
  FDigestOids.Add(TBsiObjectIdentifiers.EcdsaPlainSha512, TNistObjectIdentifiers.IdSha512);
  FDigestOids.Add(TBsiObjectIdentifiers.EcdsaPlainRipeMD160, TTeleTrusTObjectIdentifiers.RipeMD160);

  FDigestOids.Add(TBsiObjectIdentifiers.EcdsaPlainSha3_224, TNistObjectIdentifiers.IdSha3_224);
  FDigestOids.Add(TBsiObjectIdentifiers.EcdsaPlainSha3_256, TNistObjectIdentifiers.IdSha3_256);
  FDigestOids.Add(TBsiObjectIdentifiers.EcdsaPlainSha3_384, TNistObjectIdentifiers.IdSha3_384);
  FDigestOids.Add(TBsiObjectIdentifiers.EcdsaPlainSha3_512, TNistObjectIdentifiers.IdSha3_512);

  FDigestOids.Add(TEacObjectIdentifiers.IdTAEcdsaSha1, TOiwObjectIdentifiers.IdSha1);
  FDigestOids.Add(TEacObjectIdentifiers.IdTAEcdsaSha224, TNistObjectIdentifiers.IdSha224);
  FDigestOids.Add(TEacObjectIdentifiers.IdTAEcdsaSha256, TNistObjectIdentifiers.IdSha256);
  FDigestOids.Add(TEacObjectIdentifiers.IdTAEcdsaSha384, TNistObjectIdentifiers.IdSha384);
  FDigestOids.Add(TEacObjectIdentifiers.IdTAEcdsaSha512, TNistObjectIdentifiers.IdSha512);

  FDigestOids.Add(TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224, TNistObjectIdentifiers.IdSha3_224);
  FDigestOids.Add(TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256, TNistObjectIdentifiers.IdSha3_256);
  FDigestOids.Add(TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384, TNistObjectIdentifiers.IdSha3_384);
  FDigestOids.Add(TNistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512, TNistObjectIdentifiers.IdSha3_512);

  FDigestOids.Add(TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128, TTeleTrusTObjectIdentifiers.RipeMD128);
  FDigestOids.Add(TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160, TTeleTrusTObjectIdentifiers.RipeMD160);
  FDigestOids.Add(TTeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256, TTeleTrusTObjectIdentifiers.RipeMD256);

  FDigestOids.Add(TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94, TCryptoProObjectIdentifiers.GostR3411);
  FDigestOids.Add(TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001, TCryptoProObjectIdentifiers.GostR3411);
  FDigestOids.Add(TRosstandartObjectIdentifiers.IdTc26SignwithdigestGost3410_12_256, TRosstandartObjectIdentifiers.IdTc26Gost3411_12_256);
  FDigestOids.Add(TRosstandartObjectIdentifiers.IdTc26SignwithdigestGost3410_12_512, TRosstandartObjectIdentifiers.IdTc26Gost3411_12_512);

  FDigestOids.Add(TX509ObjectIdentifiers.IdRsassaPssShake128, TNistObjectIdentifiers.IdShake128);
  FDigestOids.Add(TX509ObjectIdentifiers.IdRsassaPssShake256, TNistObjectIdentifiers.IdShake256);
  FDigestOids.Add(TX509ObjectIdentifiers.IdEcdsaWithShake128, TNistObjectIdentifiers.IdShake128);
  FDigestOids.Add(TX509ObjectIdentifiers.IdEcdsaWithShake256, TNistObjectIdentifiers.IdShake256);

  FDigestOids.Add(TEdECObjectIdentifiers.IdEd25519, TNistObjectIdentifiers.IdSha512);

  FDigestOids.Add(TPkcsObjectIdentifiers.IdAlgHssLmsHashsig, TNistObjectIdentifiers.IdSha256);

  // Digest name to OID
  FDigestNameToOids.Add('SHA-1', TOiwObjectIdentifiers.IdSha1);
  FDigestNameToOids.Add('SHA-224', TNistObjectIdentifiers.IdSha224);
  FDigestNameToOids.Add('SHA-256', TNistObjectIdentifiers.IdSha256);
  FDigestNameToOids.Add('SHA-384', TNistObjectIdentifiers.IdSha384);
  FDigestNameToOids.Add('SHA-512', TNistObjectIdentifiers.IdSha512);
  FDigestNameToOids.Add('SHA-512-224', TNistObjectIdentifiers.IdSha512_224);
  FDigestNameToOids.Add('SHA-512/224', TNistObjectIdentifiers.IdSha512_224);
  FDigestNameToOids.Add('SHA-512(224)', TNistObjectIdentifiers.IdSha512_224);
  FDigestNameToOids.Add('SHA-512-256', TNistObjectIdentifiers.IdSha512_256);
  FDigestNameToOids.Add('SHA-512/256', TNistObjectIdentifiers.IdSha512_256);
  FDigestNameToOids.Add('SHA-512(256)', TNistObjectIdentifiers.IdSha512_256);

  FDigestNameToOids.Add('SHA1', TOiwObjectIdentifiers.IdSha1);
  FDigestNameToOids.Add('SHA224', TNistObjectIdentifiers.IdSha224);
  FDigestNameToOids.Add('SHA256', TNistObjectIdentifiers.IdSha256);
  FDigestNameToOids.Add('SHA384', TNistObjectIdentifiers.IdSha384);
  FDigestNameToOids.Add('SHA512', TNistObjectIdentifiers.IdSha512);
  FDigestNameToOids.Add('SHA512-224', TNistObjectIdentifiers.IdSha512_224);
  FDigestNameToOids.Add('SHA512/224', TNistObjectIdentifiers.IdSha512_224);
  FDigestNameToOids.Add('SHA512(224)', TNistObjectIdentifiers.IdSha512_224);
  FDigestNameToOids.Add('SHA512-256', TNistObjectIdentifiers.IdSha512_256);
  FDigestNameToOids.Add('SHA512/256', TNistObjectIdentifiers.IdSha512_256);
  FDigestNameToOids.Add('SHA512(256)', TNistObjectIdentifiers.IdSha512_256);

  FDigestNameToOids.Add('SHA3-224', TNistObjectIdentifiers.IdSha3_224);
  FDigestNameToOids.Add('SHA3-256', TNistObjectIdentifiers.IdSha3_256);
  FDigestNameToOids.Add('SHA3-384', TNistObjectIdentifiers.IdSha3_384);
  FDigestNameToOids.Add('SHA3-512', TNistObjectIdentifiers.IdSha3_512);

  FDigestNameToOids.Add('SHAKE128', TNistObjectIdentifiers.IdShake128);
  FDigestNameToOids.Add('SHAKE256', TNistObjectIdentifiers.IdShake256);
  FDigestNameToOids.Add('SHAKE-128', TNistObjectIdentifiers.IdShake128);
  FDigestNameToOids.Add('SHAKE-256', TNistObjectIdentifiers.IdShake256);

  FDigestNameToOids.Add('GOST3411', TCryptoProObjectIdentifiers.GostR3411);
  FDigestNameToOids.Add('GOST3411-2012-256', TRosstandartObjectIdentifiers.IdTc26Gost3411_12_256);
  FDigestNameToOids.Add('GOST3411-2012-512', TRosstandartObjectIdentifiers.IdTc26Gost3411_12_512);

  FDigestNameToOids.Add('MD2', TPkcsObjectIdentifiers.MD2);
  FDigestNameToOids.Add('MD4', TPkcsObjectIdentifiers.MD4);
  FDigestNameToOids.Add('MD5', TPkcsObjectIdentifiers.MD5);

  FDigestNameToOids.Add('RIPEMD128', TTeleTrusTObjectIdentifiers.RipeMD128);
  FDigestNameToOids.Add('RIPEMD160', TTeleTrusTObjectIdentifiers.RipeMD160);
  FDigestNameToOids.Add('RIPEMD256', TTeleTrusTObjectIdentifiers.RipeMD256);

  // AddDigestAlgID entries
  AddDigestAlgID(TOiwObjectIdentifiers.IdSha1, True);
  AddDigestAlgID(TNistObjectIdentifiers.IdSha224, False);
  AddDigestAlgID(TNistObjectIdentifiers.IdSha256, False);
  AddDigestAlgID(TNistObjectIdentifiers.IdSha384, False);
  AddDigestAlgID(TNistObjectIdentifiers.IdSha512, False);
  AddDigestAlgID(TNistObjectIdentifiers.IdSha512_224, False);
  AddDigestAlgID(TNistObjectIdentifiers.IdSha512_256, False);

  AddDigestAlgID(TNistObjectIdentifiers.IdSha3_224, False);
  AddDigestAlgID(TNistObjectIdentifiers.IdSha3_256, False);
  AddDigestAlgID(TNistObjectIdentifiers.IdSha3_384, False);
  AddDigestAlgID(TNistObjectIdentifiers.IdSha3_512, False);
  AddDigestAlgID(TNistObjectIdentifiers.IdShake128, False);
  AddDigestAlgID(TNistObjectIdentifiers.IdShake256, False);

  AddDigestAlgID(TCryptoProObjectIdentifiers.GostR3411, True);

  AddDigestAlgID(TRosstandartObjectIdentifiers.IdTc26Gost3411_12_256, False);
  AddDigestAlgID(TRosstandartObjectIdentifiers.IdTc26Gost3411_12_512, False);

  AddDigestAlgID(TPkcsObjectIdentifiers.MD2, True);
  AddDigestAlgID(TPkcsObjectIdentifiers.MD4, True);
  AddDigestAlgID(TPkcsObjectIdentifiers.MD5, True);

  AddDigestAlgID(TTeleTrusTObjectIdentifiers.RipeMD128, True);
  AddDigestAlgID(TTeleTrusTObjectIdentifiers.RipeMD160, True);
  AddDigestAlgID(TTeleTrusTObjectIdentifiers.RipeMD256, True);

  FInstance := TDefaultDigestAlgorithmFinder.Create;
end;

function TDefaultDigestAlgorithmFinder.Find(const ASignatureAlgorithm: IAlgorithmIdentifier): IAlgorithmIdentifier;
var
  LSignatureOid, LDigestOid: IDerObjectIdentifier;
  LPssParams: IRsassaPssParameters;
begin
  if ASignatureAlgorithm = nil then
  begin
    Result := nil;
    Exit;
  end;
  LSignatureOid := ASignatureAlgorithm.Algorithm;

  if TEdECObjectIdentifiers.IdEd448.Equals(LSignatureOid) then
  begin
    Result := TAlgorithmIdentifier.Create(TNistObjectIdentifiers.IdShake256Len, TDerInteger.ValueOf(512));
    Exit;
  end;

  if TPkcsObjectIdentifiers.IdRsassaPss.Equals(LSignatureOid) then
  begin
    LPssParams := TRsassaPssParameters.GetInstance(ASignatureAlgorithm.Parameters);
    if LPssParams <> nil then
    begin
      Result := Find(LPssParams.HashAlgorithm.Algorithm);
      Exit;
    end;
  end;

  LDigestOid := TCollectionUtilities.GetValueOrNull<IDerObjectIdentifier, IDerObjectIdentifier>(FDigestOids, LSignatureOid);
  Result := Find(LDigestOid);
end;

function TDefaultDigestAlgorithmFinder.Find(const ADigestOid: IDerObjectIdentifier): IAlgorithmIdentifier;
var
  LDigestAlgorithm: IAlgorithmIdentifier;
begin
  if ADigestOid = nil then
    raise EArgumentNilCryptoLibException.Create('digestOid');

  if FDigestOidToAlgIDs.TryGetValue(ADigestOid, LDigestAlgorithm) then
    Result := LDigestAlgorithm
  else
    Result := TAlgorithmIdentifier.Create(ADigestOid);
end;

function TDefaultDigestAlgorithmFinder.Find(const ADigestName: String): IAlgorithmIdentifier;
var
  LDigestOid: IDerObjectIdentifier;
begin
  if FDigestNameToOids.TryGetValue(ADigestName, LDigestOid) then
  begin
    Result := Find(LDigestOid);
    Exit;
  end;
  if TDerObjectIdentifier.TryFromID(ADigestName, LDigestOid) then
  begin
    Result := Find(LDigestOid);
    Exit;
  end;
  Result := nil;
end;

end.
