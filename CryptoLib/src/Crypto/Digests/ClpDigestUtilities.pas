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

unit ClpDigestUtilities;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  TypInfo,
  Generics.Collections,
  HlpIHash,
  HlpHashFactory,
  ClpNoOpDigest,
  ClpAsn1Objects,
  ClpCollectionUtilities,
  ClpAsn1Comparers,
  ClpCryptoLibComparers,
  ClpCryptoLibTypes,
  ClpCryptoProObjectIdentifiers,
  ClpDigest,
  ClpEnumUtilities,
  ClpIDigest,
  ClpIAsn1Objects,
  ClpMiscObjectIdentifiers,
  ClpNistObjectIdentifiers,
  ClpOiwObjectIdentifiers,
  ClpPkcsObjectIdentifiers,
  ClpRosstandartObjectIdentifiers,
  ClpTeleTrusTObjectIdentifiers;

resourcestring
  SMechanismNil = 'Mechanism Cannot be Nil';
  SAlgorithmNil = 'Algorithm Cannot be Nil';
  SUnRecognizedDigest = 'Digest "%s" not recognised.';
  SOidNotRecognised = 'Digest OID not recognised.';
  SOidNil = 'OID Cannot be Nil';

type
  TDigestUtilities = class sealed(TObject)

  strict private
    class var
      FAlgorithmMap: TDictionary<String, String>;
      FAlgorithmOidMap: TDictionary<IDerObjectIdentifier, String>;
      FOids: TDictionary<String, IDerObjectIdentifier>;

    type
      TDigestAlgorithm = (
        BLAKE2B_160,
        BLAKE2B_256,
        BLAKE2B_384,
        BLAKE2B_512,
        BLAKE2S_128,
        BLAKE2S_160,
        BLAKE2S_224,
        BLAKE2S_256,
        BLAKE3_256,
        GOST3411,
        GOST3411_2012_256,
        GOST3411_2012_512,
        KECCAK_224,
        KECCAK_256,
        KECCAK_288,
        KECCAK_384,
        KECCAK_512,
        MD2,
        MD4,
        MD5,
        NONE,
        RIPEMD128,
        RIPEMD160,
        RIPEMD256,
        RIPEMD320,
        SHA_1,
        SHA_224,
        SHA_256,
        SHA_384,
        SHA_512,
        SHA_512_224,
        SHA_512_256,
        SHA3_224,
        SHA3_256,
        SHA3_384,
        SHA3_512,
        SHAKE128_256,
        SHAKE256_512,
        TIGER,
        WHIRLPOOL);

    class function GetMechanism(const AAlgorithm: String): String; static;
    class function GetDigestForMechanism(const AMechanism: String): IDigest; static;
    class procedure Boot; static;
    class constructor Create;
    class destructor Destroy;

  public
    /// <summary>
    /// Returns a ObjectIdentifier for a given digest mechanism.
    /// </summary>
    /// <param name="mechanism">A string representation of the digest mechanism.</param>
    /// <returns>A DerObjectIdentifier, null if the Oid is not available.</returns>
    class function GetObjectIdentifier(const AMechanism: String)
      : IDerObjectIdentifier; static;
    class function GetDigest(const AOid: IDerObjectIdentifier): IDigest; overload; static;
    class function GetDigest(const AAlgorithm: String): IDigest; overload; static;

    class function GetAlgorithmName(const AOid: IDerObjectIdentifier): String; static; inline;

    class function DoFinal(const ADigest: IDigest): TCryptoLibByteArray; overload; static; inline;
    class function DoFinal(const ADigest: IDigest; const AInput: TCryptoLibByteArray): TCryptoLibByteArray; overload; static; inline;
    class function DoFinal(const ADigest: IDigest; const AInput: TCryptoLibByteArray; AOffset, ALength: Int32): TCryptoLibByteArray; overload; static; inline;

    class function CalculateDigest(const AOid: IDerObjectIdentifier; const AInput: TCryptoLibByteArray): TCryptoLibByteArray; overload; static; inline;
    class function CalculateDigest(const AAlgorithm: String; const AInput: TCryptoLibByteArray): TCryptoLibByteArray; overload; static; inline;
    class function CalculateDigest(const AAlgorithm: String; const AInput: TCryptoLibByteArray; AOffset, ALength: Int32): TCryptoLibByteArray; overload; static; inline;

  end;

implementation

{ TDigestUtilities }

class function TDigestUtilities.GetDigest(const AOid: IDerObjectIdentifier): IDigest;
var
  LMechanism: String;
  LDigest: IDigest;
begin
  if AOid = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOidNil);
  if not FAlgorithmOidMap.TryGetValue(AOid, LMechanism) then
    raise ESecurityUtilityCryptoLibException.CreateRes(@SOidNotRecognised);
  LDigest := GetDigestForMechanism(LMechanism);
  if LDigest = nil then
    raise ESecurityUtilityCryptoLibException.CreateRes(@SOidNotRecognised);
  Result := LDigest;
end;

class function TDigestUtilities.GetDigest(const AAlgorithm: String): IDigest;
var
  LMechanism: String;
  LDigest: IDigest;
begin
  if AAlgorithm = '' then
    raise EArgumentNilCryptoLibException.CreateRes(@SAlgorithmNil);
  LMechanism := GetMechanism(AAlgorithm);
  if LMechanism = '' then
    LMechanism := UpperCase(AAlgorithm);
  LDigest := GetDigestForMechanism(LMechanism);
  if LDigest = nil then
    raise ESecurityUtilityCryptoLibException.CreateResFmt(@SUnRecognizedDigest, [AAlgorithm]);
  Result := LDigest;
end;

class function TDigestUtilities.GetMechanism(const AAlgorithm: String): String;
var
  LOid: IDerObjectIdentifier;
  LMechanism: String;
begin
  if FAlgorithmMap.TryGetValue(AAlgorithm, LMechanism) then
  begin
    Result := LMechanism;
    Exit;
  end;
  if TDerObjectIdentifier.TryFromID(AAlgorithm, LOid) and FAlgorithmOidMap.TryGetValue(LOid, LMechanism) then
  begin
    Result := LMechanism;
    Exit;
  end;
  Result := '';
end;

class function TDigestUtilities.GetDigestForMechanism(const AMechanism: String): IDigest;
var
  LDigestAlg: TDigestAlgorithm;
begin
  Result := nil;
  if not TEnumUtilities.TryGetEnumValue<TDigestAlgorithm>(AMechanism, LDigestAlg) then
    Exit;
  case LDigestAlg of
    TDigestAlgorithm.BLAKE2B_160:
      Result := TDigest.Create(THashFactory.TCrypto.CreateBlake2B_160);
    TDigestAlgorithm.BLAKE2B_256:
      Result := TDigest.Create(THashFactory.TCrypto.CreateBlake2B_256);
    TDigestAlgorithm.BLAKE2B_384:
      Result := TDigest.Create(THashFactory.TCrypto.CreateBlake2B_384);
    TDigestAlgorithm.BLAKE2B_512:
      Result := TDigest.Create(THashFactory.TCrypto.CreateBlake2B_512);
    TDigestAlgorithm.BLAKE2S_128:
      Result := TDigest.Create(THashFactory.TCrypto.CreateBlake2S_128);
    TDigestAlgorithm.BLAKE2S_160:
      Result := TDigest.Create(THashFactory.TCrypto.CreateBlake2S_160);
    TDigestAlgorithm.BLAKE2S_224:
      Result := TDigest.Create(THashFactory.TCrypto.CreateBlake2S_224);
    TDigestAlgorithm.BLAKE2S_256:
      Result := TDigest.Create(THashFactory.TCrypto.CreateBlake2S_256);
    TDigestAlgorithm.BLAKE3_256:
      Result := TDigest.Create(THashFactory.TCrypto.CreateBlake3_256(nil));
    TDigestAlgorithm.GOST3411:
      Result := TDigest.Create(THashFactory.TCrypto.CreateGost());
    TDigestAlgorithm.GOST3411_2012_256:
      Result := TDigest.Create(THashFactory.TCrypto.CreateGOST3411_2012_256());
    TDigestAlgorithm.GOST3411_2012_512:
      Result := TDigest.Create(THashFactory.TCrypto.CreateGOST3411_2012_512());
    TDigestAlgorithm.KECCAK_224:
      Result := TDigest.Create(THashFactory.TCrypto.CreateKeccak_224());
    TDigestAlgorithm.KECCAK_256:
      Result := TDigest.Create(THashFactory.TCrypto.CreateKeccak_256());
    TDigestAlgorithm.KECCAK_288:
      Result := TDigest.Create(THashFactory.TCrypto.CreateKeccak_288());
    TDigestAlgorithm.KECCAK_384:
      Result := TDigest.Create(THashFactory.TCrypto.CreateKeccak_384());
    TDigestAlgorithm.KECCAK_512:
      Result := TDigest.Create(THashFactory.TCrypto.CreateKeccak_512());
    TDigestAlgorithm.MD2:
      Result := TDigest.Create(THashFactory.TCrypto.CreateMD2());
    TDigestAlgorithm.MD4:
      Result := TDigest.Create(THashFactory.TCrypto.CreateMD4());
    TDigestAlgorithm.MD5:
      Result := TDigest.Create(THashFactory.TCrypto.CreateMD5());
    TDigestAlgorithm.NONE:
      Result := TDigest.Create(TNoOpDigest.Create() as IHash);
    TDigestAlgorithm.RIPEMD128:
      Result := TDigest.Create(THashFactory.TCrypto.CreateRIPEMD128());
    TDigestAlgorithm.RIPEMD160:
      Result := TDigest.Create(THashFactory.TCrypto.CreateRIPEMD160());
    TDigestAlgorithm.RIPEMD256:
      Result := TDigest.Create(THashFactory.TCrypto.CreateRIPEMD256());
    TDigestAlgorithm.RIPEMD320:
      Result := TDigest.Create(THashFactory.TCrypto.CreateRIPEMD320());
    TDigestAlgorithm.SHA_1:
      Result := TDigest.Create(THashFactory.TCrypto.CreateSHA1());
    TDigestAlgorithm.SHA_224:
      Result := TDigest.Create(THashFactory.TCrypto.CreateSHA2_224());
    TDigestAlgorithm.SHA_256:
      Result := TDigest.Create(THashFactory.TCrypto.CreateSHA2_256());
    TDigestAlgorithm.SHA_384:
      Result := TDigest.Create(THashFactory.TCrypto.CreateSHA2_384());
    TDigestAlgorithm.SHA_512:
      Result := TDigest.Create(THashFactory.TCrypto.CreateSHA2_512());
    TDigestAlgorithm.SHA_512_224:
      Result := TDigest.Create(THashFactory.TCrypto.CreateSHA2_512_224());
    TDigestAlgorithm.SHA_512_256:
      Result := TDigest.Create(THashFactory.TCrypto.CreateSHA2_512_256());
    TDigestAlgorithm.SHA3_224:
      Result := TDigest.Create(THashFactory.TCrypto.CreateSHA3_224());
    TDigestAlgorithm.SHA3_256:
      Result := TDigest.Create(THashFactory.TCrypto.CreateSHA3_256());
    TDigestAlgorithm.SHA3_384:
      Result := TDigest.Create(THashFactory.TCrypto.CreateSHA3_384());
    TDigestAlgorithm.SHA3_512:
      Result := TDigest.Create(THashFactory.TCrypto.CreateSHA3_512());
    TDigestAlgorithm.SHAKE128_256:
      Result := TDigest.Create(THashFactory.TXOF.CreateShake_128(256));
    TDigestAlgorithm.SHAKE256_512:
      Result := TDigest.Create(THashFactory.TXOF.CreateShake_256(512));
    TDigestAlgorithm.TIGER:
      Result := TDigest.Create(THashFactory.TCrypto.CreateTiger_3_192);
    TDigestAlgorithm.WHIRLPOOL:
      Result := TDigest.Create(THashFactory.TCrypto.CreateWhirlPool);
  else
    Exit;
  end;
end;

class procedure TDigestUtilities.Boot;
begin
  FAlgorithmMap := TDictionary<String, String>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FAlgorithmOidMap := TDictionary<IDerObjectIdentifier, String>.Create(TAsn1Comparers.OidEqualityComparer);
  FOids := TDictionary<String, IDerObjectIdentifier>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);

  TPkcsObjectIdentifiers.Boot;
  TOiwObjectIdentifiers.Boot;
  TMiscObjectIdentifiers.Boot;
  TTeleTrusTObjectIdentifiers.Boot;
  TCryptoProObjectIdentifiers.Boot;
  TRosstandartObjectIdentifiers.Boot;

  // MD
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.MD2, 'MD2');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.MD4, 'MD4');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.MD5, 'MD5');

  // SHA-1
  FAlgorithmMap.AddOrSetValue('SHA1', 'SHA-1');
  FAlgorithmOidMap.AddOrSetValue(TOiwObjectIdentifiers.IdSha1, 'SHA-1');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.IdHmacWithSha1, 'SHA-1');
  FAlgorithmOidMap.AddOrSetValue(TMiscObjectIdentifiers.HmacSha1, 'SHA-1');

  // SHA-2
  FAlgorithmMap.AddOrSetValue('SHA224', 'SHA-224');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdSha224, 'SHA-224');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.IdHmacWithSha224, 'SHA-224');

  FAlgorithmMap.AddOrSetValue('SHA256', 'SHA-256');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdSha256, 'SHA-256');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.IdHmacWithSha256, 'SHA-256');

  FAlgorithmMap.AddOrSetValue('SHA384', 'SHA-384');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdSha384, 'SHA-384');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.IdHmacWithSha384, 'SHA-384');

  FAlgorithmMap.AddOrSetValue('SHA512', 'SHA-512');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdSha512, 'SHA-512');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.IdHmacWithSha512, 'SHA-512');

  FAlgorithmMap.AddOrSetValue('SHA512/224', 'SHA-512/224');
  FAlgorithmMap.AddOrSetValue('SHA512-224', 'SHA-512/224');
  FAlgorithmMap.AddOrSetValue('SHA512(224)', 'SHA-512/224');
  FAlgorithmMap.AddOrSetValue('SHA-512(224)', 'SHA-512/224');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdSha512_224, 'SHA-512/224');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.IdHmacWithSha512_224, 'SHA-512/224');

  FAlgorithmMap.AddOrSetValue('SHA512/256', 'SHA-512/256');
  FAlgorithmMap.AddOrSetValue('SHA512-256', 'SHA-512/256');
  FAlgorithmMap.AddOrSetValue('SHA512(256)', 'SHA-512/256');
  FAlgorithmMap.AddOrSetValue('SHA-512(256)', 'SHA-512/256');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdSha512_256, 'SHA-512/256');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.IdHmacWithSha512_256, 'SHA-512/256');

  // RIPEMD
  FAlgorithmMap.AddOrSetValue('RIPEMD-128', 'RIPEMD128');
  FAlgorithmOidMap.AddOrSetValue(TTeleTrusTObjectIdentifiers.RipeMD128, 'RIPEMD128');

  FAlgorithmMap.AddOrSetValue('RIPEMD-160', 'RIPEMD160');
  FAlgorithmOidMap.AddOrSetValue(TTeleTrusTObjectIdentifiers.RipeMD160, 'RIPEMD160');

  FAlgorithmMap.AddOrSetValue('RIPEMD-256', 'RIPEMD256');
  FAlgorithmOidMap.AddOrSetValue(TTeleTrusTObjectIdentifiers.RipeMD256, 'RIPEMD256');

  FAlgorithmMap.AddOrSetValue('RIPEMD-320', 'RIPEMD320');

  // GOST
  FAlgorithmOidMap.AddOrSetValue(TCryptoProObjectIdentifiers.GostR3411, 'GOST3411');

  // KECCAK
  FAlgorithmMap.AddOrSetValue('KECCAK224', 'KECCAK-224');
  FAlgorithmMap.AddOrSetValue('KECCAK256', 'KECCAK-256');
  FAlgorithmMap.AddOrSetValue('KECCAK288', 'KECCAK-288');
  FAlgorithmMap.AddOrSetValue('KECCAK384', 'KECCAK-384');
  FAlgorithmMap.AddOrSetValue('KECCAK512', 'KECCAK-512');

  // SHA-3 + SHAKE
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdSha3_224, 'SHA3-224');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdHMacWithSha3_224, 'SHA3-224');

  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdSha3_256, 'SHA3-256');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdHMacWithSha3_256, 'SHA3-256');

  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdSha3_384, 'SHA3-384');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdHMacWithSha3_384, 'SHA3-384');

  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdSha3_512, 'SHA3-512');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdHMacWithSha3_512, 'SHA3-512');

  FAlgorithmMap.AddOrSetValue('SHAKE128', 'SHAKE128-256');
  FAlgorithmMap.AddOrSetValue('SHAKE-128', 'SHAKE128-256');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdShake128, 'SHAKE128-256');

  FAlgorithmMap.AddOrSetValue('SHAKE256', 'SHAKE256-512');
  FAlgorithmMap.AddOrSetValue('SHAKE-256', 'SHAKE256-512');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdShake256, 'SHAKE256-512');

  // BLAKE
  FAlgorithmOidMap.AddOrSetValue(TMiscObjectIdentifiers.IdBlake2b160, 'BLAKE2B-160');
  FAlgorithmOidMap.AddOrSetValue(TMiscObjectIdentifiers.IdBlake2b256, 'BLAKE2B-256');
  FAlgorithmOidMap.AddOrSetValue(TMiscObjectIdentifiers.IdBlake2b384, 'BLAKE2B-384');
  FAlgorithmOidMap.AddOrSetValue(TMiscObjectIdentifiers.IdBlake2b512, 'BLAKE2B-512');

  FAlgorithmOidMap.AddOrSetValue(TMiscObjectIdentifiers.IdBlake2s128, 'BLAKE2S-128');
  FAlgorithmOidMap.AddOrSetValue(TMiscObjectIdentifiers.IdBlake2s160, 'BLAKE2S-160');
  FAlgorithmOidMap.AddOrSetValue(TMiscObjectIdentifiers.IdBlake2s224, 'BLAKE2S-224');
  FAlgorithmOidMap.AddOrSetValue(TMiscObjectIdentifiers.IdBlake2s256, 'BLAKE2S-256');

  FAlgorithmOidMap.AddOrSetValue(TMiscObjectIdentifiers.Blake3_256, 'BLAKE3-256');

  // GOST 2012
  FAlgorithmOidMap.AddOrSetValue(
    TRosstandartObjectIdentifiers.IdTc26Gost3411_12_256,
    'GOST3411-2012-256'
  );
  FAlgorithmOidMap.AddOrSetValue(
    TRosstandartObjectIdentifiers.IdTc26Gost3411_12_512,
    'GOST3411-2012-512'
  );

  // Reverse OID lookup
  FOids.AddOrSetValue('MD2', TPkcsObjectIdentifiers.MD2);
  FOids.AddOrSetValue('MD4', TPkcsObjectIdentifiers.MD4);
  FOids.AddOrSetValue('MD5', TPkcsObjectIdentifiers.MD5);
  FOids.AddOrSetValue('SHA-1', TOiwObjectIdentifiers.IdSha1);
  FOids.AddOrSetValue('SHA-224', TNistObjectIdentifiers.IdSha224);
  FOids.AddOrSetValue('SHA-256', TNistObjectIdentifiers.IdSha256);
  FOids.AddOrSetValue('SHA-384', TNistObjectIdentifiers.IdSha384);
  FOids.AddOrSetValue('SHA-512', TNistObjectIdentifiers.IdSha512);
  FOids.AddOrSetValue('SHA-512/224', TNistObjectIdentifiers.IdSha512_224);
  FOids.AddOrSetValue('SHA-512/256', TNistObjectIdentifiers.IdSha512_256);
  FOids.AddOrSetValue('SHA3-224', TNistObjectIdentifiers.IdSha3_224);
  FOids.AddOrSetValue('SHA3-256', TNistObjectIdentifiers.IdSha3_256);
  FOids.AddOrSetValue('SHA3-384', TNistObjectIdentifiers.IdSha3_384);
  FOids.AddOrSetValue('SHA3-512', TNistObjectIdentifiers.IdSha3_512);
  FOids.AddOrSetValue('SHAKE128-256', TNistObjectIdentifiers.IdShake128);
  FOids.AddOrSetValue('SHAKE256-512', TNistObjectIdentifiers.IdShake256);
  FOids.AddOrSetValue('RIPEMD128', TTeleTrusTObjectIdentifiers.RipeMD128);
  FOids.AddOrSetValue('RIPEMD160', TTeleTrusTObjectIdentifiers.RipeMD160);
  FOids.AddOrSetValue('RIPEMD256', TTeleTrusTObjectIdentifiers.RipeMD256);
  FOids.AddOrSetValue('GOST3411', TCryptoProObjectIdentifiers.GostR3411);
  FOids.AddOrSetValue('BLAKE2B-160', TMiscObjectIdentifiers.IdBlake2b160);
  FOids.AddOrSetValue('BLAKE2B-256', TMiscObjectIdentifiers.IdBlake2b256);
  FOids.AddOrSetValue('BLAKE2B-384', TMiscObjectIdentifiers.IdBlake2b384);
  FOids.AddOrSetValue('BLAKE2B-512', TMiscObjectIdentifiers.IdBlake2b512);
  FOids.AddOrSetValue('BLAKE2S-128', TMiscObjectIdentifiers.IdBlake2s128);
  FOids.AddOrSetValue('BLAKE2S-160', TMiscObjectIdentifiers.IdBlake2s160);
  FOids.AddOrSetValue('BLAKE2S-224', TMiscObjectIdentifiers.IdBlake2s224);
  FOids.AddOrSetValue('BLAKE2S-256', TMiscObjectIdentifiers.IdBlake2s256);
  FOids.AddOrSetValue('BLAKE3-256', TMiscObjectIdentifiers.Blake3_256);
  FOids.AddOrSetValue('GOST3411-2012-256', TRosstandartObjectIdentifiers.IdTc26Gost3411_12_256);
  FOids.AddOrSetValue('GOST3411-2012-512', TRosstandartObjectIdentifiers.IdTc26Gost3411_12_512);

end;

class function TDigestUtilities.DoFinal(const ADigest: IDigest)
  : TCryptoLibByteArray;
begin
  System.SetLength(Result, ADigest.GetDigestSize());
  ADigest.DoFinal(Result, 0);
end;

class function TDigestUtilities.DoFinal(const ADigest: IDigest;
  const AInput: TCryptoLibByteArray): TCryptoLibByteArray;
begin
  ADigest.BlockUpdate(AInput, 0, System.Length(AInput));
  Result := DoFinal(ADigest);
end;

class function TDigestUtilities.DoFinal(const ADigest: IDigest;
  const AInput: TCryptoLibByteArray; AOffset, ALength: Int32): TCryptoLibByteArray;
begin
  ADigest.BlockUpdate(AInput, AOffset, ALength);
  Result := DoFinal(ADigest);
end;

class function TDigestUtilities.CalculateDigest(const AOid: IDerObjectIdentifier;
  const AInput: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LDigest: IDigest;
begin
  LDigest := GetDigest(AOid);
  Result := DoFinal(LDigest, AInput);
end;

class function TDigestUtilities.CalculateDigest(const AAlgorithm: String;
  const AInput: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LDigest: IDigest;
begin
  LDigest := GetDigest(AAlgorithm);
  LDigest.BlockUpdate(AInput, 0, System.Length(AInput));
  Result := DoFinal(LDigest);
end;

class function TDigestUtilities.CalculateDigest(const AAlgorithm: String;
  const AInput: TCryptoLibByteArray; AOffset, ALength: Int32): TCryptoLibByteArray;
var
  LDigest: IDigest;
begin
  LDigest := GetDigest(AAlgorithm);
  LDigest.BlockUpdate(AInput, AOffset, ALength);
  Result := DoFinal(LDigest);
end;

class constructor TDigestUtilities.Create;
begin
  Boot;
end;

class destructor TDigestUtilities.Destroy;
begin
  FAlgorithmMap.Free;
  FAlgorithmOidMap.Free;
  FOids.Free;
end;

class function TDigestUtilities.GetAlgorithmName(const AOid: IDerObjectIdentifier): String;
begin
  Result := TCollectionUtilities.GetValueOrNull<IDerObjectIdentifier, String>(FAlgorithmOidMap, AOid);
end;

class function TDigestUtilities.GetObjectIdentifier(const AMechanism: String): IDerObjectIdentifier;
var
  LCanonical: String;
begin
  if AMechanism = '' then
    raise EArgumentNilCryptoLibException.CreateRes(@SMechanismNil);
  LCanonical := GetMechanism(AMechanism);
  if LCanonical = '' then
    LCanonical := AMechanism;
  Result := TCollectionUtilities.GetValueOrNull<String, IDerObjectIdentifier>(FOids, LCanonical);
end;

end.
