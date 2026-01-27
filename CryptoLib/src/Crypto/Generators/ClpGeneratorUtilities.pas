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

unit ClpGeneratorUtilities;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpCollectionUtilities,
  ClpCipherKeyGenerator,
  ClpCryptoLibComparers,
  ClpCryptoLibTypes,
  ClpDsaKeyPairGenerator,
  ClpECKeyPairGenerator,
  ClpEd25519,
  ClpEd25519KeyPairGenerator,
  ClpEdECObjectIdentifiers,
  ClpDHKeyPairGenerator,
  ClpIAsn1Objects,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpICipherKeyGenerator,
  ClpIDsaKeyPairGenerator,
  ClpIDHKeyPairGenerator,
  ClpIECKeyPairGenerator,
  ClpIEd25519,
  ClpIEd25519KeyPairGenerator,
  ClpIRsaKeyPairGenerator,
  ClpIX25519KeyPairGenerator,
  ClpIanaObjectIdentifiers,
  ClpNistObjectIdentifiers,
  ClpPkcsObjectIdentifiers,
  ClpRosstandartObjectIdentifiers,
  ClpRsaKeyPairGenerator,
  ClpSecObjectIdentifiers,
  ClpStringUtilities,
  ClpX25519KeyPairGenerator,
  ClpX9ObjectIdentifiers;

resourcestring
  SKeyGeneratorAlgorithmNotRecognised = 'KeyGenerator "%s" not Recognised.';
  SKeyGeneratorAlgorithmNotSupported =
    'KeyGenerator "%s" ( "%s" ) not Supported.';
  SKeyPairGeneratorAlgorithmNotRecognised =
    'KeyPairGenerator "%s" not Recognised.';
  SKeyPairGeneratorAlgorithmNotSupported =
    'KeyPairGenerator "%s" ( "%s" ) not Supported.';

type

  TGeneratorUtilities = class sealed(TObject)

  strict private
    class var
      FKgAlgorithms: TDictionary<String, String>;
      FKpgAlgorithms: TDictionary<String, String>;
      FDefaultKeySizes: TDictionary<String, Int32>;

    class function FindDefaultKeySize(const ACanonicalName: String): Int32; static;
    class procedure AddDefaultKeySizeEntries(ASize: Int32; const AAlgorithms: array of String); static;
    class procedure AddKgAlgorithm(const ACanonicalName: String; const AAliases: array of String); static;
    class procedure AddKpgAlgorithm(const ACanonicalName: String; const AAliases: array of String); static;
    class procedure AddHMacKeyGenerator(const AAlgorithm: String; const AAliases: array of String); static;
    class procedure Boot; static;
    class constructor Create;
    class destructor Destroy;

  public

    class function GetCanonicalKeyGeneratorAlgorithm(const AAlgorithm: String): String; static; inline;

    class function GetCanonicalKeyPairGeneratorAlgorithm(const AAlgorithm: String): String; static; inline;

    class function GetKeyPairGenerator(const AOid: IDerObjectIdentifier): IAsymmetricCipherKeyPairGenerator; overload; static; inline;

    class function GetKeyPairGenerator(const AAlgorithm: String): IAsymmetricCipherKeyPairGenerator; overload; static;

    class function GetKeyGenerator(const AOid: IDerObjectIdentifier): ICipherKeyGenerator; overload; static; inline;

    class function GetKeyGenerator(const AAlgorithm: String): ICipherKeyGenerator; overload; static;

    class function GetDefaultKeySize(const AOid: IDerObjectIdentifier): Int32; overload; static; inline;

    class function GetDefaultKeySize(const AAlgorithm: String): Int32; overload; static;

  end;

implementation

{ TGeneratorUtilities }

class procedure TGeneratorUtilities.AddDefaultKeySizeEntries(ASize: Int32;
  const AAlgorithms: array of String);
var
  LAlg: String;
begin
  for LAlg in AAlgorithms do
    FDefaultKeySizes.Add(LAlg, ASize);
end;

class procedure TGeneratorUtilities.AddKgAlgorithm(const ACanonicalName: String;
  const AAliases: array of String);
var
  LAlias: String;
begin
  FKgAlgorithms.AddOrSetValue(ACanonicalName, ACanonicalName);
  for LAlias in AAliases do
    FKgAlgorithms.AddOrSetValue(LAlias, ACanonicalName);
end;

class procedure TGeneratorUtilities.AddKpgAlgorithm(const ACanonicalName: String;
  const AAliases: array of String);
var
  LAlias: String;
begin
  FKpgAlgorithms.AddOrSetValue(ACanonicalName, ACanonicalName);
  for LAlias in AAliases do
    FKpgAlgorithms.AddOrSetValue(LAlias, ACanonicalName);
end;

class procedure TGeneratorUtilities.AddHMacKeyGenerator(const AAlgorithm: String;
  const AAliases: array of String);
var
  LAlias, LMainName: String;
begin
  LMainName := 'HMAC' + AAlgorithm;
  FKgAlgorithms.AddOrSetValue(LMainName, LMainName);
  FKgAlgorithms.AddOrSetValue('HMAC-' + AAlgorithm, LMainName);
  FKgAlgorithms.AddOrSetValue('HMAC/' + AAlgorithm, LMainName);
  for LAlias in AAliases do
    FKgAlgorithms.AddOrSetValue(LAlias, LMainName);
end;

class procedure TGeneratorUtilities.Boot;
begin
  FKgAlgorithms := TDictionary<String, String>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FKpgAlgorithms := TDictionary<String, String>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FDefaultKeySizes := TDictionary<String, Int32>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);

  TNistObjectIdentifiers.Boot;
  TIanaObjectIdentifiers.Boot;

  // key generators
  AddKgAlgorithm('AES', ['AESWRAP']);
  AddKgAlgorithm('AES128',
    [TNistObjectIdentifiers.IdAes128Cbc.ID,
    TNistObjectIdentifiers.IdAes128Cfb.ID,
    TNistObjectIdentifiers.IdAes128Ecb.ID,
    TNistObjectIdentifiers.IdAes128Ofb.ID]);
  AddKgAlgorithm('AES192',
    [TNistObjectIdentifiers.IdAes192Cbc.ID,
    TNistObjectIdentifiers.IdAes192Cfb.ID,
    TNistObjectIdentifiers.IdAes192Ecb.ID,
    TNistObjectIdentifiers.IdAes192Ofb.ID]);
  AddKgAlgorithm('AES256',
    [TNistObjectIdentifiers.IdAes256Cbc.ID,
    TNistObjectIdentifiers.IdAes256Cfb.ID,
    TNistObjectIdentifiers.IdAes256Ecb.ID,
    TNistObjectIdentifiers.IdAes256Ofb.ID]);

  AddKgAlgorithm('BLOWFISH', ['1.3.6.1.4.1.3029.1.2']);

  AddKgAlgorithm('SALSA20', []);

  //
  // HMac key generators
  //

  AddHMacKeyGenerator('MD2', []);
  AddHMacKeyGenerator('MD4', []);
  AddHMacKeyGenerator('MD5', [TIanaObjectIdentifiers.HmacMD5.ID]);

  TPkcsObjectIdentifiers.Boot;

  AddHMacKeyGenerator('SHA1',
    [TPkcsObjectIdentifiers.IdHmacWithSha1.ID,
    TIanaObjectIdentifiers.HmacSha1.ID]);
  AddHMacKeyGenerator('SHA224', [TPkcsObjectIdentifiers.IdHmacWithSha224.ID]);
  AddHMacKeyGenerator('SHA256', [TPkcsObjectIdentifiers.IdHmacWithSha256.ID]);
  AddHMacKeyGenerator('SHA384', [TPkcsObjectIdentifiers.IdHmacWithSha384.ID]);
  AddHMacKeyGenerator('SHA512', [TPkcsObjectIdentifiers.IdHmacWithSha512.ID]);
  AddHMacKeyGenerator('SHA512/224', []);
  AddHMacKeyGenerator('SHA512/256', []);

  AddHMacKeyGenerator('KECCAK224', []);
  AddHMacKeyGenerator('KECCAK256', []);
  AddHMacKeyGenerator('KECCAK288', []);
  AddHMacKeyGenerator('KECCAK384', []);
  AddHMacKeyGenerator('KECCAK512', []);

  AddHMacKeyGenerator('SHA3-224',
    [TNistObjectIdentifiers.IdHMacWithSha3_224.ID]);
  AddHMacKeyGenerator('SHA3-256',
    [TNistObjectIdentifiers.IdHMacWithSha3_256.ID]);
  AddHMacKeyGenerator('SHA3-384',
    [TNistObjectIdentifiers.IdHMacWithSha3_384.ID]);
  AddHMacKeyGenerator('SHA3-512',
    [TNistObjectIdentifiers.IdHMacWithSha3_512.ID]);
  AddHMacKeyGenerator('RIPEMD128', []);
  AddHMacKeyGenerator('RIPEMD160', [TIanaObjectIdentifiers.HmacRipeMD160.ID]);
  AddHMacKeyGenerator('TIGER', [TIanaObjectIdentifiers.HmacTiger.ID]);

  TRosstandartObjectIdentifiers.Boot;

  AddHMacKeyGenerator('GOST3411-2012-256',
    [TRosstandartObjectIdentifiers.IdTc26HmacGost3411_12_256.ID]);
  AddHMacKeyGenerator('GOST3411-2012-512',
    [TRosstandartObjectIdentifiers.IdTc26HmacGost3411_12_512.ID]);

  //
  // key pair generators.
  //

  TX9ObjectIdentifiers.Boot;
  TSecObjectIdentifiers.Boot;

  AddKpgAlgorithm('DH', ['DIFFIEHELLMAN']);
  AddKpgAlgorithm('DSA', []);
  AddKpgAlgorithm('RSA', [TPkcsObjectIdentifiers.RsaEncryption.ID]);
  AddKpgAlgorithm('RSASSA-PSS', []);
  AddKpgAlgorithm('EC', [
    TX9ObjectIdentifiers.DHSinglePassStdDHSha1KdfScheme.ID,
    TSecObjectIdentifiers.DhSinglePassStdDHSha224KdfScheme.ID,
    TSecObjectIdentifiers.DhSinglePassStdDHSha256KdfScheme.ID,
    TSecObjectIdentifiers.DhSinglePassStdDHSha384KdfScheme.ID,
    TSecObjectIdentifiers.DhSinglePassStdDHSha512KdfScheme.ID,
    TX9ObjectIdentifiers.DHSinglePassCofactorDHSha1KdfScheme.ID,
    TSecObjectIdentifiers.DhSinglePassCofactorDHSha224KdfScheme.ID,
    TSecObjectIdentifiers.DhSinglePassCofactorDHSha256KdfScheme.ID,
    TSecObjectIdentifiers.DhSinglePassCofactorDHSha384KdfScheme.ID,
    TSecObjectIdentifiers.DhSinglePassCofactorDHSha512KdfScheme.ID
    ]);
  AddKpgAlgorithm('ECDH', ['ECIES']);
  AddKpgAlgorithm('ECDHC', []);
  AddKpgAlgorithm('ECDSA', []);

  TEdECObjectIdentifiers.Boot;

  AddKpgAlgorithm('Ed25519', ['Ed25519ctx', 'Ed25519ph', TEdECObjectIdentifiers.IdEd25519.ID]);
  AddKpgAlgorithm('GOST3410', ['GOST-3410', 'GOST-3410-94']);
  AddKpgAlgorithm('RSA', [TPkcsObjectIdentifiers.RsaEncryption.ID]);
  AddKpgAlgorithm('RSASSA-PSS', []);
  AddKpgAlgorithm('X25519', [TEdECObjectIdentifiers.IdX25519.ID]);

  AddDefaultKeySizeEntries(128, [
    'AES128',
    'BLOWFISH',
    'CHACHA',
    'HMACMD2',
    'HMACMD4',
    'HMACMD5',
    'HMACRIPEMD128',
    'SALSA20'
    ]);
  AddDefaultKeySizeEntries(160, ['HMACRIPEMD160', 'HMACSHA1']);
  AddDefaultKeySizeEntries(192, ['AES', 'AES192', 'HMACTIGER']);
  AddDefaultKeySizeEntries(224,
    ['HMACSHA3-224',
    'HMACKECCAK224',
    'HMACSHA224',
    'HMACSHA512/224']);
  AddDefaultKeySizeEntries(256, [
    'AES256',
    'HMACGOST3411-2012-256',
    'HMACSHA3-256',
    'HMACKECCAK256',
    'HMACSHA256',
    'HMACSHA512/256'
    ]);
  AddDefaultKeySizeEntries(288, ['HMACKECCAK288']);
  AddDefaultKeySizeEntries(384, ['HMACSHA3-384', 'HMACKECCAK384', 'HMACSHA384']);
  AddDefaultKeySizeEntries(512, ['HMACGOST3411-2012-512', 'HMACSHA3-512', 'HMACKECCAK512', 'HMACSHA512']);
end;

class constructor TGeneratorUtilities.Create;
begin
  Boot;
end;

class destructor TGeneratorUtilities.Destroy;
begin
  FKgAlgorithms.Free;
  FKpgAlgorithms.Free;
  FDefaultKeySizes.Free;
end;

class function TGeneratorUtilities.FindDefaultKeySize(const ACanonicalName: String): Int32;
begin
  if not FDefaultKeySizes.TryGetValue(ACanonicalName, Result) then
    Result := -1;
end;

class function TGeneratorUtilities.GetCanonicalKeyGeneratorAlgorithm(const AAlgorithm: String): String;
begin
  Result := TCollectionUtilities.GetValueOrNull<String, String>(FKgAlgorithms, AAlgorithm);
end;

class function TGeneratorUtilities.GetCanonicalKeyPairGeneratorAlgorithm(const AAlgorithm: String): String;
begin
  Result := TCollectionUtilities.GetValueOrNull<String, String>(FKpgAlgorithms, AAlgorithm);
end;

class function TGeneratorUtilities.GetDefaultKeySize(const AAlgorithm: String): Int32;
var
  LCanonicalName: String;
  LDefaultKeySize: Int32;
begin
  LCanonicalName := GetCanonicalKeyGeneratorAlgorithm(AAlgorithm);
  if LCanonicalName = '' then
    raise ESecurityUtilityCryptoLibException.CreateResFmt(@SKeyGeneratorAlgorithmNotRecognised, [AAlgorithm]);
  LDefaultKeySize := FindDefaultKeySize(LCanonicalName);
  if LDefaultKeySize = -1 then
    raise ESecurityUtilityCryptoLibException.CreateResFmt(@SKeyGeneratorAlgorithmNotSupported, [AAlgorithm, LCanonicalName]);
  Result := LDefaultKeySize;
end;

class function TGeneratorUtilities.GetDefaultKeySize(const AOid: IDerObjectIdentifier): Int32;
begin
  Result := GetDefaultKeySize(AOid.ID);
end;

class function TGeneratorUtilities.GetKeyGenerator(const AOid: IDerObjectIdentifier): ICipherKeyGenerator;
begin
  Result := GetKeyGenerator(AOid.ID);
end;

class function TGeneratorUtilities.GetKeyGenerator(const AAlgorithm: String): ICipherKeyGenerator;
var
  LCanonicalName: String;
  LDefaultKeySize: Int32;
begin
  LCanonicalName := GetCanonicalKeyGeneratorAlgorithm(AAlgorithm);
  if LCanonicalName = '' then
    raise ESecurityUtilityCryptoLibException.CreateResFmt(@SKeyGeneratorAlgorithmNotRecognised, [AAlgorithm]);
  LDefaultKeySize := FindDefaultKeySize(LCanonicalName);
  if LDefaultKeySize = -1 then
    raise ESecurityUtilityCryptoLibException.CreateResFmt(@SKeyGeneratorAlgorithmNotSupported, [AAlgorithm, LCanonicalName]);
  Result := TCipherKeyGenerator.Create(LDefaultKeySize);
end;

class function TGeneratorUtilities.GetKeyPairGenerator(const AAlgorithm: String): IAsymmetricCipherKeyPairGenerator;
var
  LCanonicalName: String;
begin
  LCanonicalName := GetCanonicalKeyPairGeneratorAlgorithm(AAlgorithm);
  if LCanonicalName = '' then
    raise ESecurityUtilityCryptoLibException.CreateResFmt(@SKeyPairGeneratorAlgorithmNotRecognised, [AAlgorithm]);

  if LCanonicalName = 'DH' then
  begin
    Result := TDHKeyPairGenerator.Create() as IDHKeyPairGenerator;
    Exit;
  end;
  if LCanonicalName = 'DSA' then
  begin
    Result := TDsaKeyPairGenerator.Create() as IDsaKeyPairGenerator;
    Exit;
  end;
  if (LCanonicalName = 'RSA') or (LCanonicalName = 'RSASSA-PSS') then
  begin
    Result := TRsaKeyPairGenerator.Create() as IRsaKeyPairGenerator;
    Exit;
  end;
  if TStringUtilities.StartsWith(LCanonicalName, 'EC', True) then
  begin
    Result := TECKeyPairGenerator.Create(LCanonicalName) as IECKeyPairGenerator;
    Exit;
  end;
  if LCanonicalName = 'Ed25519' then
  begin
    Result := TEd25519KeyPairGenerator.Create(TEd25519.Create() as IEd25519) as IEd25519KeyPairGenerator;
    Exit;
  end;
  if LCanonicalName = 'X25519' then
  begin
    Result := TX25519KeyPairGenerator.Create() as IX25519KeyPairGenerator;
    Exit;
  end;

  raise ESecurityUtilityCryptoLibException.CreateResFmt(@SKeyPairGeneratorAlgorithmNotSupported, [AAlgorithm, LCanonicalName]);
end;

class function TGeneratorUtilities.GetKeyPairGenerator(const AOid: IDerObjectIdentifier): IAsymmetricCipherKeyPairGenerator;
begin
  Result := GetKeyPairGenerator(AOid.ID);
end;

end.
