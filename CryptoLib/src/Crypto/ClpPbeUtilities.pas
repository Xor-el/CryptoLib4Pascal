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

unit ClpPbeUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Rtti,
  Generics.Collections,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpCryptoLibTypes,
  ClpIAsn1Core,
  ClpIDigest,
  ClpICipherParameters,
  ClpIBufferedCipher,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpPkcsAsn1Objects,
  ClpIPkcsAsn1Objects,
  ClpPkcsObjectIdentifiers,
  ClpNistObjectIdentifiers,
  ClpBcObjectIdentifiers,
  ClpOiwObjectIdentifiers,
  ClpTeleTrusTObjectIdentifiers,
  ClpCipherUtilities,
  ClpDigestUtilities,
  ClpMacUtilities,
  ClpIMac,
  ClpGeneratorUtilities,
  ClpParameterUtilities,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpPbeParametersGenerator,
  ClpIPbeParametersGenerator,
  ClpPkcs5S2ParametersGenerator,
  ClpPkcs5S1ParametersGenerator,
  ClpPkcs12ParametersGenerator,
  ClpOpenSslPbeParametersGenerator,
  ClpCryptoLibComparers,
  ClpCollectionUtilities,
  ClpStringUtilities,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpArrayUtilities;

type
  /// <summary>
  /// PBE utilities for creating ciphers and generating cipher parameters
  /// from algorithm identifiers (e.g. PBES2 for PKCS#8 encrypted private keys).
  /// </summary>
  TPbeUtilities = class sealed(TObject)
  strict private
  const
    Pkcs5S1 = 'Pkcs5S1';
    Pkcs5S2 = 'Pkcs5S2';
    Pkcs12 = 'Pkcs12';
    OpenSsl = 'OpenSsl';
  class var
    FIsBooted: Boolean;
    FAlgorithms: TDictionary<String, String>;
    FAlgorithmType: TDictionary<String, String>;
    FOids: TDictionary<String, IDerObjectIdentifier>;
  class constructor Create;
  class destructor Destroy;
  strict private
    class procedure Boot; static;
    class function MakePbeGenerator(const AType: String; const ADigest: IDigest;
      const AKey: TCryptoLibByteArray; const ASalt: TCryptoLibByteArray;
      AIterationCount: Int32): IPbeParametersGenerator; static;
  public
    class function IsPkcs12(const AAlgorithm: String): Boolean; static;
    class function IsPkcs5Scheme1(const AAlgorithm: String): Boolean; static;
    class function IsPkcs5Scheme2(const AAlgorithm: String): Boolean; static;
    class function IsOpenSsl(const AAlgorithm: String): Boolean; static;
    class function IsPbes2Cipher(const AAlgorithm: String): Boolean; static;
    class function IsPbeAlgorithm(const AAlgorithm: String): Boolean; static;
    class function GetObjectIdentifier(const AMechanism: String): IDerObjectIdentifier; static;
    class function GetEncodingName(const AOid: IDerObjectIdentifier): String; static;

    /// <summary>
    /// Create a cipher or MAC engine for the given PBE algorithm (string).
    /// Returns TValue containing IMac for PBEwithHmac*, IBufferedCipher for ciphers, or TValue.Empty.
    /// Caller should use Result.TryAsType&lt;IBufferedCipher&gt;(LCipher) or Result.TryAsType&lt;IMac&gt;(LMac).
    /// </summary>
    class function CreateEngine(const AAlgorithm: String): TValue; overload; static;
    /// <summary>
    /// Create a cipher or MAC engine for the given PBE algorithm OID.
    /// </summary>
    class function CreateEngine(const AAlgorithmOid: IDerObjectIdentifier): TValue; overload; static;
    /// <summary>
    /// Create a cipher or MAC engine for the given PBE algorithm identifier.
    /// For PBES2, returns the underlying block cipher (e.g. AES/CBC).
    /// </summary>
    class function CreateEngine(const AAlgID: IAlgorithmIdentifier): TValue; overload; static;

    /// <summary>
    /// Generate algorithm parameters for the given algorithm (salt, iteration count).
    /// </summary>
    class function GenerateAlgorithmParameters(const AAlgorithm: String;
      const ASalt: TCryptoLibByteArray; AIterationCount: Int32): IAsn1Encodable; overload; static;
    /// <summary>
    /// Generate algorithm parameters for the given algorithm OID.
    /// </summary>
    class function GenerateAlgorithmParameters(const AAlgorithmOid: IDerObjectIdentifier;
      const ASalt: TCryptoLibByteArray; AIterationCount: Int32): IAsn1Encodable; overload; static;
    /// <summary>
    /// Generate PBES2 algorithm parameters (cipher + hash OIDs, salt, count, random).
    /// </summary>
    class function GenerateAlgorithmParameters(const ACipherAlgorithm, AHashAlgorithm: IDerObjectIdentifier;
      const ASalt: TCryptoLibByteArray; AIterationCount: Int32;
      const ARandom: ISecureRandom): IAsn1Encodable; overload; static;

    /// <summary>
    /// Generate cipher parameters (OID + password + params).
    /// </summary>
    class function GenerateCipherParameters(const AAlgorithmOid: IDerObjectIdentifier;
      const APassword: TCryptoLibCharArray; const APbeParameters: IAsn1Encodable): ICipherParameters; overload; static;
    /// <summary>
    /// Generate cipher parameters (OID + password + wrongPkcs12Zero + params).
    /// </summary>
    class function GenerateCipherParameters(const AAlgorithmOid: IDerObjectIdentifier;
      const APassword: TCryptoLibCharArray; AWrongPkcs12Zero: Boolean;
      const APbeParameters: IAsn1Encodable): ICipherParameters; overload; static;
    /// <summary>
    /// Generate cipher parameters (algorithm identifier + password).
    /// </summary>
    class function GenerateCipherParameters(const AAlgID: IAlgorithmIdentifier;
      const APassword: TCryptoLibCharArray): ICipherParameters; overload; static;
    /// <summary>
    /// Generate cipher parameters (algorithm identifier + password + wrongPkcs12Zero).
    /// </summary>
    class function GenerateCipherParameters(const AAlgID: IAlgorithmIdentifier;
      const APassword: TCryptoLibCharArray; AWrongPkcs12Zero: Boolean): ICipherParameters; overload; static;
    /// <summary>
    /// Generate cipher parameters (algorithm string + password + params).
    /// </summary>
    class function GenerateCipherParameters(const AAlgorithm: String;
      const APassword: TCryptoLibCharArray; const APbeParameters: IAsn1Encodable): ICipherParameters; overload; static;
    /// <summary>
    /// Generate cipher parameters (algorithm string + password + wrongPkcs12Zero + params).
    /// </summary>
    class function GenerateCipherParameters(const AAlgorithm: String;
      const APassword: TCryptoLibCharArray; AWrongPkcs12Zero: Boolean;
      const APbeParameters: IAsn1Encodable): ICipherParameters; overload; static;
  end;

implementation

class constructor TPbeUtilities.Create;
begin
  Boot;
end;

class procedure TPbeUtilities.Boot;
begin
  if FIsBooted then
    Exit;

  FAlgorithms := TDictionary<String, String>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FAlgorithmType := TDictionary<String, String>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FOids := TDictionary<String, IDerObjectIdentifier>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);

  FAlgorithms.AddOrSetValue('PKCS5SCHEME1', 'Pkcs5scheme1');
  FAlgorithms.AddOrSetValue('PKCS5SCHEME2', 'Pkcs5scheme2');
  FAlgorithms.AddOrSetValue('PBKDF2', 'Pkcs5scheme2');
  FAlgorithms.AddOrSetValue(TPkcsObjectIdentifiers.IdPbeS2.Id, 'Pkcs5scheme2');

  FAlgorithms.AddOrSetValue('PKCS12', 'Pkcs12');
  FAlgorithms.AddOrSetValue(TBcObjectIdentifiers.BcPbeSha1Pkcs12Aes128Cbc.Id, 'PBEwithSHA-1and128bitAES-CBC-BC');
  FAlgorithms.AddOrSetValue(TBcObjectIdentifiers.BcPbeSha1Pkcs12Aes192Cbc.Id, 'PBEwithSHA-1and192bitAES-CBC-BC');
  FAlgorithms.AddOrSetValue(TBcObjectIdentifiers.BcPbeSha1Pkcs12Aes256Cbc.Id, 'PBEwithSHA-1and256bitAES-CBC-BC');
  FAlgorithms.AddOrSetValue(TBcObjectIdentifiers.BcPbeSha256Pkcs12Aes128Cbc.Id, 'PBEwithSHA-256and128bitAES-CBC-BC');
  FAlgorithms.AddOrSetValue(TBcObjectIdentifiers.BcPbeSha256Pkcs12Aes192Cbc.Id, 'PBEwithSHA-256and192bitAES-CBC-BC');
  FAlgorithms.AddOrSetValue(TBcObjectIdentifiers.BcPbeSha256Pkcs12Aes256Cbc.Id, 'PBEwithSHA-256and256bitAES-CBC-BC');
  FAlgorithms.AddOrSetValue('PBEWITHSHAAND128BITAES-CBC-BC', 'PBEwithSHA-1and128bitAES-CBC-BC');
  FAlgorithms.AddOrSetValue('PBEWITHSHA1AND128BITAES-CBC-BC', 'PBEwithSHA-1and128bitAES-CBC-BC');
  FAlgorithms.AddOrSetValue('PBEWITHSHA-1AND128BITAES-CBC-BC', 'PBEwithSHA-1and128bitAES-CBC-BC');
  FAlgorithms.AddOrSetValue('PBEWITHSHAAND192BITAES-CBC-BC', 'PBEwithSHA-1and192bitAES-CBC-BC');
  FAlgorithms.AddOrSetValue('PBEWITHSHA1AND192BITAES-CBC-BC', 'PBEwithSHA-1and192bitAES-CBC-BC');
  FAlgorithms.AddOrSetValue('PBEWITHSHA-1AND192BITAES-CBC-BC', 'PBEwithSHA-1and192bitAES-CBC-BC');
  FAlgorithms.AddOrSetValue('PBEWITHSHAAND256BITAES-CBC-BC', 'PBEwithSHA-1and256bitAES-CBC-BC');
  FAlgorithms.AddOrSetValue('PBEWITHSHA1AND256BITAES-CBC-BC', 'PBEwithSHA-1and256bitAES-CBC-BC');
  FAlgorithms.AddOrSetValue('PBEWITHSHA-1AND256BITAES-CBC-BC', 'PBEwithSHA-1and256bitAES-CBC-BC');
  FAlgorithms.AddOrSetValue('PBEWITHSHA256AND128BITAES-CBC-BC', 'PBEwithSHA-256and128bitAES-CBC-BC');
  FAlgorithms.AddOrSetValue('PBEWITHSHA-256AND128BITAES-CBC-BC', 'PBEwithSHA-256and128bitAES-CBC-BC');
  FAlgorithms.AddOrSetValue('PBEWITHSHA256AND192BITAES-CBC-BC', 'PBEwithSHA-256and192bitAES-CBC-BC');
  FAlgorithms.AddOrSetValue('PBEWITHSHA-256AND192BITAES-CBC-BC', 'PBEwithSHA-256and192bitAES-CBC-BC');
  FAlgorithms.AddOrSetValue('PBEWITHSHA256AND256BITAES-CBC-BC', 'PBEwithSHA-256and256bitAES-CBC-BC');
  FAlgorithms.AddOrSetValue('PBEWITHSHA-256AND256BITAES-CBC-BC', 'PBEwithSHA-256and256bitAES-CBC-BC');

  FAlgorithms.AddOrSetValue('PBEWITHHMACSHA1', 'PBEwithHmacSHA-1');
  FAlgorithms.AddOrSetValue('PBEWITHHMACSHA-1', 'PBEwithHmacSHA-1');
  FAlgorithms.AddOrSetValue(TOiwObjectIdentifiers.IdSha1.Id, 'PBEwithHmacSHA-1');
  FAlgorithms.AddOrSetValue('PBEWITHHMACSHA224', 'PBEwithHmacSHA-224');
  FAlgorithms.AddOrSetValue('PBEWITHHMACSHA-224', 'PBEwithHmacSHA-224');
  FAlgorithms.AddOrSetValue(TNistObjectIdentifiers.IdSha224.Id, 'PBEwithHmacSHA-224');
  FAlgorithms.AddOrSetValue('PBEWITHHMACSHA256', 'PBEwithHmacSHA-256');
  FAlgorithms.AddOrSetValue('PBEWITHHMACSHA-256', 'PBEwithHmacSHA-256');
  FAlgorithms.AddOrSetValue(TNistObjectIdentifiers.IdSha256.Id, 'PBEwithHmacSHA-256');
  FAlgorithms.AddOrSetValue('PBEWITHHMACSHA384', 'PBEwithHmacSHA-384');
  FAlgorithms.AddOrSetValue('PBEWITHHMACSHA-384', 'PBEwithHmacSHA-384');
  FAlgorithms.AddOrSetValue(TNistObjectIdentifiers.IdSha384.Id, 'PBEwithHmacSHA-384');
  FAlgorithms.AddOrSetValue('PBEWITHHMACSHA512', 'PBEwithHmacSHA-512');
  FAlgorithms.AddOrSetValue('PBEWITHHMACSHA-512', 'PBEwithHmacSHA-512');
  FAlgorithms.AddOrSetValue(TNistObjectIdentifiers.IdSha512.Id, 'PBEwithHmacSHA-512');
  FAlgorithms.AddOrSetValue('PBEWITHHMACRIPEMD128', 'PBEwithHmacRipeMD128');
  FAlgorithms.AddOrSetValue(TTeleTrusTObjectIdentifiers.RipeMD128.Id, 'PBEwithHmacRipeMD128');
  FAlgorithms.AddOrSetValue('PBEWITHHMACRIPEMD160', 'PBEwithHmacRipeMD160');
  FAlgorithms.AddOrSetValue(TTeleTrusTObjectIdentifiers.RipeMD160.Id, 'PBEwithHmacRipeMD160');
  FAlgorithms.AddOrSetValue('PBEWITHHMACRIPEMD256', 'PBEwithHmacRipeMD256');
  FAlgorithms.AddOrSetValue(TTeleTrusTObjectIdentifiers.RipeMD256.Id, 'PBEwithHmacRipeMD256');
  FAlgorithms.AddOrSetValue('PBEWITHHMACTIGER', 'PBEwithHmacTiger');

  FAlgorithms.AddOrSetValue('PBEWITHMD5AND128BITAES-CBC-OPENSSL', 'PBEwithMD5and128bitAES-CBC-OpenSSL');
  FAlgorithms.AddOrSetValue('PBEWITHMD5AND192BITAES-CBC-OPENSSL', 'PBEwithMD5and192bitAES-CBC-OpenSSL');
  FAlgorithms.AddOrSetValue('PBEWITHMD5AND256BITAES-CBC-OPENSSL', 'PBEwithMD5and256bitAES-CBC-OpenSSL');

  FAlgorithmType.AddOrSetValue('Pkcs5scheme1', Pkcs5S1);
  FAlgorithmType.AddOrSetValue('Pkcs5scheme2', Pkcs5S2);
  FAlgorithmType.AddOrSetValue('Pkcs12', Pkcs12);
  FAlgorithmType.AddOrSetValue('PBEwithSHA-1and128bitAES-CBC-BC', Pkcs12);
  FAlgorithmType.AddOrSetValue('PBEwithSHA-1and192bitAES-CBC-BC', Pkcs12);
  FAlgorithmType.AddOrSetValue('PBEwithSHA-1and256bitAES-CBC-BC', Pkcs12);
  FAlgorithmType.AddOrSetValue('PBEwithSHA-256and128bitAES-CBC-BC', Pkcs12);
  FAlgorithmType.AddOrSetValue('PBEwithSHA-256and192bitAES-CBC-BC', Pkcs12);
  FAlgorithmType.AddOrSetValue('PBEwithSHA-256and256bitAES-CBC-BC', Pkcs12);
  FAlgorithmType.AddOrSetValue('PBEwithHmacSHA-1', Pkcs12);
  FAlgorithmType.AddOrSetValue('PBEwithHmacSHA-224', Pkcs12);
  FAlgorithmType.AddOrSetValue('PBEwithHmacSHA-256', Pkcs12);
  FAlgorithmType.AddOrSetValue('PBEwithHmacSHA-384', Pkcs12);
  FAlgorithmType.AddOrSetValue('PBEwithHmacSHA-512', Pkcs12);
  FAlgorithmType.AddOrSetValue('PBEwithHmacRipeMD128', Pkcs12);
  FAlgorithmType.AddOrSetValue('PBEwithHmacRipeMD160', Pkcs12);
  FAlgorithmType.AddOrSetValue('PBEwithHmacRipeMD256', Pkcs12);
  FAlgorithmType.AddOrSetValue('PBEwithHmacTiger', Pkcs12);

  FAlgorithmType.AddOrSetValue('PBEwithMD5and128bitAES-CBC-OpenSSL', OpenSsl);
  FAlgorithmType.AddOrSetValue('PBEwithMD5and192bitAES-CBC-OpenSSL', OpenSsl);
  FAlgorithmType.AddOrSetValue('PBEwithMD5and256bitAES-CBC-OpenSSL', OpenSsl);

  FOids.AddOrSetValue('PBEwithHmacSHA-1', TOiwObjectIdentifiers.IdSha1);
  FOids.AddOrSetValue('PBEwithHmacSHA-224', TNistObjectIdentifiers.IdSha224);
  FOids.AddOrSetValue('PBEwithHmacSHA-256', TNistObjectIdentifiers.IdSha256);
  FOids.AddOrSetValue('PBEwithHmacSHA-384', TNistObjectIdentifiers.IdSha384);
  FOids.AddOrSetValue('PBEwithHmacSHA-512', TNistObjectIdentifiers.IdSha512);
  FOids.AddOrSetValue('PBEwithHmacRipeMD128', TTeleTrusTObjectIdentifiers.RipeMD128);
  FOids.AddOrSetValue('PBEwithHmacRipeMD160', TTeleTrusTObjectIdentifiers.RipeMD160);
  FOids.AddOrSetValue('PBEwithHmacRipeMD256', TTeleTrusTObjectIdentifiers.RipeMD256);
  FOids.AddOrSetValue('Pkcs5scheme2', TPkcsObjectIdentifiers.IdPbeS2);

  FIsBooted := True;
end;

class destructor TPbeUtilities.Destroy;
begin
  FAlgorithms.Free;
  FAlgorithmType.Free;
  FOids.Free;
end;

class function TPbeUtilities.MakePbeGenerator(const AType: String; const ADigest: IDigest;
  const AKey: TCryptoLibByteArray; const ASalt: TCryptoLibByteArray;
  AIterationCount: Int32): IPbeParametersGenerator;
var
  LGen: IPbeParametersGenerator;
begin
  if AType = Pkcs5S1 then
    LGen := TPkcs5S1ParametersGenerator.Create(ADigest)
  else if AType = Pkcs5S2 then
    LGen := TPkcs5S2ParametersGenerator.Create(ADigest)
  else if AType = Pkcs12 then
    LGen := TPkcs12ParametersGenerator.Create(ADigest)
  else if AType = OpenSsl then
    LGen := TOpenSslPbeParametersGenerator.Create()
  else
    raise EArgumentCryptoLibException.Create('Unknown PBE type: ' + AType);
  LGen.Init(AKey, ASalt, AIterationCount);
  Result := LGen;
end;

class function TPbeUtilities.IsPkcs12(const AAlgorithm: String): Boolean;
var
  LMechanism, LAlgType: String;
begin
  Result := False;
  if not FAlgorithms.TryGetValue(AAlgorithm, LMechanism) then
    Exit;
  if not FAlgorithmType.TryGetValue(LMechanism, LAlgType) then
    Exit;
  Result := Pkcs12 = LAlgType;
end;

class function TPbeUtilities.IsPkcs5Scheme1(const AAlgorithm: String): Boolean;
var
  LMechanism, LAlgType: String;
begin
  Result := False;
  if not FAlgorithms.TryGetValue(AAlgorithm, LMechanism) then
    Exit;
  if not FAlgorithmType.TryGetValue(LMechanism, LAlgType) then
    Exit;
  Result := Pkcs5S1 = LAlgType;
end;

class function TPbeUtilities.IsPkcs5Scheme2(const AAlgorithm: String): Boolean;
var
  LMechanism, LAlgType: String;
begin
  Result := False;
  if not FAlgorithms.TryGetValue(AAlgorithm, LMechanism) then
    Exit;
  if not FAlgorithmType.TryGetValue(LMechanism, LAlgType) then
    Exit;
  Result := Pkcs5S2 = LAlgType;
end;

class function TPbeUtilities.IsOpenSsl(const AAlgorithm: String): Boolean;
var
  LMechanism, LAlgType: String;
begin
  Result := False;
  if not FAlgorithms.TryGetValue(AAlgorithm, LMechanism) then
    Exit;
  if not FAlgorithmType.TryGetValue(LMechanism, LAlgType) then
    Exit;
  Result := OpenSsl = LAlgType;
end;

class function TPbeUtilities.IsPbes2Cipher(const AAlgorithm: String): Boolean;
var
  LOidAlgorithm: IDerObjectIdentifier;
begin
  if not TDerObjectIdentifier.TryFromID(AAlgorithm, LOidAlgorithm) then
   raise EArgumentCryptoLibException.Create('Invalid Object Identifier ' + AAlgorithm);

  Result := LOidAlgorithm.Equals(TNistObjectIdentifiers.IdAes128Cbc)
   or LOidAlgorithm.Equals(TNistObjectIdentifiers.IdAes192Cbc)
   or LOidAlgorithm.Equals(TNistObjectIdentifiers.IdAes256Cbc);
end;

class function TPbeUtilities.IsPbeAlgorithm(const AAlgorithm: String): Boolean;
var
  LMechanism: String;
begin
  Result := FAlgorithms.TryGetValue(AAlgorithm, LMechanism) and
    FAlgorithmType.ContainsKey(LMechanism);
end;

class function TPbeUtilities.GetObjectIdentifier(const AMechanism: String): IDerObjectIdentifier;
var
  LAlgorithm: String;
begin
  if not FAlgorithms.TryGetValue(AMechanism, LAlgorithm) then
    Result := nil
  else
    Result := TCollectionUtilities.GetValueOrNull<String, IDerObjectIdentifier>(FOids, LAlgorithm);
end;

class function TPbeUtilities.GetEncodingName(const AOid: IDerObjectIdentifier): String;
begin
  if AOid = nil then
    Result := ''
  else
    Result := TCollectionUtilities.GetValueOrNull<String, String>(FAlgorithms, AOid.Id);
end;

class function TPbeUtilities.CreateEngine(const AAlgorithm: String): TValue;
var
  LMechanism, LDigestName: String;
  LCipher: IBufferedCipher;
  LMac: IMac;
begin
  Result := TValue.Empty;

  LMechanism := TCollectionUtilities.GetValueOrNull<String, String>(FAlgorithms, AAlgorithm);
  if LMechanism = '' then
    Exit;
  if TStringUtilities.StartsWith(LMechanism, 'PBEwithHmac') then
  begin
    LDigestName := TStringUtilities.Substring(LMechanism, 12);
    LMac := TMacUtilities.GetMac('HMAC/' + LDigestName);
    if LMac <> nil then
      Result := TValue.From<IMac>(LMac);
    Exit;
  end;

  if TStringUtilities.StartsWith(LMechanism, 'PBEwithMD2') or
     TStringUtilities.StartsWith(LMechanism, 'PBEwithMD5') or
     TStringUtilities.StartsWith(LMechanism, 'PBEwithSHA-1') or
     TStringUtilities.StartsWith(LMechanism, 'PBEwithSHA-256') then
  begin
    if TStringUtilities.EndsWith(LMechanism, 'AES-CBC-BC') or
       TStringUtilities.EndsWith(LMechanism, 'AES-CBC-OPENSSL') then
      LCipher := TCipherUtilities.GetCipher('AES/CBC');

    if LCipher <> nil then
      Result := TValue.From<IBufferedCipher>(LCipher);
  end;
end;

class function TPbeUtilities.CreateEngine(const AAlgorithmOid: IDerObjectIdentifier): TValue;
begin
  if AAlgorithmOid = nil then
    Result := TValue.Empty
  else
    Result := CreateEngine(AAlgorithmOid.Id);
end;

class function TPbeUtilities.CreateEngine(const AAlgID: IAlgorithmIdentifier): TValue;
var
  LS2P: IPbeS2Parameters;
  LEncScheme: IEncryptionScheme;
  LCipher: IBufferedCipher;
  LAlgorithm: String;
begin
  Result := TValue.Empty;
  if AAlgID = nil then
    Exit;

  LAlgorithm := AAlgID.Algorithm.Id;

  if IsPkcs5Scheme2(LAlgorithm) then
  begin
    if AAlgID.Parameters = nil then
      Exit;

    LS2P := TPbeS2Parameters.GetInstance(AAlgID.Parameters.ToAsn1Object());
    if LS2P <> nil then
    begin
      LEncScheme := LS2P.EncryptionScheme;
      if LEncScheme <> nil then
      begin
        LCipher := TCipherUtilities.GetCipher(LEncScheme.Algorithm);
        if LCipher <> nil then
          Result := TValue.From<IBufferedCipher>(LCipher);
      end;
    end;
    Exit;
  end;
  Result := CreateEngine(LAlgorithm);
end;

class function TPbeUtilities.GenerateAlgorithmParameters(const AAlgorithm: String;
  const ASalt: TCryptoLibByteArray; AIterationCount: Int32): IAsn1Encodable;
begin
  if IsPkcs12(AAlgorithm) then
    Result := TPkcs12PbeParams.Create(ASalt, AIterationCount)
  else if IsPkcs5Scheme2(AAlgorithm) then
    Result := TPbkdf2Params.Create(ASalt, AIterationCount)
  else
    Result := TPbeParameter.Create(ASalt, AIterationCount);
end;

class function TPbeUtilities.GenerateAlgorithmParameters(const AAlgorithmOid: IDerObjectIdentifier;
  const ASalt: TCryptoLibByteArray; AIterationCount: Int32): IAsn1Encodable;
begin
  if AAlgorithmOid = nil then
    raise EArgumentNilCryptoLibException.Create('algorithmOid');
  Result := GenerateAlgorithmParameters(AAlgorithmOid.Id, ASalt, AIterationCount);
end;

class function TPbeUtilities.GenerateAlgorithmParameters(const ACipherAlgorithm, AHashAlgorithm: IDerObjectIdentifier;
  const ASalt: TCryptoLibByteArray; AIterationCount: Int32;
  const ARandom: ISecureRandom): IAsn1Encodable;
var
  LEncScheme: IEncryptionScheme;
  LKeyDerivFunc: IKeyDerivationFunc;
  LPbkdf2Params: IPbkdf2Params;
  LPrf: IAlgorithmIdentifier;
  LIV: TCryptoLibByteArray;
begin
  if (ACipherAlgorithm = nil) or (AHashAlgorithm = nil) or (ARandom = nil) then
    raise EArgumentNilCryptoLibException.Create('cipherAlgorithm, hashAlgorithm and random must be non-nil');

  if TNistObjectIdentifiers.IdAes128Cbc.Id.Equals(ACipherAlgorithm.Id) or
     TNistObjectIdentifiers.IdAes192Cbc.Id.Equals(ACipherAlgorithm.Id) or
     TNistObjectIdentifiers.IdAes256Cbc.Id.Equals(ACipherAlgorithm.Id) or
     TNistObjectIdentifiers.IdAes128Cfb.Id.Equals(ACipherAlgorithm.Id) or
     TNistObjectIdentifiers.IdAes192Cfb.Id.Equals(ACipherAlgorithm.Id) or
     TNistObjectIdentifiers.IdAes256Cfb.Id.Equals(ACipherAlgorithm.Id) then
  begin
    System.SetLength(LIV, 16);
    ARandom.NextBytes(LIV);
    LEncScheme := TEncryptionScheme.Create(ACipherAlgorithm, TDerOctetString.FromContents(LIV));
  end
  else
  begin
    raise EArgumentCryptoLibException.Create('unknown cipher: ' + ACipherAlgorithm.Id);
  end;

  LPrf := TAlgorithmIdentifier.Create(AHashAlgorithm, TDerNull.Instance);
  LPbkdf2Params := TPbkdf2Params.Create(ASalt, AIterationCount, LPrf);
  LKeyDerivFunc := TKeyDerivationFunc.Create(TPkcsObjectIdentifiers.IdPbkdf2, LPbkdf2Params);
  Result := TPbeS2Parameters.Create(LKeyDerivFunc, LEncScheme);
end;

class function TPbeUtilities.GenerateCipherParameters(const AAlgorithmOid: IDerObjectIdentifier;
  const APassword: TCryptoLibCharArray; const APbeParameters: IAsn1Encodable): ICipherParameters;
begin
  Result := GenerateCipherParameters(AAlgorithmOid, APassword, False, APbeParameters);
end;

class function TPbeUtilities.GenerateCipherParameters(const AAlgorithmOid: IDerObjectIdentifier;
  const APassword: TCryptoLibCharArray; AWrongPkcs12Zero: Boolean;
  const APbeParameters: IAsn1Encodable): ICipherParameters;
begin
  if AAlgorithmOid = nil then
    raise EArgumentNilCryptoLibException.Create('algorithmOid');
  Result := GenerateCipherParameters(AAlgorithmOid.Id, APassword, AWrongPkcs12Zero, APbeParameters);
end;

class function TPbeUtilities.GenerateCipherParameters(const AAlgID: IAlgorithmIdentifier;
  const APassword: TCryptoLibCharArray): ICipherParameters;
begin
  Result := GenerateCipherParameters(AAlgID.Algorithm.Id, APassword, False, AAlgID.Parameters);
end;

class function TPbeUtilities.GenerateCipherParameters(const AAlgID: IAlgorithmIdentifier;
  const APassword: TCryptoLibCharArray; AWrongPkcs12Zero: Boolean): ICipherParameters;
begin
  if AAlgID = nil then
    raise EArgumentNilCryptoLibException.Create('algID');

  Result := GenerateCipherParameters(AAlgID.Algorithm.Id, APassword, AWrongPkcs12Zero, AAlgID.Parameters);
end;

class function TPbeUtilities.GenerateCipherParameters(const AAlgorithm: String;
  const APassword: TCryptoLibCharArray; const APbeParameters: IAsn1Encodable): ICipherParameters;
begin
  Result := GenerateCipherParameters(AAlgorithm, APassword, False, APbeParameters);
end;

class function TPbeUtilities.GenerateCipherParameters(const AAlgorithm: String;
  const APassword: TCryptoLibCharArray; AWrongPkcs12Zero: Boolean;
  const APbeParameters: IAsn1Encodable): ICipherParameters;
var
  LMechanism, LDigestName: String;
  LKeyBytes, LSalt, LIv: TCryptoLibByteArray;
  LIterationCount, LKeyLength, LBitLen: Int32;
  LPkcs12PbeParams: IPkcs12PbeParams;
  LPbeParam: IPbeParameter;
  LParameters: ICipherParameters;
  LS2P: IPbeS2Parameters;
  LEncScheme: IEncryptionScheme;
  LEncOid: IDerObjectIdentifier;
  LEncParams: IAsn1Object;
  LPbkdf2Params: IPbkdf2Params;
  LDigest: IDigest;
  LKeyLengthObject: IDerInteger;
  LGen, LGenerator: IPbeParametersGenerator;
begin
  if AAlgorithm = '' then
    raise EArgumentNilCryptoLibException.Create('algorithm');

  LMechanism := TCollectionUtilities.GetValueOrNull<String, String>(FAlgorithms, AAlgorithm);
  if LMechanism = '' then
    raise ESecurityUtilityCryptoLibException.Create('Algorithm ' + AAlgorithm + ' not recognised.');

  LKeyBytes := nil;
  LSalt := nil;
  LIterationCount := 0;

  if IsPkcs12(LMechanism) then
  begin
    LPkcs12PbeParams := TPkcs12PbeParams.GetInstance(APbeParameters);
    LSalt := LPkcs12PbeParams.IV.GetOctets();
    LIterationCount := LPkcs12PbeParams.IterationsObject.IntValueExact;
    LKeyBytes := TPbeParametersGenerator.Pkcs12PasswordToBytes(APassword, AWrongPkcs12Zero);
  end
  else if IsPkcs5Scheme2(LMechanism) then
  begin
    // See below
  end
  else
  begin
    LPbeParam := TPbeParameter.GetInstance(APbeParameters);
    LSalt := LPbeParam.Salt.GetOctets();
    LIterationCount := LPbeParam.IterationCountObject.IntValueExact;
    LKeyBytes := TPbeParametersGenerator.Pkcs5PasswordToBytes(APassword);
  end;

  LParameters := nil;

  if IsPkcs5Scheme2(LMechanism) then
  begin
    LS2P := TPbeS2Parameters.GetInstance(APbeParameters.ToAsn1Object());
    LEncScheme := LS2P.EncryptionScheme;
    LEncOid := LEncScheme.Algorithm;
    LEncParams := LEncScheme.Parameters.ToAsn1Object();

    LPbkdf2Params := TPbkdf2Params.GetInstance(LS2P.KeyDerivationFunc.Parameters);
    LDigest := TDigestUtilities.GetDigest(LPbkdf2Params.Prf.Algorithm);

    LIv := TAsn1OctetString.GetInstance(LEncParams).GetOctets();

    LSalt := LPbkdf2Params.GetSaltBytes();
    LIterationCount := LPbkdf2Params.IterationCountObject.IntValueExact;
    LKeyBytes := TPbeParametersGenerator.Pkcs5PasswordToBytes(APassword);

    LKeyLengthObject := LPbkdf2Params.KeyLengthObject;
    if LKeyLengthObject <> nil then
      LKeyLength := LKeyLengthObject.IntValueExact * 8
    else
      LKeyLength := TGeneratorUtilities.GetDefaultKeySize(LEncOid);

    LGen := MakePbeGenerator(FAlgorithmType[LMechanism], LDigest, LKeyBytes, LSalt, LIterationCount);

    LParameters := LGen.GenerateDerivedParameters(LEncOid.Id, LKeyLength);

    if LIv <> nil then
    begin
      if TArrayUtilities.AreAllZeroes(LIv, 0, System.Length(LIv)) then
      begin
        // FIXME? OpenSSL weirdness with IV of zeros (for ECB keys?)
      end
      else
      begin
        LParameters := TParametersWithIV.Create(LParameters, LIv);
      end;
    end;
  end
  else if TStringUtilities.StartsWith(LMechanism, 'PBEwithSHA-1') then
  begin
    LGenerator := MakePbeGenerator(FAlgorithmType[LMechanism],
      TDigestUtilities.GetDigest('SHA-1'), LKeyBytes, LSalt, LIterationCount);

    if LMechanism = 'PBEwithSHA-1and128bitAES-CBC-BC' then
      LParameters := LGenerator.GenerateDerivedParameters('AES', 128, 128)
    else if LMechanism = 'PBEwithSHA-1and192bitAES-CBC-BC' then
      LParameters := LGenerator.GenerateDerivedParameters('AES', 192, 128)
    else if LMechanism = 'PBEwithSHA-1and256bitAES-CBC-BC' then
      LParameters := LGenerator.GenerateDerivedParameters('AES', 256, 128);
  end
  else if TStringUtilities.StartsWith(LMechanism, 'PBEwithSHA-256') then
  begin
    LGenerator := MakePbeGenerator(FAlgorithmType[LMechanism],
      TDigestUtilities.GetDigest('SHA-256'), LKeyBytes, LSalt, LIterationCount);

    if LMechanism = 'PBEwithSHA-256and128bitAES-CBC-BC' then
      LParameters := LGenerator.GenerateDerivedParameters('AES', 128, 128)
    else if LMechanism = 'PBEwithSHA-256and192bitAES-CBC-BC' then
      LParameters := LGenerator.GenerateDerivedParameters('AES', 192, 128)
    else if LMechanism = 'PBEwithSHA-256and256bitAES-CBC-BC' then
      LParameters := LGenerator.GenerateDerivedParameters('AES', 256, 128);
  end
  else if TStringUtilities.StartsWith(LMechanism, 'PBEwithMD5') then
  begin
    LGenerator := MakePbeGenerator(FAlgorithmType[LMechanism],
      TDigestUtilities.GetDigest('MD5'), LKeyBytes, LSalt, LIterationCount);

    if LMechanism = 'PBEwithMD5and128bitAES-CBC-OpenSSL' then
      LParameters := LGenerator.GenerateDerivedParameters('AES', 128, 128)
    else if LMechanism = 'PBEwithMD5and192bitAES-CBC-OpenSSL' then
      LParameters := LGenerator.GenerateDerivedParameters('AES', 192, 128)
    else if LMechanism = 'PBEwithMD5and256bitAES-CBC-OpenSSL' then
      LParameters := LGenerator.GenerateDerivedParameters('AES', 256, 128);
  end
  else if TStringUtilities.StartsWith(LMechanism, 'PBEwithHmac') then
  begin
    LDigestName := TStringUtilities.Substring(LMechanism, 12);
    LDigest := TDigestUtilities.GetDigest(LDigestName);

    LGenerator := MakePbeGenerator(FAlgorithmType[LMechanism],
      LDigest, LKeyBytes, LSalt, LIterationCount);

    LBitLen := LDigest.GetDigestSize() * 8;
    LParameters := LGenerator.GenerateDerivedMacParameters(LBitLen);
  end;

  TArrayUtilities.Fill<Byte>(LKeyBytes, 0, System.Length(LKeyBytes), Byte(0));
  Result := LParameters;
end;

end.
