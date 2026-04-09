{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpCipherUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpAsn1Objects,
  ClpCollectionUtilities,
  ClpAsn1Comparers,
  ClpCryptoLibComparers,
  ClpCryptoLibTypes,
  ClpDigestUtilities,
  ClpEnumUtilities,
  ClpIAsn1Objects,
  ClpIBlockCipherPadding,
  ClpIBlockCipher,
  ClpIBufferedCipher,
  ClpIStreamCipher,
  ClpIAeadCipher,
  ClpIAeadBlockCipher,
  ClpNistObjectIdentifiers,
  ClpPkcsObjectIdentifiers,
  ClpMiscObjectIdentifiers,
  ClpStringUtilities,
  ClpISO10126d2Padding,
  ClpISO7816d4Padding,
  ClpPkcs7Padding,
  ClpTBCPadding,
  ClpX923Padding,
  ClpZeroBytePadding,
  ClpIBlockCipherMode,
  ClpEcbBlockCipher,
  ClpCbcBlockCipher,
  ClpCfbBlockCipher,
  ClpOfbBlockCipher,
  ClpSicBlockCipher,
  ClpCtsBlockCipher,
  ClpCcmBlockCipher,
  ClpEaxBlockCipher,
  ClpGcmBlockCipher,
  ClpOcbBlockCipher,
  ClpOpenPgpCfbBlockCipher,
  ClpChaCha20Poly1305,
  ClpBufferedAeadBlockCipher,
  ClpBufferedAeadCipher,
  ClpBufferedBlockCipher,
  ClpBufferedStreamCipher,
  ClpBufferedAsymmetricBlockCipher,
  ClpPaddedBufferedBlockCipher,
  ClpAesUtilities,
  ClpBlowfishEngine,
  ClpChaChaEngine,
  ClpChaCha7539Engine,
  ClpSalsa20Engine,
  ClpRijndaelEngine,
  ClpPkcs1Encoding,
  ClpOaepEncoding,
  ClpISO9796d1Encoding,
  ClpRsaBlindedEngine,
  ClpIAsymmetricBlockCipher,
  ClpBufferedIesCipher,
  ClpIesEngine,
  ClpDHBasicAgreement,
  ClpECDHBasicAgreement,
  ClpIBasicAgreement,
  ClpKdf2BytesGenerator,
  ClpIKdf2BytesGenerator,
  ClpHMac,
  ClpIHMac;

resourcestring
  SMechanismNil = 'Mechanism Cannot be Nil';
  SAlgorithmNil = 'Algorithm Cannot be Nil';
  SUnRecognizedCipher = 'Cipher "%s" Not Recognised.';
  SSICModeWarning =
    'Warning: SIC-Mode Can Become a TwoTime-Pad if the Blocksize of the Cipher is Too Small. Use a Cipher With a Block Size of at Least 128 bits (e.g. AES)';
  SModeAndPaddingNotNeededStreamCipher =
    'Modes and Paddings Not Used for Stream Ciphers';
  SModesAndPaddingsNotValidForAead =
    'Modes and paddings cannot be applied to AEAD ciphers';
  SBadPaddingForAead =
    'Bad padding specified for AEAD cipher.';
  SCTSNotValidForAead =
    'CTS mode not valid for AEAD ciphers.';
  SOidNotRecognised = 'Cipher OID not recognised.';
  SOidNil = 'OID Cannot be Nil';

type

  /// <remarks>
  /// Cipher Utility class contains methods that can not be specifically grouped into other classes.
  /// </remarks>
  TCipherUtilities = class sealed(TObject)

  strict private

  type
    TCipherAlgorithm = (
      AES,
      BLOWFISH,
      CHACHA,
      CHACHA20_POLY1305,
      CHACHA7539,
      SALSA20,
      RIJNDAEL,
      RSA);

    TCipherMode = (
      NONE,
      CBC,
      CCM,
      CFB,
      CTR,
      CTS,
      EAX,
      GCM,
      ECB,
      OCB,
      OFB,
      OPENPGPCFB,
      SIC);

    TCipherPadding = (
      NOPADDING,
      RAW,
      ISO10126PADDING,
      ISO10126D2PADDING,
      ISO10126_2PADDING,
      ISO7816_4PADDING,
      ISO9797_1PADDING,
      ISO9796_1,
      ISO9796_1PADDING,
      OAEP,
      OAEPPADDING,
      OAEPWITHMD5ANDMGF1PADDING,
      OAEPWITHSHA1ANDMGF1PADDING,
      OAEPWITHSHA_1ANDMGF1PADDING,
      OAEPWITHSHA224ANDMGF1PADDING,
      OAEPWITHSHA_224ANDMGF1PADDING,
      OAEPWITHSHA256ANDMGF1PADDING,
      OAEPWITHSHA_256ANDMGF1PADDING,
      OAEPWITHSHA256ANDMGF1WITHSHA256PADDING,
      OAEPWITHSHA_256ANDMGF1WITHSHA_256PADDING,
      OAEPWITHSHA256ANDMGF1WITHSHA1PADDING,
      OAEPWITHSHA_256ANDMGF1WITHSHA_1PADDING,
      OAEPWITHSHA384ANDMGF1PADDING,
      OAEPWITHSHA_384ANDMGF1PADDING,
      OAEPWITHSHA512ANDMGF1PADDING,
      OAEPWITHSHA_512ANDMGF1PADDING,
      PKCS1,
      PKCS1PADDING,
      PKCS5,
      PKCS5PADDING,
      PKCS7,
      PKCS7PADDING,
      TBCPADDING,
      WITHCTS,
      X923PADDING,
      ZEROBYTEPADDING);

  class var
      FAlgorithmMap: TDictionary<String, String>;
      FAlgorithmOidMap: TDictionary<IDerObjectIdentifier, String>;

    class function GetMechanism(const AAlgorithm: String): String; static;
    class function GetCipherForMechanism(const AMechanism: String): IBufferedCipher; static;
    class function CreateBlockCipher(ACipherAlgorithm: TCipherAlgorithm): IBlockCipher; static;

    class procedure Boot; static;
    class constructor Create;
    class destructor Destroy;

  public
    class function GetAlgorithmName(const AOid: IDerObjectIdentifier): String; static;
    class function GetCipher(const AAlgorithm: String): IBufferedCipher; overload; static;
    class function GetCipher(const AOid: IDerObjectIdentifier): IBufferedCipher; overload; static;
  end;

implementation

{ TCipherUtilities }

class procedure TCipherUtilities.Boot;
begin
  FAlgorithmMap := TDictionary<String, String>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FAlgorithmOidMap := TDictionary<IDerObjectIdentifier, String>.Create(TAsn1Comparers.OidEqualityComparer);

  TNistObjectIdentifiers.Boot;
  TPkcsObjectIdentifiers.Boot;

  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdAes128Cbc, 'AES/CBC/PKCS7PADDING');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdAes192Cbc, 'AES/CBC/PKCS7PADDING');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdAes256Cbc, 'AES/CBC/PKCS7PADDING');

  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdAes128Cfb, 'AES/CFB/NOPADDING');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdAes192Cfb, 'AES/CFB/NOPADDING');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdAes256Cfb, 'AES/CFB/NOPADDING');

  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdAes128Ecb, 'AES/ECB/PKCS7PADDING');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdAes192Ecb, 'AES/ECB/PKCS7PADDING');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdAes256Ecb, 'AES/ECB/PKCS7PADDING');

  FAlgorithmMap.AddOrSetValue('AES//PKCS7', 'AES/ECB/PKCS7PADDING');
  FAlgorithmMap.AddOrSetValue('AES//PKCS7PADDING', 'AES/ECB/PKCS7PADDING');
  FAlgorithmMap.AddOrSetValue('AES//PKCS5', 'AES/ECB/PKCS7PADDING');
  FAlgorithmMap.AddOrSetValue('AES//PKCS5PADDING', 'AES/ECB/PKCS7PADDING');

  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdAes128Gcm, 'AES/GCM/NOPADDING');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdAes192Gcm, 'AES/GCM/NOPADDING');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdAes256Gcm, 'AES/GCM/NOPADDING');

  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdAes128Ofb, 'AES/OFB/NOPADDING');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdAes192Ofb, 'AES/OFB/NOPADDING');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdAes256Ofb, 'AES/OFB/NOPADDING');

  FAlgorithmMap.AddOrSetValue('RSA/ECB/PKCS1', 'RSA//PKCS1PADDING');
  FAlgorithmMap.AddOrSetValue('RSA/ECB/PKCS1PADDING', 'RSA//PKCS1PADDING');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.RsaEncryption, 'RSA//PKCS1PADDING');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.IdRsaesOaep, 'RSA//OAEPPADDING');

  FAlgorithmMap.AddOrSetValue('PBEWITHSHA1AND128BITAES-CBC-BC', 'PBEWITHSHAAND128BITAES-CBC-BC');
  FAlgorithmMap.AddOrSetValue('PBEWITHSHA-1AND128BITAES-CBC-BC', 'PBEWITHSHAAND128BITAES-CBC-BC');

  FAlgorithmMap.AddOrSetValue('PBEWITHSHA1AND192BITAES-CBC-BC', 'PBEWITHSHAAND192BITAES-CBC-BC');
  FAlgorithmMap.AddOrSetValue('PBEWITHSHA-1AND192BITAES-CBC-BC', 'PBEWITHSHAAND192BITAES-CBC-BC');

  FAlgorithmMap.AddOrSetValue('PBEWITHSHA1AND256BITAES-CBC-BC', 'PBEWITHSHAAND256BITAES-CBC-BC');
  FAlgorithmMap.AddOrSetValue('PBEWITHSHA-1AND256BITAES-CBC-BC', 'PBEWITHSHAAND256BITAES-CBC-BC');

  FAlgorithmMap.AddOrSetValue('PBEWITHSHA-256AND128BITAES-CBC-BC', 'PBEWITHSHA256AND128BITAES-CBC-BC');
  FAlgorithmMap.AddOrSetValue('PBEWITHSHA-256AND192BITAES-CBC-BC', 'PBEWITHSHA256AND192BITAES-CBC-BC');
  FAlgorithmMap.AddOrSetValue('PBEWITHSHA-256AND256BITAES-CBC-BC', 'PBEWITHSHA256AND256BITAES-CBC-BC');

  FAlgorithmOidMap.AddOrSetValue(TMiscObjectIdentifiers.CryptlibAlgorithmBlowfishCbc, 'BLOWFISH/CBC');

  FAlgorithmMap.AddOrSetValue('CHACHA20', 'CHACHA7539');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.IdAlgAeadChaCha20Poly1305, 'CHACHA20-POLY1305');
end;

class constructor TCipherUtilities.Create;
begin
  Boot;
end;

class destructor TCipherUtilities.Destroy;
begin
  FAlgorithmMap.Free;
  FAlgorithmOidMap.Free;
end;

class function TCipherUtilities.GetMechanism(const AAlgorithm: String): String;
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

class function TCipherUtilities.GetAlgorithmName(const AOid: IDerObjectIdentifier): String;
begin
  Result := TCollectionUtilities.GetValueOrNull<IDerObjectIdentifier, String>(FAlgorithmOidMap, AOid);
end;

class function TCipherUtilities.GetCipherForMechanism(const AMechanism: String): IBufferedCipher;

  function GetDigitIndex(const AMode: String): Int32;
  var
    LI: Int32;
  begin
    for LI := 1 to System.Length(AMode) do
    begin
      if CharInSet(AMode[LI], ['0' .. '9']) then
      begin
        Result := LI;
        Exit;
      end;
    end;
    Result := -1;
  end;

var
  LAlgorithmName, LPaddingName, LMode, LModeName: String;
  LDi, LBits: Int32;
  LPadded, LCts: Boolean;
  LParts: TCryptoLibStringArray;
  LCipherAlgorithm: TCipherAlgorithm;
  LCipherPadding: TCipherPadding;
  LCipherMode: TCipherMode;
  LBlockCipher: IBlockCipher;
  LBlockCipherMode: IBlockCipherMode;
  LAsymBlockCipher: IAsymmetricBlockCipher;
  LStreamCipher: IStreamCipher;
  LAeadCipher: IAeadCipher;
  LAeadBlockCipher: IAeadBlockCipher;
  LPadding: IBlockCipherPadding;
  LAgreement: IBasicAgreement;
begin
  Result := nil;

  LAgreement := nil;
  if AMechanism = 'IES' then
    LAgreement := TDHBasicAgreement.Create()
  else if AMechanism = 'ECIES' then
    LAgreement := TECDHBasicAgreement.Create();

  if LAgreement <> nil then
  begin
    Result := TBufferedIesCipher.Create(TIesEngine.Create(
      LAgreement,
      TKdf2BytesGenerator.Create(TDigestUtilities.GetDigest('SHA-1'))
        as IKdf2BytesGenerator,
      THMac.Create(TDigestUtilities.GetDigest('SHA-1')) as IHMac));
    Exit;
  end;

  if TStringUtilities.StartsWith(AMechanism, 'PBE') then
  begin
    if TStringUtilities.EndsWith(AMechanism, '-BC') or
      TStringUtilities.EndsWith(AMechanism, '-OPENSSL') then
    begin
      if TStringUtilities.IsOneOf(AMechanism, [
        'PBEWITHSHAAND128BITAES-CBC-BC',
        'PBEWITHSHAAND192BITAES-CBC-BC',
        'PBEWITHSHAAND256BITAES-CBC-BC',
        'PBEWITHSHA256AND128BITAES-CBC-BC',
        'PBEWITHSHA256AND192BITAES-CBC-BC',
        'PBEWITHSHA256AND256BITAES-CBC-BC',
        'PBEWITHMD5AND128BITAES-CBC-OPENSSL',
        'PBEWITHMD5AND192BITAES-CBC-OPENSSL',
        'PBEWITHMD5AND256BITAES-CBC-OPENSSL']) then
      begin
        Result := TPaddedBufferedBlockCipher.Create(
          TCbcBlockCipher.Create(TAesUtilities.CreateEngine()));
        Exit;
      end;
    end;
  end;

  LParts := TStringUtilities.SplitString(AMechanism, '/');
  if System.Length(LParts) < 1 then
    Exit;

  LAlgorithmName := UpperCase(TCollectionUtilities.GetValueOrKey<String>(FAlgorithmMap, LParts[0]));
  if not (TEnumUtilities.TryGetEnumValue<TCipherAlgorithm>(LAlgorithmName, LCipherAlgorithm)) then
    Exit;

  LAeadCipher := nil;
  LBlockCipher := nil;
  LAsymBlockCipher := nil;
  LStreamCipher := nil;
  case LCipherAlgorithm of
    TCipherAlgorithm.AES:
      LBlockCipher := TAesUtilities.CreateEngine();
    TCipherAlgorithm.BLOWFISH:
      LBlockCipher := TBlowfishEngine.Create();
    TCipherAlgorithm.CHACHA:
      LStreamCipher := TChaChaEngine.Create();
    TCipherAlgorithm.CHACHA20_POLY1305:
      LAeadCipher := TChaCha20Poly1305.Create();
    TCipherAlgorithm.CHACHA7539:
      LStreamCipher := TChaCha7539Engine.Create();
    TCipherAlgorithm.RIJNDAEL:
      LBlockCipher := TRijndaelEngine.Create();
    TCipherAlgorithm.SALSA20:
      LStreamCipher := TSalsa20Engine.Create();
    TCipherAlgorithm.RSA:
      LAsymBlockCipher := TRsaBlindedEngine.Create();
  else
    Exit;
  end;

  if LAeadCipher <> nil then
  begin
    if System.Length(LParts) > 1 then
      raise EArgumentCryptoLibException.CreateRes(@SModesAndPaddingsNotValidForAead);
    Result := TBufferedAeadCipher.Create(LAeadCipher);
    Exit;
  end;

  if LStreamCipher <> nil then
  begin
    if System.Length(LParts) > 1 then
      raise EArgumentCryptoLibException.CreateRes(@SModeAndPaddingNotNeededStreamCipher);
    Result := TBufferedStreamCipher.Create(LStreamCipher);
    Exit;
  end;

  LCts := False;
  LPadded := True;
  LPadding := nil;

  if System.Length(LParts) > 2 then
  begin
    LPaddingName := LParts[2];
    if LPaddingName = '' then
      LCipherPadding := TCipherPadding.RAW
    else if LPaddingName = 'X9.23PADDING' then
      LCipherPadding := TCipherPadding.X923PADDING
    else if not (TEnumUtilities.TryGetEnumValue<TCipherPadding>(LPaddingName, LCipherPadding)) then
      Exit;

    case LCipherPadding of
      TCipherPadding.NOPADDING:
        LPadded := False;
      TCipherPadding.RAW: ;
      TCipherPadding.ISO10126PADDING, TCipherPadding.ISO10126D2PADDING, TCipherPadding.ISO10126_2PADDING:
        LPadding := TISO10126d2Padding.Create();
      TCipherPadding.ISO7816_4PADDING, TCipherPadding.ISO9797_1PADDING:
        LPadding := TISO7816d4Padding.Create();
      TCipherPadding.ISO9796_1, TCipherPadding.ISO9796_1PADDING:
        LAsymBlockCipher := TISO9796d1Encoding.Create(LAsymBlockCipher);
      TCipherPadding.OAEP, TCipherPadding.OAEPPADDING:
        LAsymBlockCipher := TOaepEncoding.Create(LAsymBlockCipher);
      TCipherPadding.OAEPWITHMD5ANDMGF1PADDING:
        LAsymBlockCipher := TOaepEncoding.Create(LAsymBlockCipher, TDigestUtilities.GetDigest('MD5'));
      TCipherPadding.OAEPWITHSHA1ANDMGF1PADDING, TCipherPadding.OAEPWITHSHA_1ANDMGF1PADDING:
        LAsymBlockCipher := TOaepEncoding.Create(LAsymBlockCipher, TDigestUtilities.GetDigest('SHA-1'));
      TCipherPadding.OAEPWITHSHA224ANDMGF1PADDING, TCipherPadding.OAEPWITHSHA_224ANDMGF1PADDING:
        LAsymBlockCipher := TOaepEncoding.Create(LAsymBlockCipher, TDigestUtilities.GetDigest('SHA-224'));
      TCipherPadding.OAEPWITHSHA256ANDMGF1PADDING, TCipherPadding.OAEPWITHSHA_256ANDMGF1PADDING,
      TCipherPadding.OAEPWITHSHA256ANDMGF1WITHSHA256PADDING, TCipherPadding.OAEPWITHSHA_256ANDMGF1WITHSHA_256PADDING:
        LAsymBlockCipher := TOaepEncoding.Create(LAsymBlockCipher, TDigestUtilities.GetDigest('SHA-256'));
      TCipherPadding.OAEPWITHSHA256ANDMGF1WITHSHA1PADDING, TCipherPadding.OAEPWITHSHA_256ANDMGF1WITHSHA_1PADDING:
        LAsymBlockCipher := TOaepEncoding.Create(LAsymBlockCipher, TDigestUtilities.GetDigest('SHA-256'), TDigestUtilities.GetDigest('SHA-1'), nil);
      TCipherPadding.OAEPWITHSHA384ANDMGF1PADDING, TCipherPadding.OAEPWITHSHA_384ANDMGF1PADDING:
        LAsymBlockCipher := TOaepEncoding.Create(LAsymBlockCipher, TDigestUtilities.GetDigest('SHA-384'));
      TCipherPadding.OAEPWITHSHA512ANDMGF1PADDING, TCipherPadding.OAEPWITHSHA_512ANDMGF1PADDING:
        LAsymBlockCipher := TOaepEncoding.Create(LAsymBlockCipher, TDigestUtilities.GetDigest('SHA-512'));
      TCipherPadding.PKCS1, TCipherPadding.PKCS1PADDING:
        LAsymBlockCipher := TPkcs1Encoding.Create(LAsymBlockCipher);
      TCipherPadding.PKCS5, TCipherPadding.PKCS5PADDING, TCipherPadding.PKCS7, TCipherPadding.PKCS7PADDING:
        LPadding := TPkcs7Padding.Create();
      TCipherPadding.TBCPADDING:
        LPadding := TTBCPadding.Create();
      TCipherPadding.WITHCTS:
        LCts := True;
      TCipherPadding.X923PADDING:
        LPadding := TX923Padding.Create();
      TCipherPadding.ZEROBYTEPADDING:
        LPadding := TZeroBytePadding.Create();
    else
      Exit;
    end;
  end;

  if System.Length(LParts) > 1 then
  begin
    LMode := LParts[1];
    LDi := GetDigitIndex(LMode);
    if LDi >= 1 then
      LModeName := TStringUtilities.Substring(LMode, 1, LDi - 1)
    else
      LModeName := LMode;

    if LModeName = '' then
      LCipherMode := TCipherMode.NONE
    else if not (TEnumUtilities.TryGetEnumValue<TCipherMode>(LModeName, LCipherMode)) then
      Exit;

    LBlockCipherMode := nil;
    LAeadBlockCipher := nil;
    case LCipherMode of
      TCipherMode.ECB, TCipherMode.NONE: ;
      TCipherMode.CBC:
        LBlockCipherMode := TCbcBlockCipher.Create(LBlockCipher);
      TCipherMode.CCM:
        LAeadBlockCipher := TCcmBlockCipher.Create(LBlockCipher);
      TCipherMode.CFB:
        begin
          if LDi < 1 then
            LBits := 8 * LBlockCipher.GetBlockSize()
          else
            LBits := StrToInt(System.Copy(LMode, LDi, System.Length(LMode) - LDi + 1));
          LBlockCipherMode := TCfbBlockCipher.Create(LBlockCipher, LBits);
        end;
      TCipherMode.CTR:
        LBlockCipherMode := TSicBlockCipher.Create(LBlockCipher);
      TCipherMode.CTS:
        begin
          LCts := True;
          LBlockCipherMode := TCbcBlockCipher.Create(LBlockCipher);
        end;
      TCipherMode.EAX:
        LAeadBlockCipher := TEaxBlockCipher.Create(LBlockCipher);
      TCipherMode.GCM:
        LAeadBlockCipher := TGcmBlockCipher.Create(LBlockCipher);
      TCipherMode.OCB:
        LAeadBlockCipher := TOcbBlockCipher.Create(LBlockCipher, CreateBlockCipher(LCipherAlgorithm));
      TCipherMode.OFB:
        begin
          if LDi < 1 then
            LBits := 8 * LBlockCipher.GetBlockSize()
          else
            LBits := StrToInt(System.Copy(LMode, LDi, System.Length(LMode) - LDi + 1));
          LBlockCipherMode := TOfbBlockCipher.Create(LBlockCipher, LBits);
        end;
      TCipherMode.OPENPGPCFB:
        LBlockCipherMode := TOpenPgpCfbBlockCipher.Create(LBlockCipher);
      TCipherMode.SIC:
        begin
          if LBlockCipher.GetBlockSize() < 16 then
            Exit;
          LBlockCipherMode := TSicBlockCipher.Create(LBlockCipher);
        end;
    else
      Exit;
    end;
  end;

  if LAeadBlockCipher <> nil then
  begin
    if LCts then
      raise ESecurityUtilityCryptoLibException.CreateRes(@SCTSNotValidForAead);
    if LPadded and (System.Length(LParts) > 2) and (LParts[2] <> '') then
      raise ESecurityUtilityCryptoLibException.CreateRes(@SBadPaddingForAead);

    Result := TBufferedAeadBlockCipher.Create(LAeadBlockCipher);
    Exit;
  end;

  if LBlockCipher <> nil then
  begin
    if LBlockCipherMode = nil then
      LBlockCipherMode := TEcbBlockCipher.GetBlockCipherMode(LBlockCipher);

    if LCts then
    begin
      Result := TCtsBlockCipher.Create(LBlockCipherMode);
      Exit;
    end;
    if LPadding <> nil then
    begin
      Result := TPaddedBufferedBlockCipher.Create(LBlockCipherMode, LPadding);
      Exit;
    end;
    if (not LPadded) or LBlockCipherMode.IsPartialBlockOkay then
    begin
      Result := TBufferedBlockCipher.Create(LBlockCipherMode);
      Exit;
    end;
    Result := TPaddedBufferedBlockCipher.Create(LBlockCipherMode);
    Exit;
  end;

  if LAsymBlockCipher <> nil then
  begin
    Result := TBufferedAsymmetricBlockCipher.Create(LAsymBlockCipher);
    Exit;
  end;
end;

class function TCipherUtilities.GetCipher(const AAlgorithm: String): IBufferedCipher;
var
  LMechanism: String;
  LCipher: IBufferedCipher;
begin
  if AAlgorithm = '' then
    raise EArgumentNilCryptoLibException.CreateRes(@SAlgorithmNil);
  LMechanism := GetMechanism(UpperCase(AAlgorithm));
  if LMechanism = '' then
    LMechanism := UpperCase(AAlgorithm);

  LCipher := GetCipherForMechanism(LMechanism);
  if LCipher = nil then
    raise ESecurityUtilityCryptoLibException.CreateResFmt(@SUnRecognizedCipher, [AAlgorithm]);
  Result := LCipher;
end;

class function TCipherUtilities.GetCipher(const AOid: IDerObjectIdentifier): IBufferedCipher;
var
  LMechanism: String;
  LCipher: IBufferedCipher;
begin
  if AOid = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOidNil);
  if not FAlgorithmOidMap.TryGetValue(AOid, LMechanism) then
    raise ESecurityUtilityCryptoLibException.CreateRes(@SOidNotRecognised);
  LCipher := GetCipherForMechanism(LMechanism);
  if LCipher = nil then
    raise ESecurityUtilityCryptoLibException.CreateRes(@SOidNotRecognised);
  Result := LCipher;
end;

class function TCipherUtilities.CreateBlockCipher(
  ACipherAlgorithm: TCipherAlgorithm): IBlockCipher;
begin
  case ACipherAlgorithm of
    TCipherAlgorithm.AES:
      Result := TAesUtilities.CreateEngine();
    TCipherAlgorithm.BLOWFISH:
      Result := TBlowfishEngine.Create();
    TCipherAlgorithm.RIJNDAEL:
      Result := TRijndaelEngine.Create();
  else
    raise ESecurityUtilityCryptoLibException.CreateResFmt(@SUnRecognizedCipher,
      [TEnumUtilities.ToString<TCipherAlgorithm>(ACipherAlgorithm)]);
  end;
end;

end.
