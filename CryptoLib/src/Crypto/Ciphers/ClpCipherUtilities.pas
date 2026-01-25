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

unit ClpCipherUtilities;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  TypInfo,
  Generics.Collections,
  ClpAsn1Objects,
  ClpCollectionUtilities,
  ClpCryptoLibComparers,
  ClpCryptoLibTypes,
  ClpDigestUtilities,
  ClpEnumUtilities,
  ClpIAsn1Objects,
  ClpIBlockCipherPadding,
  ClpIBlockCipher,
  ClpIBufferedCipher,
  ClpIStreamCipher,
  ClpNistObjectIdentifiers,
  ClpPkcsObjectIdentifiers,
  ClpStringUtils,
  ClpPaddingModes,
  ClpIPaddingModes,
  ClpBlockCipherModes,
  ClpIBlockCipherModes,
  ClpBufferedBlockCipher,
  ClpIBufferedBlockCipher,
  ClpBufferedStreamCipher,
  ClpIBufferedStreamCipher,
  ClpBufferedAsymmetricBlockCipher,
  ClpIBufferedAsymmetricBlockCipher,
  ClpPaddedBufferedBlockCipher,
  ClpIPaddedBufferedBlockCipher,
  ClpAesEngine,
  ClpIAesEngine,
  ClpBlowfishEngine,
  ClpIBlowfishEngine,
  ClpChaChaEngine,
  ClpIChaChaEngine,
  ClpSalsa20Engine,
  ClpISalsa20Engine,
  ClpRijndaelEngine,
  ClpIRijndaelEngine,
  ClpPkcs1Encoding,
  ClpIPkcs1Encoding,
  ClpOaepEncoding,
  ClpIOaepEncoding,
  ClpISO9796d1Encoding,
  ClpIISO9796d1Encoding,
  ClpRsaBlindedEngine,
  ClpIRsaBlindedEngine,
  ClpIAsymmetricBlockCipher;

resourcestring
  SMechanismNil = 'Mechanism Cannot be Nil';
  SAlgorithmNil = 'Algorithm Cannot be Nil';
  SUnRecognizedCipher = 'Cipher "%s" Not Recognised.';
  SSICModeWarning =
    'Warning: SIC-Mode Can Become a TwoTime-Pad if the Blocksize of the Cipher is Too Small. Use a Cipher With a Block Size of at Least 128 bits (e.g. AES)';
  SModeAndPaddingNotNeededStreamCipher =
    'Modes and Paddings Not Used for Stream Ciphers';
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
      SALSA20,
      RIJNDAEL,
      RSA);

    TCipherMode = (
      NONE,
      CBC,
      CFB,
      CTR,
      CTS,
      ECB,
      OFB,
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
      OAEPWITHSHA1ANDMGF1PADDING,
      OAEPWITHSHA_1ANDMGF1PADDING,
      OAEPWITHSHA256ANDMGF1PADDING,
      OAEPWITHSHA_256ANDMGF1PADDING,
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
  FAlgorithmOidMap := TDictionary<IDerObjectIdentifier, String>.Create(TCryptoLibComparers.OidEqualityComparer);

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

  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdAes128Ofb, 'AES/OFB/NOPADDING');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdAes192Ofb, 'AES/OFB/NOPADDING');
  FAlgorithmOidMap.AddOrSetValue(TNistObjectIdentifiers.IdAes256Ofb, 'AES/OFB/NOPADDING');

  FAlgorithmMap.AddOrSetValue('RSA/ECB/PKCS1', 'RSA//PKCS1PADDING');
  FAlgorithmMap.AddOrSetValue('RSA/ECB/PKCS1PADDING', 'RSA//PKCS1PADDING');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.RsaEncryption, 'RSA//PKCS1PADDING');
  FAlgorithmOidMap.AddOrSetValue(TPkcsObjectIdentifiers.IdRsaesOaep, 'RSA//OAEPPADDING');

  FAlgorithmMap.AddOrSetValue('1.3.6.1.4.1.3029.1.2', 'BLOWFISH/CBC');

  FAlgorithmMap.AddOrSetValue('CHACHA20', 'CHACHA');
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

  function GetDigitIndex(const S: String): Int32;
  var
    I: Int32;
  begin
    for I := 1 to System.Length(S) do
    begin
      if CharInSet(S[I], ['0' .. '9']) then
      begin
        Result := I;
        Exit;
      end;
    end;
    Result := -1;
  end;

var
  LAlgorithmName, LPaddingName, LMode, LModeName: String;
  LDi, LBits: Int32;
  LPadded, LCTS: Boolean;
  LParts: TCryptoLibStringArray;
  LCipherAlgorithm: TCipherAlgorithm;
  LCipherPadding: TCipherPadding;
  LCipherMode: TCipherMode;
  LBlockCipher: IBlockCipher;
  LAsymBlockCipher: IAsymmetricBlockCipher;
  LStreamCipher: IStreamCipher;
  LPadding: IBlockCipherPadding;
begin
  Result := nil;
  LParts := TStringUtils.SplitString(AMechanism, '/');
  if System.Length(LParts) < 1 then
    Exit;

  LAlgorithmName := UpperCase(TCollectionUtilities.GetValueOrKey<String>(FAlgorithmMap, LParts[0]));
  if not TEnumUtilities.TryGetEnumValue<TCipherAlgorithm>(LAlgorithmName, LCipherAlgorithm) then
    Exit;

  LBlockCipher := nil;
  LAsymBlockCipher := nil;
  LStreamCipher := nil;
  case LCipherAlgorithm of
    TCipherAlgorithm.AES:
      LBlockCipher := TAesEngine.Create() as IAesEngine;
    TCipherAlgorithm.BLOWFISH:
      LBlockCipher := TBlowfishEngine.Create() as IBlowfishEngine;
    TCipherAlgorithm.CHACHA:
      LStreamCipher := TChaChaEngine.Create() as IChaChaEngine;
    TCipherAlgorithm.RIJNDAEL:
      LBlockCipher := TRijndaelEngine.Create() as IRijndaelEngine;
    TCipherAlgorithm.SALSA20:
      LStreamCipher := TSalsa20Engine.Create() as ISalsa20Engine;
    TCipherAlgorithm.RSA:
      LAsymBlockCipher := TRsaBlindedEngine.Create() as IRsaBlindedEngine;
  else
    Exit;
  end;

  if LStreamCipher <> nil then
  begin
    if System.Length(LParts) > 1 then
      raise EArgumentCryptoLibException.CreateRes(@SModeAndPaddingNotNeededStreamCipher);
    Result := TBufferedStreamCipher.Create(LStreamCipher) as IBufferedStreamCipher;
    Exit;
  end;

  LCTS := False;
  LPadded := True;
  LPadding := nil;

  if System.Length(LParts) > 2 then
  begin
    LPaddingName := LParts[2];
    if LPaddingName = '' then
      LCipherPadding := TCipherPadding.RAW
    else if LPaddingName = 'X9.23PADDING' then
      LCipherPadding := TCipherPadding.X923PADDING
    else if not TEnumUtilities.TryGetEnumValue<TCipherPadding>(LPaddingName, LCipherPadding) then
      Exit;

    case LCipherPadding of
      TCipherPadding.NOPADDING:
        LPadded := False;
      TCipherPadding.RAW: ;
      TCipherPadding.ISO10126PADDING, TCipherPadding.ISO10126D2PADDING, TCipherPadding.ISO10126_2PADDING:
        LPadding := TISO10126d2Padding.Create() as IISO10126d2Padding;
      TCipherPadding.ISO7816_4PADDING, TCipherPadding.ISO9797_1PADDING:
        LPadding := TISO7816d4Padding.Create() as IISO7816d4Padding;
      TCipherPadding.ISO9796_1, TCipherPadding.ISO9796_1PADDING:
        LAsymBlockCipher := TISO9796d1Encoding.Create(LAsymBlockCipher) as IISO9796d1Encoding;
      TCipherPadding.OAEP, TCipherPadding.OAEPPADDING:
        LAsymBlockCipher := TOaepEncoding.Create(LAsymBlockCipher) as IOaepEncoding;
      TCipherPadding.OAEPWITHSHA1ANDMGF1PADDING, TCipherPadding.OAEPWITHSHA_1ANDMGF1PADDING:
        LAsymBlockCipher := TOaepEncoding.Create(LAsymBlockCipher, TDigestUtilities.GetDigest('SHA-1')) as IOaepEncoding;
      TCipherPadding.OAEPWITHSHA256ANDMGF1PADDING, TCipherPadding.OAEPWITHSHA_256ANDMGF1PADDING:
        LAsymBlockCipher := TOaepEncoding.Create(LAsymBlockCipher, TDigestUtilities.GetDigest('SHA-256')) as IOaepEncoding;
      TCipherPadding.PKCS1, TCipherPadding.PKCS1PADDING:
        LAsymBlockCipher := TPkcs1Encoding.Create(LAsymBlockCipher) as IPkcs1Encoding;
      TCipherPadding.PKCS5, TCipherPadding.PKCS5PADDING, TCipherPadding.PKCS7, TCipherPadding.PKCS7PADDING:
        LPadding := TPkcs7Padding.Create() as IPkcs7Padding;
      TCipherPadding.TBCPADDING:
        LPadding := TTBCPadding.Create() as ITBCPadding;
      TCipherPadding.WITHCTS:
        LCTS := True;
      TCipherPadding.X923PADDING:
        LPadding := TX923Padding.Create() as IX923Padding;
      TCipherPadding.ZEROBYTEPADDING:
        LPadding := TZeroBytePadding.Create() as IZeroBytePadding;
    else
      Exit;
    end;
  end;

  if System.Length(LParts) > 1 then
  begin
    LMode := LParts[1];
    LDi := GetDigitIndex(LMode);
    if LDi >= 1 then
      LModeName := System.Copy(LMode, 1, LDi - 1)
    else
      LModeName := LMode;

    if LModeName = '' then
      LCipherMode := TCipherMode.NONE
    else if not TEnumUtilities.TryGetEnumValue<TCipherMode>(LModeName, LCipherMode) then
      Exit;

    case LCipherMode of
      TCipherMode.ECB, TCipherMode.NONE: ;
      TCipherMode.CBC:
        LBlockCipher := TCbcBlockCipher.Create(LBlockCipher) as ICbcBlockCipher;
      TCipherMode.CFB:
        begin
          if LDi < 1 then
            LBits := 8 * LBlockCipher.GetBlockSize()
          else
            LBits := StrToInt(System.Copy(LMode, LDi, System.Length(LMode) - LDi + 1));
          LBlockCipher := TCfbBlockCipher.Create(LBlockCipher, LBits) as ICfbBlockCipher;
        end;
      TCipherMode.CTR:
        LBlockCipher := TSicBlockCipher.Create(LBlockCipher) as ISicBlockCipher;
      TCipherMode.CTS:
        begin
          LCTS := True;
          LBlockCipher := TCbcBlockCipher.Create(LBlockCipher) as ICbcBlockCipher;
        end;
      TCipherMode.OFB:
        begin
          if LDi < 1 then
            LBits := 8 * LBlockCipher.GetBlockSize()
          else
            LBits := StrToInt(System.Copy(LMode, LDi, System.Length(LMode) - LDi + 1));
          LBlockCipher := TOfbBlockCipher.Create(LBlockCipher, LBits) as IOfbBlockCipher;
        end;
      TCipherMode.SIC:
        begin
          if LBlockCipher.GetBlockSize() < 16 then
            Exit;
          LBlockCipher := TSicBlockCipher.Create(LBlockCipher) as ISicBlockCipher;
        end;
    else
      Exit;
    end;
  end;

  if LBlockCipher <> nil then
  begin
    if LCTS then
    begin
      Result := TCtsBlockCipher.Create(LBlockCipher) as ICtsBlockCipher;
      Exit;
    end;
    if LPadding <> nil then
    begin
      Result := TPaddedBufferedBlockCipher.Create(LBlockCipher, LPadding) as IPaddedBufferedBlockCipher;
      Exit;
    end;
    if (not LPadded) or LBlockCipher.IsPartialBlockOkay then
    begin
      Result := TBufferedBlockCipher.Create(LBlockCipher) as IBufferedBlockCipher;
      Exit;
    end;
    Result := TPaddedBufferedBlockCipher.Create(LBlockCipher) as IPaddedBufferedBlockCipher;
    Exit;
  end;

  if LAsymBlockCipher <> nil then
  begin
    Result := TBufferedAsymmetricBlockCipher.Create(LAsymBlockCipher) as IBufferedAsymmetricBlockCipher;
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

end.
