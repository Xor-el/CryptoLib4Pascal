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

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  TypInfo,
  Generics.Collections,
  ClpCryptoLibTypes,
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
  ClpNistObjectIdentifiers,
  ClpPkcsObjectIdentifiers,
  ClpIAsn1Objects,
  ClpIBufferedCipher,
  ClpIBlockCipher,
  ClpIStreamCipher,
  ClpAesEngine,
  ClpIAesEngine,
  ClpBlowfishEngine,
  ClpIBlowfishEngine,
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
  ClpIAsymmetricBlockCipher,
  ClpDigestUtilities,
  ClpIBlockCipherPadding;

resourcestring
  SMechanismNil = 'Mechanism Cannot be Nil';
  SAlgorithmNil = 'Algorithm Cannot be Nil';
  SUnRecognizedCipher = 'Cipher "%s" Not Recognised.';
  SSICModeWarning =
    'Warning: SIC-Mode Can Become a TwoTime-Pad if the Blocksize of the Cipher is Too Small. Use a Cipher With a Block Size of at Least 128 bits (e.g. AES)';
  SModeAndPaddingNotNeededStreamCipher =
    'Modes and Paddings Not Used for Stream Ciphers';

type

  /// <remarks>
  /// Cipher Utility class contains methods that can not be specifically grouped into other classes.
  /// </remarks>
  TCipherUtilities = class sealed(TObject)

  strict private

  type
{$SCOPEDENUMS ON}
    TCipherAlgorithm = (AES, BLOWFISH, SALSA20, RIJNDAEL, RSA);
    TCipherMode = (NONE, CBC, CFB, CTR, CTS, ECB, OFB, SIC);
    TCipherPadding = (NOPADDING, RAW, ISO10126PADDING, ISO10126D2PADDING,
      ISO10126_2PADDING, ISO7816_4PADDING, ISO9797_1PADDING, ISO9796_1,
      ISO9796_1PADDING, OAEP, OAEPPADDING, OAEPWITHSHA1ANDMGF1PADDING,
      OAEPWITHSHA_1ANDMGF1PADDING, OAEPWITHSHA256ANDMGF1PADDING,
      OAEPWITHSHA_256ANDMGF1PADDING, PKCS1, PKCS1PADDING, PKCS5, PKCS5PADDING,
      PKCS7, PKCS7PADDING, TBCPADDING, WITHCTS, X923PADDING, ZEROBYTEPADDING);
{$SCOPEDENUMS OFF}

  class var

    Falgorithms: TDictionary<String, String>;
    Foids: TDictionary<String, IDerObjectIdentifier>;

    class function GetAlgorithms: TCryptoLibStringArray; static; inline;
    class function GetDigitIndex(const s: String): Int32; static; inline;

    class procedure Boot(); static;
    class constructor CreateCipherUtilities();
    class destructor DestroyCipherUtilities();

  public
    /// <summary>
    /// Returns a ObjectIdentifier for a give encoding.
    /// </summary>
    /// <param name="mechanism">A string representation of the encoding.</param>
    /// <returns>A DerObjectIdentifier, null if the Oid is not available.</returns>
    // TODO Don't really want to support this
    class function GetObjectIdentifier(mechanism: String)
      : IDerObjectIdentifier; static;
    class function GetCipher(algorithm: String): IBufferedCipher;
      overload; static;
    class function GetCipher(const oid: IDerObjectIdentifier): IBufferedCipher;
      overload; static; inline;

    class property Algorithms: TCryptoLibStringArray read GetAlgorithms;
  end;

implementation

{ TCipherUtilities }

class procedure TCipherUtilities.Boot;
begin
  Falgorithms := TDictionary<string, string>.Create();
  Foids := TDictionary<string, IDerObjectIdentifier>.Create();

  TNistObjectIdentifiers.Boot;

  // TODO Flesh out the list of aliases

  Falgorithms.Add(TNistObjectIdentifiers.IdAes128Ecb.Id,
    'AES/ECB/PKCS7PADDING');
  Falgorithms.Add(TNistObjectIdentifiers.IdAes192Ecb.Id,
    'AES/ECB/PKCS7PADDING');
  Falgorithms.Add(TNistObjectIdentifiers.IdAes256Ecb.Id,
    'AES/ECB/PKCS7PADDING');
  Falgorithms.Add('AES//PKCS7', 'AES/ECB/PKCS7PADDING');
  Falgorithms.Add('AES//PKCS7PADDING', 'AES/ECB/PKCS7PADDING');
  Falgorithms.Add('AES//PKCS5', 'AES/ECB/PKCS7PADDING');
  Falgorithms.Add('AES//PKCS5PADDING', 'AES/ECB/PKCS7PADDING');

  Falgorithms.Add(TNistObjectIdentifiers.IdAes128Cbc.Id,
    'AES/CBC/PKCS7PADDING');
  Falgorithms.Add(TNistObjectIdentifiers.IdAes192Cbc.Id,
    'AES/CBC/PKCS7PADDING');
  Falgorithms.Add(TNistObjectIdentifiers.IdAes256Cbc.Id,
    'AES/CBC/PKCS7PADDING');

  Falgorithms.Add(TNistObjectIdentifiers.IdAes128Ofb.Id, 'AES/OFB/NOPADDING');
  Falgorithms.Add(TNistObjectIdentifiers.IdAes192Ofb.Id, 'AES/OFB/NOPADDING');
  Falgorithms.Add(TNistObjectIdentifiers.IdAes256Ofb.Id, 'AES/OFB/NOPADDING');

  Falgorithms.Add(TNistObjectIdentifiers.IdAes128Cfb.Id, 'AES/CFB/NOPADDING');
  Falgorithms.Add(TNistObjectIdentifiers.IdAes192Cfb.Id, 'AES/CFB/NOPADDING');
  Falgorithms.Add(TNistObjectIdentifiers.IdAes256Cfb.Id, 'AES/CFB/NOPADDING');

  Falgorithms.Add('1.3.6.1.4.1.3029.1.2', 'BLOWFISH/CBC');

  TPkcsObjectIdentifiers.Boot;

  // RSA
  Falgorithms.Add('RSA/ECB/PKCS1', 'RSA//PKCS1PADDING');
  Falgorithms.Add('RSA/ECB/PKCS1PADDING', 'RSA//PKCS1PADDING');
  Falgorithms.Add(TPkcsObjectIdentifiers.RsaEncryption.Id, 'RSA//PKCS1PADDING');
  Falgorithms.Add(TPkcsObjectIdentifiers.IdRsaesOaep.Id, 'RSA//OAEPPADDING');

end;

class constructor TCipherUtilities.CreateCipherUtilities;
begin
  TCipherUtilities.Boot;
end;

class destructor TCipherUtilities.DestroyCipherUtilities;
begin
  Falgorithms.Free;
  Foids.Free;
end;

class function TCipherUtilities.GetAlgorithms: TCryptoLibStringArray;
begin
  Result := Foids.Keys.ToArray;
end;

class function TCipherUtilities.GetDigitIndex(const s: String): Int32;
var
  i, LowPoint, HighPoint: Int32;
begin
  LowPoint := 1;
  HighPoint := System.Length(s);

  For i := LowPoint to HighPoint do
  begin
    if (CharInSet(s[i], ['0' .. '9'])) then
    begin
      Result := i;
      Exit;
    end;
  end;
  Result := -1;
end;

class function TCipherUtilities.GetCipher(algorithm: String): IBufferedCipher;
var
  aliased, algorithmName, temp, paddingName, mode, modeName: string;
  di, LowPoint, bits, HighPoint: Int32;
  padded, CTS: Boolean;
  parts: TCryptoLibStringArray;
  cipherAlgorithm: TCipherAlgorithm;
  cipherPadding: TCipherPadding;
  cipherMode: TCipherMode;
  blockCipher: IBlockCipher;
  asymBlockCipher: IAsymmetricBlockCipher;
  streamCipher: IStreamCipher;
  padding: IBlockCipherPadding;
begin
  if (algorithm = '') then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SAlgorithmNil);
  end;
  algorithm := UpperCase(algorithm);

  if (Falgorithms.TryGetValue(algorithm, aliased)) then
  begin
    algorithm := aliased;
  end;

  parts := TStringUtils.SplitString(algorithm, '/');

  blockCipher := Nil;
  asymBlockCipher := Nil;
  streamCipher := Nil;

  algorithmName := parts[0];

  if (Falgorithms.TryGetValue(algorithmName, aliased)) then
  begin
    algorithmName := aliased;
  end;

  temp := StringReplace(algorithmName, '-', '_', [rfReplaceAll, rfIgnoreCase]);

  temp := StringReplace(temp, '/', '_', [rfReplaceAll, rfIgnoreCase]);

  cipherAlgorithm := TCipherAlgorithm
    (GetEnumValue(TypeInfo(TCipherAlgorithm), temp));

  case cipherAlgorithm of
    TCipherAlgorithm.AES:
      begin
        blockCipher := TAesEngine.Create() as IAesEngine;
      end;
    TCipherAlgorithm.BLOWFISH:
      begin
        blockCipher := TBlowfishEngine.Create() as IBlowfishEngine;
      end;
    TCipherAlgorithm.RIJNDAEL:
      begin
        blockCipher := TRijndaelEngine.Create() as IRijndaelEngine;
      end;
    TCipherAlgorithm.SALSA20:
      begin
        streamCipher := TSalsa20Engine.Create() as ISalsa20Engine;
      end;
    TCipherAlgorithm.RSA:
      begin
        asymBlockCipher := TRsaBlindedEngine.Create() as IRsaBlindedEngine;
      end
  else
    begin
      raise ESecurityUtilityCryptoLibException.CreateResFmt
        (@SUnRecognizedCipher, [algorithm]);
    end;
  end;

  if (streamCipher <> Nil) then
  begin
    if (System.Length(parts) > 1) then
    begin
      raise EArgumentCryptoLibException.CreateRes
        (@SModeAndPaddingNotNeededStreamCipher);
    end;

    Result := TBufferedStreamCipher.Create(streamCipher)
      as IBufferedStreamCipher;
    Exit;
  end;

  CTS := False;
  padded := true;
  padding := Nil;

  if System.Length(parts) > 2 then
  begin
    paddingName := parts[2];

    temp := StringReplace(paddingName, '-', '_', [rfReplaceAll, rfIgnoreCase]);

    temp := StringReplace(temp, '/', '_', [rfReplaceAll, rfIgnoreCase]);

    cipherPadding := TCipherPadding
      (GetEnumValue(TypeInfo(TCipherPadding), temp));

    case cipherPadding of
      TCipherPadding.NOPADDING:
        begin
          padded := False;
        end;

      TCipherPadding.RAW:
        begin
          // Raw padding - do nothing
        end;

      TCipherPadding.ISO10126PADDING, TCipherPadding.ISO10126D2PADDING,
        TCipherPadding.ISO10126_2PADDING:
        begin
          padding := TISO10126d2Padding.Create() as IISO10126d2Padding;
        end;

      TCipherPadding.ISO7816_4PADDING, TCipherPadding.ISO9797_1PADDING:
        begin
          padding := TISO7816d4Padding.Create() as IISO7816d4Padding;
        end;

      TCipherPadding.ISO9796_1, TCipherPadding.ISO9796_1PADDING:
        begin
          asymBlockCipher := TISO9796d1Encoding.Create(asymBlockCipher) as IISO9796d1Encoding;
        end;

      TCipherPadding.OAEP, TCipherPadding.OAEPPADDING:
        begin
          asymBlockCipher := TOaepEncoding.Create(asymBlockCipher) as IOaepEncoding;
        end;

      TCipherPadding.OAEPWITHSHA1ANDMGF1PADDING, TCipherPadding.OAEPWITHSHA_1ANDMGF1PADDING:
        begin
          asymBlockCipher := TOaepEncoding.Create(asymBlockCipher, TDigestUtilities.GetDigest('SHA-1')) as IOaepEncoding;
        end;

      TCipherPadding.OAEPWITHSHA256ANDMGF1PADDING, TCipherPadding.OAEPWITHSHA_256ANDMGF1PADDING:
        begin
          asymBlockCipher := TOaepEncoding.Create(asymBlockCipher, TDigestUtilities.GetDigest('SHA-256')) as IOaepEncoding;
        end;

      TCipherPadding.PKCS1, TCipherPadding.PKCS1PADDING:
        begin
          asymBlockCipher := TPkcs1Encoding.Create(asymBlockCipher) as IPkcs1Encoding;
        end;

      TCipherPadding.PKCS5, TCipherPadding.PKCS5PADDING, TCipherPadding.PKCS7,
        TCipherPadding.PKCS7PADDING:
        begin
          padding := TPkcs7Padding.Create() as IPkcs7Padding;
        end;

      TCipherPadding.TBCPADDING:
        begin
          padding := TTBCPadding.Create() as ITBCPadding;
        end;

      TCipherPadding.WITHCTS:
        begin
          CTS := true;
        end;

      TCipherPadding.X923PADDING:
        begin
          padding := TX923Padding.Create() as IX923Padding;
        end;

      TCipherPadding.ZEROBYTEPADDING:
        begin
          padding := TZeroBytePadding.Create() as IZeroBytePadding;
        end

    else
      begin
        raise ESecurityUtilityCryptoLibException.CreateResFmt
          (@SUnRecognizedCipher, [algorithm]);
      end;
    end;

  end;

  mode := '';
  if (System.Length(parts) > 1) then
  begin
    mode := parts[1];

    di := GetDigitIndex(mode);
    if di >= 0 then
    begin
      LowPoint := 1;
      modeName := System.Copy(mode, LowPoint, di);
    end
    else
    begin
      modeName := mode;
    end;

    if modeName = '' then
    begin
      cipherMode := TCipherMode.NONE;
    end
    else
    begin
      temp := StringReplace(modeName, '-', '_', [rfReplaceAll, rfIgnoreCase]);

      temp := StringReplace(temp, '/', '_', [rfReplaceAll, rfIgnoreCase]);

      cipherMode := TCipherMode(GetEnumValue(TypeInfo(TCipherMode), temp));
    end;

    case cipherMode of
      TCipherMode.ECB, TCipherMode.NONE:
        begin
          // do nothing
        end;

      TCipherMode.CBC:
        begin
          blockCipher := TCbcBlockCipher.Create(blockCipher) as ICbcBlockCipher;
        end;

      TCipherMode.CFB:
        begin
          if (di < 0) then
          begin
            bits := 8 * blockCipher.GetBlockSize();
          end
          else
          begin
            HighPoint := System.Length(mode);
            bits := StrToInt(System.Copy(mode, di, HighPoint - di));
          end;

          blockCipher := TCfbBlockCipher.Create(blockCipher, bits)
            as ICfbBlockCipher;
        end;

      TCipherMode.CTR:
        begin
          blockCipher := TSicBlockCipher.Create(blockCipher) as ISicBlockCipher;
        end;

      TCipherMode.CTS:
        begin
          CTS := true;
          blockCipher := TCbcBlockCipher.Create(blockCipher) as ICbcBlockCipher;
        end;

      TCipherMode.OFB:
        begin
          if (di < 0) then
          begin
            bits := 8 * blockCipher.GetBlockSize();
          end
          else
          begin
            HighPoint := System.Length(mode);
            bits := StrToInt(System.Copy(mode, di, HighPoint - di));
          end;

          blockCipher := TOfbBlockCipher.Create(blockCipher, bits)
            as IOfbBlockCipher;
        end;

      TCipherMode.SIC:
        begin
          if (blockCipher.GetBlockSize() < 16) then
          begin
            raise EArgumentCryptoLibException.CreateRes(@SSICModeWarning);
          end;
          blockCipher := TSicBlockCipher.Create(blockCipher) as ISicBlockCipher;
        end

    else
      begin
        raise ESecurityUtilityCryptoLibException.CreateResFmt
          (@SUnRecognizedCipher, [algorithm]);
      end;
    end;
  end;

  if (blockCipher <> Nil) then
  begin

    if (CTS) then
    begin
      Result := TCtsBlockCipher.Create(blockCipher) as ICtsBlockCipher;
      Exit;
    end;

    if (padding <> Nil) then
    begin
      Result := TPaddedBufferedBlockCipher.Create(blockCipher, padding)
        as IPaddedBufferedBlockCipher;
      Exit;
    end;

    if ((not padded) or (blockCipher.IsPartialBlockOkay)) then
    begin
      Result := TBufferedBlockCipher.Create(blockCipher)
        as IBufferedBlockCipher;
      Exit;
    end;

    Result := TPaddedBufferedBlockCipher.Create(blockCipher)
      as IPaddedBufferedBlockCipher;
    Exit;
  end;

  if (asymBlockCipher <> Nil) then
  begin
    Result := TBufferedAsymmetricBlockCipher.Create(asymBlockCipher) as IBufferedAsymmetricBlockCipher;
    Exit;
  end;

  raise ESecurityUtilityCryptoLibException.CreateResFmt(@SUnRecognizedCipher,
    [algorithm]);
end;

class function TCipherUtilities.GetCipher(const oid: IDerObjectIdentifier)
  : IBufferedCipher;
begin
  Result := GetCipher(oid.Id);
end;

class function TCipherUtilities.GetObjectIdentifier(mechanism: String)
  : IDerObjectIdentifier;
var
  aliased: String;
begin
  if (mechanism = '') then
    raise EArgumentNilCryptoLibException.CreateRes(@SMechanismNil);

  mechanism := UpperCase(mechanism);
  if Falgorithms.TryGetValue(mechanism, aliased) then
  begin
    mechanism := aliased;
  end;

  Foids.TryGetValue(mechanism, Result);

end;

end.
