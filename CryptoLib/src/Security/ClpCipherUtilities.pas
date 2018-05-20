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
  ClpStringHelper,
  ClpPkcs7Padding,
  ClpIPkcs7Padding,
  ClpZeroBytePadding,
  ClpIZeroBytePadding,
  ClpCbcBlockCipher,
  ClpICbcBlockCipher,
  ClpBufferedBlockCipher,
  ClpIBufferedBlockCipher,
  ClpPaddedBufferedBlockCipher,
  ClpIPaddedBufferedBlockCipher,
  ClpNistObjectIdentifiers,
  ClpIDerObjectIdentifier,
  ClpIBufferedCipher,
  ClpIBlockCipher,
  ClpAesEngine,
  ClpIAesEngine,
  ClpIBlockCipherPadding;

resourcestring
  SMechanismNil = 'Mechanism Cannot be Nil';
  SAlgorithmNil = 'Algorithm Cannot be Nil';
  SUnRecognizedCipher = '"Cipher " %s Not Recognised.';

type

  /// <remarks>
  /// Cipher Utility class contains methods that can not be specifically grouped into other classes.
  /// </remarks>
  TCipherUtilities = class sealed(TObject)

  strict private

  type
{$SCOPEDENUMS ON}
    TCipherAlgorithm = (AES);
    TCipherMode = (NONE, CBC);
    TCipherPadding = (NOPADDING, PKCS5, PKCS5PADDING, PKCS7, PKCS7PADDING,
      ZEROBYTEPADDING);
{$SCOPEDENUMS OFF}

  class var

    Falgorithms: TDictionary<String, String>;
    Foids: TDictionary<String, IDerObjectIdentifier>;

    class function GetAlgorithms: TCryptoLibStringArray; static; inline;
    class function GetDigitIndex(const s: String): Int32; static; inline;

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
    class procedure Boot(); static;

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

  Falgorithms.Add(TNistObjectIdentifiers.IdAes128Cbc.Id,
    'AES/CBC/PKCS7PADDING');
  Falgorithms.Add(TNistObjectIdentifiers.IdAes192Cbc.Id,
    'AES/CBC/PKCS7PADDING');
  Falgorithms.Add(TNistObjectIdentifiers.IdAes256Cbc.Id,
    'AES/CBC/PKCS7PADDING');

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
{$IFDEF DELPHIXE3_UP}
  LowPoint := System.Low(s);
  HighPoint := System.High(s);
{$ELSE}
  LowPoint := 1;
  HighPoint := System.Length(s);
{$ENDIF DELPHIXE3_UP}
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
  di, LowPoint: Int32;
  padded: Boolean;
  parts: TCryptoLibStringArray;
  cipherAlgorithm: TCipherAlgorithm;
  cipherPadding: TCipherPadding;
  cipherMode: TCipherMode;
  blockCipher: IBlockCipher;
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

  parts := algorithm.SplitString('/');

  blockCipher := Nil;

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
      end
  else
    begin
      raise ESecurityUtilityCryptoLibException.CreateResFmt
        (@SUnRecognizedCipher, [algorithm]);
    end;
  end;

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
          padded := false;
        end;
      TCipherPadding.PKCS5, TCipherPadding.PKCS5PADDING, TCipherPadding.PKCS7,
        TCipherPadding.PKCS7PADDING:
        begin
          padding := TPkcs7Padding.Create() as IPkcs7Padding;
        end;
      TCipherPadding.ZEROBYTEPADDING:
        begin
          padding := TZeroBytePadding.Create() as IZeroBytePadding;
        end;
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
{$IFDEF DELPHIXE3_UP}
      LowPoint := System.Low(mode);
{$ELSE}
      LowPoint := 1;
{$ENDIF DELPHIXE3_UP}
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
      TCipherMode.NONE:
        begin
          // do nothing
        end;
      TCipherMode.CBC:
        begin
          blockCipher := TCbcBlockCipher.Create(blockCipher) as ICbcBlockCipher;
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
