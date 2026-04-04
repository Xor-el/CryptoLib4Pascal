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

unit ClpOpenSslPemUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBufferedCipher,
  ClpICipherParameters,
  ClpCipherUtilities,
  ClpParametersWithIV,
  ClpIOpenSslPbeParametersGenerator,
  ClpOpenSslPbeParametersGenerator,
  ClpPbeParametersGenerator,
  ClpEnumUtilities,
  ClpStringUtilities,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SUnknownDekAlgorithm = 'Unknown DEK algorithm: %s';

type
  /// <summary>
  /// Internal PEM encryption/decryption for OpenSSL DEK-Info.
  /// </summary>
  TOpenSslPemUtilities = class sealed(TObject)
  strict private
  type
    TPemBaseAlg = (AES_128, AES_192, AES_256, BF);
    TPemMode = (CBC, CFB, ECB, OFB);

    class procedure ParseDekAlgName(const ADekAlgName: String;
      out ABaseAlg: TPemBaseAlg; out AMode: TPemMode); static;
    class function GetCipherParameters(const APassword: TCryptoLibCharArray;
      ABaseAlg: TPemBaseAlg; const ASalt: TCryptoLibByteArray): ICipherParameters;
      static;
    class function TryGetCipherAlgorithm(ABaseAlg: TPemBaseAlg;
      out AAlgorithm: String; out AKeyBits: Int32): Boolean; static;
  public
    /// <summary>
    /// Encrypt or decrypt PEM key data. Only AES-* and BF-* DEK algorithms supported.
    /// </summary>
    class function Crypt(AEncrypt: Boolean; const ABytes: TCryptoLibByteArray;
      const APassword: TCryptoLibCharArray; const ADekAlgName: String;
      const AIV: TCryptoLibByteArray): TCryptoLibByteArray; static;
  end;

implementation

{ TOpenSslPemUtilities }

class procedure TOpenSslPemUtilities.ParseDekAlgName(const ADekAlgName: String;
  out ABaseAlg: TPemBaseAlg; out AMode: TPemMode);
var
  LPos: Int32;
  LBasePart, LModePart: String;
begin
  if (ADekAlgName = 'DES-EDE') or (ADekAlgName = 'DES-EDE3') then
    raise EArgumentCryptoLibException.CreateResFmt(@SUnknownDekAlgorithm,
      [ADekAlgName]);

  LPos := TStringUtilities.LastIndexOf(ADekAlgName, '-');
  if LPos >= 1 then
  begin
    LBasePart := TStringUtilities.Substring(ADekAlgName, 1, LPos - 1);
    LModePart := TStringUtilities.Substring(ADekAlgName, LPos + 1);

    if (TEnumUtilities.TryGetEnumValue<TPemBaseAlg>(LBasePart, ABaseAlg)) and
       (TEnumUtilities.TryGetEnumValue<TPemMode>(LModePart, AMode)) then
      Exit;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SUnknownDekAlgorithm,
    [ADekAlgName]);
end;

class function TOpenSslPemUtilities.TryGetCipherAlgorithm(ABaseAlg: TPemBaseAlg;
  out AAlgorithm: String; out AKeyBits: Int32): Boolean;
begin
  Result := True;
  case ABaseAlg of
    TPemBaseAlg.AES_128:
      begin
        AAlgorithm := 'AES128';
        AKeyBits := 128;
      end;
    TPemBaseAlg.AES_192:
      begin
        AAlgorithm := 'AES192';
        AKeyBits := 192;
      end;
    TPemBaseAlg.AES_256:
      begin
        AAlgorithm := 'AES256';
        AKeyBits := 256;
      end;
    TPemBaseAlg.BF:
      begin
        AAlgorithm := 'BLOWFISH';
        AKeyBits := 128;
      end;
  else
    AAlgorithm := '';
    AKeyBits := -1;
    Result := False;
  end;
end;

class function TOpenSslPemUtilities.GetCipherParameters(
  const APassword: TCryptoLibCharArray; ABaseAlg: TPemBaseAlg;
  const ASalt: TCryptoLibByteArray): ICipherParameters;
var
  LAlgorithm: String;
  LKeyBits: Int32;
  LPasswordBytes: TCryptoLibByteArray;
  LPGen: IOpenSslPbeParametersGenerator;
begin
  if not TryGetCipherAlgorithm(ABaseAlg, LAlgorithm, LKeyBits) then
    Exit(nil);
  LPasswordBytes := TPbeParametersGenerator.Pkcs5PasswordToBytes(APassword);
  LPGen := TOpenSslPbeParametersGenerator.Create();
  LPGen.Init(LPasswordBytes, ASalt);
  Result := LPGen.GenerateDerivedParameters(LAlgorithm, LKeyBits);
end;

class function TOpenSslPemUtilities.Crypt(AEncrypt: Boolean;
  const ABytes: TCryptoLibByteArray; const APassword: TCryptoLibCharArray;
  const ADekAlgName: String; const AIV: TCryptoLibByteArray)
  : TCryptoLibByteArray;
var
  LBaseAlg: TPemBaseAlg;
  LMode: TPemMode;
  LPadding, LAlgorithm, LCipherName: String;
  LSalt: TCryptoLibByteArray;
  LCipher: IBufferedCipher;
  LCParams: ICipherParameters;
begin
  ParseDekAlgName(ADekAlgName, LBaseAlg, LMode);

  case LMode of
    TPemMode.CBC, TPemMode.ECB:
      LPadding := 'PKCS5Padding';
    TPemMode.CFB, TPemMode.OFB:
      LPadding := 'NoPadding';
  else
    raise EArgumentCryptoLibException.CreateResFmt(@SUnknownDekAlgorithm,
      [ADekAlgName]);
  end;

  LSalt := AIV;
  case LBaseAlg of
    TPemBaseAlg.AES_128, TPemBaseAlg.AES_192, TPemBaseAlg.AES_256:
      begin
        LAlgorithm := 'AES';
        if System.Length(AIV) > 8 then
          LSalt := TArrayUtilities.CopyOfRange<Byte>(AIV, 0, 8);
      end;
    TPemBaseAlg.BF:
      begin
        LAlgorithm := 'BLOWFISH';
      end;
  else
    raise EArgumentCryptoLibException.CreateResFmt(@SUnknownDekAlgorithm,
      [ADekAlgName]);
  end;

  LCipherName := LAlgorithm + '/' + (TEnumUtilities.ToString<TPemMode>(LMode)) + '/' + LPadding;
  LCipher := TCipherUtilities.GetCipher(LCipherName);

  LCParams := GetCipherParameters(APassword, LBaseAlg, LSalt);
  if LMode <> TPemMode.ECB then
    LCParams := TParametersWithIV.Create(LCParams, AIV);

  LCipher.Init(AEncrypt, LCParams);
  Result := LCipher.DoFinal(ABytes);
end;

end.
