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

unit ClpParameterUtilities;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpAsn1Objects,
  ClpCollectionUtilities,
  ClpCryptoLibComparers,
  ClpCryptoLibTypes,
  ClpCryptoProObjectIdentifiers,
  ClpIAsn1Objects,
  ClpIKeyParameter,
  ClpICipherParameters,
  ClpIParametersWithRandom,
  ClpISecureRandom,
  ClpKeyParameter,
  ClpMiscObjectIdentifiers,
  ClpNistObjectIdentifiers,
  ClpOiwObjectIdentifiers,
  ClpParametersWithRandom,
  ClpParametersWithIV,
  ClpSecureRandom;

resourcestring
  SAlgorithmNil = 'Algorithm Cannot be Nil';
  SAlgorithmNotRecognised = 'Algorithm "%s" not recognised.';
  SCouldNotProcessAsn1Parameters = 'Could not process ASN.1 parameters';
  SCouldNotProcessAsn1ParametersFmt = 'Could not process ASN.1 parameters: %s';
  SParametersWithContextNotImpl = 'ParametersWithContext not implemented';

type
  TParameterUtilities = class sealed(TObject)
  strict private
    class var
      FAlgorithms: TDictionary<String, String>;
      FBasicIVSizes: TDictionary<String, Int32>;

    class procedure AddAlgorithm(const ACanonicalName: String;
      const AAliases: array of String); static;
    class procedure AddBasicIVSizeEntries(ASize: Int32;
      const AAlgorithms: array of String); static;
    class function FindBasicIVSize(const ACanonicalName: String): Int32; static;
    class function CreateIV(const ARandom: ISecureRandom; AIVLength: Int32): TCryptoLibByteArray; static;
    class function CreateIVOctetString(const ARandom: ISecureRandom;
      AIVLength: Int32): IAsn1Encodable; static;
    class procedure Boot; static;
    class constructor Create;
    class destructor Destroy;
  public
    class function GetCanonicalAlgorithmName(const AAlgorithm: String): String; static;
    class function CreateKeyParameter(const AAlgOid: IDerObjectIdentifier;
      const AKeyBytes: TCryptoLibByteArray): IKeyParameter; overload; static;
    class function CreateKeyParameter(const AAlgorithm: String;
      const AKeyBytes: TCryptoLibByteArray): IKeyParameter; overload; static;
    class function CreateKeyParameter(const AAlgOid: IDerObjectIdentifier;
      const AKeyBytes: TCryptoLibByteArray; AOffset, ALength: Int32): IKeyParameter; overload; static;
    class function CreateKeyParameter(const AAlgorithm: String;
      const AKeyBytes: TCryptoLibByteArray; AOffset, ALength: Int32): IKeyParameter; overload; static;
    class function GetCipherParameters(const AAlgOid: IDerObjectIdentifier;
      const AKey: ICipherParameters; const AAsn1Params: IAsn1Encodable): ICipherParameters; overload; static;
    class function GetCipherParameters(const AAlgorithm: String;
      const AKey: ICipherParameters; const AAsn1Params: IAsn1Encodable): ICipherParameters; overload; static;
    class function GenerateParameters(const AAlgId: IDerObjectIdentifier;
      const ARandom: ISecureRandom): IAsn1Encodable; overload; static;
    class function GenerateParameters(const AAlgorithm: String;
      const ARandom: ISecureRandom): IAsn1Encodable; overload; static;
    class function GetRandom(const ACipherParameters: ICipherParameters;
      out ARandom: ISecureRandom): ICipherParameters; static;
    class function IgnoreRandom(const ACipherParameters: ICipherParameters): ICipherParameters; static;
    class function WithRandom(const ACp: ICipherParameters;
      const ARandom: ISecureRandom): ICipherParameters; static;
  end;

implementation

{ TParameterUtilities }

class procedure TParameterUtilities.AddAlgorithm(const ACanonicalName: String;
  const AAliases: array of String);
var
  LAlias: String;
begin
  FAlgorithms.AddOrSetValue(ACanonicalName, ACanonicalName);
  for LAlias in AAliases do
    FAlgorithms.AddOrSetValue(LAlias, ACanonicalName);
end;

class procedure TParameterUtilities.AddBasicIVSizeEntries(ASize: Int32;
  const AAlgorithms: array of String);
var
  LAlg: String;
begin
  for LAlg in AAlgorithms do
    FBasicIVSizes.Add(LAlg, ASize);
end;

class function TParameterUtilities.FindBasicIVSize(const ACanonicalName: String): Int32;
var
  LSize: Int32;
begin
  if FBasicIVSizes.TryGetValue(ACanonicalName, LSize) then
    Result := LSize
  else
    Result := -1;
end;

class function TParameterUtilities.CreateIV(const ARandom: ISecureRandom;
  AIVLength: Int32): TCryptoLibByteArray;
begin
  Result := TSecureRandom.GetNextBytes(ARandom, AIVLength);
end;

class function TParameterUtilities.CreateIVOctetString(const ARandom: ISecureRandom;
  AIVLength: Int32): IAsn1Encodable;
begin
  Result := TDerOctetString.Create(CreateIV(ARandom, AIVLength));
end;

class procedure TParameterUtilities.Boot;
begin
  TNistObjectIdentifiers.Boot;

  FAlgorithms := TDictionary<String, String>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FBasicIVSizes := TDictionary<String, Int32>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);

  AddAlgorithm('AES', ['AESWRAP']);

  AddAlgorithm('AES128', [
    TNistObjectIdentifiers.IdAes128Cbc.ID,
    TNistObjectIdentifiers.IdAes128Cfb.ID,
    TNistObjectIdentifiers.IdAes128Ecb.ID,
    TNistObjectIdentifiers.IdAes128Ofb.ID
    ]);

  AddAlgorithm('AES192', [
    TNistObjectIdentifiers.IdAes192Cbc.ID,
    TNistObjectIdentifiers.IdAes192Cfb.ID,
    TNistObjectIdentifiers.IdAes192Ecb.ID,
    TNistObjectIdentifiers.IdAes192Ofb.ID
    ]);

  AddAlgorithm('AES256', [
    TNistObjectIdentifiers.IdAes256Cbc.ID,
    TNistObjectIdentifiers.IdAes256Cfb.ID,
    TNistObjectIdentifiers.IdAes256Ecb.ID,
    TNistObjectIdentifiers.IdAes256Ofb.ID
    ]);


  AddAlgorithm('BLOWFISH', ['1.3.6.1.4.1.3029.1.2', TMiscObjectIdentifiers.CryptlibAlgorithmBlowfishCbc.ID]);

  AddAlgorithm('RIJNDAEL', []);
  AddAlgorithm('SALSA20', []);

  AddBasicIVSizeEntries(8, ['BLOWFISH', 'SALSA20']);
  AddBasicIVSizeEntries(16, ['AES', 'AES128', 'AES192', 'AES256']);
end;

class constructor TParameterUtilities.Create;
begin
  Boot;
end;

class destructor TParameterUtilities.Destroy;
begin
  FAlgorithms.Free;
  FBasicIVSizes.Free;
end;

class function TParameterUtilities.GetCanonicalAlgorithmName(const AAlgorithm: String): String;
begin
  Result := TCollectionUtilities.GetValueOrNull<String, String>(FAlgorithms, AAlgorithm);
end;

class function TParameterUtilities.CreateKeyParameter(const AAlgorithm: String;
  const AKeyBytes: TCryptoLibByteArray; AOffset, ALength: Int32): IKeyParameter;
var
  LCanonical: String;
begin
  if AAlgorithm = '' then
    raise EArgumentNilCryptoLibException.CreateRes(@SAlgorithmNil);
  LCanonical := GetCanonicalAlgorithmName(AAlgorithm);
  if LCanonical = '' then
    raise ESecurityUtilityCryptoLibException.CreateResFmt(@SAlgorithmNotRecognised, [AAlgorithm]);

  Result := TKeyParameter.Create(AKeyBytes, AOffset, ALength) as IKeyParameter;
end;

class function TParameterUtilities.CreateKeyParameter(const AAlgorithm: String;
  const AKeyBytes: TCryptoLibByteArray): IKeyParameter;
begin
  Result := CreateKeyParameter(AAlgorithm, AKeyBytes, 0, System.Length(AKeyBytes));
end;

class function TParameterUtilities.CreateKeyParameter(const AAlgOid: IDerObjectIdentifier;
  const AKeyBytes: TCryptoLibByteArray): IKeyParameter;
begin
  Result := CreateKeyParameter(AAlgOid.ID, AKeyBytes, 0, System.Length(AKeyBytes));
end;

class function TParameterUtilities.CreateKeyParameter(const AAlgOid: IDerObjectIdentifier;
  const AKeyBytes: TCryptoLibByteArray; AOffset, ALength: Int32): IKeyParameter;
begin
  Result := CreateKeyParameter(AAlgOid.ID, AKeyBytes, AOffset, ALength);
end;

class function TParameterUtilities.GetCipherParameters(const AAlgOid: IDerObjectIdentifier;
  const AKey: ICipherParameters; const AAsn1Params: IAsn1Encodable): ICipherParameters;
begin
  Result := GetCipherParameters(AAlgOid.ID, AKey, AAsn1Params);
end;

class function TParameterUtilities.GetCipherParameters(const AAlgorithm: String;
  const AKey: ICipherParameters; const AAsn1Params: IAsn1Encodable): ICipherParameters;
var
  LCanonical: String;
  LBasicIVSize: Int32;
  LOctet: IAsn1OctetString;
  LIV: TCryptoLibByteArray;
begin
  if AAlgorithm = '' then
    raise EArgumentNilCryptoLibException.CreateRes(@SAlgorithmNil);

  LCanonical := GetCanonicalAlgorithmName(AAlgorithm);
  if LCanonical = '' then
    raise ESecurityUtilityCryptoLibException.CreateResFmt(@SAlgorithmNotRecognised, [AAlgorithm]);

  LBasicIVSize := FindBasicIVSize(LCanonical);
  if (LBasicIVSize >= 0) or (LCanonical = 'RIJNDAEL') then
  begin
    try
      LOctet := TAsn1OctetString.GetInstance(AAsn1Params as IAsn1Convertible);
      LIV := LOctet.GetOctets();
      Result := TParametersWithIV.Create(AKey, LIV);
    except
      on E: Exception do
        raise EArgumentCryptoLibException.CreateResFmt(@SCouldNotProcessAsn1ParametersFmt, [E.Message]);
    end;
    Exit;
  end;
  raise ESecurityUtilityCryptoLibException.CreateResFmt(@SAlgorithmNotRecognised, [AAlgorithm]);
end;

class function TParameterUtilities.GenerateParameters(const AAlgId: IDerObjectIdentifier;
  const ARandom: ISecureRandom): IAsn1Encodable;
begin
  Result := GenerateParameters(AAlgId.ID, ARandom);
end;

class function TParameterUtilities.GenerateParameters(const AAlgorithm: String;
  const ARandom: ISecureRandom): IAsn1Encodable;
var
  LCanonical: String;
  LBasicIVSize: Int32;
begin
  if AAlgorithm = '' then
    raise EArgumentNilCryptoLibException.CreateRes(@SAlgorithmNil);
  LCanonical := GetCanonicalAlgorithmName(AAlgorithm);
  if LCanonical = '' then
    raise ESecurityUtilityCryptoLibException.CreateResFmt(@SAlgorithmNotRecognised, [AAlgorithm]);
  LBasicIVSize := FindBasicIVSize(LCanonical);
  if LBasicIVSize >= 0 then
  begin
    Result := CreateIVOctetString(ARandom, LBasicIVSize);
    Exit;
  end;

  raise ESecurityUtilityCryptoLibException.CreateResFmt(@SAlgorithmNotRecognised, [AAlgorithm]);
end;

class function TParameterUtilities.GetRandom(const ACipherParameters: ICipherParameters;
  out ARandom: ISecureRandom): ICipherParameters;
var
  LWithRandom: IParametersWithRandom;
begin
  if Supports(ACipherParameters, IParametersWithRandom, LWithRandom) then
  begin
    ARandom := LWithRandom.Random;
    Result := LWithRandom.Parameters;
  end
  else
  begin
    ARandom := nil;
    Result := ACipherParameters;
  end;
end;

class function TParameterUtilities.IgnoreRandom(const ACipherParameters: ICipherParameters): ICipherParameters;
var
  LWithRandom: IParametersWithRandom;
begin
  if Supports(ACipherParameters, IParametersWithRandom, LWithRandom) then
    Result := LWithRandom.Parameters
  else
    Result := ACipherParameters;
end;

class function TParameterUtilities.WithRandom(const ACp: ICipherParameters;
  const ARandom: ISecureRandom): ICipherParameters;
var
  LCp: ICipherParameters;
begin
  LCp := ACp;
  if ARandom <> nil then
    LCp := TParametersWithRandom.Create(LCp, ARandom);
  Result := LCp;
end;

end.
