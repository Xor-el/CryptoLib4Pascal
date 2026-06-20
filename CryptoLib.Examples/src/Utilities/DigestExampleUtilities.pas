{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit DigestExampleUtilities;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

uses
  SysUtils,
  ClpIDigest,
  ClpIMac,
  ClpDigestUtilities,
  ClpMacUtilities,
  ClpEncoders,
  ClpKeyParameter,
  ClpPkcs5S2ParametersGenerator,
  ClpIPkcs5S2ParametersGenerator,
  ClpArgon2ParametersGenerator,
  ClpIArgon2ParametersGenerator,
  ClpScryptParametersGenerator,
  ClpIScryptParametersGenerator,
  ClpICipherParameters,
  ClpIKeyParameter,
  ClpCryptoLibTypes,
  ExampleBase,
  ExampleLogger;

type
  TDigestExampleUtilities = class sealed
  strict private
    class procedure LogDerivedKey(const ALabel: string; const AParams: ICipherParameters); static;
  public
    class procedure RunHash(const ADigestAlgorithm: string; const AInput: TBytes); static;
    class procedure RunHmac(const AHmacAlgorithm: string; const AKey, AMsg: TBytes); static;
    class procedure RunPbkdf2(const ADigestAlgorithm: string; const APassword, ASalt: TBytes;
      AIters, AKeyBits: Int32; const ALabel: string); static;
    class procedure RunArgon2(const AArgon2Type: TCryptoLibArgon2Type; const APassword, ASalt: TBytes;
      AIterations, AMemoryKb, ALanes: Int32; AKeyBits: Int32; const ALabel: string); static;
    class procedure RunScrypt(const APassword, ASalt: TBytes; AN, Ar, Ap, AKeyBits: Int32;
      const ALabel: string); static;
  end;

implementation

class procedure TDigestExampleUtilities.LogDerivedKey(const ALabel: string;
  const AParams: ICipherParameters);
var
  LKey: IKeyParameter;
  LDerived: TBytes;
  LLogger: ILogger;
begin
  LLogger := TExampleLogger.GetDefaultLogger;
  if Supports(AParams, IKeyParameter, LKey) then
  begin
    LDerived := LKey.GetKey();
    LLogger.LogInformation('{0} derived {1} bytes:{2}{3}', [ALabel, IntToStr(System.Length(LDerived)), sLineBreak,
      THexEncoder.Encode(LDerived, False)]);
  end
  else
    LLogger.LogWarning('{0}: could not get key parameter.', [ALabel]);
end;

class procedure TDigestExampleUtilities.RunHash(const ADigestAlgorithm: string;
  const AInput: TBytes);
var
  LDigest: IDigest;
  LHash: TBytes;
  LLogger: ILogger;
begin
  LLogger := TExampleLogger.GetDefaultLogger;
  LLogger.LogInformation('Digest: {0}', [ADigestAlgorithm]);
  LDigest := TDigestUtilities.GetDigest(ADigestAlgorithm);
  if LDigest = nil then
  begin
    LLogger.LogWarning('Digest "{0}" not available.', [ADigestAlgorithm]);
    Exit;
  end;
  System.SetLength(LHash, LDigest.GetDigestSize);
  LDigest.BlockUpdate(AInput, 0, System.Length(AInput));
  LDigest.DoFinal(LHash, 0);
  LLogger.LogInformation('Hash {0}:{1}{2}', [ADigestAlgorithm, sLineBreak, THexEncoder.Encode(LHash, False)]);
end;

class procedure TDigestExampleUtilities.RunHmac(const AHmacAlgorithm: string;
  const AKey, AMsg: TBytes);
var
  LMac: IMac;
  LResult: TBytes;
  LLogger: ILogger;
begin
  LLogger := TExampleLogger.GetDefaultLogger;
  LLogger.LogInformation('HMAC: {0}', [AHmacAlgorithm]);
  LMac := TMacUtilities.GetMac(AHmacAlgorithm);
  if LMac = nil then
  begin
    LLogger.LogWarning('HMAC "{0}" not available.', [AHmacAlgorithm]);
    Exit;
  end;
  LMac.Init(TKeyParameter.Create(AKey) as IKeyParameter);
  LMac.BlockUpdate(AMsg, 0, System.Length(AMsg));
  LResult := LMac.DoFinal;
  LLogger.LogInformation('{0}:{1}{2}', [AHmacAlgorithm, sLineBreak, THexEncoder.Encode(LResult, False)]);
end;

class procedure TDigestExampleUtilities.RunPbkdf2(const ADigestAlgorithm: string;
  const APassword, ASalt: TBytes; AIters, AKeyBits: Int32; const ALabel: string);
var
  LGen: IPkcs5S2ParametersGenerator;
  LDigest: IDigest;
  LParams: ICipherParameters;
  LLogger: ILogger;
begin
  LLogger := TExampleLogger.GetDefaultLogger;
  LLogger.LogInformation('PBKDF2: digest {0}, {1} iterations', [ADigestAlgorithm, IntToStr(AIters)]);
  LDigest := TDigestUtilities.GetDigest(ADigestAlgorithm);
  if LDigest = nil then
  begin
    LLogger.LogWarning('Digest "{0}" not available for PBKDF2.', [ADigestAlgorithm]);
    Exit;
  end;
  LGen := TPkcs5S2ParametersGenerator.Create(LDigest) as IPkcs5S2ParametersGenerator;
  LGen.Init(APassword, ASalt, AIters);
  LParams := LGen.GenerateDerivedParameters('AES', AKeyBits);
  LogDerivedKey(ALabel, LParams);
end;

class procedure TDigestExampleUtilities.RunArgon2(const AArgon2Type: TCryptoLibArgon2Type;
  const APassword, ASalt: TBytes; AIterations, AMemoryKb, ALanes, AKeyBits: Int32;
  const ALabel: string);
var
  LGen: IArgon2ParametersGenerator;
  LParams: ICipherParameters;
begin
  LGen := TArgon2ParametersGenerator.Create() as IArgon2ParametersGenerator;
  LGen.Init(AArgon2Type, TCryptoLibArgon2Version.Argon2Version13,
    APassword, ASalt, nil, nil, AIterations, AMemoryKb, ALanes, TCryptoLibArgon2MemoryCostType.MemoryAsKB);
  LParams := LGen.GenerateDerivedParameters('AES', AKeyBits);
  LogDerivedKey(ALabel, LParams);
end;

class procedure TDigestExampleUtilities.RunScrypt(const APassword, ASalt: TBytes;
  AN, Ar, Ap, AKeyBits: Int32; const ALabel: string);
var
  LGen: IScryptParametersGenerator;
  LParams: ICipherParameters;
begin
  LGen := TScryptParametersGenerator.Create() as IScryptParametersGenerator;
  LGen.Init(APassword, ASalt, AN, Ar, Ap);
  LParams := LGen.GenerateDerivedParameters('AES', AKeyBits);
  LogDerivedKey(ALabel, LParams);
end;

end.
