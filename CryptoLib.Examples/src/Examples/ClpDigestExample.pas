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

unit ClpDigestExample;

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
  ClpConverters,
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
  ClpExampleBase;

type
  TDigestExample = class(TExampleBase)
  public
    procedure Run; override;
  private
    procedure RunHash(const ADigestAlgorithm: string);
    procedure RunHmac(const AHmacAlgorithm: string);
    procedure RunPbkdf2(const ADigestAlgorithm: string);
    procedure RunArgon2D;
    procedure RunArgon2I;
    procedure RunArgon2Id;
    procedure RunScrypt;
  end;

implementation

procedure TDigestExample.RunHash(const ADigestAlgorithm: string);
var
  LDigest: IDigest;
  LInput, LHash: TBytes;
begin
  Logger.LogInformation('Digest: {0}', [ADigestAlgorithm]);
  LInput := TConverters.ConvertStringToBytes('Hello CryptoLib', TEncoding.UTF8);
  LDigest := TDigestUtilities.GetDigest(ADigestAlgorithm);
  if LDigest = nil then
  begin
    Logger.LogWarning('Digest "{0}" not available.', [ADigestAlgorithm]);
    Exit;
  end;
  System.SetLength(LHash, LDigest.GetDigestSize);
  LDigest.BlockUpdate(LInput, 0, System.Length(LInput));
  LDigest.DoFinal(LHash, 0);
  Logger.LogInformation('Hash {0}:{1}{2}', [ADigestAlgorithm, sLineBreak, THexEncoder.Encode(LHash, False)]);
end;

procedure TDigestExample.RunHmac(const AHmacAlgorithm: string);
var
  LMac: IMac;
  LKey, LMsg, LResult: TBytes;
begin
  Logger.LogInformation('HMAC: {0}', [AHmacAlgorithm]);
  LKey := TConverters.ConvertStringToBytes('secret-key', TEncoding.UTF8);
  LMsg := TConverters.ConvertStringToBytes('message to authenticate', TEncoding.UTF8);
  LMac := TMacUtilities.GetMac(AHmacAlgorithm);
  if LMac = nil then
  begin
    Logger.LogWarning('HMAC "{0}" not available.', [AHmacAlgorithm]);
    Exit;
  end;
  LMac.Init(TKeyParameter.Create(LKey) as IKeyParameter);
  LMac.BlockUpdate(LMsg, 0, System.Length(LMsg));
  LResult := LMac.DoFinal;
  Logger.LogInformation('{0}:{1}{2}', [AHmacAlgorithm, sLineBreak, THexEncoder.Encode(LResult, False)]);
end;

procedure TDigestExample.RunPbkdf2(const ADigestAlgorithm: string);
var
  LGen: IPkcs5S2ParametersGenerator;
  LDigest: IDigest;
  LPassword, LSalt: TBytes;
  LParams: ICipherParameters;
  LIters: Int32;
begin
  LIters := 10000;
  Logger.LogInformation('PBKDF2: digest {0}, {1} iterations', [ADigestAlgorithm, IntToStr(LIters)]);
  LPassword := TConverters.ConvertStringToBytes('password', TEncoding.UTF8);
  LSalt := TConverters.ConvertStringToBytes('salt', TEncoding.UTF8);
  LDigest := TDigestUtilities.GetDigest(ADigestAlgorithm);
  if LDigest = nil then
  begin
    Logger.LogWarning('Digest "{0}" not available for PBKDF2.', [ADigestAlgorithm]);
    Exit;
  end;
  LGen := TPkcs5S2ParametersGenerator.Create(LDigest) as IPkcs5S2ParametersGenerator;
  LGen.Init(LPassword, LSalt, LIters);
  LParams := LGen.GenerateDerivedParameters('AES', 256);
  LogDerivedKey(Format('PBKDF2-HMAC-%s (%d iters)', [ADigestAlgorithm, LIters]), LParams);
end;

procedure TDigestExample.RunArgon2D;
var
  LGen: IArgon2ParametersGenerator;
  LPassword, LSalt: TBytes;
  LParams: ICipherParameters;
begin
  LPassword := TConverters.ConvertStringToBytes('password', TEncoding.UTF8);
  LSalt := TConverters.ConvertStringToBytes('salt', TEncoding.UTF8);
  LGen := TArgon2ParametersGenerator.Create() as IArgon2ParametersGenerator;
  LGen.Init(TCryptoLibArgon2Type.Argon2D, TCryptoLibArgon2Version.Argon2Version13,
    LPassword, LSalt, nil, nil, 2, 65536, 1, TCryptoLibArgon2MemoryCostType.MemoryAsKB);
  LParams := LGen.GenerateDerivedParameters('AES', 256);
  LogDerivedKey('Argon2d (2 iters, 64 MiB, 1 lane)', LParams);
end;

procedure TDigestExample.RunArgon2I;
var
  LGen: IArgon2ParametersGenerator;
  LPassword, LSalt: TBytes;
  LParams: ICipherParameters;
begin
  LPassword := TConverters.ConvertStringToBytes('password', TEncoding.UTF8);
  LSalt := TConverters.ConvertStringToBytes('salt', TEncoding.UTF8);
  LGen := TArgon2ParametersGenerator.Create() as IArgon2ParametersGenerator;
  LGen.Init(TCryptoLibArgon2Type.Argon2I, TCryptoLibArgon2Version.Argon2Version13,
    LPassword, LSalt, nil, nil, 2, 65536, 1, TCryptoLibArgon2MemoryCostType.MemoryAsKB);
  LParams := LGen.GenerateDerivedParameters('AES', 256);
  LogDerivedKey('Argon2i (2 iters, 64 MiB, 1 lane)', LParams);
end;

procedure TDigestExample.RunArgon2Id;
var
  LGen: IArgon2ParametersGenerator;
  LPassword, LSalt: TBytes;
  LParams: ICipherParameters;
begin
  LPassword := TConverters.ConvertStringToBytes('password', TEncoding.UTF8);
  LSalt := TConverters.ConvertStringToBytes('salt', TEncoding.UTF8);
  LGen := TArgon2ParametersGenerator.Create() as IArgon2ParametersGenerator;
  LGen.Init(TCryptoLibArgon2Type.Argon2ID, TCryptoLibArgon2Version.Argon2Version13,
    LPassword, LSalt, nil, nil, 2, 65536, 1, TCryptoLibArgon2MemoryCostType.MemoryAsKB);
  LParams := LGen.GenerateDerivedParameters('AES', 256);
  LogDerivedKey('Argon2id (2 iters, 64 MiB, 1 lane)', LParams);
end;

procedure TDigestExample.RunScrypt;
var
  LGen: IScryptParametersGenerator;
  LPassword, LSalt: TBytes;
  LParams: ICipherParameters;
begin
  LPassword := TConverters.ConvertStringToBytes('password', TEncoding.UTF8);
  LSalt := TConverters.ConvertStringToBytes('salt', TEncoding.UTF8);
  LGen := TScryptParametersGenerator.Create() as IScryptParametersGenerator;
  LGen.Init(LPassword, LSalt, 16384, 8, 1);
  LParams := LGen.GenerateDerivedParameters('AES', 256);
  LogDerivedKey('Scrypt (N=16384, r=8, p=1)', LParams);
end;

procedure TDigestExample.Run;
begin
  LogWithLineBreak('--- Digest example: Hash ---');
  RunHash('SHA-256');
  LogWithLineBreak('--- Digest example: HMAC ---');
  RunHmac('HMAC-SHA256');
  LogWithLineBreak('--- Digest example: Key derivation (PBKDF2) ---');
  RunPbkdf2('SHA-256');
  LogWithLineBreak('--- Digest example: Key derivation (Argon2d) ---');
  RunArgon2D;
  LogWithLineBreak('--- Digest example: Key derivation (Argon2i) ---');
  RunArgon2I;
  LogWithLineBreak('--- Digest example: Key derivation (Argon2id) ---');
  RunArgon2Id;
  LogWithLineBreak('--- Digest example: Key derivation (Scrypt) ---');
  RunScrypt;
end;

end.
