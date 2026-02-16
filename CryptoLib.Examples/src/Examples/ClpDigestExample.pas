unit ClpDigestExample;

interface

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
  Logger.LogInformation('Digest: ' + ADigestAlgorithm);
  LInput := TConverters.ConvertStringToBytes('Hello CryptoLib', TEncoding.UTF8);
  LDigest := TDigestUtilities.GetDigest(ADigestAlgorithm);
  if LDigest = nil then
  begin
    Logger.LogWarning('Digest "' + ADigestAlgorithm + '" not available.');
    Exit;
  end;
  System.SetLength(LHash, LDigest.GetDigestSize);
  LDigest.BlockUpdate(LInput, 0, System.Length(LInput));
  LDigest.DoFinal(LHash, 0);
  Logger.LogInformation(Format('Hash %s: %s', [ADigestAlgorithm, THexEncoder.Encode(LHash, False)]));
end;

procedure TDigestExample.RunHmac(const AHmacAlgorithm: string);
var
  LMac: IMac;
  LKey, LMsg, LResult: TBytes;
begin
  Logger.LogInformation('HMAC: ' + AHmacAlgorithm);
  LKey := TConverters.ConvertStringToBytes('secret-key', TEncoding.UTF8);
  LMsg := TConverters.ConvertStringToBytes('message to authenticate', TEncoding.UTF8);
  LMac := TMacUtilities.GetMac(AHmacAlgorithm);
  if LMac = nil then
  begin
    Logger.LogWarning('HMAC "' + AHmacAlgorithm + '" not available.');
    Exit;
  end;
  LMac.Init(TKeyParameter.Create(LKey) as IKeyParameter);
  LMac.BlockUpdate(LMsg, 0, System.Length(LMsg));
  LResult := LMac.DoFinal;
  Logger.LogInformation(Format('%s: %s', [AHmacAlgorithm, THexEncoder.Encode(LResult, False)]));
end;

procedure TDigestExample.RunPbkdf2(const ADigestAlgorithm: string);
var
  LGen: IPkcs5S2ParametersGenerator;
  LDigest: IDigest;
  LPassword, LSalt: TBytes;
  LParams: ICipherParameters;
  LKey: IKeyParameter;
  LDerived: TBytes;
  LIters: Int32;
begin
  LIters := 10000;
  Logger.LogInformation(Format('PBKDF2: digest %s, %d iterations', [ADigestAlgorithm, LIters]));
  LPassword := TConverters.ConvertStringToBytes('password', TEncoding.UTF8);
  LSalt := TConverters.ConvertStringToBytes('salt', TEncoding.UTF8);
  LDigest := TDigestUtilities.GetDigest(ADigestAlgorithm);
  if LDigest = nil then
  begin
    Logger.LogWarning('Digest "' + ADigestAlgorithm + '" not available for PBKDF2.');
    Exit;
  end;
  LGen := TPkcs5S2ParametersGenerator.Create(LDigest) as IPkcs5S2ParametersGenerator;
  LGen.Init(LPassword, LSalt, LIters);
  LParams := LGen.GenerateDerivedParameters('AES', 256);
  if Supports(LParams, IKeyParameter, LKey) then
  begin
    LDerived := LKey.GetKey();
    Logger.LogInformation(Format('PBKDF2-HMAC-%s (%d iters) derived %d bytes: %s', [ADigestAlgorithm, LIters, System.Length(LDerived), THexEncoder.Encode(LDerived, False)]));
  end
  else
    Logger.LogWarning('PBKDF2: could not get key parameter.');
end;

procedure TDigestExample.RunArgon2D;
var
  LGen: IArgon2ParametersGenerator;
  LPassword, LSalt: TBytes;
  LParams: ICipherParameters;
  LKey: IKeyParameter;
  LDerived: TBytes;
begin
  LPassword := TConverters.ConvertStringToBytes('password', TEncoding.UTF8);
  LSalt := TConverters.ConvertStringToBytes('salt', TEncoding.UTF8);
  LGen := TArgon2ParametersGenerator.Create() as IArgon2ParametersGenerator;
  LGen.Init(TCryptoLibArgon2Type.Argon2D, TCryptoLibArgon2Version.Argon2Version13,
    LPassword, LSalt, nil, nil, 2, 65536, 1, TCryptoLibArgon2MemoryCostType.MemoryAsKB);
  LParams := LGen.GenerateDerivedParameters('AES', 256);
  if Supports(LParams, IKeyParameter, LKey) then
  begin
    LDerived := LKey.GetKey();
    Logger.LogInformation(Format('Argon2d (2 iters, 64 MiB, 1 lane) derived %d bytes: %s', [System.Length(LDerived), THexEncoder.Encode(LDerived, False)]));
  end
  else
    Logger.LogWarning('Argon2d: could not get key parameter.');
end;

procedure TDigestExample.RunArgon2I;
var
  LGen: IArgon2ParametersGenerator;
  LPassword, LSalt: TBytes;
  LParams: ICipherParameters;
  LKey: IKeyParameter;
  LDerived: TBytes;
begin
  LPassword := TConverters.ConvertStringToBytes('password', TEncoding.UTF8);
  LSalt := TConverters.ConvertStringToBytes('salt', TEncoding.UTF8);
  LGen := TArgon2ParametersGenerator.Create() as IArgon2ParametersGenerator;
  LGen.Init(TCryptoLibArgon2Type.Argon2I, TCryptoLibArgon2Version.Argon2Version13,
    LPassword, LSalt, nil, nil, 2, 65536, 1, TCryptoLibArgon2MemoryCostType.MemoryAsKB);
  LParams := LGen.GenerateDerivedParameters('AES', 256);
  if Supports(LParams, IKeyParameter, LKey) then
  begin
    LDerived := LKey.GetKey();
    Logger.LogInformation(Format('Argon2i (2 iters, 64 MiB, 1 lane) derived %d bytes: %s', [System.Length(LDerived), THexEncoder.Encode(LDerived, False)]));
  end
  else
    Logger.LogWarning('Argon2i: could not get key parameter.');
end;

procedure TDigestExample.RunArgon2Id;
var
  LGen: IArgon2ParametersGenerator;
  LPassword, LSalt: TBytes;
  LParams: ICipherParameters;
  LKey: IKeyParameter;
  LDerived: TBytes;
begin
  LPassword := TConverters.ConvertStringToBytes('password', TEncoding.UTF8);
  LSalt := TConverters.ConvertStringToBytes('salt', TEncoding.UTF8);
  LGen := TArgon2ParametersGenerator.Create() as IArgon2ParametersGenerator;
  LGen.Init(TCryptoLibArgon2Type.Argon2ID, TCryptoLibArgon2Version.Argon2Version13,
    LPassword, LSalt, nil, nil, 2, 65536, 1, TCryptoLibArgon2MemoryCostType.MemoryAsKB);
  LParams := LGen.GenerateDerivedParameters('AES', 256);
  if Supports(LParams, IKeyParameter, LKey) then
  begin
    LDerived := LKey.GetKey();
    Logger.LogInformation(Format('Argon2id (2 iters, 64 MiB, 1 lane) derived %d bytes: %s', [System.Length(LDerived), THexEncoder.Encode(LDerived, False)]));
  end
  else
    Logger.LogWarning('Argon2id: could not get key parameter.');
end;

procedure TDigestExample.RunScrypt;
var
  LGen: IScryptParametersGenerator;
  LPassword, LSalt: TBytes;
  LParams: ICipherParameters;
  LKey: IKeyParameter;
  LDerived: TBytes;
begin
  LPassword := TConverters.ConvertStringToBytes('password', TEncoding.UTF8);
  LSalt := TConverters.ConvertStringToBytes('salt', TEncoding.UTF8);
  LGen := TScryptParametersGenerator.Create() as IScryptParametersGenerator;
  LGen.Init(LPassword, LSalt, 16384, 8, 1);
  LParams := LGen.GenerateDerivedParameters('AES', 256);
  if Supports(LParams, IKeyParameter, LKey) then
  begin
    LDerived := LKey.GetKey();
    Logger.LogInformation(Format('Scrypt (N=16384, r=8, p=1) derived %d bytes: %s', [System.Length(LDerived), THexEncoder.Encode(LDerived, False)]));
  end
  else
    Logger.LogWarning('Scrypt: could not get key parameter.');
end;

procedure TDigestExample.Run;
begin
  Logger.LogInformation('--- Digest example: Hash ---');
  RunHash('SHA-256');
  Logger.LogInformation('--- Digest example: HMAC ---');
  RunHmac('HMAC-SHA256');
  Logger.LogInformation('--- Digest example: Key derivation (PBKDF2) ---');
  RunPbkdf2('SHA-256');
  Logger.LogInformation('--- Digest example: Key derivation (Argon2d) ---');
  RunArgon2D;
  Logger.LogInformation('--- Digest example: Key derivation (Argon2i) ---');
  RunArgon2I;
  Logger.LogInformation('--- Digest example: Key derivation (Argon2id) ---');
  RunArgon2Id;
  Logger.LogInformation('--- Digest example: Key derivation (Scrypt) ---');
  RunScrypt;
end;

end.
