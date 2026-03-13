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

unit ClpExampleBase;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
  Rtti,
  ClpValueHelper,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpICipherParameters,
  ClpLogger,
  ClpGeneratorUtilities,
  ClpSecureRandom,
  ClpBigInteger,
  ClpRsaParameters,
  ClpIRsaParameters,
  ClpECParameters,
  ClpIECParameters,
  ClpEd25519Parameters,
  ClpIEd25519Parameters,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpISecureRandom,
  ClpECGenerators,
  ClpIECGenerators,
  ClpIKeyParameter,
  ClpIOpenSslPemWriter,
  ClpOpenSslPemWriter,
  ClpIOpenSslPemReader,
  ClpOpenSslPemReader,
  ClpEncoders;

type
  TExampleLogger = class
  private
    class var FDefaultLogger: ILogger;
  public
    class procedure SetDefaultLogger(const ALogger: ILogger);
    class function GetDefaultLogger: ILogger;
  end;

  IExample = interface(IInterface)
    ['{30D86CA2-0F19-4AA6-B106-0A13241BC5AA}']
    procedure Run;
  end;

  TExampleBase = class(TInterfacedObject, IExample)
  protected
    function ExportToPem(const AValue: TValue): string;
    function ImportFromPem(const APem: string): TValue;
    function ImportKeyPairFromPem(const APem: string;
      out AKeyPair: IAsymmetricCipherKeyPair): Boolean;
    function ImportKeyFromPem(const APem: string;
      out AKey: IAsymmetricKeyParameter): Boolean;
    function GenerateRsaKeyPair(AKeySize: Int32 = 2048): IAsymmetricCipherKeyPair;
    function GenerateEcKeyPair(const ADomain: IECDomainParameters): IAsymmetricCipherKeyPair;
    function GenerateEd25519KeyPair: IAsymmetricCipherKeyPair;
    procedure VerifyPemRoundtrip(const AKeyPair: IAsymmetricCipherKeyPair;
      const AKeyType: string);
    procedure LogDerivedKey(const ALabel: string;
      const AParams: ICipherParameters);
    procedure LogWithLineBreak(const AMessage: string);
  public
    function Logger: ILogger;
    procedure Run; virtual; abstract;
  end;

implementation

{ TClpLogger }

class procedure TExampleLogger.SetDefaultLogger(const ALogger: ILogger);
begin
  FDefaultLogger := ALogger;
end;

class function TExampleLogger.GetDefaultLogger: ILogger;
begin
  Result := FDefaultLogger;
end;

function TExampleBase.Logger: ILogger;
begin
  Result := TExampleLogger.GetDefaultLogger;
end;

function TExampleBase.ExportToPem(const AValue: TValue): string;
var
  LStream: TStringStream;
  LWriter: IOpenSslPemWriter;
begin
  LStream := TStringStream.Create('', TEncoding.ASCII);
  try
    LWriter := TOpenSslPemWriter.Create(LStream);
    LWriter.WriteObject(AValue);
    Result := LStream.DataString;
  finally
    LStream.Free;
  end;
end;

function TExampleBase.ImportFromPem(const APem: string): TValue;
var
  LStream: TStringStream;
  LReader: IOpenSslPemReader;
begin
  Result := TValue.Empty;
  if (APem = '') then
    Exit;
  LStream := TStringStream.Create(APem, TEncoding.ASCII);
  try
    LReader := TOpenSslPemReader.Create(LStream);
    Result := LReader.ReadObject();
  finally
    LStream.Free;
  end;
end;

function TExampleBase.ImportKeyPairFromPem(const APem: string;
  out AKeyPair: IAsymmetricCipherKeyPair): Boolean;
var
  LStream: TStringStream;
  LReader: IOpenSslPemReader;
  LReadVal: TValue;
begin
  Result := False;
  LStream := TStringStream.Create(APem, TEncoding.ASCII);
  try
    LReader := TOpenSslPemReader.Create(LStream);
    LReadVal := LReader.ReadObject();
    if LReadVal.IsEmpty then
      Exit;
    Result := LReadVal.TryGetAsType<IAsymmetricCipherKeyPair>(AKeyPair);
  finally
    LStream.Free;
  end;
end;

function TExampleBase.ImportKeyFromPem(const APem: string;
  out AKey: IAsymmetricKeyParameter): Boolean;
var
  LStream: TStringStream;
  LReader: IOpenSslPemReader;
  LReadVal: TValue;
begin
  Result := False;
  LStream := TStringStream.Create(APem, TEncoding.ASCII);
  try
    LReader := TOpenSslPemReader.Create(LStream);
    LReadVal := LReader.ReadObject();
    if LReadVal.IsEmpty then
      Exit;
    Result := LReadVal.TryGetAsType<IAsymmetricKeyParameter>(AKey);
  finally
    LStream.Free;
  end;
end;

function TExampleBase.GenerateRsaKeyPair(AKeySize: Int32): IAsymmetricCipherKeyPair;
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
begin
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('RSA');
  LKpg.Init(TRsaKeyGenerationParameters.Create(TBigInteger.ValueOf(65537),
    TSecureRandom.Create() as ISecureRandom, AKeySize, 25) as IRsaKeyGenerationParameters);
  Result := LKpg.GenerateKeyPair();
end;

function TExampleBase.GenerateEcKeyPair(
  const ADomain: IECDomainParameters): IAsymmetricCipherKeyPair;
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
begin
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('ECDSA');
  LKpg.Init(TECKeyGenerationParameters.Create(ADomain,
    TSecureRandom.Create() as ISecureRandom) as IECKeyGenerationParameters);
  Result := LKpg.GenerateKeyPair();
end;

function TExampleBase.GenerateEd25519KeyPair: IAsymmetricCipherKeyPair;
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
begin
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('Ed25519');
  LKpg.Init(TEd25519KeyGenerationParameters.Create(
    TSecureRandom.Create() as ISecureRandom) as IEd25519KeyGenerationParameters);
  Result := LKpg.GenerateKeyPair();
end;

procedure TExampleBase.VerifyPemRoundtrip(const AKeyPair: IAsymmetricCipherKeyPair;
  const AKeyType: string);
var
  LPrivPem, LPubPem: string;
  LReadPair: IAsymmetricCipherKeyPair;
  LReadPriv, LReadPub: IAsymmetricKeyParameter;
begin
  LPrivPem := ExportToPem(TValue.From<IAsymmetricKeyParameter>(AKeyPair.Private));
  Logger.LogInformation('{0} Private Key PEM:{1}{2}', [AKeyType, sLineBreak, LPrivPem]);

  LPubPem := ExportToPem(TValue.From<IAsymmetricKeyParameter>(AKeyPair.Public));
  Logger.LogInformation('{0} Public Key PEM:{1}{2}', [AKeyType, sLineBreak, LPubPem]);

  if ImportKeyPairFromPem(LPrivPem, LReadPair) then
  begin
    if LReadPair.Private.Equals(AKeyPair.Private) then
      Logger.LogInformation('Private key roundtrip: match.', [])
    else
      Logger.LogWarning('Private key roundtrip: mismatch.', []);
    if LReadPair.Public.Equals(AKeyPair.Public) then
      Logger.LogInformation('Public key (from private PEM) roundtrip: match.', [])
    else
      Logger.LogWarning('Public key (from private PEM) roundtrip: mismatch.', []);
  end
  else if ImportKeyFromPem(LPrivPem, LReadPriv) then
  begin
    if LReadPriv.Equals(AKeyPair.Private) then
      Logger.LogInformation('Private key roundtrip: match.', [])
    else
      Logger.LogWarning('Private key roundtrip: mismatch.', []);
  end
  else
  begin
    Logger.LogError('Failed to read back {0} private key from PEM.', [AKeyType]);
    Exit;
  end;

  if not ImportKeyFromPem(LPubPem, LReadPub) then
  begin
    Logger.LogError('Failed to read back {0} public key from PEM.', [AKeyType]);
    Exit;
  end;
  if LReadPub.Equals(AKeyPair.Public) then
    Logger.LogInformation('Public key roundtrip: match.', [])
  else
    Logger.LogWarning('Public key roundtrip: mismatch.', []);
end;

procedure TExampleBase.LogDerivedKey(const ALabel: string;
  const AParams: ICipherParameters);
var
  LKey: IKeyParameter;
  LDerived: TBytes;
begin
  if Supports(AParams, IKeyParameter, LKey) then
  begin
    LDerived := LKey.GetKey();
    Logger.LogInformation('{0} derived {1} bytes:{2}{3}', [ALabel, IntToStr(System.Length(LDerived)), sLineBreak, THexEncoder.Encode(LDerived, False)]);
  end
  else
    Logger.LogWarning('{0}: could not get key parameter.', [ALabel]);
end;

procedure TExampleBase.LogWithLineBreak(const AMessage: string);
begin
  Logger.LogInformation('{0}{1}', [AMessage, sLineBreak])
end;

end.
