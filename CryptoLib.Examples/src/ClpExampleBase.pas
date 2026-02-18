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
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
  Rtti,
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
  IExample = interface(IInterface)
    ['{30D86CA2-0F19-4AA6-B106-0A13241BC5AA}']
    procedure Run;
  end;

  TExampleBase = class(TInterfacedObject, IExample)
  protected
    function ExportToPem(const AValue: TValue): string;
    function ImportKeyPairFromPem(const APem: string;
      out AKeyPair: IAsymmetricCipherKeyPair): Boolean;
    function ImportPublicKeyFromPem(const APem: string;
      out AKey: IAsymmetricKeyParameter): Boolean;
    function GenerateRsaKeyPair(AKeySize: Int32 = 2048): IAsymmetricCipherKeyPair;
    function GenerateEcKeyPair(const ADomain: IECDomainParameters): IAsymmetricCipherKeyPair;
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

function TExampleBase.Logger: ILogger;
begin
  Result := TClpLogger.GetDefaultLogger;
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
    Result := LReadVal.TryAsType<IAsymmetricCipherKeyPair>(AKeyPair);
  finally
    LStream.Free;
  end;
end;

function TExampleBase.ImportPublicKeyFromPem(const APem: string;
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
    Result := LReadVal.TryAsType<IAsymmetricKeyParameter>(AKey);
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

procedure TExampleBase.VerifyPemRoundtrip(const AKeyPair: IAsymmetricCipherKeyPair;
  const AKeyType: string);
var
  LPrivPem, LPubPem: string;
  LReadPair: IAsymmetricCipherKeyPair;
  LReadPub: IAsymmetricKeyParameter;
begin
  LPrivPem := ExportToPem(TValue.From<IAsymmetricKeyParameter>(AKeyPair.Private));
  Logger.LogInformation(AKeyType + ' Private Key PEM:' + sLineBreak + LPrivPem);

  LPubPem := ExportToPem(TValue.From<IAsymmetricKeyParameter>(AKeyPair.Public));
  Logger.LogInformation(AKeyType + ' Public Key PEM:' + sLineBreak + LPubPem);

  if not ImportKeyPairFromPem(LPrivPem, LReadPair) then
  begin
    Logger.LogError('Failed to read back ' + AKeyType + ' private key from PEM.');
    Exit;
  end;
  if LReadPair.Private.Equals(AKeyPair.Private) then
    Logger.LogInformation('Private key roundtrip: match.')
  else
    Logger.LogWarning('Private key roundtrip: mismatch.');
  if LReadPair.Public.Equals(AKeyPair.Public) then
    Logger.LogInformation('Public key (from private PEM) roundtrip: match.')
  else
    Logger.LogWarning('Public key (from private PEM) roundtrip: mismatch.');

  if not ImportPublicKeyFromPem(LPubPem, LReadPub) then
  begin
    Logger.LogError('Failed to read back ' + AKeyType + ' public key from PEM.');
    Exit;
  end;
  if LReadPub.Equals(AKeyPair.Public) then
    Logger.LogInformation('Public key roundtrip: match.')
  else
    Logger.LogWarning('Public key roundtrip: mismatch.');
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
    Logger.LogInformation(Format('%s derived %d bytes:' + sLineBreak + '%s',
      [ALabel, System.Length(LDerived), THexEncoder.Encode(LDerived, False)]));
  end
  else
    Logger.LogWarning(ALabel + ': could not get key parameter.');
end;

procedure TExampleBase.LogWithLineBreak(const AMessage: string);
begin
  Logger.LogInformation(AMessage + sLineBreak)
end;

end.
