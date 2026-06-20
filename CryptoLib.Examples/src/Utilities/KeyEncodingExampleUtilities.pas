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

unit KeyEncodingExampleUtilities;

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
  ClpPrivateKeyFactory,
  ClpPublicKeyFactory,
  ClpPrivateKeyInfoFactory,
  ClpSubjectPublicKeyInfoFactory,
  ClpIOpenSslPemWriter,
  ClpOpenSslPemWriter,
  ClpIOpenSslPemReader,
  ClpOpenSslPemReader,
  ExampleBase,
  ExampleLogger;

type
  TKeyEncodingExampleUtilities = class sealed
  public
    class function ExportToPem(const AValue: TValue): string; static;
    class function ImportFromPem(const APem: string): TValue; static;
    class function ImportKeyPairFromPem(const APem: string;
      out AKeyPair: IAsymmetricCipherKeyPair): Boolean; static;
    class function ImportKeyFromPem(const APem: string;
      out AKey: IAsymmetricKeyParameter): Boolean; static;
    class procedure VerifyPemRoundtrip(const AKeyPair: IAsymmetricCipherKeyPair;
      const AKeyType: string); static;
    class procedure VerifyDerRoundtrip(const AKeyPair: IAsymmetricCipherKeyPair;
      const AKeyType: string); static;
  end;

implementation

class function TKeyEncodingExampleUtilities.ExportToPem(const AValue: TValue): string;
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

class function TKeyEncodingExampleUtilities.ImportFromPem(const APem: string): TValue;
var
  LStream: TStringStream;
  LReader: IOpenSslPemReader;
begin
  Result := TValue.Empty;
  if APem = '' then
    Exit;
  LStream := TStringStream.Create(APem, TEncoding.ASCII);
  try
    LReader := TOpenSslPemReader.Create(LStream);
    Result := LReader.ReadObject();
  finally
    LStream.Free;
  end;
end;

class function TKeyEncodingExampleUtilities.ImportKeyPairFromPem(const APem: string;
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

class function TKeyEncodingExampleUtilities.ImportKeyFromPem(const APem: string;
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

class procedure TKeyEncodingExampleUtilities.VerifyPemRoundtrip(
  const AKeyPair: IAsymmetricCipherKeyPair; const AKeyType: string);
var
  LPrivPem, LPubPem: string;
  LReadPair: IAsymmetricCipherKeyPair;
  LReadPriv, LReadPub: IAsymmetricKeyParameter;
  LLogger: ILogger;
begin
  LLogger := TExampleLogger.GetDefaultLogger;
  LPrivPem := ExportToPem(TValue.From<IAsymmetricKeyParameter>(AKeyPair.Private));
  LLogger.LogInformation('{0} Private Key PEM:{1}{2}', [AKeyType, sLineBreak, LPrivPem]);

  LPubPem := ExportToPem(TValue.From<IAsymmetricKeyParameter>(AKeyPair.Public));
  LLogger.LogInformation('{0} Public Key PEM:{1}{2}', [AKeyType, sLineBreak, LPubPem]);

  if ImportKeyPairFromPem(LPrivPem, LReadPair) then
  begin
    if LReadPair.Private.Equals(AKeyPair.Private) then
      LLogger.LogInformation('Private key roundtrip: match.', [])
    else
      LLogger.LogWarning('Private key roundtrip: mismatch.', []);
    if LReadPair.Public.Equals(AKeyPair.Public) then
      LLogger.LogInformation('Public key (from private PEM) roundtrip: match.', [])
    else
      LLogger.LogWarning('Public key (from private PEM) roundtrip: mismatch.', []);
  end
  else if ImportKeyFromPem(LPrivPem, LReadPriv) then
  begin
    if LReadPriv.Equals(AKeyPair.Private) then
      LLogger.LogInformation('Private key roundtrip: match.', [])
    else
      LLogger.LogWarning('Private key roundtrip: mismatch.', []);
  end
  else
  begin
    LLogger.LogError('Failed to read back {0} private key from PEM.', [AKeyType]);
    Exit;
  end;

  if not ImportKeyFromPem(LPubPem, LReadPub) then
  begin
    LLogger.LogError('Failed to read back {0} public key from PEM.', [AKeyType]);
    Exit;
  end;
  if LReadPub.Equals(AKeyPair.Public) then
    LLogger.LogInformation('Public key roundtrip: match.', [])
  else
    LLogger.LogWarning('Public key roundtrip: mismatch.', []);
end;

class procedure TKeyEncodingExampleUtilities.VerifyDerRoundtrip(
  const AKeyPair: IAsymmetricCipherKeyPair; const AKeyType: string);
var
  LPrivBytes, LPubBytes: TBytes;
  LRegenPriv, LRegenPub: IAsymmetricKeyParameter;
  LLogger: ILogger;
begin
  LLogger := TExampleLogger.GetDefaultLogger;
  LPrivBytes := TPrivateKeyInfoFactory.CreatePrivateKeyInfo(AKeyPair.Private).GetEncoded();
  LLogger.LogInformation('{0} private key DER encoded: {1} bytes', [AKeyType, IntToStr(System.Length(LPrivBytes))]);

  LPubBytes := TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(AKeyPair.Public).GetEncoded();
  LLogger.LogInformation('{0} public key DER encoded: {1} bytes', [AKeyType, IntToStr(System.Length(LPubBytes))]);

  LRegenPriv := TPrivateKeyFactory.CreateKey(LPrivBytes);
  if LRegenPriv.Equals(AKeyPair.Private) then
    LLogger.LogInformation('Private key roundtrip: match.', [])
  else
    LLogger.LogError('Private key roundtrip: mismatch.', []);

  LRegenPub := TPublicKeyFactory.CreateKey(LPubBytes);
  if LRegenPub.Equals(AKeyPair.Public) then
    LLogger.LogInformation('Public key roundtrip: match.', [])
  else
    LLogger.LogError('Public key roundtrip: mismatch.', []);
end;

end.
