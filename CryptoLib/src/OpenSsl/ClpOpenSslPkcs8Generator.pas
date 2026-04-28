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

unit ClpOpenSslPkcs8Generator;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIPemObject,
  ClpIOpenSslPkcs8Generator,
  ClpPemObject,
  ClpIPkcsAsn1Objects,
  ClpPrivateKeyInfoFactory,
  ClpEncryptedPrivateKeyInfoFactory,
  ClpIAsymmetricKeyParameter,
  ClpCryptoServicesRegistrar,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// PEM generator for PKCS#8 private keys (unencrypted or encrypted).
  /// </summary>
  TOpenSslPkcs8Generator = class sealed(TInterfacedObject, IPemObjectGenerator, IOpenSslPkcs8Generator)
  strict private
    const
      DefaultIterations = 2048;
     var
    FPassword: TCryptoLibCharArray;
    FAlgorithm: String;
    FIterationCount: Int32;
    FPrivKey: IAsymmetricKeyParameter;
    FRandom: ISecureRandom;

  public
    /// <summary>
    /// Constructor for an unencrypted private key PEM object.
    /// </summary>
    /// <param name="APrivKey">Private key to be encoded.</param>
    constructor Create(const APrivKey: IAsymmetricKeyParameter); overload;

    /// <summary>
    /// Constructor for an encrypted private key PEM object.
    /// </summary>
    /// <param name="APrivKey">Private key to be encoded.</param>
    /// <param name="AAlgorithm">Encryption algorithm to use.</param>
    constructor Create(const APrivKey: IAsymmetricKeyParameter; const AAlgorithm: String); overload;

    procedure SetSecureRandom(const AValue: ISecureRandom);
    procedure SetPassword(const AValue: TCryptoLibCharArray);
    procedure SetIterationCount(AValue: Int32);

    function Generate(): IPemObject;
  end;

implementation

{ TPkcs8Generator }

constructor TOpenSslPkcs8Generator.Create(const APrivKey: IAsymmetricKeyParameter);
begin
  inherited Create();
  FPrivKey := APrivKey;
  FAlgorithm := '';
  FPassword := nil;
  FIterationCount := DefaultIterations;
  FRandom := nil;
end;

constructor TOpenSslPkcs8Generator.Create(const APrivKey: IAsymmetricKeyParameter; const AAlgorithm: String);
begin
  inherited Create();
  FPrivKey := APrivKey;
  FAlgorithm := AAlgorithm;
  FPassword := nil;
  FIterationCount := DefaultIterations;
  FRandom := nil;
end;

procedure TOpenSslPkcs8Generator.SetSecureRandom(const AValue: ISecureRandom);
begin
  FRandom := AValue;
end;

procedure TOpenSslPkcs8Generator.SetPassword(const AValue: TCryptoLibCharArray);
begin
  FPassword := AValue;
end;

procedure TOpenSslPkcs8Generator.SetIterationCount(AValue: Int32);
begin
  FIterationCount := AValue;
end;

function TOpenSslPkcs8Generator.Generate(): IPemObject;
var
  LPrivInfo: IPrivateKeyInfo;
  LSalt: TCryptoLibByteArray;
  LEpki: IEncryptedPrivateKeyInfo;
begin
  if FAlgorithm = '' then
  begin
    LPrivInfo := TPrivateKeyInfoFactory.CreatePrivateKeyInfo(FPrivKey);
    Result := TPemObject.Create('PRIVATE KEY', LPrivInfo.GetEncoded());
    Exit;
  end;

  // TODO: The amount of salt needed depends on the algorithm?
  SetLength(LSalt, 20);
  FRandom := TCryptoServicesRegistrar.GetSecureRandom(FRandom);
  FRandom.NextBytes(LSalt);

  try
    LEpki := TEncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
      FAlgorithm, FPassword, LSalt, FIterationCount, FPrivKey);
    Result := TPemObject.Create('ENCRYPTED PRIVATE KEY', LEpki.GetEncoded());
  except
    on E: Exception do
      raise EPemGenerationCryptoLibException.Create('Couldn''t encrypt private key');
  end;
end;

end.
