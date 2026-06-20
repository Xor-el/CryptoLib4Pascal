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

unit PqcSampleCredentials;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
  ClpCryptoLibTypes,
  ClpIAsymmetricCipherKeyPair,
  ClpAsymmetricCipherKeyPair,
  ClpIX509Certificate,
  ClpX509Certificate,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIPemReader,
  ClpPemReader,
  ClpIPemObject,
  ClpPrivateKeyFactory,
  ClpPublicKeyFactory,
  ClpIAsymmetricKeyParameter,
  ClpArrayUtilities,
  CertVectors;

type
  TPqcSampleCredentials = record
    KeyPair: IAsymmetricCipherKeyPair;
    Certificate: IX509Certificate;
  end;

  TPqcSampleCredentialsLoader = class sealed
  public
    class function Load(const ACertId: string): TPqcSampleCredentials; static;
    class function MlDsa44: TPqcSampleCredentials; static;
    class function MlDsa65: TPqcSampleCredentials; static;
    class function MlDsa87: TPqcSampleCredentials; static;
    class function MlKem512: TPqcSampleCredentials; static;
    class function MlKem768: TPqcSampleCredentials; static;
    class function MlKem1024: TPqcSampleCredentials; static;
    class function SlhDsaSha2128S: TPqcSampleCredentials; static;
  end;

implementation

function ExpectPemObject(const APemReader: IPemReader; const AExpectedType: string): IPemObject;
begin
  Result := APemReader.ReadPemObject();
  if Result = nil then
    raise Exception.CreateFmt('Expected PEM object of type %s', [AExpectedType]);
  if not SameText(AExpectedType, Result.&Type) then
    raise Exception.CreateFmt('Expected PEM type %s but got %s', [AExpectedType, Result.&Type]);
end;

{ TPqcSampleCredentialsLoader }

class function TPqcSampleCredentialsLoader.Load(const ACertId: string): TPqcSampleCredentials;
var
  LStream: TStringStream;
  LPemReader: IPemReader;
  LPrivObj, LPubObj, LCertObj: IPemObject;
  LPrivateKey, LPublicKey: IAsymmetricKeyParameter;
  LSpki: ISubjectPublicKeyInfo;
  LStruct: IX509CertificateStructure;
begin
  LStream := TStringStream.Create(TCertVectors.LoadPemString(ACertId), TEncoding.ASCII);
  try
    LPemReader := TPemReader.Create(LStream);
    LPrivObj := ExpectPemObject(LPemReader, 'PRIVATE KEY');
    LPubObj := ExpectPemObject(LPemReader, 'PUBLIC KEY');
    LCertObj := ExpectPemObject(LPemReader, 'CERTIFICATE');

    LPrivateKey := TPrivateKeyFactory.CreateKey(LPrivObj.Content);
    LSpki := TSubjectPublicKeyInfo.GetInstance(LPubObj.Content);
    LPublicKey := TPublicKeyFactory.CreateKey(LSpki);
    LStruct := TX509CertificateStructure.GetInstance(LCertObj.Content);
    Result.Certificate := TX509Certificate.Create(LStruct);
    Result.KeyPair := TAsymmetricCipherKeyPair.Create(LPublicKey, LPrivateKey);

    if not TArrayUtilities.AreEqual(LSpki.GetEncoded, Result.Certificate.SubjectPublicKeyInfo.GetEncoded) then
      raise Exception.CreateFmt('SubjectPublicKeyInfo mismatch in %s credentials', [ACertId]);
  finally
    LStream.Free;
  end;
end;

class function TPqcSampleCredentialsLoader.MlDsa44: TPqcSampleCredentials;
begin
  Result := Load('PqcMlDsa44');
end;

class function TPqcSampleCredentialsLoader.MlDsa65: TPqcSampleCredentials;
begin
  Result := Load('PqcMlDsa65');
end;

class function TPqcSampleCredentialsLoader.MlDsa87: TPqcSampleCredentials;
begin
  Result := Load('PqcMlDsa87');
end;

class function TPqcSampleCredentialsLoader.MlKem512: TPqcSampleCredentials;
begin
  Result := Load('PqcMlKem512');
end;

class function TPqcSampleCredentialsLoader.MlKem768: TPqcSampleCredentials;
begin
  Result := Load('PqcMlKem768');
end;

class function TPqcSampleCredentialsLoader.MlKem1024: TPqcSampleCredentials;
begin
  Result := Load('PqcMlKem1024');
end;

class function TPqcSampleCredentialsLoader.SlhDsaSha2128S: TPqcSampleCredentials;
begin
  Result := Load('PqcSlhDsaSha2128S');
end;

end.
