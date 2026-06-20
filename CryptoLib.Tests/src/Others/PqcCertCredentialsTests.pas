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

unit PqcCertCredentialsTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  CryptoLibTestBase,
  ClpIX509Certificate,
  PqcSampleCredentials;

type
  TPqcCertCredentialsTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    procedure CheckSelfSigned(const ACreds: TPqcSampleCredentials);
    procedure CheckCaSigned(const ASubject, AIssuer: TPqcSampleCredentials);
  published
    procedure TestSampleMlDsa44;
    procedure TestSampleMlDsa65;
    procedure TestSampleMlDsa87;
    procedure TestSampleMlKem512;
    procedure TestSampleMlKem768;
    procedure TestSampleMlKem1024;
    procedure TestSampleSlhDsaSha2128S;
  end;

implementation

{ TPqcCertCredentialsTest }

procedure TPqcCertCredentialsTest.CheckSelfSigned(const ACreds: TPqcSampleCredentials);
begin
  Check(ACreds.Certificate.IsSignatureValid(ACreds.Certificate.GetPublicKey),
    'self-signed certificate signature valid');
end;

procedure TPqcCertCredentialsTest.CheckCaSigned(const ASubject, AIssuer: TPqcSampleCredentials);
begin
  Check(ASubject.Certificate.IsSignatureValid(AIssuer.Certificate.GetPublicKey),
    'CA-signed certificate signature valid');
end;

procedure TPqcCertCredentialsTest.TestSampleMlDsa44;
begin
  CheckSelfSigned(TPqcSampleCredentialsLoader.MlDsa44);
end;

procedure TPqcCertCredentialsTest.TestSampleMlDsa65;
begin
  CheckSelfSigned(TPqcSampleCredentialsLoader.MlDsa65);
end;

procedure TPqcCertCredentialsTest.TestSampleMlDsa87;
begin
  CheckSelfSigned(TPqcSampleCredentialsLoader.MlDsa87);
end;

procedure TPqcCertCredentialsTest.TestSampleMlKem512;
begin
  CheckCaSigned(TPqcSampleCredentialsLoader.MlKem512, TPqcSampleCredentialsLoader.MlDsa44);
end;

procedure TPqcCertCredentialsTest.TestSampleMlKem768;
begin
  CheckCaSigned(TPqcSampleCredentialsLoader.MlKem768, TPqcSampleCredentialsLoader.MlDsa65);
end;

procedure TPqcCertCredentialsTest.TestSampleMlKem1024;
begin
  CheckCaSigned(TPqcSampleCredentialsLoader.MlKem1024, TPqcSampleCredentialsLoader.MlDsa87);
end;

procedure TPqcCertCredentialsTest.TestSampleSlhDsaSha2128S;
begin
  CheckSelfSigned(TPqcSampleCredentialsLoader.SlhDsaSha2128S);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TPqcCertCredentialsTest);
{$ELSE}
  RegisterTest(TPqcCertCredentialsTest.Suite);
{$ENDIF FPC}

end.
