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

unit SubjectKeyIdentifierTests;

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
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpX509ExtensionUtilities,
  ClpArrayUtilities,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TSubjectKeyIdentifierTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    var
      FPubKeyInfo: TCryptoLibByteArray;
      FShaID: TCryptoLibByteArray;
      FShaTruncID: TCryptoLibByteArray;

    procedure SetUpTestData;

  protected
    procedure SetUp; override;

  published
    procedure TestCreateSubjectKeyIdentifier;

  end;

implementation

{ TSubjectKeyIdentifierTest }

procedure TSubjectKeyIdentifierTest.SetUpTestData;
begin
  FPubKeyInfo := DecodeBase64('MFgwCwYJKoZIhvcNAQEBA0kAMEYCQQC6wMMmHYMZszT/7bNFMn+gaZoiWJLVP8ODRuu1C2jeAe' +
    'QpxM+5Oe7PaN2GNy3nBE4EOYkB5pMJWA0y9n04FX8NAgED');

  FShaID := DecodeHex('d8128a06d6c2feb0865994a2936e7b75b836a021');

  FShaTruncID := DecodeHex('436e7b75b836a021');
end;

procedure TSubjectKeyIdentifierTest.SetUp;
begin
  inherited SetUp;
  SetUpTestData;
end;

procedure TSubjectKeyIdentifierTest.TestCreateSubjectKeyIdentifier;
var
  LPubInfo: ISubjectPublicKeyInfo;
  LSki: ISubjectKeyIdentifier;
begin
  LPubInfo := TSubjectPublicKeyInfo.GetInstance(FPubKeyInfo);
  LSki := TX509ExtensionUtilities.CreateSubjectKeyIdentifier(LPubInfo);

  if not AreEqual(FShaID, LSki.GetKeyIdentifier()) then
  begin
    Fail('SHA-1 ID does not match');
  end;

  LSki := TX509ExtensionUtilities.CreateTruncatedSubjectKeyIdentifier(LPubInfo);

  if not AreEqual(FShaTruncID, LSki.GetKeyIdentifier()) then
  begin
    Fail('truncated SHA-1 ID does not match');
  end;
end;

initialization

{$IFDEF FPC}
RegisterTest(TSubjectKeyIdentifierTest);
{$ELSE}
RegisterTest(TSubjectKeyIdentifierTest.Suite);
{$ENDIF FPC}

end.
