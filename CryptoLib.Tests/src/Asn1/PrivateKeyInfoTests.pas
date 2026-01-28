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

unit PrivateKeyInfoTests;

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
  ClpIAsn1Objects,
  ClpPkcsAsn1Objects,
  ClpIPkcsAsn1Objects,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TPrivateKeyInfoTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    var
      FPriv: TCryptoLibByteArray;
      FPrivWithPub: TCryptoLibByteArray;

    procedure SetUpTestData;

  protected
    procedure SetUp; override;

  published
    procedure TestPrivateKeyWithoutPublicKey;
    procedure TestPrivateKeyWithPublicKey;

  end;

implementation

{ TPrivateKeyInfoTest }

procedure TPrivateKeyInfoTest.SetUpTestData;
begin
  FPriv := DecodeBase64('MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC');

  FPrivWithPub := DecodeBase64('MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC' +
    'oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB' +
    'Z9w7lshQhqowtrbLDFw4rXAxZuE=');
end;

procedure TPrivateKeyInfoTest.SetUp;
begin
  inherited SetUp;
  SetUpTestData;
end;

procedure TPrivateKeyInfoTest.TestPrivateKeyWithoutPublicKey;
var
  LPrivInfo1, LPrivInfo2: IPrivateKeyInfo;
begin
  LPrivInfo1 := TPrivateKeyInfo.GetInstance(FPriv);

  CheckFalse(LPrivInfo1.HasPublicKey, 'PrivateKeyInfo should not have public key');

  LPrivInfo2 := TPrivateKeyInfo.Create(LPrivInfo1.PrivateKeyAlgorithm, LPrivInfo1.ParsePrivateKey());

  CheckTrue(AreEqual(FPriv, LPrivInfo2.GetEncoded()), 'Encoding round-trip failed for private key without public key');
end;

procedure TPrivateKeyInfoTest.TestPrivateKeyWithPublicKey;
var
  LPrivInfo1, LPrivInfo2: IPrivateKeyInfo;
  LPublicKey: IDerBitString;
begin
  LPrivInfo1 := TPrivateKeyInfo.GetInstance(FPrivWithPub);

  CheckTrue(LPrivInfo1.HasPublicKey, 'PrivateKeyInfo should have public key');

  LPublicKey := LPrivInfo1.PublicKey;

  LPrivInfo2 := TPrivateKeyInfo.Create(LPrivInfo1.PrivateKeyAlgorithm, LPrivInfo1.ParsePrivateKey(),
    LPrivInfo1.Attributes, LPublicKey.GetOctets());

  CheckTrue(AreEqual(FPrivWithPub, LPrivInfo2.GetEncoded()), 'Encoding round-trip failed for private key with public key');
end;

initialization

{$IFDEF FPC}
RegisterTest(TPrivateKeyInfoTest);
{$ELSE}
RegisterTest(TPrivateKeyInfoTest.Suite);
{$ENDIF FPC}

end.
