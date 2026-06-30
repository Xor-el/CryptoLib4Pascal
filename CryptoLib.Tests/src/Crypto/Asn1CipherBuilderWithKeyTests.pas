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

unit Asn1CipherBuilderWithKeyTests;

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
  ClpAsn1CipherBuilderWithKey,
  ClpICipherBuilderWithKey,
  ClpIAsn1Objects,
  ClpNistObjectIdentifiers,
  ClpIKeyParameter,
  ClpCryptoServicesRegistrar,
  ClpISecureRandom,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type
  TTestAsn1CipherBuilderWithKey = class(TCryptoLibAlgorithmTestCase)
  strict private
  var
    FSecureRandom: ISecureRandom;

    procedure DoCheckKeySize(const AOid: IDerObjectIdentifier; AKeySize: Int32;
      AExpectedKeyBytes: Int32);

  protected
    procedure SetUp; override;

  published
    procedure TestDefaultKeySizeAes128Cbc;
    procedure TestExplicitKeySizeAes128Cbc;
    procedure TestExplicitKeySizeAes256Cbc;
  end;

implementation

{ TTestAsn1CipherBuilderWithKey }

procedure TTestAsn1CipherBuilderWithKey.SetUp;
begin
  inherited;
  FSecureRandom := TCryptoServicesRegistrar.GetSecureRandom();
end;

procedure TTestAsn1CipherBuilderWithKey.DoCheckKeySize(
  const AOid: IDerObjectIdentifier; AKeySize: Int32; AExpectedKeyBytes: Int32);
var
  LBuilder: ICipherBuilderWithKey;
  LKey: IKeyParameter;
begin
  LBuilder := TAsn1CipherBuilderWithKey.Create(AOid, AKeySize, FSecureRandom);
  CheckNotNull(LBuilder.AlgorithmDetails, 'AlgorithmDetails should not be nil');
  LKey := LBuilder.Key as IKeyParameter;
  CheckNotNull(LKey, 'Key should not be nil');
  CheckEquals(AExpectedKeyBytes, System.Length(LKey.GetKey()),
    Format('Key length for OID %s with keySize %d', [AOid.Id, AKeySize]));
end;

procedure TTestAsn1CipherBuilderWithKey.TestDefaultKeySizeAes128Cbc;
begin
  DoCheckKeySize(TNistObjectIdentifiers.IdAes128Cbc, -1, 16);
end;

procedure TTestAsn1CipherBuilderWithKey.TestExplicitKeySizeAes128Cbc;
begin
  DoCheckKeySize(TNistObjectIdentifiers.IdAes128Cbc, 128, 16);
end;

procedure TTestAsn1CipherBuilderWithKey.TestExplicitKeySizeAes256Cbc;
begin
  DoCheckKeySize(TNistObjectIdentifiers.IdAes256Cbc, 256, 32);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestAsn1CipherBuilderWithKey);
{$ELSE}
  RegisterTest(TTestAsn1CipherBuilderWithKey.Suite);
{$ENDIF FPC}

end.
