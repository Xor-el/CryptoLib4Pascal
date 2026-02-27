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

unit ParameterUtilitiesTests;

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
  ClpNistObjectIdentifiers,
  ClpParameterUtilities,
  ClpIKeyParameter,
  ClpCryptoServicesRegistrar,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  /// <summary>
  /// Tests for TParameterUtilities.CreateKeyParameter.
  /// </summary>
  TTestParameterUtilities = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FSecureRandom: ISecureRandom;

    procedure DoTestCreateKeyParameter(const AAlgorithm: String;
      const AOid: IDerObjectIdentifier; AKeyBits: Int32);
    procedure DoCheckKeyParameter(const AKey: IKeyParameter;
      const AExpectedBytes: TCryptoLibByteArray);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestCreateKeyParameter;

  end;

implementation

{ TTestParameterUtilities }

procedure TTestParameterUtilities.SetUp;
begin
  inherited;
  FSecureRandom := TCryptoServicesRegistrar.GetSecureRandom();
end;

procedure TTestParameterUtilities.TearDown;
begin
  inherited;
end;

procedure TTestParameterUtilities.DoTestCreateKeyParameter(
  const AAlgorithm: String; const AOid: IDerObjectIdentifier;
  AKeyBits: Int32);
var
  LKeyLength, LOffset: Int32;
  LBytes, LExpected: TCryptoLibByteArray;
  LKey: IKeyParameter;
begin
  LKeyLength := AKeyBits div 8;

  System.SetLength(LBytes, LKeyLength);
  FSecureRandom.NextBytes(LBytes);

  // Test CreateKeyParameter(algorithm, bytes)
  LKey := TParameterUtilities.CreateKeyParameter(AAlgorithm, LBytes);
  DoCheckKeyParameter(LKey, LBytes);

  // Test CreateKeyParameter(oid, bytes)
  LKey := TParameterUtilities.CreateKeyParameter(AOid, LBytes);
  DoCheckKeyParameter(LKey, LBytes);

  // Test with offset and length
  System.SetLength(LBytes, LKeyLength * 2);
  FSecureRandom.NextBytes(LBytes);

  LOffset := FSecureRandom.Next(1, LKeyLength);
  System.SetLength(LExpected, LKeyLength);
  System.Move(LBytes[LOffset], LExpected[0], LKeyLength);

  // Test CreateKeyParameter(algorithm, bytes, offset, length)
  LKey := TParameterUtilities.CreateKeyParameter(AAlgorithm, LBytes, LOffset, LKeyLength);
  DoCheckKeyParameter(LKey, LExpected);

  // Test CreateKeyParameter(oid, bytes, offset, length)
  LKey := TParameterUtilities.CreateKeyParameter(AOid, LBytes, LOffset, LKeyLength);
  DoCheckKeyParameter(LKey, LExpected);
end;

procedure TTestParameterUtilities.DoCheckKeyParameter(
  const AKey: IKeyParameter; const AExpectedBytes: TCryptoLibByteArray);
begin
  CheckNotNull(AKey, 'Key should not be nil');
  CheckTrue(AreEqual(AExpectedBytes, AKey.GetKey()),
    'Key bytes do not match expected');
end;

procedure TTestParameterUtilities.TestCreateKeyParameter;
begin
  DoTestCreateKeyParameter('AES', TNistObjectIdentifiers.IdAes128Cbc, 128);
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestParameterUtilities);
{$ELSE}
  RegisterTest(TTestParameterUtilities.Suite);
{$ENDIF FPC}

end.
