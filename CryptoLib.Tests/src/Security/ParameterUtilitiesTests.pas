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
  ClpKeyParameter,
  ClpIAeadParameters,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpICipherParameters,
  ClpAsn1Objects,
  ClpIAsn1Core,
  ClpCryptoServicesRegistrar,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
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

    function Nonce12: TCryptoLibByteArray;
    function GcmAsn1Params(AIcvLen: Int32): IAsn1Encodable;
    function CcmAsn1Params(AIcvLen: Int32): IAsn1Encodable;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestCreateKeyParameter;
    procedure TestGetCipherParametersGcm;
    procedure TestGetCipherParametersCcm;
    procedure TestGetCipherParametersGcmRequiresKeyParameter;
    procedure TestGetCipherParametersCbcIvPath;

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

function TTestParameterUtilities.Nonce12: TCryptoLibByteArray;
begin
  Result := TCryptoLibByteArray.Create(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12);
end;

function TTestParameterUtilities.GcmAsn1Params(AIcvLen: Int32): IAsn1Encodable;
begin
  Result := TDerSequence.Create([
    TDerOctetString.FromContents(Nonce12),
    TDerInteger.ValueOf(AIcvLen)
  ]);
end;

function TTestParameterUtilities.CcmAsn1Params(AIcvLen: Int32): IAsn1Encodable;
begin
  Result := TDerSequence.Create([
    TDerOctetString.FromContents(Nonce12),
    TDerInteger.ValueOf(AIcvLen)
  ]);
end;

procedure TTestParameterUtilities.TestGetCipherParametersGcm;
var
  LKeyBytes: TCryptoLibByteArray;
  LKey: IKeyParameter;
  LParams: ICipherParameters;
  LAead: IAeadParameters;
  LIcvLen: Int32;
begin
  LIcvLen := 16;
  System.SetLength(LKeyBytes, 16);
  FSecureRandom.NextBytes(LKeyBytes);
  LKey := TKeyParameter.Create(LKeyBytes);

  LParams := TParameterUtilities.GetCipherParameters(
    TNistObjectIdentifiers.IdAes128Gcm.ID, LKey, GcmAsn1Params(LIcvLen));
  CheckTrue(Supports(LParams, IAeadParameters, LAead), 'expected IAeadParameters');
  CheckEquals(LIcvLen * 8, LAead.MacSize, 'GCM mac size in bits');
  CheckTrue(AreEqual(Nonce12, LAead.GetNonce()), 'GCM nonce mismatch');
  CheckTrue(AreEqual(LKeyBytes, LAead.Key.GetKey()), 'GCM key mismatch');
end;

procedure TTestParameterUtilities.TestGetCipherParametersCcm;
var
  LKeyBytes: TCryptoLibByteArray;
  LKey: IKeyParameter;
  LParams: ICipherParameters;
  LAead: IAeadParameters;
  LIcvLen: Int32;
begin
  LIcvLen := 12;
  System.SetLength(LKeyBytes, 32);
  FSecureRandom.NextBytes(LKeyBytes);
  LKey := TKeyParameter.Create(LKeyBytes);

  LParams := TParameterUtilities.GetCipherParameters(
    TNistObjectIdentifiers.IdAes256Ccm.ID, LKey, CcmAsn1Params(LIcvLen));
  CheckTrue(Supports(LParams, IAeadParameters, LAead), 'expected IAeadParameters');
  CheckEquals(LIcvLen * 8, LAead.MacSize, 'CCM mac size in bits');
  CheckTrue(AreEqual(Nonce12, LAead.GetNonce()), 'CCM nonce mismatch');
  CheckTrue(AreEqual(LKeyBytes, LAead.Key.GetKey()), 'CCM key mismatch');
end;

procedure TTestParameterUtilities.TestGetCipherParametersGcmRequiresKeyParameter;
var
  LKeyBytes, LIV: TCryptoLibByteArray;
  LKey: IKeyParameter;
  LWrapped: ICipherParameters;
begin
  System.SetLength(LKeyBytes, 16);
  FSecureRandom.NextBytes(LKeyBytes);
  LKey := TKeyParameter.Create(LKeyBytes);
  System.SetLength(LIV, 16);
  FSecureRandom.NextBytes(LIV);
  LWrapped := TParametersWithIV.Create(LKey, LIV);

  try
    TParameterUtilities.GetCipherParameters(
      TNistObjectIdentifiers.IdAes128Gcm.ID, LWrapped, GcmAsn1Params(12));
    Fail('Expected exception when key is not IKeyParameter');
  except
    on E: EArgumentCryptoLibException do
      CheckTrue(E.Message.Contains('GCM'), 'unexpected exception: ' + E.Message);
    else
      raise;
  end;
end;

procedure TTestParameterUtilities.TestGetCipherParametersCbcIvPath;
var
  LKeyBytes, LIV, LResultIV: TCryptoLibByteArray;
  LKey: IKeyParameter;
  LParams: ICipherParameters;
  LWithIV: IParametersWithIV;
begin
  System.SetLength(LKeyBytes, 16);
  FSecureRandom.NextBytes(LKeyBytes);
  LKey := TKeyParameter.Create(LKeyBytes);
  System.SetLength(LIV, 16);
  FSecureRandom.NextBytes(LIV);

  LParams := TParameterUtilities.GetCipherParameters(
    TNistObjectIdentifiers.IdAes128Cbc.ID, LKey,
    TDerOctetString.FromContents(LIV));
  CheckTrue(Supports(LParams, IParametersWithIV, LWithIV), 'expected IParametersWithIV');
  LResultIV := LWithIV.GetIV();
  CheckTrue(AreEqual(LIV, LResultIV), 'CBC IV mismatch');
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestParameterUtilities);
{$ELSE}
  RegisterTest(TTestParameterUtilities.Suite);
{$ENDIF FPC}

end.
