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

unit SimdSelectSlotTests;

interface

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  CryptoLibTestBase,
  ClpSimdLevels,
  ClpX86SimdFeatures,
  ClpArmSimdFeatures;

type

  // Exercises the pure overload of TX86SimdFeatures.SelectSlot, which
  // takes the active level as a parameter and is therefore fully
  // deterministic and host-CPU-independent.
  TTestX86SelectSlot = class(TCryptoLibTestCase)
  published
    procedure TestExactMatch;
    procedure TestStepDownOnUnsupportedTier;
    procedure TestAllDeclaredTiersAboveActive;
    procedure TestEmptyTiers;
    procedure TestTierOrderIndependence;
    procedure TestScalarHost;
    procedure TestScalarTierAlwaysReachable;
  end;

type

  // Symmetric coverage for the ARM surface, since the same SelectSlot
  // shape lives on TArmSimdFeatures.
  TTestArmSelectSlot = class(TCryptoLibTestCase)
  published
    procedure TestExactMatch;
    procedure TestStepDownOnUnsupportedTier;
    procedure TestAllDeclaredTiersAboveActive;
    procedure TestEmptyTiers;
    procedure TestTierOrderIndependence;
    procedure TestScalarHost;
  end;

implementation

function X86LevelName(ALevel: TX86SimdLevel): string;
begin
  case ALevel of
    TX86SimdLevel.Scalar: Result := 'Scalar';
    TX86SimdLevel.SSE2:   Result := 'SSE2';
    TX86SimdLevel.SSE3:   Result := 'SSE3';
    TX86SimdLevel.SSSE3:  Result := 'SSSE3';
    TX86SimdLevel.SSE41:  Result := 'SSE41';
    TX86SimdLevel.SSE42:  Result := 'SSE42';
    TX86SimdLevel.AVX2:   Result := 'AVX2';
  else
    Result := 'Unknown';
  end;
end;

function ArmLevelName(ALevel: TArmSimdLevel): string;
begin
  case ALevel of
    TArmSimdLevel.Scalar: Result := 'Scalar';
    TArmSimdLevel.NEON:   Result := 'NEON';
    TArmSimdLevel.SVE:    Result := 'SVE';
    TArmSimdLevel.SVE2:   Result := 'SVE2';
  else
    Result := 'Unknown';
  end;
end;

{ TTestX86SelectSlot }

procedure TTestX86SelectSlot.TestExactMatch;
var
  LResult: TX86SimdLevel;
begin
  LResult := TX86SimdFeatures.SelectSlot(TX86SimdLevel.AVX2,
    [TX86SimdLevel.AVX2, TX86SimdLevel.SSE2]);
  CheckTrue(LResult = TX86SimdLevel.AVX2,
    Format('Expected AVX2 but got %s.', [X86LevelName(LResult)]));
end;

procedure TTestX86SelectSlot.TestStepDownOnUnsupportedTier;
var
  LResult: TX86SimdLevel;
begin
  LResult := TX86SimdFeatures.SelectSlot(TX86SimdLevel.SSE41,
    [TX86SimdLevel.AVX2, TX86SimdLevel.SSE2]);
  CheckTrue(LResult = TX86SimdLevel.SSE2,
    Format('Expected SSE2 but got %s.', [X86LevelName(LResult)]));
end;

procedure TTestX86SelectSlot.TestAllDeclaredTiersAboveActive;
var
  LResult: TX86SimdLevel;
begin
  LResult := TX86SimdFeatures.SelectSlot(TX86SimdLevel.SSE2,
    [TX86SimdLevel.AVX2]);
  CheckTrue(LResult = TX86SimdLevel.Scalar,
    Format('Expected Scalar but got %s.', [X86LevelName(LResult)]));
end;

procedure TTestX86SelectSlot.TestEmptyTiers;
var
  LResult: TX86SimdLevel;
  LEmpty: array of TX86SimdLevel;
begin
  System.SetLength(LEmpty, 0);
  LResult := TX86SimdFeatures.SelectSlot(TX86SimdLevel.AVX2, LEmpty);
  CheckTrue(LResult = TX86SimdLevel.Scalar,
    Format('Expected Scalar but got %s.', [X86LevelName(LResult)]));
end;

procedure TTestX86SelectSlot.TestTierOrderIndependence;
var
  LDescending, LAscending: TX86SimdLevel;
begin
  LDescending := TX86SimdFeatures.SelectSlot(TX86SimdLevel.SSE42,
    [TX86SimdLevel.AVX2, TX86SimdLevel.SSE2]);
  LAscending := TX86SimdFeatures.SelectSlot(TX86SimdLevel.SSE42,
    [TX86SimdLevel.SSE2, TX86SimdLevel.AVX2]);
  CheckTrue(LDescending = LAscending,
    Format('Order-dependent result: descending=%s ascending=%s.',
      [X86LevelName(LDescending), X86LevelName(LAscending)]));
  CheckTrue(LDescending = TX86SimdLevel.SSE2,
    Format('Expected SSE2 but got %s.', [X86LevelName(LDescending)]));
end;

procedure TTestX86SelectSlot.TestScalarHost;
var
  LResult: TX86SimdLevel;
begin
  LResult := TX86SimdFeatures.SelectSlot(TX86SimdLevel.Scalar,
    [TX86SimdLevel.AVX2, TX86SimdLevel.SSE2]);
  CheckTrue(LResult = TX86SimdLevel.Scalar,
    Format('Expected Scalar but got %s.', [X86LevelName(LResult)]));
end;

procedure TTestX86SelectSlot.TestScalarTierAlwaysReachable;
var
  LResult: TX86SimdLevel;
begin
  LResult := TX86SimdFeatures.SelectSlot(TX86SimdLevel.Scalar,
    [TX86SimdLevel.Scalar]);
  CheckTrue(LResult = TX86SimdLevel.Scalar,
    Format('Expected Scalar but got %s.', [X86LevelName(LResult)]));
end;

{ TTestArmSelectSlot }

procedure TTestArmSelectSlot.TestExactMatch;
var
  LResult: TArmSimdLevel;
begin
  LResult := TArmSimdFeatures.SelectSlot(TArmSimdLevel.SVE2,
    [TArmSimdLevel.SVE2, TArmSimdLevel.NEON]);
  CheckTrue(LResult = TArmSimdLevel.SVE2,
    Format('Expected SVE2 but got %s.', [ArmLevelName(LResult)]));
end;

procedure TTestArmSelectSlot.TestStepDownOnUnsupportedTier;
var
  LResult: TArmSimdLevel;
begin
  LResult := TArmSimdFeatures.SelectSlot(TArmSimdLevel.SVE,
    [TArmSimdLevel.SVE2, TArmSimdLevel.NEON]);
  CheckTrue(LResult = TArmSimdLevel.NEON,
    Format('Expected NEON but got %s.', [ArmLevelName(LResult)]));
end;

procedure TTestArmSelectSlot.TestAllDeclaredTiersAboveActive;
var
  LResult: TArmSimdLevel;
begin
  LResult := TArmSimdFeatures.SelectSlot(TArmSimdLevel.NEON,
    [TArmSimdLevel.SVE2]);
  CheckTrue(LResult = TArmSimdLevel.Scalar,
    Format('Expected Scalar but got %s.', [ArmLevelName(LResult)]));
end;

procedure TTestArmSelectSlot.TestEmptyTiers;
var
  LResult: TArmSimdLevel;
  LEmpty: array of TArmSimdLevel;
begin
  System.SetLength(LEmpty, 0);
  LResult := TArmSimdFeatures.SelectSlot(TArmSimdLevel.SVE2, LEmpty);
  CheckTrue(LResult = TArmSimdLevel.Scalar,
    Format('Expected Scalar but got %s.', [ArmLevelName(LResult)]));
end;

procedure TTestArmSelectSlot.TestTierOrderIndependence;
var
  LDescending, LAscending: TArmSimdLevel;
begin
  LDescending := TArmSimdFeatures.SelectSlot(TArmSimdLevel.SVE,
    [TArmSimdLevel.SVE2, TArmSimdLevel.NEON]);
  LAscending := TArmSimdFeatures.SelectSlot(TArmSimdLevel.SVE,
    [TArmSimdLevel.NEON, TArmSimdLevel.SVE2]);
  CheckTrue(LDescending = LAscending,
    Format('Order-dependent result: descending=%s ascending=%s.',
      [ArmLevelName(LDescending), ArmLevelName(LAscending)]));
  CheckTrue(LDescending = TArmSimdLevel.NEON,
    Format('Expected NEON but got %s.', [ArmLevelName(LDescending)]));
end;

procedure TTestArmSelectSlot.TestScalarHost;
var
  LResult: TArmSimdLevel;
begin
  LResult := TArmSimdFeatures.SelectSlot(TArmSimdLevel.Scalar,
    [TArmSimdLevel.SVE2, TArmSimdLevel.NEON]);
  CheckTrue(LResult = TArmSimdLevel.Scalar,
    Format('Expected Scalar but got %s.', [ArmLevelName(LResult)]));
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestX86SelectSlot);
  RegisterTest(TTestArmSelectSlot);
{$ELSE}
  RegisterTest(TTestX86SelectSlot.Suite);
  RegisterTest(TTestArmSelectSlot.Suite);
{$ENDIF FPC}

end.
