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

unit ECDHBinaryConstantTimeTests;

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
  ClpSecureRandom,
  ClpISecureRandom,
  ClpBigInteger,
  ClpCustomNamedCurves,
  ClpIX9ECAsn1Objects,
  ClpMultipliers,
  ClpIECCommon,
  ClpPlatformUtilities,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  /// <summary>
  /// Verifies the constant-time López–Dahab ladder wired as the default
  /// multiplier for the custom sect283k1 binary curve.
  /// </summary>
  TTestECDHBinaryConstantTime = class(TCryptoLibAlgorithmTestCase)
  private
  const
    CurveName = String('sect283k1');
    TestRounds = Int32(8);
  var
    FRandom: ISecureRandom;
    function GetCurve: IX9ECParameters;
    function RandomScalar(const AN: TBigInteger): TBigInteger;
    procedure AssertPointsEqual(const AMsg: String; const AA, AB: IECPoint);
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestDefaultMultiplierIsConstantTime;
    procedure TestParityWithWNaf;
    procedure TestEdgeScalars;
    procedure TestBlindingTransparency;
  end;

implementation

{ TTestECDHBinaryConstantTime }

procedure TTestECDHBinaryConstantTime.SetUp;
begin
  FRandom := TSecureRandom.Create();
end;

procedure TTestECDHBinaryConstantTime.TearDown;
begin
  inherited;
end;

function TTestECDHBinaryConstantTime.GetCurve: IX9ECParameters;
begin
  Result := TCustomNamedCurves.GetByName(CurveName);
end;

function TTestECDHBinaryConstantTime.RandomScalar(const AN: TBigInteger): TBigInteger;
begin
  Result := TBigInteger.Create(AN.BitLength, FRandom).&Mod(AN);
  if Result.SignValue = 0 then
    Result := TBigInteger.One;
end;

procedure TTestECDHBinaryConstantTime.AssertPointsEqual(const AMsg: String;
  const AA, AB: IECPoint);
begin
  CheckEquals(True, AA.Equals(AB), AMsg);
  CheckEquals(True, AB.Equals(AA), AMsg);
end;

procedure TTestECDHBinaryConstantTime.TestDefaultMultiplierIsConstantTime;
var
  LX9: IX9ECParameters;
  LMul: IECMultiplier;
begin
  LX9 := GetCurve;
  CheckTrue(LX9 <> nil, CurveName + ' not found');
  LMul := LX9.Curve.Multiplier;
  CheckEquals('TF2mMontgomeryLadderCTMultiplier', TPlatformUtilities.GetTypeName(LMul as TObject),
    'default multiplier for ' + CurveName + ' is not the constant-time ladder');
end;

procedure TTestECDHBinaryConstantTime.TestParityWithWNaf;
var
  LJ: Int32;
  LX9: IX9ECParameters;
  LCurve: IECCurve;
  LWNaf, LCT: IECMultiplier;
  LN, LR, LK: TBigInteger;
  LQ, LRef, LGot: IECPoint;
begin
  LWNaf := TWNafL2RMultiplier.Create() as IECMultiplier;
  LX9 := GetCurve;
  LCurve := LX9.Curve;
  LN := LX9.N;
  LCT := LCurve.Multiplier;
  for LJ := 0 to TestRounds - 1 do
  begin
    LR := RandomScalar(LN);
    LQ := LWNaf.Multiply(LX9.G, LR).Normalize();
    LK := RandomScalar(LN);
    LRef := LWNaf.Multiply(LQ, LK).Normalize();
    LGot := LCT.Multiply(LQ, LK).Normalize();
    AssertPointsEqual('parity ' + CurveName, LRef, LGot);
  end;
end;

procedure TTestECDHBinaryConstantTime.TestEdgeScalars;
var
  LJ: Int32;
  LX9: IX9ECParameters;
  LCurve: IECCurve;
  LWNaf, LCT: IECMultiplier;
  LN: TBigInteger;
  LScalars: TCryptoLibGenericArray<TBigInteger>;
  LRef, LGot: IECPoint;
begin
  LWNaf := TWNafL2RMultiplier.Create() as IECMultiplier;
  LX9 := GetCurve;
  LCurve := LX9.Curve;
  LN := LX9.N;
  LCT := LCurve.Multiplier;
  LScalars := TCryptoLibGenericArray<TBigInteger>.Create(
    TBigInteger.One,
    TBigInteger.Two,
    TBigInteger.ValueOf(7),
    LN.Subtract(TBigInteger.One),
    LN.Subtract(TBigInteger.Two));
  for LJ := 0 to System.Length(LScalars) - 1 do
  begin
    LRef := LWNaf.Multiply(LX9.G, LScalars[LJ]).Normalize();
    LGot := LCT.Multiply(LX9.G, LScalars[LJ]).Normalize();
    AssertPointsEqual('edge idx ' + IntToStr(LJ), LRef, LGot);
  end;
end;

procedure TTestECDHBinaryConstantTime.TestBlindingTransparency;
var
  LX9: IX9ECParameters;
  LCT: IECMultiplier;
  LN, LK: TBigInteger;
  LI: Int32;
  LFirst, LAgain: IECPoint;
begin
  // Randomized internals (scalar blind + projective coordinate) must not change the result.
  LX9 := GetCurve;
  LCT := LX9.Curve.Multiplier;
  LN := LX9.N;
  for LI := 0 to 5 do
  begin
    LK := RandomScalar(LN);
    LFirst := LCT.Multiply(LX9.G, LK).Normalize();
    LAgain := LCT.Multiply(LX9.G, LK).Normalize();
    AssertPointsEqual('transparency', LFirst, LAgain);
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestECDHBinaryConstantTime);
{$ELSE}
  RegisterTest(TTestECDHBinaryConstantTime.Suite);
{$ENDIF FPC}

end.
