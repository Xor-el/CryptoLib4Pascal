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

unit ECDHPrimeConstantTimeTests;

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
  ClpNat,
  ClpCustomNamedCurves,
  ClpIX9ECAsn1Objects,
  ClpMultipliers,
  ClpIFpFieldOps,
  ClpCTFieldValue,
  ClpCTJacPoint,
  ClpFpCTMultiplier,
  ClpSecP256R1Custom,
  ClpSecP256K1Custom,
  ClpSecP384R1Custom,
  ClpSecP521R1Custom,
  ClpECParameters,
  ClpIECParameters,
  ClpECGenerators,
  ClpECDHBasicAgreement,
  ClpIBasicAgreement,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpICipherParameters,
  ClpIECCommon,
  ClpIECFieldElement,
  ClpPlatformUtilities,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  CryptoLibTestBase;

type
  TTestECDHPrimeConstantTime = class(TCryptoLibAlgorithmTestCase)
  private
  const
    TestsPerCurve = Int32(16);
  var
    FRandom: ISecureRandom;
    function CurveNames: TCryptoLibStringArray;
    function MakeFieldOps(const AName: String; const ACurve: IECCurve): IFpFieldOps;
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
    procedure TestExceptionalFormulas;
    procedure TestECDHAgreement;
    procedure TestScalarRangeGuard;
    procedure TestBlindBitsValidation;
  end;

implementation

{ TTestECDHPrimeConstantTime }

procedure TTestECDHPrimeConstantTime.SetUp;
begin
  FRandom := TSecureRandom.Create();
end;

procedure TTestECDHPrimeConstantTime.TearDown;
begin
  inherited;
end;

function TTestECDHPrimeConstantTime.CurveNames: TCryptoLibStringArray;
begin
  Result := TCryptoLibStringArray.Create('secp256r1', 'secp384r1', 'secp521r1', 'secp256k1');
end;

function TTestECDHPrimeConstantTime.MakeFieldOps(const AName: String;
  const ACurve: IECCurve): IFpFieldOps;
begin
  if AName = 'secp256r1' then
    Result := TSecP256R1FpFieldOps.Create(ACurve.A, ACurve.B, ACurve.Order)
  else if AName = 'secp384r1' then
    Result := TSecP384R1FpFieldOps.Create(ACurve.A, ACurve.B, ACurve.Order)
  else if AName = 'secp521r1' then
    Result := TSecP521R1FpFieldOps.Create(ACurve.A, ACurve.B, ACurve.Order)
  else
    Result := TSecP256K1FpFieldOps.Create(ACurve.A, ACurve.B, ACurve.Order);
end;

function TTestECDHPrimeConstantTime.RandomScalar(const AN: TBigInteger): TBigInteger;
begin
  Result := TBigInteger.Create(AN.BitLength, FRandom).&Mod(AN);
  if Result.SignValue = 0 then
    Result := TBigInteger.One;
end;

procedure TTestECDHPrimeConstantTime.AssertPointsEqual(const AMsg: String;
  const AA, AB: IECPoint);
begin
  CheckEquals(True, AA.Equals(AB), AMsg);
  CheckEquals(True, AB.Equals(AA), AMsg);
end;

procedure TTestECDHPrimeConstantTime.TestDefaultMultiplierIsConstantTime;
var
  LNames: TCryptoLibStringArray;
  LI: Int32;
  LX9: IX9ECParameters;
  LMul: IECMultiplier;
  LTypeName: String;
begin
  LNames := CurveNames;
  for LI := 0 to System.Length(LNames) - 1 do
  begin
    LX9 := TCustomNamedCurves.GetByName(LNames[LI]);
    CheckTrue(LX9 <> nil, LNames[LI] + ' not found');
    LMul := LX9.Curve.Multiplier;
    LTypeName := TPlatformUtilities.GetTypeName(LMul as TObject);
    CheckTrue(Pos('CTMultiplier', LTypeName) > 0,
      'default multiplier for ' + LNames[LI] + ' is not constant-time (' + LTypeName + ')');
  end;
end;

procedure TTestECDHPrimeConstantTime.TestParityWithWNaf;
var
  LNames: TCryptoLibStringArray;
  LI, LJ: Int32;
  LX9: IX9ECParameters;
  LCurve: IECCurve;
  LWNaf, LCT: IECMultiplier;
  LN, LR, LK: TBigInteger;
  LQ, LRef, LGot: IECPoint;
begin
  LWNaf := TWNafL2RMultiplier.Create() as IECMultiplier;
  LNames := CurveNames;
  for LI := 0 to System.Length(LNames) - 1 do
  begin
    LX9 := TCustomNamedCurves.GetByName(LNames[LI]);
    LCurve := LX9.Curve;
    LN := LX9.N;
    LCT := LCurve.Multiplier;
    for LJ := 0 to TestsPerCurve - 1 do
    begin
      LR := RandomScalar(LN);
      LQ := LWNaf.Multiply(LX9.G, LR).Normalize();
      LK := RandomScalar(LN);
      LRef := LWNaf.Multiply(LQ, LK).Normalize();
      LGot := LCT.Multiply(LQ, LK).Normalize();
      AssertPointsEqual('parity ' + LNames[LI], LRef, LGot);
    end;
  end;
end;

procedure TTestECDHPrimeConstantTime.TestEdgeScalars;
var
  LNames: TCryptoLibStringArray;
  LI, LJ: Int32;
  LX9: IX9ECParameters;
  LCurve: IECCurve;
  LWNaf, LCT: IECMultiplier;
  LN: TBigInteger;
  LScalars: TCryptoLibGenericArray<TBigInteger>;
  LRef, LGot: IECPoint;
begin
  LWNaf := TWNafL2RMultiplier.Create() as IECMultiplier;
  LNames := CurveNames;
  for LI := 0 to System.Length(LNames) - 1 do
  begin
    LX9 := TCustomNamedCurves.GetByName(LNames[LI]);
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
      AssertPointsEqual('edge ' + LNames[LI] + ' idx ' + IntToStr(LJ), LRef, LGot);
    end;
  end;
end;

procedure TTestECDHPrimeConstantTime.TestBlindingTransparency;
var
  LX9: IX9ECParameters;
  LCT: IECMultiplier;
  LN, LK: TBigInteger;
  LI: Int32;
  LFirst, LAgain: IECPoint;
begin
  // Randomized internals (scalar blind + projective coordinate) must not change the result.
  LX9 := TCustomNamedCurves.GetByName('secp256r1');
  LCT := LX9.Curve.Multiplier;
  LN := LX9.N;
  for LI := 0 to 7 do
  begin
    LK := RandomScalar(LN);
    LFirst := LCT.Multiply(LX9.G, LK).Normalize();
    LAgain := LCT.Multiply(LX9.G, LK).Normalize();
    AssertPointsEqual('transparency', LFirst, LAgain);
  end;
end;

procedure TTestECDHPrimeConstantTime.TestExceptionalFormulas;
var
  LX9: IX9ECParameters;
  LCurve: IECCurve;
  LFO: IFpFieldOps;
  LWNaf: IECMultiplier;
  LP, LDbl, LNeg, LSum, LInf: TFePoint;
  LZero: TFe;
  LXa, LYa: TCryptoLibUInt32Array;
  LG, LNegG, LRef2G: IECPoint;

  function ToPoint(const AP: TFePoint): IECPoint;
  var
    LXo, LYo: TCryptoLibUInt32Array;
    LInfLocal: Boolean;
  begin
    LXo := TNat.Create(LFO.GetFieldInts);
    LYo := TNat.Create(LFO.GetFieldInts);
    TCTJacPoint<TSecP256R1FieldArith>.ToAffine(LFO, AP, LXo, LYo, LInfLocal);
    if LInfLocal then
      Exit(LCurve.Infinity);
    Result := LCurve.CreateRawPoint(LFO.CreateFieldElement(LXo),
      LFO.CreateFieldElement(LYo));
  end;

begin
  // Exercise the LIVE incomplete-Jacobian formulas on the exceptional inputs the
  // end-to-end [d]Q test does not deterministically hit: the masked-infinity
  // completion and the P=Q detect-and-double backstop.
  LWNaf := TWNafL2RMultiplier.Create() as IECMultiplier;
  LX9 := TCustomNamedCurves.GetByName('secp256r1');
  LCurve := LX9.Curve;
  LFO := MakeFieldOps('secp256r1', LCurve);

  LG := LX9.G.Normalize();
  LXa := TNat.Create(LFO.GetFieldInts);
  LYa := TNat.Create(LFO.GetFieldInts);
  LFO.FieldFromBigInteger(LG.AffineXCoord.ToBigInteger(), LXa);
  LFO.FieldFromBigInteger(LG.AffineYCoord.ToBigInteger(), LYa);
  TCTJacPoint<TSecP256R1FieldArith>.FromAffine(LFO, LXa, LYa, LP);

  // Add must handle P == Q (doubling): Add(P,P) == Double(P) == 2G
  TCTJacPoint<TSecP256R1FieldArith>.PointDouble(LP, LDbl);
  TCTJacPoint<TSecP256R1FieldArith>.PointAdd(LP, LP, LSum);
  LRef2G := LWNaf.Multiply(LX9.G, TBigInteger.Two).Normalize();
  AssertPointsEqual('Double(P)=2G', LRef2G, ToPoint(LDbl));
  AssertPointsEqual('Add(P,P)=2G', LRef2G, ToPoint(LSum));

  // P + (-P) == O   (-P = (X : -Y : Z) in the Montgomery domain)
  LNeg := LP;
  System.FillChar(LZero, SizeOf(LZero), 0);
  TSecP256R1FieldArith.Sub(LZero, LP.Y, LNeg.Y);
  TCTJacPoint<TSecP256R1FieldArith>.PointAdd(LP, LNeg, LSum);
  CheckEquals(True, ToPoint(LSum).IsInfinity, 'P+(-P)=O');
  // cross-check the affine (-P) really is the curve negation of P
  LNegG := LX9.G.Negate().Normalize();
  AssertPointsEqual('(-P) affine', LNegG, ToPoint(LNeg));

  // P + O == P and O + P == P
  TCTJacPoint<TSecP256R1FieldArith>.Infinity(LFO, LInf);
  TCTJacPoint<TSecP256R1FieldArith>.PointAdd(LP, LInf, LSum);
  AssertPointsEqual('P+O=P', LG, ToPoint(LSum));
  TCTJacPoint<TSecP256R1FieldArith>.PointAdd(LInf, LP, LSum);
  AssertPointsEqual('O+P=P', LG, ToPoint(LSum));

  // O + O == O
  TCTJacPoint<TSecP256R1FieldArith>.PointAdd(LInf, LInf, LSum);
  CheckEquals(True, ToPoint(LSum).IsInfinity, 'O+O=O');
end;

procedure TTestECDHPrimeConstantTime.TestECDHAgreement;
var
  LNames: TCryptoLibStringArray;
  LI: Int32;
  LX9: IX9ECParameters;
  LEC: IECDomainParameters;
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LP1, LP2: IAsymmetricCipherKeyPair;
  LE1, LE2: IBasicAgreement;
  LK1, LK2: TBigInteger;
begin
  LNames := CurveNames;
  for LI := 0 to System.Length(LNames) - 1 do
  begin
    LX9 := TCustomNamedCurves.GetByName(LNames[LI]);
    LEC := TECDomainParameters.Create(LX9.Curve, LX9.G, LX9.N, LX9.H);
    LKpg := TECKeyPairGenerator.Create();
    LKpg.Init(TECKeyGenerationParameters.Create(LEC, FRandom) as IECKeyGenerationParameters);
    LP1 := LKpg.GenerateKeyPair();
    LP2 := LKpg.GenerateKeyPair();

    LE1 := TECDHBasicAgreement.Create();
    LE2 := TECDHBasicAgreement.Create();
    LE1.Init(LP1.Private);
    LE2.Init(LP2.Private);

    LK1 := LE1.CalculateAgreement(LP2.Public as ICipherParameters);
    LK2 := LE2.CalculateAgreement(LP1.Public as ICipherParameters);
    CheckEquals(True, LK1.Equals(LK2), 'ECDH agreement mismatch ' + LNames[LI]);
  end;
end;

procedure TTestECDHPrimeConstantTime.TestScalarRangeGuard;
var
  LNames: TCryptoLibStringArray;
  LI, LOrderBits: Int32;
  LX9: IX9ECParameters;
  LMul: IECMultiplier;
  LN: TBigInteger;

  function Raises(const AK: TBigInteger): Boolean;
  begin
    Result := False;
    try
      LMul.Multiply(LX9.G, AK);
    except
      on E: EInvalidOperationCryptoLibException do
        Result := True;
    end;
  end;

begin
  LNames := CurveNames;
  for LI := 0 to System.Length(LNames) - 1 do
  begin
    LX9 := TCustomNamedCurves.GetByName(LNames[LI]);
    LMul := LX9.Curve.Multiplier;
    LN := LX9.N;
    LOrderBits := LN.BitLength;
    // k = n (BitLength = order bits) is in range and must not raise
    CheckFalse(Raises(LN), 'k = n unexpectedly rejected for ' + LNames[LI]);
    // scalars wider than the order must raise
    CheckTrue(Raises(TBigInteger.One.ShiftLeft(LOrderBits)),
      'k = 2^orderbits not rejected for ' + LNames[LI]);
    CheckTrue(Raises(TBigInteger.One.ShiftLeft(LOrderBits + 1)),
      'k = 2^(orderbits+1) not rejected for ' + LNames[LI]);
  end;
end;

procedure TTestECDHPrimeConstantTime.TestBlindBitsValidation;
var
  LX9: IX9ECParameters;
  LFO: IFpFieldOps;

  function Rejects(ABlindBits: Int32): Boolean;
  var
    LMul: IECMultiplier;
  begin
    Result := False;
    try
      LMul := TFpCTMultiplier<TSecP256R1FieldArith>.Create(LFO, ABlindBits);
    except
      on E: EArgumentCryptoLibException do
        Result := True;
    end;
  end;

begin
  LX9 := TCustomNamedCurves.GetByName('secp256r1');
  LFO := MakeFieldOps('secp256r1', LX9.Curve);
  // 0 and 32 are the distinguished ephemeral opt-in (single-use ECDHE runs the
  // exact-length unblinded ladder); the default and every reused/static scalar
  // keep a full blind in [64, 512].
  CheckFalse(Rejects(0), '0 (ephemeral) rejected');
  CheckFalse(Rejects(32), '32 (ephemeral) rejected');
  CheckTrue(Rejects(16), '16 (non-multiple of 32) accepted');
  CheckTrue(Rejects(48), '48 (non-multiple of 32) accepted');
  CheckTrue(Rejects(544), '544 (above cap) accepted');
  CheckFalse(Rejects(64), '64 rejected');
  CheckFalse(Rejects(128), '128 rejected');
  CheckFalse(Rejects(512), '512 (cap) rejected');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestECDHPrimeConstantTime);
{$ELSE}
  RegisterTest(TTestECDHPrimeConstantTime.Suite);
{$ENDIF FPC}

end.
