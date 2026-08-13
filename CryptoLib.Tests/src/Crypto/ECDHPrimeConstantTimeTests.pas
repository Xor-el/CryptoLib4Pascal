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
  ClpCTLadder,
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
    function FePointFromAffine(const AFO: IFpFieldOps; const AP: IECPoint): TFePoint;
    function FePointToPoint(const AFO: IFpFieldOps; const ACurve: IECCurve;
      const AP: TFePoint): IECPoint;
    function FeInfinity(const AFO: IFpFieldOps): TFePoint;
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

function TTestECDHPrimeConstantTime.FePointFromAffine(const AFO: IFpFieldOps;
  const AP: IECPoint): TFePoint;
var
  LN: Int32;
  LX, LY, LOne: TCryptoLibUInt32Array;
  LQ: IECPoint;
begin
  LN := AFO.GetFieldInts;
  LQ := AP.Normalize();
  LX := TNat.Create(LN);
  LY := TNat.Create(LN);
  LOne := TNat.Create(LN);
  AFO.FieldFromBigInteger(LQ.AffineXCoord.ToBigInteger(), LX);
  AFO.FieldFromBigInteger(LQ.AffineYCoord.ToBigInteger(), LY);
  AFO.FieldOne(LOne);
  System.FillChar(Result, SizeOf(Result), 0);
  System.Move(LX[0], Result.X.W[0], LN * SizeOf(UInt32));
  System.Move(LY[0], Result.Y.W[0], LN * SizeOf(UInt32));
  System.Move(LOne[0], Result.Z.W[0], LN * SizeOf(UInt32));
end;

function TTestECDHPrimeConstantTime.FeInfinity(const AFO: IFpFieldOps): TFePoint;
var
  LN: Int32;
  LOne: TCryptoLibUInt32Array;
begin
  // identity in homogeneous coords is (0 : 1 : 0)
  LN := AFO.GetFieldInts;
  LOne := TNat.Create(LN);
  AFO.FieldOne(LOne);
  System.FillChar(Result, SizeOf(Result), 0);
  System.Move(LOne[0], Result.Y.W[0], LN * SizeOf(UInt32));
end;

function TTestECDHPrimeConstantTime.FePointToPoint(const AFO: IFpFieldOps;
  const ACurve: IECCurve; const AP: TFePoint): IECPoint;
var
  LN: Int32;
  LZ, LZInv, LXtmp, LYtmp, LXa, LYa: TCryptoLibUInt32Array;
begin
  LN := AFO.GetFieldInts;
  LZ := TNat.Create(LN);
  System.Move(AP.Z.W[0], LZ[0], LN * SizeOf(UInt32));
  if AFO.IsZero(LZ) then
    Exit(ACurve.Infinity);
  LZInv := TNat.Create(LN);
  LXtmp := TNat.Create(LN);
  LYtmp := TNat.Create(LN);
  LXa := TNat.Create(LN);
  LYa := TNat.Create(LN);
  System.Move(AP.X.W[0], LXtmp[0], LN * SizeOf(UInt32));
  System.Move(AP.Y.W[0], LYtmp[0], LN * SizeOf(UInt32));
  AFO.Inv(LZ, LZInv);
  AFO.Mul(LXtmp, LZInv, LXa);
  AFO.Mul(LYtmp, LZInv, LYa);
  Result := ACurve.CreateRawPoint(AFO.CreateFieldElement(LXa), AFO.CreateFieldElement(LYa));
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
  LN: Int32;
  LP, LDbl, LNeg, LSum, LInf: TFePoint;
  LNegY, LZeroArr, LYtmp: TCryptoLibUInt32Array;
  LG, LNegG, LRef2G: IECPoint;
begin
  // Exercise the LIVE value-type complete-addition formulas (TCTLadder) on the
  // exceptional inputs the end-to-end [d]Q test does not deterministically hit.
  LWNaf := TWNafL2RMultiplier.Create() as IECMultiplier;
  LX9 := TCustomNamedCurves.GetByName('secp256r1');
  LCurve := LX9.Curve;
  LFO := MakeFieldOps('secp256r1', LCurve);
  LN := LFO.GetFieldInts;

  LG := LX9.G.Normalize();
  LP := FePointFromAffine(LFO, LG);

  // complete Add must handle P == Q (doubling): Add(P,P) == Double(P) == 2G
  TCTLadder<TSecP256R1Ops>.PointDouble(LP, LDbl);
  TCTLadder<TSecP256R1Ops>.PointAdd(LP, LP, LSum);
  LRef2G := LWNaf.Multiply(LX9.G, TBigInteger.Two).Normalize();
  AssertPointsEqual('Double(P)=2G', LRef2G, FePointToPoint(LFO, LCurve, LDbl));
  AssertPointsEqual('Add(P,P)=2G', LRef2G, FePointToPoint(LFO, LCurve, LSum));

  // P + (-P) == O   (-P = (X : -Y : Z))
  LNeg := LP;
  LYtmp := TNat.Create(LN);
  System.Move(LP.Y.W[0], LYtmp[0], LN * SizeOf(UInt32));
  LZeroArr := TNat.Create(LN);
  LNegY := TNat.Create(LN);
  LFO.Sub(LZeroArr, LYtmp, LNegY);
  System.Move(LNegY[0], LNeg.Y.W[0], LN * SizeOf(UInt32));
  TCTLadder<TSecP256R1Ops>.PointAdd(LP, LNeg, LSum);
  CheckEquals(True, FePointToPoint(LFO, LCurve, LSum).IsInfinity, 'P+(-P)=O');
  // cross-check the affine (-P) really is the curve negation of P
  LNegG := LX9.G.Negate().Normalize();
  AssertPointsEqual('(-P) affine', LNegG, FePointToPoint(LFO, LCurve, LNeg));

  // P + O == P and O + P == P
  LInf := FeInfinity(LFO);
  TCTLadder<TSecP256R1Ops>.PointAdd(LP, LInf, LSum);
  AssertPointsEqual('P+O=P', LG, FePointToPoint(LFO, LCurve, LSum));
  TCTLadder<TSecP256R1Ops>.PointAdd(LInf, LP, LSum);
  AssertPointsEqual('O+P=P', LG, FePointToPoint(LFO, LCurve, LSum));

  // O + O == O
  TCTLadder<TSecP256R1Ops>.PointAdd(LInf, LInf, LSum);
  CheckEquals(True, FePointToPoint(LFO, LCurve, LSum).IsInfinity, 'O+O=O');
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
      LMul := TFpCTMultiplier<TSecP256R1Ops>.Create(LFO, ABlindBits);
    except
      on E: EArgumentCryptoLibException do
        Result := True;
    end;
  end;

begin
  LX9 := TCustomNamedCurves.GetByName('secp256r1');
  LFO := MakeFieldOps('secp256r1', LX9.Curve);
  CheckTrue(Rejects(0), '0 accepted');
  CheckTrue(Rejects(32), '32 (below floor) accepted');
  CheckTrue(Rejects(48), '48 (non-multiple of 32) accepted');
  CheckTrue(Rejects(544), '544 (above cap) accepted');
  CheckFalse(Rejects(64), '64 rejected');
  CheckFalse(Rejects(128), '128 rejected');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestECDHPrimeConstantTime);
{$ELSE}
  RegisterTest(TTestECDHPrimeConstantTime.Suite);
{$ENDIF FPC}

end.
