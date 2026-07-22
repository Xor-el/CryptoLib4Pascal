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
  ClpECAlgorithms,
  ClpIFpFieldOps,
  ClpHomogeneousPoint,
  ClpFixedWindowCTMultiplier,
  ClpSecP256R1Custom,
  ClpSecP256K1Custom,
  ClpSecP384R1Custom,
  ClpSecP521R1Custom,
  ClpECParameters,
  ClpIECParameters,
  ClpECGenerators,
  ClpIECGenerators,
  ClpECDHBasicAgreement,
  ClpIBasicAgreement,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIKeyGenerationParameters,
  ClpICipherParameters,
  ClpIECCommon,
  ClpIECFieldElement,
  ClpPlatformUtilities,
  ClpCryptoLibTypes,
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
    function HomogFromAffine(const AFO: IFpFieldOps; const AP: IECPoint): TCTHomogPoint;
    function HomogToPoint(const AFO: IFpFieldOps; const ACurve: IECCurve;
      const AP: TCTHomogPoint): IECPoint;
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

function TTestECDHPrimeConstantTime.HomogFromAffine(const AFO: IFpFieldOps;
  const AP: IECPoint): TCTHomogPoint;
var
  LN: Int32;
  LX, LY: TCryptoLibUInt32Array;
  LQ: IECPoint;
begin
  LN := AFO.GetFieldInts;
  LQ := AP.Normalize();
  LX := TNat.Create(LN);
  LY := TNat.Create(LN);
  AFO.FieldFromBigInteger(LQ.AffineXCoord.ToBigInteger(), LX);
  AFO.FieldFromBigInteger(LQ.AffineYCoord.ToBigInteger(), LY);
  Result := TCTHomogeneousMath.FromAffine(AFO, LX, LY);
end;

function TTestECDHPrimeConstantTime.HomogToPoint(const AFO: IFpFieldOps;
  const ACurve: IECCurve; const AP: TCTHomogPoint): IECPoint;
var
  LX, LY: TCryptoLibUInt32Array;
  LIsInfinity: Boolean;
begin
  TCTHomogeneousMath.ToAffine(AFO, AP, LX, LY, LIsInfinity);
  if LIsInfinity then
    Result := ACurve.Infinity
  else
    Result := ACurve.CreateRawPoint(AFO.CreateFieldElement(LX), AFO.CreateFieldElement(LY));
end;

procedure TTestECDHPrimeConstantTime.TestDefaultMultiplierIsConstantTime;
var
  LNames: TCryptoLibStringArray;
  LI: Int32;
  LX9: IX9ECParameters;
  LMul: IECMultiplier;
begin
  LNames := CurveNames;
  for LI := 0 to System.Length(LNames) - 1 do
  begin
    LX9 := TCustomNamedCurves.GetByName(LNames[LI]);
    CheckTrue(LX9 <> nil, LNames[LI] + ' not found');
    LMul := LX9.Curve.Multiplier;
    CheckEquals('TFixedWindowCTMultiplier', TPlatformUtilities.GetTypeName(LMul as TObject),
      'default multiplier for ' + LNames[LI] + ' is not constant-time');
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
  LP, LDbl, LNeg, LSum, LInf: TCTHomogPoint;
  LNegY, LZeroArr: TCryptoLibUInt32Array;
  LG, LNegG, LRef2G: IECPoint;
begin
  LWNaf := TWNafL2RMultiplier.Create() as IECMultiplier;
  LX9 := TCustomNamedCurves.GetByName('secp256r1');
  LCurve := LX9.Curve;
  LFO := MakeFieldOps('secp256r1', LCurve);
  LN := LFO.GetFieldInts;

  LG := LX9.G.Normalize();
  LP := HomogFromAffine(LFO, LG);

  // complete Add must handle P == Q (doubling): Add(P,P) == Double(P) == 2G
  LDbl := TCTHomogeneousMath.Double(LFO, LP);
  LSum := TCTHomogeneousMath.Add(LFO, LP, LP);
  LRef2G := LWNaf.Multiply(LX9.G, TBigInteger.Two).Normalize();
  AssertPointsEqual('Double(P)=2G', LRef2G, HomogToPoint(LFO, LCurve, LDbl));
  AssertPointsEqual('Add(P,P)=2G', LRef2G, HomogToPoint(LFO, LCurve, LSum));

  // P + (-P) == O
  LZeroArr := TNat.Create(LN);
  LNegY := TNat.Create(LN);
  LFO.Sub(LZeroArr, HomogFromAffine(LFO, LG).Y, LNegY);
  LNeg.X := HomogFromAffine(LFO, LG).X;
  LNeg.Y := LNegY;
  LNeg.Z := HomogFromAffine(LFO, LG).Z;
  LSum := TCTHomogeneousMath.Add(LFO, LP, LNeg);
  CheckEquals(True, HomogToPoint(LFO, LCurve, LSum).IsInfinity, 'P+(-P)=O');
  // cross-check the affine (-P) really is the curve negation of P
  LNegG := LX9.G.Negate().Normalize();
  AssertPointsEqual('(-P) affine', LNegG, HomogToPoint(LFO, LCurve, LNeg));

  // P + O == P and O + P == P
  LInf := TCTHomogeneousMath.Infinity(LFO);
  AssertPointsEqual('P+O=P', LG, HomogToPoint(LFO, LCurve, TCTHomogeneousMath.Add(LFO, LP, LInf)));
  AssertPointsEqual('O+P=P', LG, HomogToPoint(LFO, LCurve, TCTHomogeneousMath.Add(LFO, LInf, LP)));

  // O + O == O
  CheckEquals(True, HomogToPoint(LFO, LCurve,
    TCTHomogeneousMath.Add(LFO, LInf, LInf)).IsInfinity, 'O+O=O');
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

initialization

{$IFDEF FPC}
  RegisterTest(TTestECDHPrimeConstantTime);
{$ELSE}
  RegisterTest(TTestECDHPrimeConstantTime.Suite);
{$ENDIF FPC}

end.
