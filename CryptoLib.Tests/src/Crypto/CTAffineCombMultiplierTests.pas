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

unit CTAffineCombMultiplierTests;

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
  ClpBigInteger,
  ClpCustomNamedCurves,
  ClpIX9ECAsn1Objects,
  ClpIECCommon,
  ClpMultipliers,
  ClpBigIntegerUtilities,
  ClpScalarFieldRegistry,
  ClpIScalarFieldOps,
  ClpSecureRandom,
  ClpISecureRandom,
  CryptoLibTestBase;

type
  /// <summary>
  /// Equivalence safety net for the fixed-base affine (no-doubling) comb across
  /// every custom Fp curve now wired to it (secp256r1/k1 and secp384r1/521r1,
  /// covering a=-3 and a=0). For each curve the affine multiplier (the flipped
  /// base-point multiplier) must produce exactly the same [k]G as the independent
  /// variable-time wNAF multiplier, over adversarial scalars (1, n-1, window
  /// boundaries, all-ones runs, Booth-digit extremes) and random scalars. Any
  /// recode / gather / mixed-add / digit-zero-skip bug shows up as a mismatch.
  /// </summary>
  TTestCTAffineComb = class(TCryptoLibAlgorithmTestCase)
  strict private
    FRandom: ISecureRandom;
    function PointsEqual(const AA, AB: IECPoint): Boolean;
    procedure CheckScalar(const AAffine, AWnaf: IECMultiplier;
      const AG: IECPoint; const AK: TBigInteger; const AText: String);
    procedure RunBattery(const ACurveName: String; const AAffine, AWnaf: IECMultiplier;
      const AG: IECPoint; const AN: TBigInteger);
  protected
    procedure SetUp; override;
  published
    procedure TestSecP256R1;
    procedure TestSecP256K1;
    procedure TestSecP384R1;
    procedure TestSecP521R1;
    procedure TestScalarFieldOps;
  end;

implementation

{ TTestCTAffineComb }

procedure TTestCTAffineComb.SetUp;
begin
  inherited SetUp;
  FRandom := TSecureRandom.Create();
end;

function TTestCTAffineComb.PointsEqual(const AA, AB: IECPoint): Boolean;
begin
  if AA.IsInfinity or AB.IsInfinity then
    Exit(AA.IsInfinity and AB.IsInfinity);
  Result :=
    (AA.AffineXCoord.ToBigInteger.CompareTo(AB.AffineXCoord.ToBigInteger) = 0) and
    (AA.AffineYCoord.ToBigInteger.CompareTo(AB.AffineYCoord.ToBigInteger) = 0);
end;

procedure TTestCTAffineComb.CheckScalar(const AAffine, AWnaf: IECMultiplier;
  const AG: IECPoint; const AK: TBigInteger; const AText: String);
var
  LA, LW: IECPoint;
begin
  LA := AAffine.Multiply(AG, AK).Normalize();
  LW := AWnaf.Multiply(AG, AK).Normalize();
  if not PointsEqual(LA, LW) then
    Fail(Format('%s: affine comb disagrees with wNAF', [AText]));
end;

procedure TTestCTAffineComb.RunBattery(const ACurveName: String;
  const AAffine, AWnaf: IECMultiplier; const AG: IECPoint; const AN: TBigInteger);
var
  LI: Int32;
  LPow, LK: TBigInteger;
begin
  CheckScalar(AAffine, AWnaf, AG, TBigInteger.One, ACurveName + ' k=1');
  CheckScalar(AAffine, AWnaf, AG, TBigInteger.Two, ACurveName + ' k=2');
  CheckScalar(AAffine, AWnaf, AG, AN.Subtract(TBigInteger.One),
    ACurveName + ' k=n-1');
  CheckScalar(AAffine, AWnaf, AG, AN.Subtract(TBigInteger.Two),
    ACurveName + ' k=n-2');
  CheckScalar(AAffine, AWnaf, AG, AN.ShiftRight(1), ACurveName + ' k=n/2');

  // w=7 window boundaries: 2^(7i) and neighbours exercise the Booth carry and
  // the digit=64 / digit=0 corners across every window.
  for LI := 0 to (AN.BitLength div 7) + 1 do
  begin
    LPow := TBigInteger.One.ShiftLeft(7 * LI);
    if LPow.CompareTo(AN) >= 0 then
      Break;
    CheckScalar(AAffine, AWnaf, AG, LPow,
      Format('%s k=2^%d', [ACurveName, 7 * LI]));
    if LI > 0 then
    begin
      CheckScalar(AAffine, AWnaf, AG, LPow.Subtract(TBigInteger.One),
        Format('%s k=2^%d-1', [ACurveName, 7 * LI]));
      CheckScalar(AAffine, AWnaf, AG, LPow.Add(TBigInteger.One),
        Format('%s k=2^%d+1', [ACurveName, 7 * LI]));
    end;
  end;

  for LI := 1 to 150 do
  begin
    LK := TBigInteger.Create(AN.BitLength, FRandom).&Mod(AN);
    if LK.SignValue = 0 then
      LK := TBigInteger.One;
    CheckScalar(AAffine, AWnaf, AG, LK,
      Format('%s random #%d', [ACurveName, LI]));
  end;
end;

procedure TTestCTAffineComb.TestSecP256R1;
var
  LX9: IX9ECParameters;
  LAff, LWnaf: IECMultiplier;
begin
  LX9 := TCustomNamedCurves.GetByName('secp256r1');
  LAff := LX9.Curve.GetBasePointMultiplier;
  LWnaf := TWNafL2RMultiplier.Create();
  RunBattery('secp256r1', LAff, LWnaf, LX9.G, LX9.N);
end;

procedure TTestCTAffineComb.TestSecP256K1;
var
  LX9: IX9ECParameters;
  LAff, LWnaf: IECMultiplier;
begin
  LX9 := TCustomNamedCurves.GetByName('secp256k1');
  LAff := LX9.Curve.GetBasePointMultiplier;
  LWnaf := TWNafL2RMultiplier.Create();
  RunBattery('secp256k1', LAff, LWnaf, LX9.G, LX9.N);
end;

procedure TTestCTAffineComb.TestSecP384R1;
var
  LX9: IX9ECParameters;
  LAff, LWnaf: IECMultiplier;
begin
  LX9 := TCustomNamedCurves.GetByName('secp384r1');
  LAff := LX9.Curve.GetBasePointMultiplier;
  LWnaf := TWNafL2RMultiplier.Create();
  RunBattery('secp384r1', LAff, LWnaf, LX9.G, LX9.N);
end;

procedure TTestCTAffineComb.TestSecP521R1;
var
  LX9: IX9ECParameters;
  LAff, LWnaf: IECMultiplier;
begin
  LX9 := TCustomNamedCurves.GetByName('secp521r1');
  LAff := LX9.Curve.GetBasePointMultiplier;
  LWnaf := TWNafL2RMultiplier.Create();
  RunBattery('secp521r1', LAff, LWnaf, LX9.G, LX9.N);
end;

procedure TTestCTAffineComb.TestScalarFieldOps;
var
  LN, LA, LB, LK, LE, LD, LR, LExp: TBigInteger;
  LOps: IScalarFieldOps;
  LI: Int32;
begin
  LN := TCustomNamedCurves.GetByName('secp256r1').N;
  if not TScalarFieldRegistry.TryGet(LN, LOps) then
    Fail('no scalar-field ops registered for secp256r1');
  for LI := 1 to 200 do
  begin
    LA := TBigInteger.Create(256, FRandom).&Mod(LN);
    if LA.SignValue = 0 then LA := TBigInteger.One;
    LB := TBigInteger.Create(256, FRandom).&Mod(LN);

    if LOps.InvModN(LA).CompareTo(TBigIntegerUtilities.ModOddInverse(LN, LA)) <> 0 then
      Fail(Format('InvModN mismatch #%d', [LI]));
    if LOps.MulModN(LA, LB).CompareTo(LA.Multiply(LB).&Mod(LN)) <> 0 then
      Fail(Format('MulModN mismatch #%d', [LI]));
    if LOps.AddModN(LA, LB).CompareTo(LA.Add(LB).&Mod(LN)) <> 0 then
      Fail(Format('AddModN mismatch #%d', [LI]));

    LK := LA; LE := LB;
    LD := TBigInteger.Create(256, FRandom).&Mod(LN);
    LR := TBigInteger.Create(256, FRandom).&Mod(LN);
    LExp := TBigIntegerUtilities.ModOddInverse(LN, LK)
      .Multiply(LE.Add(LD.Multiply(LR))).&Mod(LN);
    if LOps.ComputeS(LK, LE, LD, LR).CompareTo(LExp) <> 0 then
      Fail(Format('ComputeS mismatch #%d', [LI]));
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestCTAffineComb);
{$ELSE}
  RegisterTest(TTestCTAffineComb.Suite);
{$ENDIF FPC}

end.
