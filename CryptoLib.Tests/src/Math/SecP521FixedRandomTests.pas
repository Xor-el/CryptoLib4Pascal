{ Reproducible P-521 EC checks using a large fixed byte pool (TFixedSecureRandom).
  Logs the same details on every iteration (success and failure) for cross-platform
  comparison; run alone via fpcunit: --suite=TTestSecP521FixedRandom }
unit SecP521FixedRandomTests;

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
  ClpIECCommon,
  ClpBigInteger,
  ClpECNamedCurveTable,
  ClpCustomNamedCurves,
  ClpMultipliers,
  ClpECAlgorithms,
  ClpIX9ECAsn1Objects,
  ClpCryptoLibTypes,
  ClpFixedSecureRandom,
  CryptoLibTestBase;

const
  SecP521_Curve = 'secp521r1';

type
  TTestSecP521FixedRandom = class(TCryptoLibAlgorithmTestCase)
  private
    FRandom: ISecureRandom;
    procedure LogLine(const S: String);
    procedure LogAffine(const ALabel: String; const P: IECPoint);
    { Deterministic, >= 4 KiB, so TBigInteger.Create(521, random) never exhausts. }
    class function BuildFixedRandom: ISecureRandom; static;
  published
    { Reference multiply vs fixed-point comb on secp521r1, fixed k stream; logs each step. }
    procedure TestReferenceVsFixedPointDeterministic;
    { Same as FixedPoint test driver but only P-521; also logs when points match. }
    procedure TestGeneratorIsOnCurve;
  end;

implementation

{ TTestSecP521FixedRandom }

class function TTestSecP521FixedRandom.BuildFixedRandom: ISecureRandom;
const
  PoolSize = 8192;
var
  B: TCryptoLibByteArray;
  I: Int32;
begin
  SetLength(B, PoolSize);
  { Distinct, repeatable stream (not all zeros; avoids edge cases in big-int paths). }
  for I := 0 to PoolSize - 1 do
    B[I] := Byte((I * 131 + $2B) xor (I shr 3) xor $5A);
  Result := TFixedSecureRandom.From(TCryptoLibMatrixByteArray.Create(B));
end;

procedure TTestSecP521FixedRandom.LogLine(const S: String);
begin
  WriteLn(Output, '[SecP521FixedRandom] ', S);
  Flush(Output);
end;

procedure TTestSecP521FixedRandom.LogAffine(const ALabel: String; const P: IECPoint);
var
  Q: IECPoint;
begin
  Q := P.Normalize;
  if Q.IsInfinity then
  begin
    LogLine(ALabel + ' = Infinity');
    Exit;
  end;
  LogLine(ALabel + ' x=' + Q.XCoord.ToBigInteger.ToString(16));
  LogLine(ALabel + ' y=' + Q.YCoord.ToBigInteger.ToString(16));
  LogLine(ALabel + ' IsValid=' + BoolToStr(Q.IsValid, True));
end;

procedure TTestSecP521FixedRandom.TestReferenceVsFixedPointDeterministic;
var
  LName: String;
  i: Int32;
  Lx9, LX9A, LX9B: IX9ECParameters;
  M: IECMultiplier;
  Lk: TBigInteger;
  pRef, pA, pB: IECPoint;
  LKBits: Int32;
  LBitLen: Int32;
begin
  FRandom := BuildFixedRandom;
  M := TFixedPointCombMultiplier.Create;
  LName := SecP521_Curve;
  Lx9 := nil;
  LX9A := TECNamedCurveTable.GetByName(LName);
  LX9B := TCustomNamedCurves.GetByName(LName);
  if (LX9B <> nil) then
    Lx9 := LX9B
  else
    Lx9 := LX9A;
  if Lx9 = nil then
  begin
    LogLine('SKIP: no parameters for ' + LName);
    Exit;
  end;
  LBitLen := Lx9.N.BitLength;
  LogLine('--- begin curve=' + LName + ' N bitlen=' + IntToStr(LBitLen) + ' (named=' + BoolToStr(
    LX9A <> nil, True) + ' custom=' + BoolToStr(LX9B <> nil, True) + ')');
  LogAffine('G (normalized)', Lx9.G);
  i := 0;
  while i < 8 do
  begin
    LKBits := -1;
    Lk := TBigInteger.Create(LBitLen, FRandom);
    LKBits := Lk.BitLength;
    LogLine(Format('--- i=%d k bitlen=%d k(hex)=%s', [i, LKBits, Lk.ToString(16)]));
    pRef := TECAlgorithms.ReferenceMultiply(Lx9.G, Lk);
    LogLine('pRef: ReferenceMultiply');
    LogAffine('pRef', pRef);
    if (LX9A <> nil) then
    begin
      pA := M.Multiply(LX9A.G, Lk);
      LogLine('pA: TECNamed FPC comb');
      LogAffine('pA', pA);
      if not pRef.Equals(pA) then
      begin
        LogLine('MISMATCH TECNamed vs ref');
        Fail(Format('TECNamed secp521r1 i=%d: ref vs fixed-point', [i]));
      end
      else
        LogLine(Format('OK TECNamed i=%d: ref = comb', [i]));
    end;
    if (LX9B <> nil) then
    begin
      pB := M.Multiply(LX9B.G, Lk);
      LogLine('pB: TCustomNamed FPC comb');
      LogAffine('pB', pB);
      if not pRef.Equals(pB) then
      begin
        LogLine('MISMATCH TCustom vs ref');
        Fail(Format('TCustom secp521r1 i=%d: ref vs fixed-point', [i]));
      end
      else
        LogLine(Format('OK TCustom i=%d: ref = comb', [i]));
    end;
    Inc(i);
  end;
  LogLine('--- end ' + LName);
end;

procedure TTestSecP521FixedRandom.TestGeneratorIsOnCurve;
var
  Lx9: IX9ECParameters;
begin
  FRandom := BuildFixedRandom; { register field for symmetry with other test }
  Lx9 := TECNamedCurveTable.GetByName(SecP521_Curve);
  if Lx9 = nil then
    Lx9 := TCustomNamedCurves.GetByName(SecP521_Curve);
  if Lx9 = nil then
  begin
    LogLine('SKIP: ' + SecP521_Curve + ' not found');
    Exit;
  end;
  LogLine('--- ' + SecP521_Curve + ' G only');
  LogAffine('G', Lx9.G);
  if not Lx9.G.IsValid then
    Fail('G is not valid on ' + SecP521_Curve);
  LogLine('G IsValid True');
end;

{$IFDEF FPC}
initialization
  RegisterTest(TTestSecP521FixedRandom);
{$ELSE}
initialization
  RegisterTest(TTestSecP521FixedRandom.Suite);
{$ENDIF FPC}

end.
