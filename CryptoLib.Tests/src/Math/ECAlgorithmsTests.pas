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

unit ECAlgorithmsTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$WARNINGS OFF}
{$NOTES OFF}
{$HINTS OFF}
{$ENDIF FPC}

uses
  Classes,
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  Generics.Collections,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpECC,
  ClpIECC,
  ClpBigInteger,
  ClpECNamedCurveTable,
  ClpCustomNamedCurves,
  ClpECAlgorithms,
  ClpX9ECParameters,
  ClpIX9ECParameters,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestECAlgorithms = class(TCryptoLibAlgorithmTestCase)
  private

    class var

      FRandom: ISecureRandom;

  const
    Scale = Int32(4);

    procedure DoTestSumOfMultiplies(const x9: IX9ECParameters);
    procedure DoTestSumOfTwoMultiplies(const x9: IX9ECParameters);
    procedure AssertPointsEqual(const msg: String; const a, b: IECPoint);
    function CopyPoints(const ps: TCryptoLibGenericArray<IECPoint>; len: Int32)
      : TCryptoLibGenericArray<IECPoint>;
    function CopyScalars(const ks: TCryptoLibGenericArray<TBigInteger>;
      len: Int32): TCryptoLibGenericArray<TBigInteger>;

    function GetRandomPoint(const x9: IX9ECParameters): IECPoint;
    function GetRandomScalar(const x9: IX9ECParameters): TBigInteger;

    function GetTestCurves(): TCryptoLibGenericArray<IX9ECParameters>;

    procedure AddTestCurves(x9s: TList<IX9ECParameters>;
      const x9: IX9ECParameters);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestSumOfMultiplies;
    procedure TestSumOfMultipliesComplete;
    procedure TestSumOfTwoMultiplies;
    procedure TestSumOfTwoMultipliesComplete;

  end;

implementation

{ TTestECAlgorithms }

procedure TTestECAlgorithms.AddTestCurves(x9s: TList<IX9ECParameters>;
  const x9: IX9ECParameters);
var
  curve, c: IECCurve;
  point: IECPoint;
  params: IX9ECParameters;
  coord, i: Int32;
  coords: TCryptoLibInt32Array;
begin
  curve := x9.curve;

  coords := TECCurve.GetAllCoordinateSystems();
  for i := 0 to System.Pred(System.Length(coords)) do

  begin
    coord := coords[i];
    if (curve.CoordinateSystem = coord) then
    begin
      x9s.Add(x9);
    end
    else if (curve.SupportsCoordinateSystem(coord)) then
    begin
      c := curve.Configure().SetCoordinateSystem(coord).CreateCurve();
      point := c.ImportPoint(x9.G);
      params := TX9ECParameters.Create(c, point, x9.N, x9.H);
      x9s.Add(params);
    end;
  end;
end;

procedure TTestECAlgorithms.AssertPointsEqual(const msg: String;
  const a, b: IECPoint);
begin
  CheckEquals(True, a.Equals(b), msg);
end;

function TTestECAlgorithms.CopyPoints
  (const ps: TCryptoLibGenericArray<IECPoint>; len: Int32)
  : TCryptoLibGenericArray<IECPoint>;
begin
  System.SetLength(Result, len);
  Result := System.Copy(ps, 0, len);
end;

function TTestECAlgorithms.CopyScalars
  (const ks: TCryptoLibGenericArray<TBigInteger>; len: Int32)
  : TCryptoLibGenericArray<TBigInteger>;
begin
  System.SetLength(Result, len);
  Result := System.Copy(ks, 0, len);
end;

procedure TTestECAlgorithms.DoTestSumOfMultiplies(const x9: IX9ECParameters);
var
  points, results: TCryptoLibGenericArray<IECPoint>;
  scalars: TCryptoLibGenericArray<TBigInteger>;
  i: Int32;
  u, v: IECPoint;
begin
  System.SetLength(points, Scale);
  System.SetLength(scalars, Scale);

  for i := 0 to System.Pred(Scale) do

  begin
    points[i] := GetRandomPoint(x9);
    scalars[i] := GetRandomScalar(x9);
  end;

  u := x9.curve.Infinity;

  for i := 0 to System.Pred(Scale) do
  begin
    u := u.Add(points[i].Multiply(scalars[i]));

    v := TECAlgorithms.SumOfMultiplies(CopyPoints(points, i + 1),
      CopyScalars(scalars, i + 1));

    results := TCryptoLibGenericArray<IECPoint>.Create(u, v);
    x9.curve.NormalizeAll(results);

    AssertPointsEqual('ECAlgorithms.SumOfMultiplies is incorrect', results[0],
      results[1]);
  end;

end;

procedure TTestECAlgorithms.DoTestSumOfTwoMultiplies(const x9: IX9ECParameters);
var
  i: Int32;
  p, q, u, v, w: IECPoint;
  a, b: TBigInteger;
  results: TCryptoLibGenericArray<IECPoint>;
begin
  p := GetRandomPoint(x9);
  a := GetRandomScalar(x9);

  i := 0;
  while i < Scale do
  begin
    q := GetRandomPoint(x9);
    b := GetRandomScalar(x9);

    u := p.Multiply(a).Add(q.Multiply(b));
    v := TECAlgorithms.ShamirsTrick(p, a, q, b);
    w := TECAlgorithms.SumOfTwoMultiplies(p, a, q, b);

    results := TCryptoLibGenericArray<IECPoint>.Create(u, v, w);
    x9.curve.NormalizeAll(results);

    AssertPointsEqual('TECAlgorithms.ShamirsTrick is incorrect', results[0],
      results[1]);
    AssertPointsEqual('TECAlgorithms.SumOfTwoMultiplies is incorrect',
      results[0], results[2]);

    p := q;
    a := b;
    System.Inc(i);
  end;
end;

function TTestECAlgorithms.GetRandomPoint(const x9: IX9ECParameters): IECPoint;
begin
  Result := x9.G.Multiply(GetRandomScalar(x9));
end;

function TTestECAlgorithms.GetRandomScalar(const x9: IX9ECParameters)
  : TBigInteger;
begin
  Result := TBigInteger.Create(x9.N.BitLength, FRandom);
end;

function TTestECAlgorithms.GetTestCurves
  : TCryptoLibGenericArray<IX9ECParameters>;
var
  name: string;
  x9s: TList<IX9ECParameters>;
  tempList: TList<String>;
  tempDict: TDictionary<String, String>;
  names: TCryptoLibStringArray;
  x9: IX9ECParameters;
  s: string;
begin
  x9s := TList<IX9ECParameters>.Create();
  try

    tempList := TList<String>.Create();
    try
      tempList.AddRange(TECNamedCurveTable.names); // get all collections
      tempList.AddRange(TCustomNamedCurves.names);
      tempDict := TDictionary<String, String>.Create();
      try
        for s in tempList do
        begin
          tempDict.AddOrSetValue(s, s); // make sure they are unique
        end;
        names := tempDict.Values.ToArray; // save unique instances to array
      finally
        tempDict.Free;
      end;
    finally
      tempList.Free;
    end;

    for name in names do
    begin
      x9 := TECNamedCurveTable.GetByName(name);
      if (x9 <> Nil) then
      begin
        AddTestCurves(x9s, x9);
      end;

      x9 := TCustomNamedCurves.GetByName(name);
      if (x9 <> Nil) then
      begin
        AddTestCurves(x9s, x9);
      end;
    end;
    Result := x9s.ToArray;
  finally
    x9s.Free;
  end;
end;

procedure TTestECAlgorithms.SetUp;
begin
  FRandom := TSecureRandom.Create();
end;

procedure TTestECAlgorithms.TearDown;
begin
  inherited;

end;

procedure TTestECAlgorithms.TestSumOfMultiplies;
var
  x9: IX9ECParameters;
begin
  x9 := TCustomNamedCurves.GetByName('secp256r1');
  CheckNotNull(x9);
  DoTestSumOfMultiplies(x9);
end;

procedure TTestECAlgorithms.TestSumOfMultipliesComplete;
var
  x9: IX9ECParameters;
begin
  for x9 in GetTestCurves() do
  begin
    DoTestSumOfMultiplies(x9);
  end;
end;

procedure TTestECAlgorithms.TestSumOfTwoMultiplies;
var
  x9: IX9ECParameters;
begin
  x9 := TCustomNamedCurves.GetByName('secp256r1');
  CheckNotNull(x9);
  DoTestSumOfTwoMultiplies(x9);
end;

procedure TTestECAlgorithms.TestSumOfTwoMultipliesComplete;
var
  x9: IX9ECParameters;
begin
  for x9 in GetTestCurves() do
  begin
    DoTestSumOfTwoMultiplies(x9);
  end;

end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestECAlgorithms);
{$ELSE}
  RegisterTest(TTestECAlgorithms.Suite);
{$ENDIF FPC}

end.
