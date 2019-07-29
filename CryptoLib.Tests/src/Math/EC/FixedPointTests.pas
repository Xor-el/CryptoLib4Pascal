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

unit FixedPointTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  Generics.Collections,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpIECC,
  ClpBigInteger,
  ClpECNamedCurveTable,
  ClpCustomNamedCurves,
  ClpMultipliers,
  ClpIMultipliers,
  ClpECAlgorithms,
  ClpIX9ECParameters,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestFixedPoint = class(TCryptoLibAlgorithmTestCase)
  private

    class var

      FRandom: ISecureRandom;

  const
    TestsPerCurve = Int32(5);

    procedure AssertPointsEqual(const msg: String; const a, b: IECPoint);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestFixedPointMultiplier;

  end;

implementation

{ TTestFixedPoint }

procedure TTestFixedPoint.AssertPointsEqual(const msg: String;
  const a, b: IECPoint);
begin
  // NOTE: We intentionally test points for equality in both directions
  CheckEquals(True, a.Equals(b), msg);
  CheckEquals(True, b.Equals(a), msg);
end;

procedure TTestFixedPoint.TestFixedPointMultiplier;
var
  name, s: string;
  i: Int32;
  tempList: TList<String>;
  tempDict: TDictionary<String, String>;
  names: TCryptoLibStringArray;
  x9, X9A, X9B: IX9ECParameters;
  M: IFixedPointCombMultiplier;
  k: TBigInteger;
  pRef, pA, pB: IECPoint;

begin
  M := TFixedPointCombMultiplier.Create();

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
    X9A := TECNamedCurveTable.GetByName(name);
    X9B := TCustomNamedCurves.GetByName(name);
    if (X9B <> Nil) then
    begin
      x9 := X9B
    end
    else
    begin
      x9 := X9A;
    end;

    i := 0;
    while i < TestsPerCurve do
    begin
      k := TBigInteger.Create(x9.N.BitLength, FRandom);
      pRef := TECAlgorithms.ReferenceMultiply(x9.G, k);

      if (X9A <> Nil) then
      begin
        pA := M.Multiply(X9A.G, k);
        AssertPointsEqual('Standard curve fixed-point failure', pRef, pA);
      end;

      if (X9B <> Nil) then
      begin
        pB := M.Multiply(X9B.G, k);
        AssertPointsEqual('Custom curve fixed-point failure', pRef, pB);
      end;
      System.Inc(i);
    end;

  end;

end;

procedure TTestFixedPoint.SetUp;
begin
  FRandom := TSecureRandom.Create();
end;

procedure TTestFixedPoint.TearDown;
begin
  inherited;

end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestFixedPoint);
{$ELSE}
  RegisterTest(TTestFixedPoint.Suite);
{$ENDIF FPC}

end.
