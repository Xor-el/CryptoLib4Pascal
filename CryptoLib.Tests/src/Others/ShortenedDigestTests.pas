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

unit ShortenedDigestTests;

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
  ClpIDigest,
  ClpIShortenedDigest,
  ClpShortenedDigest,
  ClpDigestUtilities,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestShortenedDigest = class(TCryptoLibAlgorithmTestCase)

  private
    procedure DoTestShortenedDigest();

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestShortenedDigest();

  end;

implementation

{ TTestShortenedDigest }

procedure TTestShortenedDigest.DoTestShortenedDigest;
var
  d: IDigest;
  sd: IShortenedDigest;
  temp, temp2: TBytes;
begin
  d := TDigestUtilities.GetDigest('SHA-1');
  sd := TShortenedDigest.Create(TDigestUtilities.GetDigest('SHA-1'), 10);

  if (sd.GetDigestSize() <> 10) then
  begin
    Fail('size check wrong for SHA-1');
  end;

  if (sd.GetByteLength() <> d.GetByteLength()) then
  begin
    Fail('byte length check wrong for SHA-1');
  end;

  //
  // check output fits
  //
  System.SetLength(temp, 10);
  System.SetLength(temp2, 10);
  sd.DoFinal(temp, 0);
  sd.DoFinal(temp2, 0);

  CheckTrue(AreEqual(temp, temp2),
    Format('DoFinal(temp, 0) <> temp := DoFinal() %s', [sd.AlgorithmName]));

  d := TDigestUtilities.GetDigest('SHA-512');
  sd := TShortenedDigest.Create(TDigestUtilities.GetDigest('SHA-512'), 20);

  if (sd.GetDigestSize() <> 20) then
  begin
    Fail('size check wrong for SHA-512');
  end;

  if (sd.GetByteLength() <> d.GetByteLength()) then
  begin
    Fail('byte length check wrong for SHA-512');
  end;

  //
  // check output fits
  //
  System.SetLength(temp, 20);
  System.SetLength(temp2, 20);
  sd.DoFinal(temp, 0);
  sd.DoFinal(temp2, 0);

  CheckTrue(AreEqual(temp, temp2),
    Format('DoFinal(temp, 0) <> temp := DoFinal() %s', [sd.AlgorithmName]));

  try
    TShortenedDigest.Create(Nil, 20);
    Fail('Nil parameter not caught');
  except
    on e: EArgumentNilCryptoLibException do
    begin
      // expected
    end;

  end;

  try
    TShortenedDigest.Create(TDigestUtilities.GetDigest('SHA-1'), 50);
    Fail('short digest not caught');
  except
    on e: EArgumentCryptoLibException do
    begin
      // expected
    end;

  end;

end;

procedure TTestShortenedDigest.SetUp;
begin
  inherited;

end;

procedure TTestShortenedDigest.TearDown;
begin
  inherited;

end;

procedure TTestShortenedDigest.TestShortenedDigest;
begin
  DoTestShortenedDigest();
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestShortenedDigest);
{$ELSE}
  RegisterTest(TTestShortenedDigest.Suite);
{$ENDIF FPC}

end.
