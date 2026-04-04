{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit Int64Tests;

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
  ClpBitOperations,
  ClpInt64Utilities,
  CryptoLibTestBase;

type

  TTestInt64Utilities = class(TCryptoLibAlgorithmTestCase)
  private
    class function SimpleBitCount(AN: Int64; ALo, AHi: Int32): Int32; static;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestNumberOfLeadingZeros;
    procedure TestNumberOfTrailingZeros;
    procedure TestPopCount;

  end;

implementation

{ TTestInt64Utilities }

procedure TTestInt64Utilities.SetUp;
begin
  inherited;
  Randomize;
end;

procedure TTestInt64Utilities.TearDown;
begin
  inherited;
end;

procedure TTestInt64Utilities.TestNumberOfLeadingZeros;
var
  LI: Int32;
begin
  for LI := 0 to 62 do
  begin
    CheckEquals(LI, TInt64Utilities.NumberOfLeadingZeros(Int64(UInt64($8000000000000000) shr LI)));
    CheckEquals(LI, TInt64Utilities.NumberOfLeadingZeros(Int64(UInt64($FFFFFFFFFFFFFFFF) shr LI)));
  end;

  CheckEquals(63, TInt64Utilities.NumberOfLeadingZeros(Int64(1)));
  CheckEquals(64, TInt64Utilities.NumberOfLeadingZeros(Int64(0)));
end;

procedure TTestInt64Utilities.TestNumberOfTrailingZeros;
var
  LI: Int32;
begin
  for LI := 0 to 62 do
  begin
    CheckEquals(LI, TInt64Utilities.NumberOfTrailingZeros(Int64(1) shl LI));
    CheckEquals(LI, TInt64Utilities.NumberOfTrailingZeros(Int64(-1) shl LI));
  end;

  CheckEquals(63, TInt64Utilities.NumberOfTrailingZeros(Low(Int64)));
  CheckEquals(64, TInt64Utilities.NumberOfTrailingZeros(Int64(0)));
end;

procedure TTestInt64Utilities.TestPopCount;
var
  LRound, LPos: Int32;
  LRand, LPattern, LInput: Int64;
  LI, LInit, LExpected: Int32;
begin
  for LRound := 0 to 9 do
  begin
    LRand := (Int64(Random(MaxInt)) shl 36) xor (Int64(Random(MaxInt)) shl 8);
    LInit := SimpleBitCount(LRand, 8, 64);

    for LI := 0 to 255 do
    begin
      LPattern := LRand or Int64(LI);
      LExpected := LInit + SimpleBitCount(Int64(LI), 0, 8);

      for LPos := 0 to 63 do
      begin
        LInput := TInt64Utilities.RotateLeft(LPattern, LPos);

        CheckEquals(LExpected, TInt64Utilities.PopCount(LInput));
        CheckEquals(LExpected, TInt64Utilities.PopCount(UInt64(LInput)));
      end;
    end;
  end;
end;

class function TTestInt64Utilities.SimpleBitCount(AN: Int64;
  ALo, AHi: Int32): Int32;
var
  LI: Int32;
  LCount: Int64;
begin
  LCount := 0;
  for LI := ALo to AHi - 1 do
    LCount := LCount + (TBitOperations.Asr64(AN, LI) and Int64(1));
  Result := Int32(LCount);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestInt64Utilities);
{$ELSE}
  RegisterTest(TTestInt64Utilities.Suite);
{$ENDIF FPC}

end.
