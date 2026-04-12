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

unit Int32Tests;

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
  ClpInt32Utilities,
  CryptoLibTestBase;

type

  TTestInt32Utilities = class(TCryptoLibAlgorithmTestCase)
  private
    class function SimpleBitCount(AN: Int32; ALo, AHi: Int32): Int32; static;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestBitLength;
    procedure TestNumberOfLeadingZeros;
    procedure TestNumberOfTrailingZeros;
    procedure TestPopCount;

  end;

implementation

{ TTestInt32Utilities }

procedure TTestInt32Utilities.SetUp;
begin
  inherited;
  Randomize;
end;

procedure TTestInt32Utilities.TearDown;
begin
  inherited;
end;

procedure TTestInt32Utilities.TestBitLength;
var
  LI: Int32;
begin
  CheckEquals(0, TInt32Utilities.BitLength(Int32(0)));
  CheckEquals(1, TInt32Utilities.BitLength(Int32(1)));
  CheckEquals(32, TInt32Utilities.BitLength(Int32(-1)));
  CheckEquals(7, TInt32Utilities.BitLength(Int32($7F)));
  CheckEquals(8, TInt32Utilities.BitLength(Int32($80)));
  for LI := 0 to 30 do
    CheckEquals(32 - LI, TInt32Utilities.BitLength(Int32(UInt32($80000000) shr LI)));
end;

procedure TTestInt32Utilities.TestNumberOfLeadingZeros;
var
  LI: Int32;
begin
  for LI := 0 to 30 do
  begin
    CheckEquals(LI, TInt32Utilities.NumberOfLeadingZeros(Int32(UInt32($80000000) shr LI)));
    CheckEquals(LI, TInt32Utilities.NumberOfLeadingZeros(Int32(UInt32($FFFFFFFF) shr LI)));
  end;

  CheckEquals(31, TInt32Utilities.NumberOfLeadingZeros(1));
  CheckEquals(32, TInt32Utilities.NumberOfLeadingZeros(0));
end;

procedure TTestInt32Utilities.TestNumberOfTrailingZeros;
var
  LI: Int32;
begin
  for LI := 0 to 30 do
  begin
    CheckEquals(LI, TInt32Utilities.NumberOfTrailingZeros(1 shl LI));
    CheckEquals(LI, TInt32Utilities.NumberOfTrailingZeros((-1) shl LI));
  end;

  CheckEquals(31, TInt32Utilities.NumberOfTrailingZeros(Low(Int32)));
  CheckEquals(32, TInt32Utilities.NumberOfTrailingZeros(0));
end;

procedure TTestInt32Utilities.TestPopCount;
var
  LRound, LRand, LInit, LI, LPattern, LExpected, LPos, LInput: Int32;
begin
  for LRound := 0 to 9 do
  begin
    LRand := Random(MaxInt) shl 8;
    LInit := SimpleBitCount(LRand, 8, 32);

    for LI := 0 to $FF do
    begin
      LPattern := LRand or LI;
      LExpected := LInit + SimpleBitCount(LI, 0, 8);

      for LPos := 0 to 31 do
      begin
        LInput := TInt32Utilities.RotateLeft(LPattern, LPos);

        CheckEquals(LExpected, TInt32Utilities.PopCount(LInput));
        CheckEquals(LExpected, TInt32Utilities.PopCount(UInt32(LInput)));
      end;
    end;
  end;
end;

class function TTestInt32Utilities.SimpleBitCount(AN: Int32;
  ALo, AHi: Int32): Int32;
var
  LI: Int32;
begin
  Result := 0;
  for LI := ALo to AHi - 1 do
    Result := Result + (TBitOperations.Asr32(AN, LI) and 1);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestInt32Utilities);
{$ELSE}
  RegisterTest(TTestInt32Utilities.Suite);
{$ENDIF FPC}

end.
