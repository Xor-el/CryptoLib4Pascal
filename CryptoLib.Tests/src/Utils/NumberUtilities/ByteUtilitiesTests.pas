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

unit ByteUtilitiesTests;

interface

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpByteUtilities,
  CryptoLibTestBase;

type
  TTestByteUtilities = class(TCryptoLibAlgorithmTestCase)
  published
    procedure TestArrayVsPointerXor16;
    procedure TestMisalignedPointerXor;
    procedure TestXorToVsThreeWayXor;
  end;

implementation

procedure FillPattern(var ABuf: TBytes; AStart: Byte);
var
  LI: Integer;
begin
  for LI := 0 to System.Length(ABuf) - 1 do
    ABuf[LI] := Byte(AStart + LI);
end;

procedure TTestByteUtilities.TestArrayVsPointerXor16;
var
  LX, LY, LFromArray, LFromPointer: TBytes;
  LI: Integer;
begin
  SetLength(LX, 16);
  SetLength(LY, 16);
  SetLength(LFromArray, 16);
  SetLength(LFromPointer, 16);
  FillPattern(LX, $10);
  FillPattern(LY, $A0);

  TByteUtilities.&Xor(16, LX, LY, LFromArray);
  TByteUtilities.&Xor(16, PByte(LX), PByte(LY), PByte(LFromPointer));

  CheckTrue(AreEqual(LFromArray, LFromPointer), 'array and pointer Xor must match');
  for LI := 0 to 15 do
    CheckEquals(Byte(LX[LI] xor LY[LI]), LFromArray[LI]);
end;

procedure TTestByteUtilities.TestMisalignedPointerXor;
var
  LX, LY, LExpected, LActual: TBytes;
  LI: Integer;
begin
  SetLength(LX, 17);
  SetLength(LY, 17);
  SetLength(LExpected, 16);
  SetLength(LActual, 16);
  FillPattern(LX, $21);
  FillPattern(LY, $43);

  for LI := 0 to 15 do
    LExpected[LI] := Byte(LX[1 + LI] xor LY[1 + LI]);

  TByteUtilities.&Xor(16, PByte(LX), PByte(LY), PByte(LActual), 1, 1, 0);
  CheckTrue(AreEqual(LExpected, LActual), 'misaligned pointer Xor must match byte reference');
end;

procedure TTestByteUtilities.TestXorToVsThreeWayXor;
var
  LX, LY, LFromXor, LFromXorTo: TBytes;
begin
  SetLength(LX, 16);
  SetLength(LY, 16);
  SetLength(LFromXor, 16);
  SetLength(LFromXorTo, 16);
  FillPattern(LX, $55);
  FillPattern(LY, $66);

  TByteUtilities.&Xor(16, LX, LY, LFromXor);

  FillChar(LFromXorTo[0], 16, 0);
  TByteUtilities.XorTo(16, LX, LFromXorTo);
  TByteUtilities.XorTo(16, LY, LFromXorTo);

  CheckTrue(AreEqual(LFromXor, LFromXorTo), 'XorTo accumulate must match three-way Xor');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestByteUtilities);
{$ELSE}
  RegisterTest(TTestByteUtilities.Suite);
{$ENDIF FPC}

end.
