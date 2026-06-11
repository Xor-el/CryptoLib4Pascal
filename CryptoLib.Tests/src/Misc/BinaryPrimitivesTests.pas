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

unit BinaryPrimitivesTests;

interface

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpBinaryPrimitives,
  CryptoLibTestBase;

type

  TTestBinaryPrimitives = class(TCryptoLibTestCase)
  published
    procedure TestUInt16LittleEndianArrayVsPointer;
    procedure TestUInt16BigEndianArrayVsPointer;
    procedure TestUInt32LittleEndianArrayVsPointer;
    procedure TestUInt32BigEndianArrayVsPointer;
    procedure TestUInt64LittleEndianArrayVsPointer;
    procedure TestUInt64BigEndianArrayVsPointer;
    procedure TestUInt32MisalignedPointerRead;
    procedure TestCopyUInt32LittleEndianAligned;
    procedure TestCopyUInt32LittleEndianMisaligned;
    procedure TestCopyUInt32BigEndianWireFormat;
    procedure TestCopyUInt64LittleEndianAligned;
  end;

implementation

const
  TEST_UINT16 = UInt16($1122);
  TEST_UINT32 = UInt32($11223344);
  TEST_UINT64 = UInt64($1122334455667788);

procedure TTestBinaryPrimitives.TestUInt16LittleEndianArrayVsPointer;
var
  LBuf: TBytes;
  LFromArray, LFromPointer: UInt16;
begin
  SetLength(LBuf, 4);
  TBinaryPrimitives.WriteUInt16LittleEndian(LBuf, 1, TEST_UINT16);
  LFromArray := TBinaryPrimitives.ReadUInt16LittleEndian(LBuf, 1);
  LFromPointer := TBinaryPrimitives.ReadUInt16LittleEndian(PByte(@LBuf[1]), 0);
  CheckEquals(TEST_UINT16, LFromArray);
  CheckEquals(LFromArray, LFromPointer);
  CheckEquals(Byte(TEST_UINT16), LBuf[1]);
  CheckEquals(Byte(TEST_UINT16 shr 8), LBuf[2]);
end;

procedure TTestBinaryPrimitives.TestUInt16BigEndianArrayVsPointer;
var
  LBuf: TBytes;
  LFromArray, LFromPointer: UInt16;
begin
  SetLength(LBuf, 4);
  TBinaryPrimitives.WriteUInt16BigEndian(LBuf, 1, TEST_UINT16);
  LFromArray := TBinaryPrimitives.ReadUInt16BigEndian(LBuf, 1);
  LFromPointer := TBinaryPrimitives.ReadUInt16BigEndian(PByte(@LBuf[1]), 0);
  CheckEquals(TEST_UINT16, LFromArray);
  CheckEquals(LFromArray, LFromPointer);
  CheckEquals(Byte(TEST_UINT16 shr 8), LBuf[1]);
  CheckEquals(Byte(TEST_UINT16), LBuf[2]);
end;

procedure TTestBinaryPrimitives.TestUInt32LittleEndianArrayVsPointer;
var
  LBuf: TBytes;
  LFromArray, LFromPointer: UInt32;
begin
  SetLength(LBuf, 8);
  TBinaryPrimitives.WriteUInt32LittleEndian(LBuf, 2, TEST_UINT32);
  LFromArray := TBinaryPrimitives.ReadUInt32LittleEndian(LBuf, 2);
  LFromPointer := TBinaryPrimitives.ReadUInt32LittleEndian(PByte(@LBuf[2]), 0);
  CheckEquals(TEST_UINT32, LFromArray);
  CheckEquals(LFromArray, LFromPointer);
end;

procedure TTestBinaryPrimitives.TestUInt32BigEndianArrayVsPointer;
var
  LBuf: TBytes;
  LFromArray, LFromPointer: UInt32;
begin
  SetLength(LBuf, 8);
  TBinaryPrimitives.WriteUInt32BigEndian(LBuf, 2, TEST_UINT32);
  LFromArray := TBinaryPrimitives.ReadUInt32BigEndian(LBuf, 2);
  LFromPointer := TBinaryPrimitives.ReadUInt32BigEndian(PByte(@LBuf[2]), 0);
  CheckEquals(TEST_UINT32, LFromArray);
  CheckEquals(LFromArray, LFromPointer);
end;

procedure TTestBinaryPrimitives.TestUInt64LittleEndianArrayVsPointer;
var
  LBuf: TBytes;
  LFromArray, LFromPointer: UInt64;
begin
  SetLength(LBuf, 16);
  TBinaryPrimitives.WriteUInt64LittleEndian(LBuf, 4, TEST_UINT64);
  LFromArray := TBinaryPrimitives.ReadUInt64LittleEndian(LBuf, 4);
  LFromPointer := TBinaryPrimitives.ReadUInt64LittleEndian(PByte(@LBuf[4]), 0);
  CheckEquals(TEST_UINT64, LFromArray);
  CheckEquals(LFromArray, LFromPointer);
end;

procedure TTestBinaryPrimitives.TestUInt64BigEndianArrayVsPointer;
var
  LBuf: TBytes;
  LFromArray, LFromPointer: UInt64;
begin
  SetLength(LBuf, 16);
  TBinaryPrimitives.WriteUInt64BigEndian(LBuf, 4, TEST_UINT64);
  LFromArray := TBinaryPrimitives.ReadUInt64BigEndian(LBuf, 4);
  LFromPointer := TBinaryPrimitives.ReadUInt64BigEndian(PByte(@LBuf[4]), 0);
  CheckEquals(TEST_UINT64, LFromArray);
  CheckEquals(LFromArray, LFromPointer);
end;

procedure TTestBinaryPrimitives.TestUInt32MisalignedPointerRead;
var
  LBuf: TBytes;
  LValue: UInt32;
begin
  SetLength(LBuf, 9);
  LBuf[0] := $AA;
  TBinaryPrimitives.WriteUInt32LittleEndian(LBuf, 1, TEST_UINT32);
  LValue := TBinaryPrimitives.ReadUInt32LittleEndian(PByte(@LBuf[0]), 1);
  CheckEquals(TEST_UINT32, LValue);

  FillChar(LBuf[0], Length(LBuf), 0);
  LBuf[0] := $AA;
  TBinaryPrimitives.WriteUInt32BigEndian(LBuf, 1, TEST_UINT32);
  LValue := TBinaryPrimitives.ReadUInt32BigEndian(PByte(@LBuf[0]), 1);
  CheckEquals(TEST_UINT32, LValue);
end;

procedure TTestBinaryPrimitives.TestCopyUInt32LittleEndianAligned;
var
  LSource, LDest: TBytes;
  LI: Integer;
begin
  SetLength(LSource, 12);
  SetLength(LDest, 12);
  for LI := 0 to 11 do
    LSource[LI] := Byte(LI + 1);
  FillChar(LDest[0], Length(LDest), 0);
  TBinaryPrimitives.CopyUInt32LittleEndian(@LSource[0], 0, @LDest[0], 0, 12);
  for LI := 0 to 11 do
    CheckEquals(LSource[LI], LDest[LI], Format('byte %d', [LI]));
end;

procedure TTestBinaryPrimitives.TestCopyUInt32LittleEndianMisaligned;
var
  LSource, LDest: TBytes;
  LI: Integer;
begin
  SetLength(LSource, 14);
  SetLength(LDest, 14);
  for LI := 0 to 13 do
    LSource[LI] := Byte(LI + $10);
  FillChar(LDest[0], Length(LDest), 0);
  TBinaryPrimitives.CopyUInt32LittleEndian(@LSource[0], 1, @LDest[0], 2, 8);
  for LI := 0 to 7 do
    CheckEquals(LSource[1 + LI], LDest[2 + LI], Format('byte %d', [LI]));
end;

procedure TTestBinaryPrimitives.TestCopyUInt32BigEndianWireFormat;
var
  LSource, LDest: TBytes;
  LWireValue, LNativeValue: UInt32;
begin
  SetLength(LSource, 4);
  SetLength(LDest, 4);
  LWireValue := UInt32($11223344);
  TBinaryPrimitives.WriteUInt32BigEndian(LSource, 0, LWireValue);
  FillChar(LDest[0], 4, 0);
  TBinaryPrimitives.CopyUInt32BigEndian(@LSource[0], 0, @LDest[0], 0, 4);
  // On LE hosts, CopyUInt32BigEndian byte-reverses into dest; LE read recovers the wire value
  LNativeValue := TBinaryPrimitives.ReadUInt32LittleEndian(LDest, 0);
  CheckEquals(LWireValue, LNativeValue);
end;

procedure TTestBinaryPrimitives.TestCopyUInt64LittleEndianAligned;
var
  LSource, LDest: TBytes;
  LI: Integer;
begin
  SetLength(LSource, 16);
  SetLength(LDest, 16);
  for LI := 0 to 15 do
    LSource[LI] := Byte(LI + $20);
  FillChar(LDest[0], Length(LDest), 0);
  TBinaryPrimitives.CopyUInt64LittleEndian(@LSource[0], 0, @LDest[0], 0, 16);
  for LI := 0 to 15 do
    CheckEquals(LSource[LI], LDest[LI], Format('byte %d', [LI]));
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestBinaryPrimitives);
{$ELSE}
  RegisterTest(TTestBinaryPrimitives.Suite);
{$ENDIF FPC}

end.
