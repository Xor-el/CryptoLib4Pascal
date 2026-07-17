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

unit ClpPoly1305ArmBackend;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCpuFeatures,
  ClpPoly1305State,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// ARM (NEON) SIMD backend for Poly1305: owns the r/r^2 power-table
  /// builder and the 2-way bulk kernel (body in
  /// <c>Include\Simd\Poly1305\</c>), sharing the radix-2^26 field
  /// arithmetic and power-table layout with the x86 2-way kernel.
  /// Compiles on every target - when built without AArch64 SIMD
  /// <c>TryInitPowerTable</c> returns <c>False</c> (leaving the caller on
  /// the scalar path) and <c>ProcessBulk</c> consumes zero blocks.
  /// </summary>
  TPoly1305ArmBackend = class sealed
  public
    /// <summary>
    /// If the NEON tier is available, (re)allocate and populate
    /// <paramref name="APowTable"/> with the precomputed power table for the
    /// r currently in <paramref name="AState"/>, and return True. Otherwise
    /// leave <paramref name="APowTable"/> untouched and return False.
    /// </summary>
    class function TryInitPowerTable(var APowTable: TCryptoLibByteArray;
      const AState: TPoly1305State): Boolean; static;
    /// <summary>
    /// Process the leading lane-multiple of <paramref name="ANumBlocks"/>
    /// 16-byte blocks with the NEON kernel and return the number of blocks
    /// consumed (a multiple of 2). Returns 0 - leaving the whole batch to
    /// the caller's scalar path - when no power table is present, fewer than
    /// 2 blocks are available, or the build has no AArch64 SIMD.
    /// </summary>
    class function ProcessBulk(var AState: TPoly1305State; APowTable: PByte;
      const ABuf: TCryptoLibByteArray; AOff, ANumBlocks: Int32): Int32; static;
  end;

implementation

{$IFDEF CRYPTOLIB_AARCH64_ASM}

procedure Poly1305MulLimbs(out AProduct: array of UInt32;
  const ALhs, ARhs: array of UInt32);
var
  LS1, LS2, LS3, LS4: UInt32;
  LD0, LD1, LD2, LD3, LD4: UInt64;
begin
  LS1 := ARhs[1] * 5;
  LS2 := ARhs[2] * 5;
  LS3 := ARhs[3] * 5;
  LS4 := ARhs[4] * 5;

  LD0 := UInt64(ALhs[0]) * ARhs[0] + UInt64(ALhs[1]) * LS4 +
    UInt64(ALhs[2]) * LS3 + UInt64(ALhs[3]) * LS2 + UInt64(ALhs[4]) * LS1;
  LD1 := UInt64(ALhs[0]) * ARhs[1] + UInt64(ALhs[1]) * ARhs[0] +
    UInt64(ALhs[2]) * LS4 + UInt64(ALhs[3]) * LS3 + UInt64(ALhs[4]) * LS2;
  LD2 := UInt64(ALhs[0]) * ARhs[2] + UInt64(ALhs[1]) * ARhs[1] +
    UInt64(ALhs[2]) * ARhs[0] + UInt64(ALhs[3]) * LS4 + UInt64(ALhs[4]) * LS3;
  LD3 := UInt64(ALhs[0]) * ARhs[3] + UInt64(ALhs[1]) * ARhs[2] +
    UInt64(ALhs[2]) * ARhs[1] + UInt64(ALhs[3]) * ARhs[0] +
    UInt64(ALhs[4]) * LS4;
  LD4 := UInt64(ALhs[0]) * ARhs[4] + UInt64(ALhs[1]) * ARhs[3] +
    UInt64(ALhs[2]) * ARhs[2] + UInt64(ALhs[3]) * ARhs[1] +
    UInt64(ALhs[4]) * ARhs[0];

  AProduct[0] := UInt32(LD0) and $3FFFFFF;
  LD1 := LD1 + (LD0 shr 26);
  AProduct[1] := UInt32(LD1) and $3FFFFFF;
  LD2 := LD2 + (LD1 shr 26);
  AProduct[2] := UInt32(LD2) and $3FFFFFF;
  LD3 := LD3 + (LD2 shr 26);
  AProduct[3] := UInt32(LD3) and $3FFFFFF;
  LD4 := LD4 + (LD3 shr 26);
  AProduct[4] := UInt32(LD4) and $3FFFFFF;
  AProduct[0] := AProduct[0] + UInt32(LD4 shr 26) * 5;
  AProduct[1] := AProduct[1] + (AProduct[0] shr 26);
  AProduct[0] := AProduct[0] and $3FFFFFF;
end;

procedure Poly1305NeonInitPowerTable(var APowTable: TCryptoLibByteArray;
  const AState: TPoly1305State);
const
  TableSize = Int32(160);
type
  TPowTableLayout = array[0..9, 0..3] of UInt32;
  PPowTableLayout = ^TPowTableLayout;
var
  LTbl: PPowTableLayout;
  Lr1, Lr2: array[0..4] of UInt32;
  LIdx, LRow, LJ: Int32;
begin
  System.SetLength(APowTable, TableSize);
  LTbl := PPowTableLayout(APowTable);

  Lr1[0] := AState.R0;
  Lr1[1] := AState.R1;
  Lr1[2] := AState.R2;
  Lr1[3] := AState.R3;
  Lr1[4] := AState.R4;

  Poly1305MulLimbs(Lr2, Lr1, Lr1);

  for LIdx := 0 to 4 do
  begin
    LTbl^[LIdx, 0] := Lr2[LIdx];
    LTbl^[LIdx, 1] := Lr2[LIdx];
    LTbl^[LIdx, 2] := Lr2[LIdx];
    LTbl^[LIdx, 3] := Lr1[LIdx];
  end;

  for LRow := 5 to 8 do
  begin
    LJ := LRow - 4; // 1..4
    LTbl^[LRow, 0] := Lr2[LJ] * 5;
    LTbl^[LRow, 1] := Lr2[LJ] * 5;
    LTbl^[LRow, 2] := Lr2[LJ] * 5;
    LTbl^[LRow, 3] := Lr1[LJ] * 5;
  end;

  for LIdx := 0 to 3 do
    LTbl^[9, LIdx] := 0;
end;

// NEON 2-way bulk kernel (r/r^2 power table, 32-byte stride).
procedure Poly1305BlocksBulkNeonCore(ACtx, APowTable, AInp: PByte;
  ALen: NativeUInt; APad: Int32);
{$I ..\..\Include\Simd\Common\ClpSimdProc5Begin_aarch64.inc}
{$I ..\..\Include\Simd\Poly1305\Poly1305BlocksBulkNeon_aarch64.inc}
end;

{$ENDIF CRYPTOLIB_AARCH64_ASM}

{ TPoly1305ArmBackend }

class function TPoly1305ArmBackend.TryInitPowerTable(
  var APowTable: TCryptoLibByteArray; const AState: TPoly1305State): Boolean;
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  if TCpuFeatures.Arm.HasNEON() then
  begin
    Poly1305NeonInitPowerTable(APowTable, AState);
    Exit(True);
  end;
{$ENDIF}
  Result := False;
end;

class function TPoly1305ArmBackend.ProcessBulk(var AState: TPoly1305State;
  APowTable: PByte; const ABuf: TCryptoLibByteArray;
  AOff, ANumBlocks: Int32): Int32;
{$IFDEF CRYPTOLIB_AARCH64_ASM}
var
  LSimdBlocks: Int32;
{$ENDIF}
begin
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  if (APowTable = nil) then
    Exit(0);
  if TCpuFeatures.Arm.HasNEON() then
  begin
    if ANumBlocks < 2 then
      Exit(0);
    LSimdBlocks := ANumBlocks and not 1;
    Poly1305BlocksBulkNeonCore(@AState, APowTable, @ABuf[AOff],
      NativeUInt(LSimdBlocks) * 16, 1);
    Exit(LSimdBlocks);
  end;
{$ENDIF}
  Result := 0;
end;

end.
