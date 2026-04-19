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

unit ClpBlockCipherBulkUtilities;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIBlockCipherMode,
  ClpIBulkBlockCipher,
  ClpIBulkBlockCipherMode;

type
  /// <summary>
  /// Shared scalar helpers for bulk block-cipher mode implementations.
  /// Hosts the 16/64/128-byte triple-XOR primitives used by the fused /
  /// pipelined batch routines in SIC, GCM, GCM-SIV, OCB, CFB and CTS,
  /// plus the IBulkBlockCipher / IBulkBlockCipherMode capability probes
  /// that every bulk-aware mode re-runs on Init.
  /// </summary>
  TBlockCipherBulkUtilities = class sealed(TObject)
  public
    /// <summary>Scalar triple-XOR of 16 bytes (2 x UInt64):
    /// PDst^ := PSrcA^ xor PSrcB^. Declared as a static class procedure --
    /// and deliberately NOT inline -- so that each call establishes a fresh
    /// stack frame with its own register allocation, matching the 64- and
    /// 128-byte siblings. Used by OCB for its 16-byte offset / checksum /
    /// HASH folds.</summary>
    class procedure Xor16Bytes(PDst, PSrcA, PSrcB: PByte); static;

    /// <summary>Scalar triple-XOR of 64 bytes (8 x UInt64):
    /// PDst^ := PSrcA^ xor PSrcB^. Declared as a static class procedure --
    /// and deliberately NOT inline -- so that each call establishes a fresh
    /// stack frame with its own register allocation. FPC 3.2 for i386
    /// miscompiles the equivalent inline loop inside the pipelined GCM
    /// steps at -O3, rewriting `LI := LI + 1` to `addl $1, LI_mem` and then
    /// using a stale `%edx` (left over from an earlier caller-side load)
    /// as if it held LI. The CALL boundary forces the caller to spill and
    /// dodges the bug.</summary>
    class procedure Xor64Bytes(PDst, PSrcA, PSrcB: PByte); static;

    /// <summary>128-byte (16 x UInt64) counterpart of Xor64Bytes, used by
    /// the 8-block pipelines in GCM and the CTR bulk step in SIC. See
    /// Xor64Bytes for why this must remain a real (non-inline) call.</summary>
    class procedure Xor128Bytes(PDst, PSrcA, PSrcB: PByte); static;

    /// <summary>
    /// Probe ACipher for the IBulkBlockCipher capability. On True,
    /// ABulk points at the resolved interface; on False, ABulk is
    /// guaranteed nil so the caller can store the result back into a
    /// field that was populated on a previous Init.
    /// Centralises the ~4-line "re-probe on Init" ritual used by every
    /// bulk-aware mode (SIC, CBC, ECB, CFB, OCB, GCM, GCM-SIV, EAX, CCM).
    /// </summary>
    class function TryResolveBulkCipher(const ACipher: IBlockCipher;
      out ABulk: IBulkBlockCipher): Boolean; static;

    /// <summary>
    /// Mode-side sibling of TryResolveBulkCipher: probe AMode for the
    /// IBulkBlockCipherMode capability. Clears ABulkMode on False so the
    /// caller can blindly assign without a preceding nil-out.
    /// </summary>
    class function TryResolveBulkCipherMode(const AMode: IBlockCipherMode;
      out ABulkMode: IBulkBlockCipherMode): Boolean; static;
  end;

implementation

{ TBlockCipherBulkUtilities }

class procedure TBlockCipherBulkUtilities.Xor16Bytes(PDst, PSrcA,
  PSrcB: PByte);
begin
  PUInt64(PDst)^ := PUInt64(PSrcA)^ xor PUInt64(PSrcB)^;
  PUInt64(PDst + 8)^ := PUInt64(PSrcA + 8)^ xor PUInt64(PSrcB + 8)^;
end;

class procedure TBlockCipherBulkUtilities.Xor64Bytes(PDst, PSrcA,
  PSrcB: PByte);
var
  LI: Int32;
begin
  for LI := 0 to 7 do
    PUInt64(PDst + LI * 8)^ := PUInt64(PSrcA + LI * 8)^ xor
      PUInt64(PSrcB + LI * 8)^;
end;

class procedure TBlockCipherBulkUtilities.Xor128Bytes(PDst, PSrcA,
  PSrcB: PByte);
var
  LI: Int32;
begin
  for LI := 0 to 15 do
    PUInt64(PDst + LI * 8)^ := PUInt64(PSrcA + LI * 8)^ xor
      PUInt64(PSrcB + LI * 8)^;
end;

class function TBlockCipherBulkUtilities.TryResolveBulkCipher(
  const ACipher: IBlockCipher; out ABulk: IBulkBlockCipher): Boolean;
begin
  ABulk := nil;
  Result := (ACipher <> nil) and Supports(ACipher, IBulkBlockCipher, ABulk);
end;

class function TBlockCipherBulkUtilities.TryResolveBulkCipherMode(
  const AMode: IBlockCipherMode; out ABulkMode: IBulkBlockCipherMode): Boolean;
begin
  ABulkMode := nil;
  Result := (AMode <> nil) and Supports(AMode, IBulkBlockCipherMode, ABulkMode);
end;

end.
