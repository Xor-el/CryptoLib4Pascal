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
  ///   Shared scalar helpers for bulk block-cipher mode
  ///   implementations: 16 / 64 / 128-byte triple-XOR primitives plus
  ///   the IBulkBlockCipher / IBulkBlockCipherMode capability probes.
  /// </summary>
  TBlockCipherBulkUtilities = class sealed(TObject)
  public
    /// <summary>Scalar triple-XOR of 16 bytes:
    /// PDst^ := PSrcA^ xor PSrcB^.</summary>
    class procedure Xor16Bytes(PDst, PSrcA, PSrcB: PByte); static;

    /// <summary>
    ///   Scalar triple-XOR of 64 bytes. Intentionally NOT inline: FPC
    ///   3.2 for i386 miscompiles the equivalent inline loop inside
    ///   the pipelined GCM steps at -O3 (stale %edx reused as the loop
    ///   index), so the CALL boundary is load-bearing.
    /// </summary>
    class procedure Xor64Bytes(PDst, PSrcA, PSrcB: PByte); static;

    /// <summary>128-byte counterpart of Xor64Bytes. Same non-inline
    /// constraint applies.</summary>
    class procedure Xor128Bytes(PDst, PSrcA, PSrcB: PByte); static;

    /// <summary>
    ///   Probe ACipher for IBulkBlockCipher. ABulk is nil on False so
    ///   the caller can blindly assign into an existing field.
    /// </summary>
    class function TryResolveBulkCipher(const ACipher: IBlockCipher;
      out ABulk: IBulkBlockCipher): Boolean; static;

    /// <summary>
    ///   Mode-side sibling of TryResolveBulkCipher; probes AMode for
    ///   IBulkBlockCipherMode. ABulkMode is nil on False.
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
