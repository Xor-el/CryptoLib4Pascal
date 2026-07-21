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

unit ClpBinPolyMulBase;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpInterleave,
  ClpIBinPolyMul;

type
  /// <summary>
  /// Abstract base for <c>IBinPolyMul</c> implementations. Holds the shared state
  /// (<c>FN</c>, <c>FSize</c>, <c>FSizeExt</c>, <c>FReduce</c>) and the squaring helpers
  /// (<c>Square</c>, <c>SquareN</c>). <c>Multiply</c> is abstract and is supplied by
  /// concrete subclasses.
  /// </summary>
  /// <remarks>
  /// <para>
  /// Polynomials are stored bit-packed in <c>TCryptoLibUInt64Array</c> with little-endian
  /// word order. The caller is responsible for size-checking buffer arguments.
  /// </para>
  /// <para>
  /// <c>FSizeExt</c> is always <c>2 * FSize</c>. An extended product of two n-bit polynomials
  /// fits in <c>2*n - 1</c> bits, so the topmost limb of the extended buffer may carry only
  /// a few bits; the wasted single limb is preferable to tighter bound tracking.
  /// </para>
  /// <para>
  /// The leaf multiply (below the Karatsuba recursion cutoff) is arbitrary-degree Karatsuba
  /// over UInt64 words with a 16-entry-table 1x1 multiply.
  /// </para>
  /// </remarks>
  TBinPolyMulBase = class abstract(TInterfacedObject, IBinPolyMul)
  public const
    /// <summary>
    /// Stack-scratch capacity in limbs for extended-product buffers
    /// (2 * Size); covers every field up to GF(2^2048). Larger custom
    /// fields fall back to a heap buffer.
    /// </summary>
    MaxStackExtLimbs = 64;
  protected
    FN: Int32;
    FSize: Int32;
    FSizeExt: Int32;
    FReduce: IBinPolyReduce;
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    /// <summary>
    /// Expand FSize limbs at AX[AXOff] into the 2*FSize-limb carryless square
    /// at Att (bits spread to even positions). Default is the scalar
    /// bit-interleave; SIMD subclasses override with a carryless-multiply
    /// square.
    /// </summary>
    procedure ExpandSquare(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      Att: PUInt64); virtual;
  public
    function GetN: Int32;
    function GetSize: Int32;
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); virtual; abstract;
    procedure Square(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32);
    procedure SquareN(const AX: TCryptoLibUInt64Array; AXOff: Int32; AN: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32);
    property N: Int32 read GetN;
    property Size: Int32 read GetSize;
  public
    /// <summary>Decompose a bit position into its word index and bit offset within the word.</summary>
    class procedure BitPos(ABit: Int32; out AW, ABitShift: Int32); static;
    {$IFDEF DEBUG}
    /// <summary>
    /// Verify the per-call input contract of <c>IBinPolyReduce.Reduce</c>: <c>Att</c> must
    /// contain no bits at positions above <c>2n - 2</c>. Fully elided in release builds.
    /// </summary>
    class procedure DebugAssertReducePreconditions(AN: Int32;
      Att: PUInt64); static;
    {$ENDIF}
  end;

implementation

{ TBinPolyMulBase }

constructor TBinPolyMulBase.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create;
  FN := AN;
  FSize := (AN + 63) shr 6;
  FSizeExt := FSize * 2;
  FReduce := AReduce;
end;

function TBinPolyMulBase.GetN: Int32;
begin
  Result := FN;
end;

function TBinPolyMulBase.GetSize: Int32;
begin
  Result := FSize;
end;

procedure TBinPolyMulBase.ExpandSquare(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  Att: PUInt64);
begin
  TInterleave.Expand64To128(AX, AXOff, FSize, Att);
end;

procedure TBinPolyMulBase.Square(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  LStk: array [0 .. MaxStackExtLimbs - 1] of UInt64;
  LHeap: TCryptoLibUInt64Array;
  Ltt: PUInt64;
begin
  // Scratch on the stack for every real field size; heap only for outsized
  // custom fields. Wiped either way (the extended square is key-dependent).
  if FSizeExt <= MaxStackExtLimbs then
    Ltt := @LStk[0]
  else
  begin
    SetLength(LHeap, FSizeExt);
    Ltt := @LHeap[0];
  end;
  try
    ExpandSquare(AX, AXOff, Ltt);
    FReduce.Reduce(Ltt, @AZ[AZOff]);
  finally
    FillChar(Ltt^, FSizeExt * System.SizeOf(UInt64), 0);
  end;
end;

procedure TBinPolyMulBase.SquareN(const AX: TCryptoLibUInt64Array; AXOff: Int32; AN: Int32;
  const AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  LStk: array [0 .. MaxStackExtLimbs - 1] of UInt64;
  LHeap: TCryptoLibUInt64Array;
  Ltt: PUInt64;
  LI: Int32;
begin
  if AN < 1 then
    raise EArgumentOutOfRangeException.Create('n must be positive');

  if FSizeExt <= MaxStackExtLimbs then
    Ltt := @LStk[0]
  else
  begin
    SetLength(LHeap, FSizeExt);
    Ltt := @LHeap[0];
  end;
  try
    ExpandSquare(AX, AXOff, Ltt);
    FReduce.Reduce(Ltt, @AZ[AZOff]);

    for LI := AN - 1 downto 1 do
    begin
      ExpandSquare(AZ, AZOff, Ltt);
      FReduce.Reduce(Ltt, @AZ[AZOff]);
    end;
  finally
    FillChar(Ltt^, FSizeExt * System.SizeOf(UInt64), 0);
  end;
end;

class procedure TBinPolyMulBase.BitPos(ABit: Int32; out AW, ABitShift: Int32);
begin
  AW := ABit shr 6;
  ABitShift := ABit and 63;
end;

{$IFDEF DEBUG}
class procedure TBinPolyMulBase.DebugAssertReducePreconditions(AN: Int32;
  Att: PUInt64);
var
  LSizeExt: Int32;
  LSlackBit: Int32;
  LSlackWord: Int32;
  LSlack: UInt64;
  LI: Int32;
begin
  LSizeExt := ((AN + 63) shr 6) shl 1;
  LSlackBit := 2 * AN - 1;
  LSlackWord := LSlackBit shr 6;
  LSlack := Att[LSlackWord] shr (LSlackBit and 63);
  for LI := LSlackWord + 1 to LSizeExt - 1 do
    LSlack := LSlack or Att[LI];
  System.Assert(LSlack = 0,
    'IBinPolyReduce.Reduce: tt has bits set above position 2n-2; slack must be zero.');
end;
{$ENDIF}

end.
