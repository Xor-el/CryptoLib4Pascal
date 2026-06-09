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
  ClpArrayUtilities,
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
  protected
    FN: Int32;
    FSize: Int32;
    FSizeExt: Int32;
    FReduce: IBinPolyReduce;
    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
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
      const Att: TCryptoLibUInt64Array; AttOff: Int32); static;
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

procedure TBinPolyMulBase.Square(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  Ltt: TCryptoLibUInt64Array;
begin
  SetLength(Ltt, FSizeExt);
  try
    TInterleave.Expand64To128(AX, AXOff, FSize, Ltt, 0);
    FReduce.Reduce(Ltt, 0, AZ, AZOff);
  finally
    TArrayUtilities.Fill<UInt64>(Ltt, 0, FSizeExt, 0);
  end;
end;

procedure TBinPolyMulBase.SquareN(const AX: TCryptoLibUInt64Array; AXOff: Int32; AN: Int32;
  const AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  Ltt: TCryptoLibUInt64Array;
  LI: Int32;
begin
  if AN < 1 then
    raise EArgumentOutOfRangeException.Create('n must be positive');

  SetLength(Ltt, FSizeExt);
  try
    TInterleave.Expand64To128(AX, AXOff, FSize, Ltt, 0);
    FReduce.Reduce(Ltt, 0, AZ, AZOff);

    for LI := AN - 1 downto 1 do
    begin
      TInterleave.Expand64To128(AZ, AZOff, FSize, Ltt, 0);
      FReduce.Reduce(Ltt, 0, AZ, AZOff);
    end;
  finally
    TArrayUtilities.Fill<UInt64>(Ltt, 0, FSizeExt, 0);
  end;
end;

class procedure TBinPolyMulBase.BitPos(ABit: Int32; out AW, ABitShift: Int32);
begin
  AW := ABit shr 6;
  ABitShift := ABit and 63;
end;

{$IFDEF DEBUG}
class procedure TBinPolyMulBase.DebugAssertReducePreconditions(AN: Int32;
  const Att: TCryptoLibUInt64Array; AttOff: Int32);
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
  LSlack := Att[AttOff + LSlackWord] shr (LSlackBit and 63);
  for LI := LSlackWord + 1 to LSizeExt - 1 do
    LSlack := LSlack or Att[AttOff + LI];
  System.Assert(LSlack = 0,
    'IBinPolyReduce.Reduce: tt has bits set above position 2n-2; slack must be zero.');
end;
{$ENDIF}

end.
