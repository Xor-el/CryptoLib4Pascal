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

unit ClpBinPolyScalarLarge;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpIBinPolyMul,
  ClpBinPolyMulBase,
  ClpArrayUtilities,
  ClpBinPolyScalarKernels;

type
  /// <summary>
  /// Scalar <c>IBinPolyMul</c> implementation for sizes at or above
  /// <c>KaratsubaCutoff</c>. Implements multiplication via in-class Karatsuba recursion whose
  /// leaf is the scalar 16-entry-table multiply. The class name reflects the dispatch criterion
  /// (large operand size); the algorithm inside is Karatsuba.
  /// </summary>
  /// <remarks>
  /// The recursion's scratch buffer is allocated per call and threaded through as a parameter,
  /// so instances are safe to use concurrently.
  /// </remarks>
  TBinPolyScalarLarge = class sealed(TBinPolyMulBase)
  strict private
    class function KaratsubaScratchSize(ALen: Int32): Int32; static;
    class procedure ImplLeaf(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZz: TCryptoLibUInt64Array; AZzOff: Int32); static;
    class procedure ImplKaratsuba(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZz: TCryptoLibUInt64Array; AZzOff: Int32;
      const AScratch: TCryptoLibUInt64Array; AScratchOff: Int32); static;
  public
    /// <summary>
    /// Karatsuba cutoff (in machine words). Below this, the table-based
    /// <c>TBinPolyScalarKernels.ImplMul</c> leaf is called directly; above it,
    /// <c>ImplKaratsuba</c> recurses by halving. Must be &gt;= 2 for recursion termination.
    /// </summary>
    const
      KaratsubaCutoff = 8;

    constructor Create(AN: Int32; const AReduce: IBinPolyReduce);
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32); override;
  end;

implementation

{ TBinPolyScalarLarge }

constructor TBinPolyScalarLarge.Create(AN: Int32; const AReduce: IBinPolyReduce);
begin
  inherited Create(AN, AReduce);
end;

procedure TBinPolyScalarLarge.Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  Ltt: TCryptoLibUInt64Array;
  LScratch: TCryptoLibUInt64Array;
  LScratchSize: Int32;
begin
  LScratchSize := KaratsubaScratchSize(FSize);
  SetLength(Ltt, FSizeExt);
  SetLength(LScratch, LScratchSize);
  try
    ImplKaratsuba(FSize, AX, AXOff, AY, AYOff, Ltt, 0, LScratch, 0);
    FReduce.Reduce(Ltt, 0, AZ, AZOff);
  finally
    TArrayUtilities.Fill<UInt64>(LScratch, 0, LScratchSize, 0);
    TArrayUtilities.Fill<UInt64>(Ltt, 0, FSizeExt, 0);
  end;
end;

class function TBinPolyScalarLarge.KaratsubaScratchSize(ALen: Int32): Int32;
var
  LTotal: Int32;
  LLen: Int32;
begin
{$IFDEF DEBUG}
  System.Assert(KaratsubaCutoff >= 2);
{$ENDIF}
  LTotal := 0;
  LLen := ALen;
  while LLen >= KaratsubaCutoff do
  begin
    LLen := (LLen + 1) shr 1;
    LTotal := LTotal + LLen;
  end;
  Result := LTotal shl 1;
end;

class procedure TBinPolyScalarLarge.ImplLeaf(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZz: TCryptoLibUInt64Array; AZzOff: Int32);
begin
  TBinPolyScalarKernels.ImplMul(ALen, AX, AXOff, AY, AYOff, AZz, AZzOff);
end;

class procedure TBinPolyScalarLarge.ImplKaratsuba(ALen: Int32; const AX: TCryptoLibUInt64Array; AXOff: Int32;
  const AY: TCryptoLibUInt64Array; AYOff: Int32; const AZz: TCryptoLibUInt64Array; AZzOff: Int32;
  const AScratch: TCryptoLibUInt64Array; AScratchOff: Int32);
var
  LM: Int32;
  LN: Int32;
  LNx2: Int32;
  LMx2: Int32;
  LZMidOffset: Int32;
  LChildScratchOff: Int32;
  LI: Int32;
  LU: UInt64;
begin
  if ALen < KaratsubaCutoff then
  begin
    ImplLeaf(ALen, AX, AXOff, AY, AYOff, AZz, AZzOff);
    Exit;
  end;

  if (ALen and 1) = 0 then
  begin
    LM := ALen shr 1;
    LZMidOffset := AScratchOff;
    LChildScratchOff := AScratchOff + 2 * LM;

    for LI := 0 to LM - 1 do
    begin
      AZz[AZzOff + LI] := AX[AXOff + LI] xor AX[AXOff + LM + LI];
      AZz[AZzOff + LM + LI] := AY[AYOff + LI] xor AY[AYOff + LM + LI];
    end;

    ImplKaratsuba(LM, AZz, AZzOff, AZz, AZzOff + LM, AScratch, LZMidOffset, AScratch, LChildScratchOff);
    ImplKaratsuba(LM, AX, AXOff, AY, AYOff, AZz, AZzOff, AScratch, LChildScratchOff);
    ImplKaratsuba(LM, AX, AXOff + LM, AY, AYOff + LM, AZz, AZzOff + ALen, AScratch, LChildScratchOff);

    for LI := 0 to LM - 1 do
    begin
      LU := AZz[AZzOff + LM + LI] xor AZz[AZzOff + ALen + LI];
      AZz[AZzOff + LM + LI] := LU xor AZz[AZzOff + LI] xor AScratch[LZMidOffset + LI];
      AZz[AZzOff + ALen + LI] := LU xor AZz[AZzOff + ALen + LM + LI] xor AScratch[LZMidOffset + LM + LI];
    end;
  end
  else
  begin
    LN := ALen shr 1;
    LM := LN + 1;
    LNx2 := LN shl 1;
    LMx2 := LM shl 1;
    LZMidOffset := AScratchOff;
    LChildScratchOff := AScratchOff + LMx2;

    for LI := 0 to LN - 1 do
    begin
      AZz[AZzOff + LI] := AX[AXOff + LI] xor AX[AXOff + LN + LI];
      AZz[AZzOff + LM + LI] := AY[AYOff + LI] xor AY[AYOff + LN + LI];
    end;
    AZz[AZzOff + LN] := AX[AXOff + LNx2];
    AZz[AZzOff + LM + LN] := AY[AYOff + LNx2];

    ImplKaratsuba(LM, AZz, AZzOff, AZz, AZzOff + LM, AScratch, LZMidOffset, AScratch, LChildScratchOff);
    ImplKaratsuba(LN, AX, AXOff, AY, AYOff, AZz, AZzOff, AScratch, LChildScratchOff);
    ImplKaratsuba(LM, AX, AXOff + LN, AY, AYOff + LN, AZz, AZzOff + LNx2, AScratch, LChildScratchOff);

    for LI := 0 to LN - 1 do
    begin
      LU := AZz[AZzOff + LN + LI] xor AZz[AZzOff + LNx2 + LI];
      AZz[AZzOff + LN + LI] := LU xor AZz[AZzOff + LI] xor AScratch[LZMidOffset + LI];
      AZz[AZzOff + LNx2 + LI] := LU xor AZz[AZzOff + LNx2 + LN + LI] xor AScratch[LZMidOffset + LN + LI];
    end;

    AZz[AZzOff + LN + LNx2] := AZz[AZzOff + LN + LNx2] xor AScratch[LZMidOffset + LNx2] xor AZz[AZzOff + LNx2 + LNx2];
    AZz[AZzOff + LN + LNx2 + 1] := AZz[AZzOff + LN + LNx2 + 1] xor AScratch[LZMidOffset + LNx2 + 1] xor AZz[AZzOff + LNx2 + LNx2 + 1];
  end;
end;

end.
