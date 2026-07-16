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

unit ClpBinPolyMulBaseBinomialReduce;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpNat,
  ClpBitOperations,
  ClpBinPolyMulBase,
  ClpIBinPolyMul;

type
  /// <summary>
  /// Reduction by <c>x^n + 1</c>. The factory selects <c>TUnaligned</c> for the common case
  /// (<c>(n and 63) &lt;&gt; 0</c>, partial top limb) or <c>TAligned</c> for n a multiple of 64
  /// (full top limb, word-aligned fold).
  /// </summary>
  TBinPolyMulBaseBinomialReduce = class
  public
    type
    /// <summary>
    /// Sub-case for <c>(n and 63) &lt;&gt; 0</c>: the top result limb is partial. Folds the high
    /// half up by <c>excessBits = (-n) and 63</c> and masks the partial top limb.
    /// </summary>
    TUnaligned = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
    public
      constructor Create(AN: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;

    /// <summary>
    /// Sub-case for n a multiple of 64. The ring period is word-aligned, so <c>x^n = 1</c>
    /// folds limb-for-limb with no shift or mask: <c>Az = low xor high</c> over
    /// <c>Size = n div 64</c> limbs.
    /// </summary>
    TAligned = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
    public
      constructor Create(AN: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
  public
    /// <summary>Select a binomial reducer for bit length <paramref name="AN"/>.</summary>
    class function Create(AN: Int32): IBinPolyReduce; static;
  end;

implementation

{ TBinPolyMulBaseBinomialReduce }

class function TBinPolyMulBaseBinomialReduce.Create(AN: Int32): IBinPolyReduce;
begin
  if (AN and 63) = 0 then
    Result := TBinPolyMulBaseBinomialReduce.TAligned.Create(AN)
  else
    Result := TBinPolyMulBaseBinomialReduce.TUnaligned.Create(AN);
end;

{ TBinPolyMulBaseBinomialReduce.TUnaligned }

constructor TBinPolyMulBaseBinomialReduce.TUnaligned.Create(AN: Int32);
begin
  inherited Create;
  FN := AN;
{$IFDEF DEBUG}
  System.Assert((AN and 63) <> 0);
{$ENDIF}
end;

procedure TBinPolyMulBaseBinomialReduce.TUnaligned.Reduce(Att: PUInt64; Az: PUInt64);
var
  LN: Int32;
  LLast: Int32;
  LSize: Int32;
  LExcessBits: Int32;
  LI: Int32;
  LC, LXi: UInt64;
begin
  LN := FN;
  {$IFDEF DEBUG}
  TBinPolyMulBase.DebugAssertReducePreconditions(LN, Att);
  {$ENDIF}

  LLast := LN shr 6;
  LSize := LLast + 1;
  LExcessBits := -LN and 63;

  // Shift the upper half up by LExcessBits (carry seeded from Att[LLast])
  // and xor with the lower half into Az.
  LC := Att[LLast];
  for LI := 0 to LSize - 1 do
  begin
    LXi := Att[LSize + LI];
    Az[LI] := ((LXi shl LExcessBits) or
      TBitOperations.NegativeRightShift64(LC, -LExcessBits)) xor Att[LI];
    LC := LXi;
  end;
{$IFDEF DEBUG}
  System.Assert(TBitOperations.NegativeRightShift64(LC, -LExcessBits) = 0);
{$ENDIF}
  Az[LLast] := Az[LLast] and (UInt64.MaxValue shr LExcessBits);
end;

{ TBinPolyMulBaseBinomialReduce.TAligned }

constructor TBinPolyMulBaseBinomialReduce.TAligned.Create(AN: Int32);
begin
  inherited Create;
  FN := AN;
{$IFDEF DEBUG}
  System.Assert((AN and 63) = 0);
{$ENDIF}
end;

procedure TBinPolyMulBaseBinomialReduce.TAligned.Reduce(Att: PUInt64; Az: PUInt64);
var
  LN: Int32;
  LSize: Int32;
  LI: Int32;
begin
  LN := FN;
  {$IFDEF DEBUG}
  TBinPolyMulBase.DebugAssertReducePreconditions(LN, Att);
  {$ENDIF}

  LSize := TBitOperations.Asr32(LN, 6);
  for LI := 0 to LSize - 1 do
    Az[LI] := Att[LI] xor Att[LSize + LI];
end;

end.
