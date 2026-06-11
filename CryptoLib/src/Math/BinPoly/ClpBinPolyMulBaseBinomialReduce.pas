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
  ClpIBinPolyMul,
  ClpBinPolyMulBase;

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
      procedure Reduce(const Att: TCryptoLibUInt64Array; AttOff: Int32;
        const Az: TCryptoLibUInt64Array; AzOff: Int32);
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
      procedure Reduce(const Att: TCryptoLibUInt64Array; AttOff: Int32;
        const Az: TCryptoLibUInt64Array; AzOff: Int32);
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

procedure TBinPolyMulBaseBinomialReduce.TUnaligned.Reduce(const Att: TCryptoLibUInt64Array; AttOff: Int32;
  const Az: TCryptoLibUInt64Array; AzOff: Int32);
var
  LN: Int32;
  LLast: Int32;
  LSize: Int32;
  LExcessBits: Int32;
  LC: UInt64;
begin
  LN := FN;
  {$IFDEF DEBUG}
  TBinPolyMulBase.DebugAssertReducePreconditions(LN, Att, AttOff);
  {$ENDIF}

  LLast := LN shr 6;
  LSize := LLast + 1;
  LExcessBits := -LN and 63;

  LC := TNat.ShiftUpBitsXor64(LSize, Att, AttOff + LSize, LExcessBits, Att[AttOff + LLast],
    Att, AttOff, Az, AzOff);
{$IFDEF DEBUG}
  System.Assert(LC = 0);
{$ENDIF}
  Az[AzOff + LLast] := Az[AzOff + LLast] and (UInt64.MaxValue shr LExcessBits);
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

procedure TBinPolyMulBaseBinomialReduce.TAligned.Reduce(const Att: TCryptoLibUInt64Array; AttOff: Int32;
  const Az: TCryptoLibUInt64Array; AzOff: Int32);
var
  LN: Int32;
  LSize: Int32;
begin
  LN := FN;
  {$IFDEF DEBUG}
  TBinPolyMulBase.DebugAssertReducePreconditions(LN, Att, AttOff);
  {$ENDIF}

  LSize := TBitOperations.Asr32(LN, 6);
  TNat.Xor64(LSize, Att, AttOff, Att, AttOff + LSize, Az, AzOff);
end;

end.
