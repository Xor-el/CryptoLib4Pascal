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

unit ClpBinPolyMulBaseTrinomialReduce;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBitOperations,
  ClpCryptoLibTypes,
  ClpNat,
  ClpIBinPolyMul,
  ClpBinPolyMulBase;

type
  /// <summary>
  /// Trinomial reduction by <c>x^n + x^k + 1</c>. The factory selects one of several
  /// specialised implementations based on <c>(n, k)</c>; each has a streamlined
  /// <c>Reduce</c> body for its case.
  /// </summary>
  /// <remarks>
  /// <para>
  /// Each bit at position <c>p &gt;= n</c> folds via the "+1" tap to position <c>(p - n)</c>
  /// and via the "+x^k" tap to position <c>(p - n + k)</c>. n need not be odd; the
  /// word-at-a-time variants require a partial top limb (<c>(n and 63) &lt;&gt; 0</c>).
  /// </para>
  /// <para>
  /// Factory dispatch branch order is critical — see the implementation comments in
  /// <c>Create</c>. Sub-case naming: A-family (<c>k &lt; 64</c>), B (<c>k</c> a multiple of
  /// 64), C-family (<c>k &gt;= 64</c> with <c>(k and 63) &lt;&gt; 0</c>), D/E (bitwise /
  /// word-aligned edge cases).
  /// </para>
  /// </remarks>
  TBinPolyMulBaseTrinomialReduce = class
  public
    type
    TA = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
      FK: Int32;
    public
      constructor Create(AN: Int32; AK: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
    TA3 = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
      FK: Int32;
    public
      constructor Create(AN: Int32; AK: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
    TA4 = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
      FK: Int32;
    public
      constructor Create(AN: Int32; AK: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
    TA5 = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
      FK: Int32;
    public
      constructor Create(AN: Int32; AK: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
    TA6 = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
      FK: Int32;
    public
      constructor Create(AN: Int32; AK: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
    TA7 = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
      FK: Int32;
    public
      constructor Create(AN: Int32; AK: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
    TA8 = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
      FK: Int32;
    public
      constructor Create(AN: Int32; AK: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
    TB = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
      FK: Int32;
    public
      constructor Create(AN: Int32; AK: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
    TC = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
      FK: Int32;
    public
      constructor Create(AN: Int32; AK: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
    TC5 = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
      FK: Int32;
    public
      constructor Create(AN: Int32; AK: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
    TC6 = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
      FK: Int32;
    public
      constructor Create(AN: Int32; AK: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
    TC7 = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
      FK: Int32;
    public
      constructor Create(AN: Int32; AK: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
    TC8 = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
      FK: Int32;
    public
      constructor Create(AN: Int32; AK: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
    TD = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
      FK: Int32;
    public
      constructor Create(AN: Int32; AK: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
    TE = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
      FK: Int32;
    public
      constructor Create(AN: Int32; AK: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
  public
    /// <summary>Select a trinomial reducer for bit length <paramref name="AN"/> and tap <paramref name="AK"/>.</summary>
    class function Create(AN: Int32; AK: Int32): IBinPolyReduce; static;
  end;

implementation

{ TBinPolyMulBaseTrinomialReduce }

class function TBinPolyMulBaseTrinomialReduce.Create(AN: Int32; AK: Int32): IBinPolyReduce;
begin
  if (AN and 63) = 0 then
  begin
    if (AN - AK >= 64) and ((AK and 63) <> 0) then
      Result := TBinPolyMulBaseTrinomialReduce.TE.Create(AN, AK)
    else
      Result := TBinPolyMulBaseTrinomialReduce.TD.Create(AN, AK);
    Exit;
  end;
  if AN - AK < 64 then
  begin
    Result := TBinPolyMulBaseTrinomialReduce.TD.Create(AN, AK);
    Exit;
  end;
  if AK < 64 then
  begin
    case AN div 32 of
      2: Result := TBinPolyMulBaseTrinomialReduce.TA3.Create(AN, AK);
      3: Result := TBinPolyMulBaseTrinomialReduce.TA4.Create(AN, AK);
      4: Result := TBinPolyMulBaseTrinomialReduce.TA5.Create(AN, AK);
      5: Result := TBinPolyMulBaseTrinomialReduce.TA6.Create(AN, AK);
      6: Result := TBinPolyMulBaseTrinomialReduce.TA7.Create(AN, AK);
      7: Result := TBinPolyMulBaseTrinomialReduce.TA8.Create(AN, AK);
    else
      Result := TBinPolyMulBaseTrinomialReduce.TA.Create(AN, AK);
    end;
    Exit;
  end;
  if (AK and 63) = 0 then
  begin
    Result := TBinPolyMulBaseTrinomialReduce.TB.Create(AN, AK);
    Exit;
  end;
  case AN div 32 of
    4: Result := TBinPolyMulBaseTrinomialReduce.TC5.Create(AN, AK);
    5: Result := TBinPolyMulBaseTrinomialReduce.TC6.Create(AN, AK);
    6: Result := TBinPolyMulBaseTrinomialReduce.TC7.Create(AN, AK);
    7: Result := TBinPolyMulBaseTrinomialReduce.TC8.Create(AN, AK);
  else
    Result := TBinPolyMulBaseTrinomialReduce.TC.Create(AN, AK);
  end;
end;

{ TBinPolyMulBaseTrinomialReduce.TA }

constructor TBinPolyMulBaseTrinomialReduce.TA.Create(AN: Int32; AK: Int32);
begin
  inherited Create;
  FN := AN;
  FK := AK;
{$IFDEF DEBUG}
  System.Assert(((AN and 63) <> 0) and (AK < 64) and (AN - AK >= 64) and (AN div 32 >= 8));
{$ENDIF}
end;

procedure TBinPolyMulBaseTrinomialReduce.TA.Reduce(Att: PUInt64; Az: PUInt64);
var
  Lk: Int32;
  Ln: Int32;
  Lw_n: Int32;
  Ls_n: Int32;
  Lpos: Int32;
  Lt: UInt64;
  LtHigh: UInt64;
  LtLow: UInt64;
  LtFirst: UInt64;
  Lr: UInt64;
begin
  Ln := FN;
  Lk := FK;
{$IFDEF DEBUG}
  TBinPolyMulBase.DebugAssertReducePreconditions(Ln, Att);
{$ENDIF}
  TBinPolyMulBase.BitPos(Ln, Lw_n, Ls_n);
{$IFDEF DEBUG}
  System.Assert(Lw_n >= 4);
{$ENDIF}
  {Inter-iteration register-carry. Lr holds the in-flight value of}
  {tt[Lpos + 1] coming into each iteration. The upper-half load is also}
  {carried across iterations via a 2-limb rolling window (LtHigh, LtLow):}
  {this iter's LtLow (= tt[Lpos + Lw_n]) is exactly the next iter's LtHigh}
  {(= tt[(Lpos - 1) + Lw_n + 1]), so each tt limb is loaded once.}
  Lpos := Lw_n;
  LtHigh := Att[Lpos + Lw_n + 1];
  LtLow := Att[Lpos + Lw_n];
  LtFirst := ((LtLow shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(LtHigh, -Ls_n));
  Lr := Att[Lpos] xor LtFirst xor (LtFirst shl Lk);
  Att[Lpos + 1] := Att[Lpos + 1] xor TBitOperations.NegativeRightShift64(LtFirst, -Lk);
  System.Dec(Lpos);
  while Lpos >= 0 do
  begin
    LtHigh := LtLow;
    LtLow := Att[Lpos + Lw_n];
  Lt := ((LtLow shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(LtHigh, -Ls_n));
  Lr := Lr xor TBitOperations.NegativeRightShift64(Lt, -Lk);
    Att[Lpos + 1] := Lr;
    Lr := Att[Lpos] xor Lt xor (Lt shl Lk);
    System.Dec(Lpos);
  end;
  Az[0] := Lr;
  System.Move((Att + 1)^, (Az + 1)^, (Lw_n - 1) * System.SizeOf(UInt64));
  Az[Lw_n] := Att[Lw_n] and not (UInt64.MaxValue shl Ls_n);
end;

{ TBinPolyMulBaseTrinomialReduce.TA3 }

constructor TBinPolyMulBaseTrinomialReduce.TA3.Create(AN: Int32; AK: Int32);
begin
  inherited Create;
  FN := AN;
  FK := AK;
{$IFDEF DEBUG}
  System.Assert(((AN and 63) <> 0) and (AK < 64) and (AN - AK >= 64) and (AN div 32 = 2));
{$ENDIF}
end;

procedure TBinPolyMulBaseTrinomialReduce.TA3.Reduce(Att: PUInt64; Az: PUInt64);
var
  Lk: Int32;
  Ln: Int32;
  Lw_n: Int32;
  Ls_n: Int32;
  Lt0: UInt64;
  Lt1: UInt64;
  Lt2: UInt64;
  Lt: UInt64;
begin
  Ln := FN;
  Lk := FK;
{$IFDEF DEBUG}
  TBinPolyMulBase.DebugAssertReducePreconditions(Ln, Att);
{$ENDIF}
  TBinPolyMulBase.BitPos(Ln, Lw_n, Ls_n);
{$IFDEF DEBUG}
  System.Assert(Lw_n = 1);
{$ENDIF}
  {Load tt[0..2] into locals; tt[3] is slack (= 0 by contract) and elided.}
  Lt0 := Att[0];
  Lt1 := Att[1];
  Lt2 := Att[2];
  {Unrolled top-down word fold (Lpos = 1, 0). At Lpos = 1 the read simplifies}
  {because tt[3] = 0.}
  Lt := (Lt2 shr Ls_n);
  Lt1 := Lt1 xor Lt xor (Lt shl Lk);
  Lt2 := Lt2 xor TBitOperations.NegativeRightShift64(Lt, -Lk);
  Lt := ((Lt1 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt2, -Ls_n));
  Lt0 := Lt0 xor Lt xor (Lt shl Lk);
  Lt1 := Lt1 xor TBitOperations.NegativeRightShift64(Lt, -Lk);
  Az[0] := Lt0;
  Az[1] := Lt1 and not (UInt64.MaxValue shl Ls_n);
end;

{ TBinPolyMulBaseTrinomialReduce.TA4 }

constructor TBinPolyMulBaseTrinomialReduce.TA4.Create(AN: Int32; AK: Int32);
begin
  inherited Create;
  FN := AN;
  FK := AK;
{$IFDEF DEBUG}
  System.Assert(((AN and 63) <> 0) and (AK < 64) and (AN - AK >= 64) and (AN div 32 = 3));
{$ENDIF}
end;

procedure TBinPolyMulBaseTrinomialReduce.TA4.Reduce(Att: PUInt64; Az: PUInt64);
var
  Lk: Int32;
  Ln: Int32;
  Lw_n: Int32;
  Ls_n: Int32;
  Lt0: UInt64;
  Lt1: UInt64;
  Lt2: UInt64;
  Lt3: UInt64;
  Lt: UInt64;
begin
  Ln := FN;
  Lk := FK;
{$IFDEF DEBUG}
  TBinPolyMulBase.DebugAssertReducePreconditions(Ln, Att);
{$ENDIF}
  TBinPolyMulBase.BitPos(Ln, Lw_n, Ls_n);
{$IFDEF DEBUG}
  System.Assert(Lw_n = 1);
{$ENDIF}
  Lt0 := Att[0];
  Lt1 := Att[1];
  Lt2 := Att[2];
  Lt3 := Att[3];
  Lt := ((Lt2 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt3, -Ls_n));
  Lt1 := Lt1 xor Lt xor (Lt shl Lk);
  Lt2 := Lt2 xor TBitOperations.NegativeRightShift64(Lt, -Lk);
  Lt := ((Lt1 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt2, -Ls_n));
  Lt0 := Lt0 xor Lt xor (Lt shl Lk);
  Lt1 := Lt1 xor TBitOperations.NegativeRightShift64(Lt, -Lk);
  Az[0] := Lt0;
  Az[1] := Lt1 and not (UInt64.MaxValue shl Ls_n);
end;

{ TBinPolyMulBaseTrinomialReduce.TA5 }

constructor TBinPolyMulBaseTrinomialReduce.TA5.Create(AN: Int32; AK: Int32);
begin
  inherited Create;
  FN := AN;
  FK := AK;
{$IFDEF DEBUG}
  System.Assert(((AN and 63) <> 0) and (AK < 64) and (AN - AK >= 64) and (AN div 32 = 4));
{$ENDIF}
end;

procedure TBinPolyMulBaseTrinomialReduce.TA5.Reduce(Att: PUInt64; Az: PUInt64);
var
  Lk: Int32;
  Ln: Int32;
  Lw_n: Int32;
  Ls_n: Int32;
  Lt0: UInt64;
  Lt1: UInt64;
  Lt2: UInt64;
  Lt3: UInt64;
  Lt4: UInt64;
  Lt: UInt64;
begin
  Ln := FN;
  Lk := FK;
{$IFDEF DEBUG}
  TBinPolyMulBase.DebugAssertReducePreconditions(Ln, Att);
{$ENDIF}
  TBinPolyMulBase.BitPos(Ln, Lw_n, Ls_n);
{$IFDEF DEBUG}
  System.Assert(Lw_n = 2);
{$ENDIF}
  {Load tt[0..4] into locals; tt[5] is slack (= 0 by contract) and elided.}
  Lt0 := Att[0];
  Lt1 := Att[1];
  Lt2 := Att[2];
  Lt3 := Att[3];
  Lt4 := Att[4];
  {Unrolled top-down word fold (Lpos = 2, 1, 0). With Lw_k = 0 (Lk < 64),}
  {each iteration fuses "+1" and "+x^Lk low" into one XOR into tt[Lpos]}
  {and one XOR into tt[Lpos + 1]. At Lpos = 2 the read simplifies because}
  {tt[5] = 0.}
  Lt := (Lt4 shr Ls_n);
  Lt2 := Lt2 xor Lt xor (Lt shl Lk);
  Lt3 := Lt3 xor TBitOperations.NegativeRightShift64(Lt, -Lk);
  Lt := ((Lt3 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt4, -Ls_n));
  Lt1 := Lt1 xor Lt xor (Lt shl Lk);
  Lt2 := Lt2 xor TBitOperations.NegativeRightShift64(Lt, -Lk);
  Lt := ((Lt2 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt3, -Ls_n));
  Lt0 := Lt0 xor Lt xor (Lt shl Lk);
  Lt1 := Lt1 xor TBitOperations.NegativeRightShift64(Lt, -Lk);
  {Mask off bits above position Ln - 1 in the top result limb.}
  Lt2 := Lt2 and not (UInt64.MaxValue shl Ls_n);
  {Write the three result limbs directly to z, bypassing the tt staging copy.}
  Az[0] := Lt0;
  Az[1] := Lt1;
  Az[2] := Lt2;
end;

{ TBinPolyMulBaseTrinomialReduce.TA6 }

constructor TBinPolyMulBaseTrinomialReduce.TA6.Create(AN: Int32; AK: Int32);
begin
  inherited Create;
  FN := AN;
  FK := AK;
{$IFDEF DEBUG}
  System.Assert(((AN and 63) <> 0) and (AK < 64) and (AN - AK >= 64) and (AN div 32 = 5));
{$ENDIF}
end;

procedure TBinPolyMulBaseTrinomialReduce.TA6.Reduce(Att: PUInt64; Az: PUInt64);
var
  Lk: Int32;
  Ln: Int32;
  Lw_n: Int32;
  Ls_n: Int32;
  Lt0: UInt64;
  Lt1: UInt64;
  Lt2: UInt64;
  Lt3: UInt64;
  Lt4: UInt64;
  Lt5: UInt64;
  Lt: UInt64;
begin
  Ln := FN;
  Lk := FK;
{$IFDEF DEBUG}
  TBinPolyMulBase.DebugAssertReducePreconditions(Ln, Att);
{$ENDIF}
  TBinPolyMulBase.BitPos(Ln, Lw_n, Ls_n);
{$IFDEF DEBUG}
  System.Assert(Lw_n = 2);
{$ENDIF}
  {Load tt[0..5] into locals.}
  Lt0 := Att[0];
  Lt1 := Att[1];
  Lt2 := Att[2];
  Lt3 := Att[3];
  Lt4 := Att[4];
  Lt5 := Att[5];
  {Unrolled top-down word fold (Lpos = 2, 1, 0). With Lw_k = 0 (Lk < 64),}
  {each iteration fuses "+1" and "+x^Lk low" into one XOR into tt[Lpos]}
  {and one XOR into tt[Lpos + 1].}
  Lt := ((Lt4 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt5, -Ls_n));
  Lt2 := Lt2 xor Lt xor (Lt shl Lk);
  Lt3 := Lt3 xor TBitOperations.NegativeRightShift64(Lt, -Lk);
  Lt := ((Lt3 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt4, -Ls_n));
  Lt1 := Lt1 xor Lt xor (Lt shl Lk);
  Lt2 := Lt2 xor TBitOperations.NegativeRightShift64(Lt, -Lk);
  Lt := ((Lt2 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt3, -Ls_n));
  Lt0 := Lt0 xor Lt xor (Lt shl Lk);
  Lt1 := Lt1 xor TBitOperations.NegativeRightShift64(Lt, -Lk);
  {Mask off bits above position Ln - 1 in the top result limb.}
  Lt2 := Lt2 and not (UInt64.MaxValue shl Ls_n);
  {Write the three result limbs directly to z, bypassing the tt staging copy.}
  Az[0] := Lt0;
  Az[1] := Lt1;
  Az[2] := Lt2;
end;

{ TBinPolyMulBaseTrinomialReduce.TA7 }

constructor TBinPolyMulBaseTrinomialReduce.TA7.Create(AN: Int32; AK: Int32);
begin
  inherited Create;
  FN := AN;
  FK := AK;
{$IFDEF DEBUG}
  System.Assert(((AN and 63) <> 0) and (AK < 64) and (AN - AK >= 64) and (AN div 32 = 6));
{$ENDIF}
end;

procedure TBinPolyMulBaseTrinomialReduce.TA7.Reduce(Att: PUInt64; Az: PUInt64);
var
  Lk: Int32;
  Ln: Int32;
  Lw_n: Int32;
  Ls_n: Int32;
  Lt0: UInt64;
  Lt1: UInt64;
  Lt2: UInt64;
  Lt3: UInt64;
  Lt4: UInt64;
  Lt5: UInt64;
  Lt6: UInt64;
  Lt: UInt64;
begin
  Ln := FN;
  Lk := FK;
{$IFDEF DEBUG}
  TBinPolyMulBase.DebugAssertReducePreconditions(Ln, Att);
{$ENDIF}
  TBinPolyMulBase.BitPos(Ln, Lw_n, Ls_n);
{$IFDEF DEBUG}
  System.Assert(Lw_n = 3);
{$ENDIF}
  {Load tt[0..6] into locals; tt[7] is slack (= 0 by contract) and elided.}
  Lt0 := Att[0];
  Lt1 := Att[1];
  Lt2 := Att[2];
  Lt3 := Att[3];
  Lt4 := Att[4];
  Lt5 := Att[5];
  Lt6 := Att[6];
  {Unrolled top-down word fold (Lpos = 3, 2, 1, 0). With Lw_k = 0 (Lk < 64),}
  {A's per-iteration writes collapse the "+1" and "+x^Lk" low-part into one}
  {XOR into tt[Lpos] and one XOR into tt[Lpos + 1]. At Lpos = 3 the read}
  {simplifies because tt[7] = 0.}
  Lt := (Lt6 shr Ls_n);
  Lt3 := Lt3 xor Lt xor (Lt shl Lk);
  Lt4 := Lt4 xor TBitOperations.NegativeRightShift64(Lt, -Lk);
  Lt := ((Lt5 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt6, -Ls_n));
  Lt2 := Lt2 xor Lt xor (Lt shl Lk);
  Lt3 := Lt3 xor TBitOperations.NegativeRightShift64(Lt, -Lk);
  Lt := ((Lt4 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt5, -Ls_n));
  Lt1 := Lt1 xor Lt xor (Lt shl Lk);
  Lt2 := Lt2 xor TBitOperations.NegativeRightShift64(Lt, -Lk);
  Lt := ((Lt3 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt4, -Ls_n));
  Lt0 := Lt0 xor Lt xor (Lt shl Lk);
  Lt1 := Lt1 xor TBitOperations.NegativeRightShift64(Lt, -Lk);
  {Mask off bits above position Ln - 1 in the top result limb.}
  Lt3 := Lt3 and not (UInt64.MaxValue shl Ls_n);
  {Write the four result limbs directly to z, bypassing the tt staging copy.}
  Az[0] := Lt0;
  Az[1] := Lt1;
  Az[2] := Lt2;
  Az[3] := Lt3;
end;

{ TBinPolyMulBaseTrinomialReduce.TA8 }

constructor TBinPolyMulBaseTrinomialReduce.TA8.Create(AN: Int32; AK: Int32);
begin
  inherited Create;
  FN := AN;
  FK := AK;
{$IFDEF DEBUG}
  System.Assert(((AN and 63) <> 0) and (AK < 64) and (AN - AK >= 64) and (AN div 32 = 7));
{$ENDIF}
end;

procedure TBinPolyMulBaseTrinomialReduce.TA8.Reduce(Att: PUInt64; Az: PUInt64);
var
  Lk: Int32;
  Ln: Int32;
  Lw_n: Int32;
  Ls_n: Int32;
  Lt0: UInt64;
  Lt1: UInt64;
  Lt2: UInt64;
  Lt3: UInt64;
  Lt4: UInt64;
  Lt5: UInt64;
  Lt6: UInt64;
  Lt7: UInt64;
  Lt: UInt64;
begin
  Ln := FN;
  Lk := FK;
{$IFDEF DEBUG}
  TBinPolyMulBase.DebugAssertReducePreconditions(Ln, Att);
{$ENDIF}
  TBinPolyMulBase.BitPos(Ln, Lw_n, Ls_n);
{$IFDEF DEBUG}
  System.Assert(Lw_n = 3);
{$ENDIF}
  {Load tt[0..7] into locals.}
  Lt0 := Att[0];
  Lt1 := Att[1];
  Lt2 := Att[2];
  Lt3 := Att[3];
  Lt4 := Att[4];
  Lt5 := Att[5];
  Lt6 := Att[6];
  Lt7 := Att[7];
  {Unrolled top-down word fold (Lpos = 3, 2, 1, 0). With Lw_k = 0 (Lk < 64),}
  {each iteration fuses "+1" and "+x^Lk low" into one XOR into tt[Lpos] and}
  {one XOR into tt[Lpos + 1].}
  Lt := ((Lt6 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt7, -Ls_n));
  Lt3 := Lt3 xor Lt xor (Lt shl Lk);
  Lt4 := Lt4 xor TBitOperations.NegativeRightShift64(Lt, -Lk);
  Lt := ((Lt5 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt6, -Ls_n));
  Lt2 := Lt2 xor Lt xor (Lt shl Lk);
  Lt3 := Lt3 xor TBitOperations.NegativeRightShift64(Lt, -Lk);
  Lt := ((Lt4 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt5, -Ls_n));
  Lt1 := Lt1 xor Lt xor (Lt shl Lk);
  Lt2 := Lt2 xor TBitOperations.NegativeRightShift64(Lt, -Lk);
  Lt := ((Lt3 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt4, -Ls_n));
  Lt0 := Lt0 xor Lt xor (Lt shl Lk);
  Lt1 := Lt1 xor TBitOperations.NegativeRightShift64(Lt, -Lk);
  {Mask off bits above position Ln - 1 in the top result limb.}
  Lt3 := Lt3 and not (UInt64.MaxValue shl Ls_n);
  {Write the four result limbs directly to z, bypassing the tt staging copy.}
  Az[0] := Lt0;
  Az[1] := Lt1;
  Az[2] := Lt2;
  Az[3] := Lt3;
end;

{ TBinPolyMulBaseTrinomialReduce.TB }

constructor TBinPolyMulBaseTrinomialReduce.TB.Create(AN: Int32; AK: Int32);
begin
  inherited Create;
  FN := AN;
  FK := AK;
{$IFDEF DEBUG}
  System.Assert(((AN and 63) <> 0) and (AK >= 64) and ((AK and 63) = 0) and (AN - AK >= 64));
{$ENDIF}
end;

procedure TBinPolyMulBaseTrinomialReduce.TB.Reduce(Att: PUInt64; Az: PUInt64);
var
  Lk: Int32;
  Ln: Int32;
  Lw_n: Int32;
  Ls_n: Int32;
  Lw_k: Int32;
  Lpos: Int32;
  Lt: UInt64;
begin
  Ln := FN;
  Lk := FK;
{$IFDEF DEBUG}
  TBinPolyMulBase.DebugAssertReducePreconditions(Ln, Att);
{$ENDIF}
  TBinPolyMulBase.BitPos(Ln, Lw_n, Ls_n);
  Lw_k := (Lk shr 6);
  Lpos := Lw_n;
  repeat
    Lt := (Att[Lpos + Lw_n] shr Ls_n)
      or TBitOperations.NegativeLeftShift64(Att[Lpos + Lw_n + 1], -Ls_n);
    Att[Lpos] := Att[Lpos] xor Lt;
    Att[Lpos + Lw_k] := Att[Lpos + Lw_k] xor Lt;
    System.Dec(Lpos);
  until Lpos < 0;
  System.Move(Att^, Az^, (Lw_n) * System.SizeOf(UInt64));
  Az[Lw_n] := Att[Lw_n] and not (UInt64.MaxValue shl Ls_n);
end;

{ TBinPolyMulBaseTrinomialReduce.TC }

constructor TBinPolyMulBaseTrinomialReduce.TC.Create(AN: Int32; AK: Int32);
begin
  inherited Create;
  FN := AN;
  FK := AK;
{$IFDEF DEBUG}
  System.Assert(((AN and 63) <> 0) and (AK >= 64) and ((AK and 63) <> 0) and (AN - AK >= 64) and (AN div 32 >= 8));
{$ENDIF}
end;

procedure TBinPolyMulBaseTrinomialReduce.TC.Reduce(Att: PUInt64; Az: PUInt64);
var
  Lk: Int32;
  Ln: Int32;
  Lw_n: Int32;
  Ls_n: Int32;
  Lw_k: Int32;
  Ls_k: Int32;
  Lpos: Int32;
  Lt: UInt64;
begin
  Ln := FN;
  Lk := FK;
{$IFDEF DEBUG}
  TBinPolyMulBase.DebugAssertReducePreconditions(Ln, Att);
{$ENDIF}
  TBinPolyMulBase.BitPos(Ln, Lw_n, Ls_n);
  TBinPolyMulBase.BitPos(Lk, Lw_k, Ls_k);
{$IFDEF DEBUG}
  System.Assert(Lw_n >= 4);
{$ENDIF}
  Lpos := Lw_n;
  repeat
    Lt := (Att[Lpos + Lw_n] shr Ls_n)
      or TBitOperations.NegativeLeftShift64(Att[Lpos + Lw_n + 1], -Ls_n);
    Att[Lpos] := Att[Lpos] xor Lt;
    Att[Lpos + Lw_k] := Att[Lpos + Lw_k] xor (Lt shl Ls_k);
    Att[Lpos + Lw_k + 1] := Att[Lpos + Lw_k + 1] xor TBitOperations.NegativeRightShift64(Lt, -Ls_k);
    System.Dec(Lpos);
  until Lpos < 0;
  System.Move(Att^, Az^, (Lw_n) * System.SizeOf(UInt64));
  Az[Lw_n] := Att[Lw_n] and not (UInt64.MaxValue shl Ls_n);
end;

{ TBinPolyMulBaseTrinomialReduce.TC5 }

constructor TBinPolyMulBaseTrinomialReduce.TC5.Create(AN: Int32; AK: Int32);
begin
  inherited Create;
  FN := AN;
  FK := AK;
{$IFDEF DEBUG}
  System.Assert(((AN and 63) <> 0) and (AK >= 64) and ((AK and 63) <> 0) and (AN - AK >= 64) and (AN div 32 = 4));
{$ENDIF}
end;

procedure TBinPolyMulBaseTrinomialReduce.TC5.Reduce(Att: PUInt64; Az: PUInt64);
var
  Lk: Int32;
  Ln: Int32;
  Lw_n: Int32;
  Ls_n: Int32;
  Lw_k: Int32;
  Ls_k: Int32;
  Lt0: UInt64;
  Lt1: UInt64;
  Lt2: UInt64;
  Lt3: UInt64;
  Lt4: UInt64;
  Lt: UInt64;
begin
  Ln := FN;
  Lk := FK;
{$IFDEF DEBUG}
  TBinPolyMulBase.DebugAssertReducePreconditions(Ln, Att);
{$ENDIF}
  TBinPolyMulBase.BitPos(Ln, Lw_n, Ls_n);
  TBinPolyMulBase.BitPos(Lk, Lw_k, Ls_k);
{$IFDEF DEBUG}
  System.Assert(Lw_n = 2);
{$ENDIF}
{$IFDEF DEBUG}
  System.Assert(Lw_k = 1);
{$ENDIF}
  {Load tt[0..4] into locals; tt[5] is slack (= 0 by contract) and elided.}
  Lt0 := Att[0];
  Lt1 := Att[1];
  Lt2 := Att[2];
  Lt3 := Att[3];
  Lt4 := Att[4];
  {Unrolled top-down word fold (Lpos = 2, 1, 0). With Lw_k = 1, the "+x^Lk"}
  {tap writes to tt[Lpos + 1] (low) and tt[Lpos + 2] (high). At Lpos = 2 the}
  {read simplifies because tt[5] = 0.}
  Lt := (Lt4 shr Ls_n);
  Lt2 := Lt2 xor Lt;
  Lt3 := Lt3 xor (Lt shl Ls_k);
  Lt4 := Lt4 xor TBitOperations.NegativeRightShift64(Lt, -Ls_k);
  Lt := ((Lt3 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt4, -Ls_n));
  Lt1 := Lt1 xor Lt;
  Lt2 := Lt2 xor (Lt shl Ls_k);
  Lt3 := Lt3 xor TBitOperations.NegativeRightShift64(Lt, -Ls_k);
  Lt := ((Lt2 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt3, -Ls_n));
  Lt0 := Lt0 xor Lt;
  Lt1 := Lt1 xor (Lt shl Ls_k);
  Lt2 := Lt2 xor TBitOperations.NegativeRightShift64(Lt, -Ls_k);
  {Mask off bits above position Ln - 1 in the top result limb.}
  Lt2 := Lt2 and not (UInt64.MaxValue shl Ls_n);
  {Write the three result limbs directly to z, bypassing the tt staging copy.}
  Az[0] := Lt0;
  Az[1] := Lt1;
  Az[2] := Lt2;
end;

{ TBinPolyMulBaseTrinomialReduce.TC6 }

constructor TBinPolyMulBaseTrinomialReduce.TC6.Create(AN: Int32; AK: Int32);
begin
  inherited Create;
  FN := AN;
  FK := AK;
{$IFDEF DEBUG}
  System.Assert(((AN and 63) <> 0) and (AK >= 64) and ((AK and 63) <> 0) and (AN - AK >= 64) and (AN div 32 = 5));
{$ENDIF}
end;

procedure TBinPolyMulBaseTrinomialReduce.TC6.Reduce(Att: PUInt64; Az: PUInt64);
var
  Lk: Int32;
  Ln: Int32;
  Lw_n: Int32;
  Ls_n: Int32;
  Lw_k: Int32;
  Ls_k: Int32;
  Lt0: UInt64;
  Lt1: UInt64;
  Lt2: UInt64;
  Lt3: UInt64;
  Lt4: UInt64;
  Lt5: UInt64;
  Lt: UInt64;
begin
  Ln := FN;
  Lk := FK;
{$IFDEF DEBUG}
  TBinPolyMulBase.DebugAssertReducePreconditions(Ln, Att);
{$ENDIF}
  TBinPolyMulBase.BitPos(Ln, Lw_n, Ls_n);
  TBinPolyMulBase.BitPos(Lk, Lw_k, Ls_k);
{$IFDEF DEBUG}
  System.Assert(Lw_n = 2);
{$ENDIF}
{$IFDEF DEBUG}
  System.Assert(Lw_k = 1);
{$ENDIF}
  {Load tt[0..5] into locals.}
  Lt0 := Att[0];
  Lt1 := Att[1];
  Lt2 := Att[2];
  Lt3 := Att[3];
  Lt4 := Att[4];
  Lt5 := Att[5];
  {Unrolled top-down word fold (Lpos = 2, 1, 0). With Lw_k = 1, the "+x^Lk"}
  {tap writes to tt[Lpos + 1] (low) and tt[Lpos + 2] (high).}
  Lt := ((Lt4 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt5, -Ls_n));
  Lt2 := Lt2 xor Lt;
  Lt3 := Lt3 xor (Lt shl Ls_k);
  Lt4 := Lt4 xor TBitOperations.NegativeRightShift64(Lt, -Ls_k);
  Lt := ((Lt3 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt4, -Ls_n));
  Lt1 := Lt1 xor Lt;
  Lt2 := Lt2 xor (Lt shl Ls_k);
  Lt3 := Lt3 xor TBitOperations.NegativeRightShift64(Lt, -Ls_k);
  Lt := ((Lt2 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt3, -Ls_n));
  Lt0 := Lt0 xor Lt;
  Lt1 := Lt1 xor (Lt shl Ls_k);
  Lt2 := Lt2 xor TBitOperations.NegativeRightShift64(Lt, -Ls_k);
  {Mask off bits above position Ln - 1 in the top result limb.}
  Lt2 := Lt2 and not (UInt64.MaxValue shl Ls_n);
  {Write the three result limbs directly to z, bypassing the tt staging copy.}
  Az[0] := Lt0;
  Az[1] := Lt1;
  Az[2] := Lt2;
end;

{ TBinPolyMulBaseTrinomialReduce.TC7 }

constructor TBinPolyMulBaseTrinomialReduce.TC7.Create(AN: Int32; AK: Int32);
begin
  inherited Create;
  FN := AN;
  FK := AK;
{$IFDEF DEBUG}
  System.Assert(((AN and 63) <> 0) and (AK >= 64) and ((AK and 63) <> 0) and (AN - AK >= 64) and (AN div 32 = 6));
{$ENDIF}
end;

procedure TBinPolyMulBaseTrinomialReduce.TC7.Reduce(Att: PUInt64; Az: PUInt64);
var
  Lk: Int32;
  Ln: Int32;
  Lw_n: Int32;
  Ls_n: Int32;
  Lw_k: Int32;
  Ls_k: Int32;
  Lt0: UInt64;
  Lt1: UInt64;
  Lt2: UInt64;
  Lt3: UInt64;
  Lt4: UInt64;
  Lt5: UInt64;
  Lt6: UInt64;
  Lt: UInt64;
begin
  Ln := FN;
  Lk := FK;
{$IFDEF DEBUG}
  TBinPolyMulBase.DebugAssertReducePreconditions(Ln, Att);
{$ENDIF}
  TBinPolyMulBase.BitPos(Ln, Lw_n, Ls_n);
  TBinPolyMulBase.BitPos(Lk, Lw_k, Ls_k);
{$IFDEF DEBUG}
  System.Assert(Lw_n = 3);
{$ENDIF}
{$IFDEF DEBUG}
  System.Assert((Lw_k = 1) or (Lw_k = 2));
{$ENDIF}
  {Load tt[0..6] into locals; tt[7] is slack (= 0 by contract) and elided.}
  Lt0 := Att[0];
  Lt1 := Att[1];
  Lt2 := Att[2];
  Lt3 := Att[3];
  Lt4 := Att[4];
  Lt5 := Att[5];
  Lt6 := Att[6];
  {Unrolled top-down word fold (Lpos = 3, 2, 1, 0). At Lpos = 3 the read}
  {simplifies because tt[7] = 0. The destinations of the "+x^Lk" tap}
  {depend on Lw_k (in [1, 2]), so the body branches once on Lw_k and}
  {inlines the destinations in each arm.}
  if Lw_k = 1 then
  begin
  Lt := (Lt6 shr Ls_n);
  Lt3 := Lt3 xor Lt;
  Lt4 := Lt4 xor (Lt shl Ls_k);
  Lt5 := Lt5 xor TBitOperations.NegativeRightShift64(Lt, -Ls_k);
  Lt := ((Lt5 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt6, -Ls_n));
  Lt2 := Lt2 xor Lt;
  Lt3 := Lt3 xor (Lt shl Ls_k);
  Lt4 := Lt4 xor TBitOperations.NegativeRightShift64(Lt, -Ls_k);
  Lt := ((Lt4 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt5, -Ls_n));
  Lt1 := Lt1 xor Lt;
  Lt2 := Lt2 xor (Lt shl Ls_k);
  Lt3 := Lt3 xor TBitOperations.NegativeRightShift64(Lt, -Ls_k);
  Lt := ((Lt3 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt4, -Ls_n));
  Lt0 := Lt0 xor Lt;
  Lt1 := Lt1 xor (Lt shl Ls_k);
  Lt2 := Lt2 xor TBitOperations.NegativeRightShift64(Lt, -Ls_k);
  end
  else
  begin
  Lt := (Lt6 shr Ls_n);
  Lt3 := Lt3 xor Lt;
  Lt5 := Lt5 xor (Lt shl Ls_k);
  Lt6 := Lt6 xor TBitOperations.NegativeRightShift64(Lt, -Ls_k);
  Lt := ((Lt5 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt6, -Ls_n));
  Lt2 := Lt2 xor Lt;
  Lt4 := Lt4 xor (Lt shl Ls_k);
  Lt5 := Lt5 xor TBitOperations.NegativeRightShift64(Lt, -Ls_k);
  Lt := ((Lt4 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt5, -Ls_n));
  Lt1 := Lt1 xor Lt;
  Lt3 := Lt3 xor (Lt shl Ls_k);
  Lt4 := Lt4 xor TBitOperations.NegativeRightShift64(Lt, -Ls_k);
  Lt := ((Lt3 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt4, -Ls_n));
  Lt0 := Lt0 xor Lt;
  Lt2 := Lt2 xor (Lt shl Ls_k);
  Lt3 := Lt3 xor TBitOperations.NegativeRightShift64(Lt, -Ls_k);
  end;
  {Mask off bits above position Ln - 1 in the top result limb.}
  Lt3 := Lt3 and not (UInt64.MaxValue shl Ls_n);
  {Write the four result limbs directly to z, bypassing the tt staging copy.}
  Az[0] := Lt0;
  Az[1] := Lt1;
  Az[2] := Lt2;
  Az[3] := Lt3;
end;

{ TBinPolyMulBaseTrinomialReduce.TC8 }

constructor TBinPolyMulBaseTrinomialReduce.TC8.Create(AN: Int32; AK: Int32);
begin
  inherited Create;
  FN := AN;
  FK := AK;
{$IFDEF DEBUG}
  System.Assert(((AN and 63) <> 0) and (AK >= 64) and ((AK and 63) <> 0) and (AN - AK >= 64) and (AN div 32 = 7));
{$ENDIF}
end;

procedure TBinPolyMulBaseTrinomialReduce.TC8.Reduce(Att: PUInt64; Az: PUInt64);
var
  Lk: Int32;
  Ln: Int32;
  Lw_n: Int32;
  Ls_n: Int32;
  Lw_k: Int32;
  Ls_k: Int32;
  Lt0: UInt64;
  Lt1: UInt64;
  Lt2: UInt64;
  Lt3: UInt64;
  Lt4: UInt64;
  Lt5: UInt64;
  Lt6: UInt64;
  Lt7: UInt64;
  Lt: UInt64;
begin
  Ln := FN;
  Lk := FK;
{$IFDEF DEBUG}
  TBinPolyMulBase.DebugAssertReducePreconditions(Ln, Att);
{$ENDIF}
  TBinPolyMulBase.BitPos(Ln, Lw_n, Ls_n);
  TBinPolyMulBase.BitPos(Lk, Lw_k, Ls_k);
{$IFDEF DEBUG}
  System.Assert(Lw_n = 3);
{$ENDIF}
{$IFDEF DEBUG}
  System.Assert((Lw_k = 1) or (Lw_k = 2));
{$ENDIF}
  //Load tt[0..7] into locals
  Lt0 := Att[0];
  Lt1 := Att[1];
  Lt2 := Att[2];
  Lt3 := Att[3];
  Lt4 := Att[4];
  Lt5 := Att[5];
  Lt6 := Att[6];
  Lt7 := Att[7];
  {Unrolled top-down word fold (Lpos = 3, 2, 1, 0). Each iteration:}
  {Lt            = (tt[Lpos+3] >> Ls_n) | (tt[Lpos+4] << -Ls_n)}
  {tt[Lpos]      ^= Lt                                          (+1 tap)}
  {tt[Lpos+Lw_k]  ^= Lt << Ls_k                                   (+x^Lk low)}
  {tt[Lpos+Lw_k+1]^= Lt >> -Ls_k                                  (+x^Lk high)}
  {The destinations of the +x^Lk tap depend on Lw_k (in [1, 2]), so the body}
  {branches once on Lw_k and inlines the destinations in each arm.}
  if Lw_k = 1 then
  begin
  Lt := ((Lt6 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt7, -Ls_n));
  Lt3 := Lt3 xor Lt;
  Lt4 := Lt4 xor (Lt shl Ls_k);
  Lt5 := Lt5 xor TBitOperations.NegativeRightShift64(Lt, -Ls_k);
  Lt := ((Lt5 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt6, -Ls_n));
  Lt2 := Lt2 xor Lt;
  Lt3 := Lt3 xor (Lt shl Ls_k);
  Lt4 := Lt4 xor TBitOperations.NegativeRightShift64(Lt, -Ls_k);
  Lt := ((Lt4 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt5, -Ls_n));
  Lt1 := Lt1 xor Lt;
  Lt2 := Lt2 xor (Lt shl Ls_k);
  Lt3 := Lt3 xor TBitOperations.NegativeRightShift64(Lt, -Ls_k);
  Lt := ((Lt3 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt4, -Ls_n));
  Lt0 := Lt0 xor Lt;
  Lt1 := Lt1 xor (Lt shl Ls_k);
  Lt2 := Lt2 xor TBitOperations.NegativeRightShift64(Lt, -Ls_k);
  end
  else
  begin
  Lt := ((Lt6 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt7, -Ls_n));
  Lt3 := Lt3 xor Lt;
  Lt5 := Lt5 xor (Lt shl Ls_k);
  Lt6 := Lt6 xor TBitOperations.NegativeRightShift64(Lt, -Ls_k);
  Lt := ((Lt5 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt6, -Ls_n));
  Lt2 := Lt2 xor Lt;
  Lt4 := Lt4 xor (Lt shl Ls_k);
  Lt5 := Lt5 xor TBitOperations.NegativeRightShift64(Lt, -Ls_k);
  Lt := ((Lt4 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt5, -Ls_n));
  Lt1 := Lt1 xor Lt;
  Lt3 := Lt3 xor (Lt shl Ls_k);
  Lt4 := Lt4 xor TBitOperations.NegativeRightShift64(Lt, -Ls_k);
  Lt := ((Lt3 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt4, -Ls_n));
  Lt0 := Lt0 xor Lt;
  Lt2 := Lt2 xor (Lt shl Ls_k);
  Lt3 := Lt3 xor TBitOperations.NegativeRightShift64(Lt, -Ls_k);
  end;
  {Mask off the bits above position Ln - 1 in the top result limb.}
  Lt3 := Lt3 and not (UInt64.MaxValue shl Ls_n);
  {Write the four result limbs directly to z, bypassing the tt staging copy.}
  Az[0] := Lt0;
  Az[1] := Lt1;
  Az[2] := Lt2;
  Az[3] := Lt3;
end;

{ TBinPolyMulBaseTrinomialReduce.TD }

constructor TBinPolyMulBaseTrinomialReduce.TD.Create(AN: Int32; AK: Int32);
begin
  inherited Create;
  FN := AN;
  FK := AK;
{$IFDEF DEBUG}
  System.Assert((AN - AK < 64) or (((AN and 63) = 0) and ((AK and 63) = 0)));
{$ENDIF}
end;

procedure TBinPolyMulBaseTrinomialReduce.TD.Reduce(Att: PUInt64; Az: PUInt64);
var
  Lk: Int32;
  Ln: Int32;
  Lpos_0: Int32;
  Lw_n: Int32;
  Ls_n: Int32;
  Lw_0: Int32;
  Ls_0: Int32;
  Lw_k: Int32;
  Ls_k: Int32;
  Lw_top: Int32;
  Ls_top: Int32;
  Lbit_n: UInt64;
begin
  Ln := FN;
  Lk := FK;
{$IFDEF DEBUG}
  TBinPolyMulBase.DebugAssertReducePreconditions(Ln, Att);
{$ENDIF}
  Lpos_0 := Ln - 1;
  while Lpos_0 >= 0 do
  begin
    TBinPolyMulBase.BitPos(Lpos_0 + Ln, Lw_n, Ls_n);
    Lbit_n := (Att[Lw_n] shr Ls_n) and 1;
    TBinPolyMulBase.BitPos(Lpos_0, Lw_0, Ls_0);
    Att[Lw_0] := Att[Lw_0] xor (Lbit_n shl Ls_0);
    TBinPolyMulBase.BitPos(Lpos_0 + Lk, Lw_k, Ls_k);
    Att[Lw_k] := Att[Lw_k] xor (Lbit_n shl Ls_k);
    System.Dec(Lpos_0);
  end;
  TBinPolyMulBase.BitPos(Ln, Lw_top, Ls_top);
  System.Move(Att^, Az^, (Lw_top) * System.SizeOf(UInt64));
  {Ls_top = 0 (Ln a multiple of 64): the copy above already wrote the full top}
  {limb (Lw_top = Lsize); no partial-limb mask, and z has no limb Lw_top to write.}
  if Ls_top <> 0 then
  Az[Lw_top] := Att[Lw_top] and not (UInt64.MaxValue shl Ls_top);
end;

{ TBinPolyMulBaseTrinomialReduce.TE }

constructor TBinPolyMulBaseTrinomialReduce.TE.Create(AN: Int32; AK: Int32);
begin
  inherited Create;
  FN := AN;
  FK := AK;
{$IFDEF DEBUG}
  System.Assert(((AN and 63) = 0) and ((AK and 63) <> 0) and (AN - AK >= 64));
{$ENDIF}
end;

procedure TBinPolyMulBaseTrinomialReduce.TE.Reduce(Att: PUInt64; Az: PUInt64);
var
  Lk: Int32;
  Ln: Int32;
  LW: Int32;
  Lw_k: Int32;
  Ls_k: Int32;
  Lpos: Int32;
  Lt: UInt64;
begin
  Ln := FN;
  Lk := FK;
{$IFDEF DEBUG}
  TBinPolyMulBase.DebugAssertReducePreconditions(Ln, Att);
{$ENDIF}
  LW := (Ln shr 6);
  TBinPolyMulBase.BitPos(Lk, Lw_k, Ls_k);
{$IFDEF DEBUG}
  System.Assert((Ls_k <> 0) and (Lw_k <= LW - 2));
{$ENDIF}
  Lpos := LW - 1;
  repeat
    Lt := Att[Lpos + LW];
    Att[Lpos] := Att[Lpos] xor Lt;
    Att[Lpos + Lw_k] := Att[Lpos + Lw_k] xor (Lt shl Ls_k);
    Att[Lpos + Lw_k + 1] := Att[Lpos + Lw_k + 1] xor TBitOperations.NegativeRightShift64(Lt, -Ls_k);
    System.Dec(Lpos);
  until Lpos < 0;
  System.Move(Att^, Az^, (LW) * System.SizeOf(UInt64));
end;

end.