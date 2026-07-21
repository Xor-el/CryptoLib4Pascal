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

unit ClpBinPolyMulBasePentanomialReduce;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBitOperations,
  ClpCryptoLibTypes,
  ClpIBinPolyMul,
  ClpBinPolyMulBase;

type
  /// <summary>
  /// Pentanomial reduction by <c>x^n + x^k3 + x^k2 + x^k1 + 1</c>. The factory selects one
  /// of several specialised implementations based on <c>(n, k1, k2, k3)</c>.
  /// </summary>
  /// <remarks>
  /// Each bit at position <c>p &gt;= n</c> folds via the "+1" tap and three "+x^ki" taps.
  /// Factory dispatch branch order is critical — see the implementation comments in
  /// <c>Create</c>.
  /// </remarks>
  TBinPolyMulBasePentanomialReduce = class
  public
    type
    TA = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
      FK1: Int32;
      FK2: Int32;
      FK3: Int32;
    public
      constructor Create(AN: Int32; AK1: Int32; AK2: Int32; AK3: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
    TA3 = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
      FK1: Int32;
      FK2: Int32;
      FK3: Int32;
    public
      constructor Create(AN: Int32; AK1: Int32; AK2: Int32; AK3: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
    TA4 = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
      FK1: Int32;
      FK2: Int32;
      FK3: Int32;
    public
      constructor Create(AN: Int32; AK1: Int32; AK2: Int32; AK3: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
    TA5 = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
      FK1: Int32;
      FK2: Int32;
      FK3: Int32;
    public
      constructor Create(AN: Int32; AK1: Int32; AK2: Int32; AK3: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
    TA6 = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
      FK1: Int32;
      FK2: Int32;
      FK3: Int32;
    public
      constructor Create(AN: Int32; AK1: Int32; AK2: Int32; AK3: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
    TA7 = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
      FK1: Int32;
      FK2: Int32;
      FK3: Int32;
    public
      constructor Create(AN: Int32; AK1: Int32; AK2: Int32; AK3: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
    TA8 = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
      FK1: Int32;
      FK2: Int32;
      FK3: Int32;
    public
      constructor Create(AN: Int32; AK1: Int32; AK2: Int32; AK3: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
    TB = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
      FK1: Int32;
      FK2: Int32;
      FK3: Int32;
    public
      constructor Create(AN: Int32; AK1: Int32; AK2: Int32; AK3: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
    TD = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
      FK1: Int32;
      FK2: Int32;
      FK3: Int32;
    public
      constructor Create(AN: Int32; AK1: Int32; AK2: Int32; AK3: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
    TC = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
      FK1: Int32;
      FK2: Int32;
      FK3: Int32;
    public
      constructor Create(AN: Int32; AK1: Int32; AK2: Int32; AK3: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
    TE = class sealed(TInterfacedObject, IBinPolyReduce)
    private
      FN: Int32;
      FK1: Int32;
      FK2: Int32;
      FK3: Int32;
    public
      constructor Create(AN: Int32; AK1: Int32; AK2: Int32; AK3: Int32);
      procedure Reduce(Att: PUInt64; Az: PUInt64);
    end;
  public
    /// <summary>
    /// Select a pentanomial reducer for bit length <paramref name="AN"/> and taps
    /// <paramref name="AK1"/>, <paramref name="AK2"/>, <paramref name="AK3"/>.
    /// </summary>
    class function Create(AN: Int32; AK1: Int32; AK2: Int32; AK3: Int32): IBinPolyReduce; static;
  end;

implementation

{ TBinPolyMulBasePentanomialReduce }

class function TBinPolyMulBasePentanomialReduce.Create(AN: Int32; AK1: Int32; AK2: Int32; AK3: Int32): IBinPolyReduce;
begin
  if (AN and 63) = 0 then
  begin
    if (AN - AK3 >= 64) and ((AK1 and 63) <> 0) and ((AK2 and 63) <> 0) and ((AK3 and 63) <> 0) then
      Result := TBinPolyMulBasePentanomialReduce.TE.Create(AN, AK1, AK2, AK3)
    else
      Result := TBinPolyMulBasePentanomialReduce.TC.Create(AN, AK1, AK2, AK3);
    Exit;
  end;
  if AN - AK3 < 64 then
  begin
    Result := TBinPolyMulBasePentanomialReduce.TC.Create(AN, AK1, AK2, AK3);
    Exit;
  end;
  if AK3 < 64 then
  begin
    case AN div 32 of
      2: Result := TBinPolyMulBasePentanomialReduce.TA3.Create(AN, AK1, AK2, AK3);
      3: Result := TBinPolyMulBasePentanomialReduce.TA4.Create(AN, AK1, AK2, AK3);
      4: Result := TBinPolyMulBasePentanomialReduce.TA5.Create(AN, AK1, AK2, AK3);
      5: Result := TBinPolyMulBasePentanomialReduce.TA6.Create(AN, AK1, AK2, AK3);
      6: Result := TBinPolyMulBasePentanomialReduce.TA7.Create(AN, AK1, AK2, AK3);
      7: Result := TBinPolyMulBasePentanomialReduce.TA8.Create(AN, AK1, AK2, AK3);
    else
      Result := TBinPolyMulBasePentanomialReduce.TA.Create(AN, AK1, AK2, AK3);
    end;
    Exit;
  end;
  if (AK2 < 64) and ((AK3 and 63) <> 0) then
  begin
    Result := TBinPolyMulBasePentanomialReduce.TD.Create(AN, AK1, AK2, AK3);
    Exit;
  end;
  if ((AK1 and 63) <> 0) and ((AK2 and 63) <> 0) and ((AK3 and 63) <> 0) then
  begin
    Result := TBinPolyMulBasePentanomialReduce.TB.Create(AN, AK1, AK2, AK3);
    Exit;
  end;
  Result := TBinPolyMulBasePentanomialReduce.TC.Create(AN, AK1, AK2, AK3);
end;

{ TBinPolyMulBasePentanomialReduce.TA }

constructor TBinPolyMulBasePentanomialReduce.TA.Create(AN: Int32; AK1: Int32; AK2: Int32; AK3: Int32);
begin
  inherited Create;
  FN := AN;
  FK1 := AK1;
  FK2 := AK2;
  FK3 := AK3;
{$IFDEF DEBUG}
  System.Assert(((AN and 63) <> 0) and (AK3 < 64) and (AN - AK3 >= 64) and (AN div 32 >= 8));
{$ENDIF}
end;

procedure TBinPolyMulBasePentanomialReduce.TA.Reduce(Att: PUInt64; Az: PUInt64);
var
  Lk1: Int32;
  Lk2: Int32;
  Lk3: Int32;
  Ln: Int32;
  Lw_n: Int32;
  Ls_n: Int32;
  Lpos: Int32;
  Lt: UInt64;
  LtHigh: UInt64;
  LtLow: UInt64;
begin
  Ln := FN;
  Lk1 := FK1;
  Lk2 := FK2;
  Lk3 := FK3;
{$IFDEF DEBUG}
  TBinPolyMulBase.DebugAssertReducePreconditions(Ln, Att);
{$ENDIF}
  TBinPolyMulBase.BitPos(Ln, Lw_n, Ls_n);
{$IFDEF DEBUG}
  System.Assert(Lw_n >= 4);
{$ENDIF}
  {Inter-iteration upper-half load cache: this iter's LtLow}
  {(= tt[Lpos + Lw_n]) is exactly the next iter's LtHigh}
  {(= tt[(Lpos - 1) + Lw_n + 1] = tt[Lpos + Lw_n]), so we carry it}
  {forward in LtHigh instead of re-loading.}
  Lpos := Lw_n;
  LtHigh := Att[Lpos + Lw_n + 1];
  LtLow := Att[Lpos + Lw_n];
  Lt := ((LtLow shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(LtHigh, -Ls_n));
  Att[Lpos] := Att[Lpos] xor Lt xor (Lt shl Lk1) xor (Lt shl Lk2) xor (Lt shl Lk3);
  Att[Lpos + 1] := Att[Lpos + 1] xor TBitOperations.NegativeRightShift64(Lt, -Lk1) xor TBitOperations.NegativeRightShift64(Lt, -Lk2) xor TBitOperations.NegativeRightShift64(Lt, -Lk3);
  System.Dec(Lpos);
  while Lpos >= 0 do
  begin
    LtHigh := LtLow;
    LtLow := Att[Lpos + Lw_n];
    Lt := ((LtLow shr Ls_n)) or (TBitOperations.NegativeLeftShift64(LtHigh, -Ls_n));
    Att[Lpos] := Att[Lpos] xor Lt xor (Lt shl Lk1) xor (Lt shl Lk2) xor (Lt shl Lk3);
    Att[Lpos + 1] := Att[Lpos + 1] xor TBitOperations.NegativeRightShift64(Lt, -Lk1) xor TBitOperations.NegativeRightShift64(Lt, -Lk2) xor TBitOperations.NegativeRightShift64(Lt, -Lk3);
    System.Dec(Lpos);
  end;
  System.Move(Att^, Az^, (Lw_n) * System.SizeOf(UInt64));
  Az[Lw_n] := Att[Lw_n] and not (UInt64.MaxValue shl Ls_n);
end;

{ TBinPolyMulBasePentanomialReduce.TA3 }

constructor TBinPolyMulBasePentanomialReduce.TA3.Create(AN: Int32; AK1: Int32; AK2: Int32; AK3: Int32);
begin
  inherited Create;
  FN := AN;
  FK1 := AK1;
  FK2 := AK2;
  FK3 := AK3;
{$IFDEF DEBUG}
  System.Assert(((AN and 63) <> 0) and (AK3 < 64) and (AN - AK3 >= 64) and (AN div 32 = 2));
{$ENDIF}
end;

procedure TBinPolyMulBasePentanomialReduce.TA3.Reduce(Att: PUInt64; Az: PUInt64);
var
  Lk1: Int32;
  Lk2: Int32;
  Lk3: Int32;
  Ln: Int32;
  Lw_n: Int32;
  Ls_n: Int32;
  Lt0: UInt64;
  Lt1: UInt64;
  Lt2: UInt64;
  Lt: UInt64;
begin
  Ln := FN;
  Lk1 := FK1;
  Lk2 := FK2;
  Lk3 := FK3;
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
  {Unrolled top-down word fold (Lpos = 1, 0). At Lpos = 1 the read}
  {simplifies because tt[3] = 0.}
  Lt := (Lt2 shr Ls_n);
  Lt1 := Lt1 xor Lt xor (Lt shl Lk1) xor (Lt shl Lk2) xor (Lt shl Lk3);
  Lt2 := Lt2 xor TBitOperations.NegativeRightShift64(Lt, -Lk1) xor TBitOperations.NegativeRightShift64(Lt, -Lk2) xor TBitOperations.NegativeRightShift64(Lt, -Lk3);
  Lt := ((Lt1 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt2, -Ls_n));
  Lt0 := Lt0 xor Lt xor (Lt shl Lk1) xor (Lt shl Lk2) xor (Lt shl Lk3);
  Lt1 := Lt1 xor TBitOperations.NegativeRightShift64(Lt, -Lk1) xor TBitOperations.NegativeRightShift64(Lt, -Lk2) xor TBitOperations.NegativeRightShift64(Lt, -Lk3);
  Az[0] := Lt0;
  Az[1] := Lt1 and not (UInt64.MaxValue shl Ls_n);
end;

{ TBinPolyMulBasePentanomialReduce.TA4 }

constructor TBinPolyMulBasePentanomialReduce.TA4.Create(AN: Int32; AK1: Int32; AK2: Int32; AK3: Int32);
begin
  inherited Create;
  FN := AN;
  FK1 := AK1;
  FK2 := AK2;
  FK3 := AK3;
{$IFDEF DEBUG}
  System.Assert(((AN and 63) <> 0) and (AK3 < 64) and (AN - AK3 >= 64) and (AN div 32 = 3));
{$ENDIF}
end;

procedure TBinPolyMulBasePentanomialReduce.TA4.Reduce(Att: PUInt64; Az: PUInt64);
var
  Lk1: Int32;
  Lk2: Int32;
  Lk3: Int32;
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
  Lk1 := FK1;
  Lk2 := FK2;
  Lk3 := FK3;
{$IFDEF DEBUG}
  TBinPolyMulBase.DebugAssertReducePreconditions(Ln, Att);
{$ENDIF}
  TBinPolyMulBase.BitPos(Ln, Lw_n, Ls_n);
{$IFDEF DEBUG}
  System.Assert(Lw_n = 1);
{$ENDIF}
  {Load tt[0..3] into locals.}
  Lt0 := Att[0];
  Lt1 := Att[1];
  Lt2 := Att[2];
  Lt3 := Att[3];
  {Unrolled top-down word fold (Lpos = 1, 0).}
  Lt := ((Lt2 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt3, -Ls_n));
  Lt1 := Lt1 xor Lt xor (Lt shl Lk1) xor (Lt shl Lk2) xor (Lt shl Lk3);
  Lt2 := Lt2 xor TBitOperations.NegativeRightShift64(Lt, -Lk1) xor TBitOperations.NegativeRightShift64(Lt, -Lk2) xor TBitOperations.NegativeRightShift64(Lt, -Lk3);
  Lt := ((Lt1 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt2, -Ls_n));
  Lt0 := Lt0 xor Lt xor (Lt shl Lk1) xor (Lt shl Lk2) xor (Lt shl Lk3);
  Lt1 := Lt1 xor TBitOperations.NegativeRightShift64(Lt, -Lk1) xor TBitOperations.NegativeRightShift64(Lt, -Lk2) xor TBitOperations.NegativeRightShift64(Lt, -Lk3);
  Az[0] := Lt0;
  Az[1] := Lt1 and not (UInt64.MaxValue shl Ls_n);
end;

{ TBinPolyMulBasePentanomialReduce.TA5 }

constructor TBinPolyMulBasePentanomialReduce.TA5.Create(AN: Int32; AK1: Int32; AK2: Int32; AK3: Int32);
begin
  inherited Create;
  FN := AN;
  FK1 := AK1;
  FK2 := AK2;
  FK3 := AK3;
{$IFDEF DEBUG}
  System.Assert(((AN and 63) <> 0) and (AK3 < 64) and (AN - AK3 >= 64) and (AN div 32 = 4));
{$ENDIF}
end;

procedure TBinPolyMulBasePentanomialReduce.TA5.Reduce(Att: PUInt64; Az: PUInt64);
var
  Lk1: Int32;
  Lk2: Int32;
  Lk3: Int32;
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
  Lk1 := FK1;
  Lk2 := FK2;
  Lk3 := FK3;
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
  {Unrolled top-down word fold (Lpos = 2, 1, 0). At Lpos = 2 the read}
  {simplifies because tt[5] = 0.}
  Lt := (Lt4 shr Ls_n);
  Lt2 := Lt2 xor Lt xor (Lt shl Lk1) xor (Lt shl Lk2) xor (Lt shl Lk3);
  Lt3 := Lt3 xor TBitOperations.NegativeRightShift64(Lt, -Lk1) xor TBitOperations.NegativeRightShift64(Lt, -Lk2) xor TBitOperations.NegativeRightShift64(Lt, -Lk3);
  Lt := ((Lt3 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt4, -Ls_n));
  Lt1 := Lt1 xor Lt xor (Lt shl Lk1) xor (Lt shl Lk2) xor (Lt shl Lk3);
  Lt2 := Lt2 xor TBitOperations.NegativeRightShift64(Lt, -Lk1) xor TBitOperations.NegativeRightShift64(Lt, -Lk2) xor TBitOperations.NegativeRightShift64(Lt, -Lk3);
  Lt := ((Lt2 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt3, -Ls_n));
  Lt0 := Lt0 xor Lt xor (Lt shl Lk1) xor (Lt shl Lk2) xor (Lt shl Lk3);
  Lt1 := Lt1 xor TBitOperations.NegativeRightShift64(Lt, -Lk1) xor TBitOperations.NegativeRightShift64(Lt, -Lk2) xor TBitOperations.NegativeRightShift64(Lt, -Lk3);
  {Mask off bits above position Ln - 1 in the top result limb.}
  Lt2 := Lt2 and not (UInt64.MaxValue shl Ls_n);
  Az[0] := Lt0;
  Az[1] := Lt1;
  Az[2] := Lt2;
end;

{ TBinPolyMulBasePentanomialReduce.TA6 }

constructor TBinPolyMulBasePentanomialReduce.TA6.Create(AN: Int32; AK1: Int32; AK2: Int32; AK3: Int32);
begin
  inherited Create;
  FN := AN;
  FK1 := AK1;
  FK2 := AK2;
  FK3 := AK3;
{$IFDEF DEBUG}
  System.Assert(((AN and 63) <> 0) and (AK3 < 64) and (AN - AK3 >= 64) and (AN div 32 = 5));
{$ENDIF}
end;

procedure TBinPolyMulBasePentanomialReduce.TA6.Reduce(Att: PUInt64; Az: PUInt64);
var
  Lk1: Int32;
  Lk2: Int32;
  Lk3: Int32;
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
  Lk1 := FK1;
  Lk2 := FK2;
  Lk3 := FK3;
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
  {Unrolled top-down word fold (Lpos = 2, 1, 0).}
  Lt := ((Lt4 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt5, -Ls_n));
  Lt2 := Lt2 xor Lt xor (Lt shl Lk1) xor (Lt shl Lk2) xor (Lt shl Lk3);
  Lt3 := Lt3 xor TBitOperations.NegativeRightShift64(Lt, -Lk1) xor TBitOperations.NegativeRightShift64(Lt, -Lk2) xor TBitOperations.NegativeRightShift64(Lt, -Lk3);
  Lt := ((Lt3 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt4, -Ls_n));
  Lt1 := Lt1 xor Lt xor (Lt shl Lk1) xor (Lt shl Lk2) xor (Lt shl Lk3);
  Lt2 := Lt2 xor TBitOperations.NegativeRightShift64(Lt, -Lk1) xor TBitOperations.NegativeRightShift64(Lt, -Lk2) xor TBitOperations.NegativeRightShift64(Lt, -Lk3);
  Lt := ((Lt2 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt3, -Ls_n));
  Lt0 := Lt0 xor Lt xor (Lt shl Lk1) xor (Lt shl Lk2) xor (Lt shl Lk3);
  Lt1 := Lt1 xor TBitOperations.NegativeRightShift64(Lt, -Lk1) xor TBitOperations.NegativeRightShift64(Lt, -Lk2) xor TBitOperations.NegativeRightShift64(Lt, -Lk3);
  {Mask off bits above position Ln - 1 in the top result limb.}
  Lt2 := Lt2 and not (UInt64.MaxValue shl Ls_n);
  Az[0] := Lt0;
  Az[1] := Lt1;
  Az[2] := Lt2;
end;

{ TBinPolyMulBasePentanomialReduce.TA7 }

constructor TBinPolyMulBasePentanomialReduce.TA7.Create(AN: Int32; AK1: Int32; AK2: Int32; AK3: Int32);
begin
  inherited Create;
  FN := AN;
  FK1 := AK1;
  FK2 := AK2;
  FK3 := AK3;
{$IFDEF DEBUG}
  System.Assert(((AN and 63) <> 0) and (AK3 < 64) and (AN - AK3 >= 64) and (AN div 32 = 6));
{$ENDIF}
end;

procedure TBinPolyMulBasePentanomialReduce.TA7.Reduce(Att: PUInt64; Az: PUInt64);
var
  Lk1: Int32;
  Lk2: Int32;
  Lk3: Int32;
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
  Lk1 := FK1;
  Lk2 := FK2;
  Lk3 := FK3;
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
  {Unrolled top-down word fold (Lpos = 3, 2, 1, 0). At Lpos = 3 the read}
  {simplifies because tt[7] = 0.}
  Lt := (Lt6 shr Ls_n);
  Lt3 := Lt3 xor Lt xor (Lt shl Lk1) xor (Lt shl Lk2) xor (Lt shl Lk3);
  Lt4 := Lt4 xor TBitOperations.NegativeRightShift64(Lt, -Lk1) xor TBitOperations.NegativeRightShift64(Lt, -Lk2) xor TBitOperations.NegativeRightShift64(Lt, -Lk3);
  Lt := ((Lt5 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt6, -Ls_n));
  Lt2 := Lt2 xor Lt xor (Lt shl Lk1) xor (Lt shl Lk2) xor (Lt shl Lk3);
  Lt3 := Lt3 xor TBitOperations.NegativeRightShift64(Lt, -Lk1) xor TBitOperations.NegativeRightShift64(Lt, -Lk2) xor TBitOperations.NegativeRightShift64(Lt, -Lk3);
  Lt := ((Lt4 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt5, -Ls_n));
  Lt1 := Lt1 xor Lt xor (Lt shl Lk1) xor (Lt shl Lk2) xor (Lt shl Lk3);
  Lt2 := Lt2 xor TBitOperations.NegativeRightShift64(Lt, -Lk1) xor TBitOperations.NegativeRightShift64(Lt, -Lk2) xor TBitOperations.NegativeRightShift64(Lt, -Lk3);
  Lt := ((Lt3 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt4, -Ls_n));
  Lt0 := Lt0 xor Lt xor (Lt shl Lk1) xor (Lt shl Lk2) xor (Lt shl Lk3);
  Lt1 := Lt1 xor TBitOperations.NegativeRightShift64(Lt, -Lk1) xor TBitOperations.NegativeRightShift64(Lt, -Lk2) xor TBitOperations.NegativeRightShift64(Lt, -Lk3);
  {Mask off bits above position Ln - 1 in the top result limb.}
  Lt3 := Lt3 and not (UInt64.MaxValue shl Ls_n);
  Az[0] := Lt0;
  Az[1] := Lt1;
  Az[2] := Lt2;
  Az[3] := Lt3;
end;

{ TBinPolyMulBasePentanomialReduce.TA8 }

constructor TBinPolyMulBasePentanomialReduce.TA8.Create(AN: Int32; AK1: Int32; AK2: Int32; AK3: Int32);
begin
  inherited Create;
  FN := AN;
  FK1 := AK1;
  FK2 := AK2;
  FK3 := AK3;
{$IFDEF DEBUG}
  System.Assert(((AN and 63) <> 0) and (AK3 < 64) and (AN - AK3 >= 64) and (AN div 32 = 7));
{$ENDIF}
end;

procedure TBinPolyMulBasePentanomialReduce.TA8.Reduce(Att: PUInt64; Az: PUInt64);
var
  Lk1: Int32;
  Lk2: Int32;
  Lk3: Int32;
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
  Lk1 := FK1;
  Lk2 := FK2;
  Lk3 := FK3;
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
  {Unrolled top-down word fold (Lpos = 3, 2, 1, 0).}
  Lt := ((Lt6 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt7, -Ls_n));
  Lt3 := Lt3 xor Lt xor (Lt shl Lk1) xor (Lt shl Lk2) xor (Lt shl Lk3);
  Lt4 := Lt4 xor TBitOperations.NegativeRightShift64(Lt, -Lk1) xor TBitOperations.NegativeRightShift64(Lt, -Lk2) xor TBitOperations.NegativeRightShift64(Lt, -Lk3);
  Lt := ((Lt5 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt6, -Ls_n));
  Lt2 := Lt2 xor Lt xor (Lt shl Lk1) xor (Lt shl Lk2) xor (Lt shl Lk3);
  Lt3 := Lt3 xor TBitOperations.NegativeRightShift64(Lt, -Lk1) xor TBitOperations.NegativeRightShift64(Lt, -Lk2) xor TBitOperations.NegativeRightShift64(Lt, -Lk3);
  Lt := ((Lt4 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt5, -Ls_n));
  Lt1 := Lt1 xor Lt xor (Lt shl Lk1) xor (Lt shl Lk2) xor (Lt shl Lk3);
  Lt2 := Lt2 xor TBitOperations.NegativeRightShift64(Lt, -Lk1) xor TBitOperations.NegativeRightShift64(Lt, -Lk2) xor TBitOperations.NegativeRightShift64(Lt, -Lk3);
  Lt := ((Lt3 shr Ls_n))  or  (TBitOperations.NegativeLeftShift64(Lt4, -Ls_n));
  Lt0 := Lt0 xor Lt xor (Lt shl Lk1) xor (Lt shl Lk2) xor (Lt shl Lk3);
  Lt1 := Lt1 xor TBitOperations.NegativeRightShift64(Lt, -Lk1) xor TBitOperations.NegativeRightShift64(Lt, -Lk2) xor TBitOperations.NegativeRightShift64(Lt, -Lk3);
  {Mask off bits above position Ln - 1 in the top result limb.}
  Lt3 := Lt3 and not (UInt64.MaxValue shl Ls_n);
  Az[0] := Lt0;
  Az[1] := Lt1;
  Az[2] := Lt2;
  Az[3] := Lt3;
end;

{ TBinPolyMulBasePentanomialReduce.TB }

constructor TBinPolyMulBasePentanomialReduce.TB.Create(AN: Int32; AK1: Int32; AK2: Int32; AK3: Int32);
begin
  inherited Create;
  FN := AN;
  FK1 := AK1;
  FK2 := AK2;
  FK3 := AK3;
{$IFDEF DEBUG}
  System.Assert(((AN and 63) <> 0) and (AK2 >= 64) and (AN - AK3 >= 64) and ((AK1 and 63) <> 0) and ((AK2 and 63) <> 0) and ((AK3 and 63) <> 0));
{$ENDIF}
end;

procedure TBinPolyMulBasePentanomialReduce.TB.Reduce(Att: PUInt64; Az: PUInt64);
var
  Lk1: Int32;
  Lk2: Int32;
  Lk3: Int32;
  Ln: Int32;
  Lw_n: Int32;
  Ls_n: Int32;
  Lw_k1: Int32;
  Ls_k1: Int32;
  Lw_k2: Int32;
  Ls_k2: Int32;
  Lw_k3: Int32;
  Ls_k3: Int32;
  Lpos: Int32;
  Lt: UInt64;
begin
  Ln := FN;
  Lk1 := FK1;
  Lk2 := FK2;
  Lk3 := FK3;
{$IFDEF DEBUG}
  TBinPolyMulBase.DebugAssertReducePreconditions(Ln, Att);
{$ENDIF}
  TBinPolyMulBase.BitPos(Ln, Lw_n, Ls_n);
  TBinPolyMulBase.BitPos(Lk1, Lw_k1, Ls_k1);
  TBinPolyMulBase.BitPos(Lk2, Lw_k2, Ls_k2);
  TBinPolyMulBase.BitPos(Lk3, Lw_k3, Ls_k3);
  Lpos := Lw_n;
  repeat
    Lt := (Att[Lpos + Lw_n] shr Ls_n)
      or TBitOperations.NegativeLeftShift64(Att[Lpos + Lw_n + 1], -Ls_n);
    Att[Lpos] := Att[Lpos] xor Lt;
    Att[Lpos + Lw_k1] := Att[Lpos + Lw_k1] xor (Lt shl Ls_k1);
    Att[Lpos + Lw_k1 + 1] := Att[Lpos + Lw_k1 + 1] xor TBitOperations.NegativeRightShift64(Lt, -Ls_k1);
    Att[Lpos + Lw_k2] := Att[Lpos + Lw_k2] xor (Lt shl Ls_k2);
    Att[Lpos + Lw_k2 + 1] := Att[Lpos + Lw_k2 + 1] xor TBitOperations.NegativeRightShift64(Lt, -Ls_k2);
    Att[Lpos + Lw_k3] := Att[Lpos + Lw_k3] xor (Lt shl Ls_k3);
    Att[Lpos + Lw_k3 + 1] := Att[Lpos + Lw_k3 + 1] xor TBitOperations.NegativeRightShift64(Lt, -Ls_k3);
    System.Dec(Lpos);
  until Lpos < 0;
  System.Move(Att^, Az^, (Lw_n) * System.SizeOf(UInt64));
  Az[Lw_n] := Att[Lw_n] and not (UInt64.MaxValue shl Ls_n);
end;

{ TBinPolyMulBasePentanomialReduce.TD }

constructor TBinPolyMulBasePentanomialReduce.TD.Create(AN: Int32; AK1: Int32; AK2: Int32; AK3: Int32);
begin
  inherited Create;
  FN := AN;
  FK1 := AK1;
  FK2 := AK2;
  FK3 := AK3;
{$IFDEF DEBUG}
  System.Assert(((AN and 63) <> 0) and (AK2 < 64) and (AK3 >= 64) and ((AK3 and 63) <> 0) and (AN - AK3 >= 64));
{$ENDIF}
end;

procedure TBinPolyMulBasePentanomialReduce.TD.Reduce(Att: PUInt64; Az: PUInt64);
var
  Lk1: Int32;
  Lk2: Int32;
  Lk3: Int32;
  Ln: Int32;
  Lw_n: Int32;
  Ls_n: Int32;
  Lw_k3: Int32;
  Ls_k3: Int32;
  Lpos: Int32;
  Lt: UInt64;
begin
  Ln := FN;
  Lk1 := FK1;
  Lk2 := FK2;
  Lk3 := FK3;
{$IFDEF DEBUG}
  TBinPolyMulBase.DebugAssertReducePreconditions(Ln, Att);
{$ENDIF}
  TBinPolyMulBase.BitPos(Ln, Lw_n, Ls_n);
  TBinPolyMulBase.BitPos(Lk3, Lw_k3, Ls_k3);
{$IFDEF DEBUG}
  System.Assert(Lw_n >= 2);
{$ENDIF}
  Lpos := Lw_n;
  repeat
    Lt := (Att[Lpos + Lw_n] shr Ls_n)
      or TBitOperations.NegativeLeftShift64(Att[Lpos + Lw_n + 1], -Ls_n);
    Att[Lpos] := Att[Lpos] xor Lt xor (Lt shl Lk1) xor (Lt shl Lk2);
    Att[Lpos + 1] := Att[Lpos + 1] xor TBitOperations.NegativeRightShift64(Lt, -Lk1)
      xor TBitOperations.NegativeRightShift64(Lt, -Lk2);
    Att[Lpos + Lw_k3] := Att[Lpos + Lw_k3] xor (Lt shl Ls_k3);
    Att[Lpos + Lw_k3 + 1] := Att[Lpos + Lw_k3 + 1] xor TBitOperations.NegativeRightShift64(Lt, -Ls_k3);
    System.Dec(Lpos);
  until Lpos < 0;
  System.Move(Att^, Az^, (Lw_n) * System.SizeOf(UInt64));
  Az[Lw_n] := Att[Lw_n] and not (UInt64.MaxValue shl Ls_n);
end;

{ TBinPolyMulBasePentanomialReduce.TC }

constructor TBinPolyMulBasePentanomialReduce.TC.Create(AN: Int32; AK1: Int32; AK2: Int32; AK3: Int32);
begin
  inherited Create;
  FN := AN;
  FK1 := AK1;
  FK2 := AK2;
  FK3 := AK3;
{$IFDEF DEBUG}
  System.Assert((AN - AK3 < 64) or ((AK1 and 63) = 0) or ((AK2 and 63) = 0) or ((AK3 and 63) = 0));
{$ENDIF}
end;

procedure TBinPolyMulBasePentanomialReduce.TC.Reduce(Att: PUInt64; Az: PUInt64);
var
  Lk1: Int32;
  Lk2: Int32;
  Lk3: Int32;
  Ln: Int32;
  Lpos_0: Int32;
  Lw_n: Int32;
  Ls_n: Int32;
  Lw_0: Int32;
  Ls_0: Int32;
  Lw_k1: Int32;
  Ls_k1: Int32;
  Lw_k2: Int32;
  Ls_k2: Int32;
  Lw_k3: Int32;
  Ls_k3: Int32;
  Lw_top: Int32;
  Ls_top: Int32;
  Lbit_n: UInt64;
begin
  Ln := FN;
  Lk1 := FK1;
  Lk2 := FK2;
  Lk3 := FK3;
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
    TBinPolyMulBase.BitPos(Lpos_0 + Lk1, Lw_k1, Ls_k1);
    Att[Lw_k1] := Att[Lw_k1] xor (Lbit_n shl Ls_k1);
    TBinPolyMulBase.BitPos(Lpos_0 + Lk2, Lw_k2, Ls_k2);
    Att[Lw_k2] := Att[Lw_k2] xor (Lbit_n shl Ls_k2);
    TBinPolyMulBase.BitPos(Lpos_0 + Lk3, Lw_k3, Ls_k3);
    Att[Lw_k3] := Att[Lw_k3] xor (Lbit_n shl Ls_k3);
    System.Dec(Lpos_0);
  end;
  TBinPolyMulBase.BitPos(Ln, Lw_top, Ls_top);
  System.Move(Att^, Az^, (Lw_top) * System.SizeOf(UInt64));
  {Ls_top = 0 (Ln a multiple of 64): the copy above already wrote the full top}
  {limb (Lw_top = Lsize); no partial-limb mask, and z has no limb Lw_top to write.}
  if Ls_top <> 0 then
  Az[Lw_top] := Att[Lw_top] and not (UInt64.MaxValue shl Ls_top);
end;

{ TBinPolyMulBasePentanomialReduce.TE }

constructor TBinPolyMulBasePentanomialReduce.TE.Create(AN: Int32; AK1: Int32; AK2: Int32; AK3: Int32);
begin
  inherited Create;
  FN := AN;
  FK1 := AK1;
  FK2 := AK2;
  FK3 := AK3;
{$IFDEF DEBUG}
  System.Assert(((AN and 63) = 0) and ((AK1 and 63) <> 0) and ((AK2 and 63) <> 0) and ((AK3 and 63) <> 0) and (AN - AK3 >= 64));
{$ENDIF}
end;

procedure TBinPolyMulBasePentanomialReduce.TE.Reduce(Att: PUInt64; Az: PUInt64);
var
  Lk1: Int32;
  Lk2: Int32;
  Lk3: Int32;
  Ln: Int32;
  LW: Int32;
  Lw_k1: Int32;
  Ls_k1: Int32;
  Lw_k2: Int32;
  Ls_k2: Int32;
  Lw_k3: Int32;
  Ls_k3: Int32;
  Lpos: Int32;
  Lt: UInt64;
begin
  Ln := FN;
  Lk1 := FK1;
  Lk2 := FK2;
  Lk3 := FK3;
{$IFDEF DEBUG}
  TBinPolyMulBase.DebugAssertReducePreconditions(Ln, Att);
{$ENDIF}
  LW := (Ln shr 6);
  TBinPolyMulBase.BitPos(Lk1, Lw_k1, Ls_k1);
  TBinPolyMulBase.BitPos(Lk2, Lw_k2, Ls_k2);
  TBinPolyMulBase.BitPos(Lk3, Lw_k3, Ls_k3);
{$IFDEF DEBUG}
  System.Assert((Ls_k1 <> 0) and (Ls_k2 <> 0) and (Ls_k3 <> 0) and (Lw_k3 <= LW - 2));
{$ENDIF}
  Lpos := LW - 1;
  repeat
    Lt := Att[Lpos + LW];
    Att[Lpos] := Att[Lpos] xor Lt;
    Att[Lpos + Lw_k1] := Att[Lpos + Lw_k1] xor (Lt shl Ls_k1);
    Att[Lpos + Lw_k1 + 1] := Att[Lpos + Lw_k1 + 1] xor TBitOperations.NegativeRightShift64(Lt, -Ls_k1);
    Att[Lpos + Lw_k2] := Att[Lpos + Lw_k2] xor (Lt shl Ls_k2);
    Att[Lpos + Lw_k2 + 1] := Att[Lpos + Lw_k2 + 1] xor TBitOperations.NegativeRightShift64(Lt, -Ls_k2);
    Att[Lpos + Lw_k3] := Att[Lpos + Lw_k3] xor (Lt shl Ls_k3);
    Att[Lpos + Lw_k3 + 1] := Att[Lpos + Lw_k3 + 1] xor TBitOperations.NegativeRightShift64(Lt, -Ls_k3);
    System.Dec(Lpos);
  until Lpos < 0;
  System.Move(Att^, Az^, (LW) * System.SizeOf(UInt64));
end;

end.
