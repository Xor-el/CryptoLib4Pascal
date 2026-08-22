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

unit ClpCTFieldArith;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpFpKernelSimd,
  ClpCTFieldValue,
  ClpCryptoLibTypes;

type
  /// <summary>The Montgomery-domain constants a curve supplies to the shared field
  /// arithmetic: the CIOS context plus the fixed operands the domain ops need.</summary>
  TMontParams = record
    CtxData: array [0 .. 10] of UInt64; // [n0', N, p0..p(N-1)] (N in [1], max N = 9)
    R2: TFe;      // R^2 mod p       (ToMont operand)
    MontOne: TFe; // R mod p         (Montgomery form of 1)
    Fb3: TFe;     // 3b * R mod p    (MulByB3 operand, Montgomery form)
  end;

  PMontParams = ^TMontParams;

  /// <summary>
  /// Per-curve prime-field arithmetic for the value-type constant-time ladder. The
  /// ladder runs in the Montgomery domain (every field element is x*R mod p); the
  /// domain ops (<c>Mul</c>/<c>Sqr</c>/<c>MulByB3</c>/<c>SetOne</c>/<c>ToMont</c>/
  /// <c>FromMont</c>) are implemented ONCE here and are identical for every curve -
  /// a curve only supplies its constants (<c>MontParams</c>) and the genuinely
  /// curve-specific ops (<c>Add</c>/<c>Sub</c>/<c>MulByA</c>, which depend on p and a).
  /// The generic <c>TCTPoint&lt;TOps: TCTFieldArithBase&gt;</c> dispatches to it with
  /// no interface dispatch and every temporary a stack <see cref="TFe"/>.
  /// </summary>
  TCTFieldArithBase = class
  strict private
    /// <summary>128-bit product APHi:APLo := AX * AY.</summary>
    class procedure Mul64(AX, AY: UInt64; out APHi, APLo: UInt64); static;
  public
    // ---- curve-specific providers ----
    /// <summary>uint32 limb count N for this curve (P-256 = 8).</summary>
    class function FieldLimbs: Int32; virtual; abstract;
    /// <summary>Pointer to this curve's Montgomery constants.</summary>
    class function MontParams: PMontParams; virtual; abstract;
    /// <summary>AZ := a * AX mod p (curve coefficient a; a=-3 folds to MulByMinusThree,
    /// a=0 to FillChar). The only genuinely per-curve op left.</summary>
    class procedure MulByA(const AX: TFe; var AZ: TFe; var ATT: TFeExt); virtual; abstract;

    // ---- shared ops (one implementation for every curve) ----
    /// <summary>AZ := MontMul(AX, AY) = AX*AY*R^-1 mod p. ATT is caller-owned scratch.</summary>
    class procedure Mul(const AX, AY: TFe; var AZ: TFe; var ATT: TFeExt); virtual;
    /// <summary>AZ := MontMul(AX, AX).</summary>
    class procedure Sqr(const AX: TFe; var AZ: TFe; var ATT: TFeExt); virtual;
    /// <summary>AZ := AX + AY mod p (domain-agnostic; modulus from MontParams).</summary>
    class procedure Add(const AX, AY: TFe; var AZ: TFe); virtual;
    /// <summary>AZ := AX - AY mod p (domain-agnostic; modulus from MontParams).</summary>
    class procedure Sub(const AX, AY: TFe; var AZ: TFe); virtual;
    /// <summary>AZ := -3 * AX = -(AX+AX+AX) mod p (for a=-3 curves' MulByA).</summary>
    class procedure MulByMinusThree(const AX: TFe; var AZ: TFe);
    /// <summary>AZ := 3b * AX (Fb3 held in Montgomery form).</summary>
    class procedure MulByB3(const AX: TFe; var AZ: TFe; var ATT: TFeExt); virtual;
    /// <summary>AZ := Montgomery form of 1 (= R mod p).</summary>
    class procedure SetOne(var AZ: TFe); virtual;
    /// <summary>AZ := AX*R mod p (normal domain -> Montgomery).</summary>
    class procedure ToMont(const AX: TFe; var AZ: TFe; var ATT: TFeExt); virtual;
    /// <summary>AZ := AX*R^-1 mod p (Montgomery -> normal domain).</summary>
    class procedure FromMont(const AX: TFe; var AZ: TFe; var ATT: TFeExt); virtual;

    // ---- shared helpers (curve setup + scalar fallback) ----
    /// <summary>Zero-fill AFe then copy ALimbs uint32 limbs of AArr into it.</summary>
    class procedure ArrToFe(const AArr: TCryptoLibUInt32Array; ALimbs: Int32; out AFe: TFe); static;
    /// <summary>n0' = -p^-1 mod 2^64 from the low 64-bit limb of p (Newton).</summary>
    class function ComputeN0Prime(AP0: UInt64): UInt64; static;
    /// <summary>Width-general CIOS Montgomery multiply - the fallback used when the
    /// asm kernel is unavailable (forced-scalar / unsupported CPU). Same contract as
    /// the asm kernel: APCtx = [n0', N, p[0..N-1]] (64-bit limbs), APR receives the
    /// reduced N-limb result (needs N+2 scratch limbs of headroom).</summary>
    class procedure MontMul(APR, APA, APB, APCtx: PUInt64); static;
    /// <summary>Width-general constant-time modular add/sub - the fallback used when
    /// the asm kernel is unavailable. APCtx = [n0'(unused), N, p[0..N-1]]; inputs < p.</summary>
    class procedure ModAdd(APR, APA, APB, APCtx: PUInt64); static;
    class procedure ModSub(APR, APA, APB, APCtx: PUInt64); static;
  end;

implementation

class procedure TCTFieldArithBase.Mul64(AX, AY: UInt64; out APHi, APLo: UInt64);
var
  LXl, LXh, LYl, LYh, LLL, LLh, LHl, LMid: UInt64;
begin
  LXl := AX and $FFFFFFFF; LXh := AX shr 32;
  LYl := AY and $FFFFFFFF; LYh := AY shr 32;
  LLL := LXl * LYl; LLh := LXl * LYh; LHl := LXh * LYl;
  LMid := (LLL shr 32) + (LLh and $FFFFFFFF) + (LHl and $FFFFFFFF);
  APLo := (LLL and $FFFFFFFF) or (LMid shl 32);
  APHi := LXh * LYh + (LLh shr 32) + (LHl shr 32) + (LMid shr 32);
end;

class procedure TCTFieldArithBase.ArrToFe(const AArr: TCryptoLibUInt32Array;
  ALimbs: Int32; out AFe: TFe);
begin
  FillChar(AFe, SizeOf(AFe), 0);
  Move(AArr[0], AFe.W[0], ALimbs * SizeOf(UInt32));
end;

class function TCTFieldArithBase.ComputeN0Prime(AP0: UInt64): UInt64;
var
  LInv: UInt64;
  LI: Int32;
begin
  // p is odd => p0^-1 mod 2^8 == p0 mod 2^8 (3 correct bits); Newton doubles them.
  LInv := AP0;
  for LI := 1 to 5 do
    LInv := LInv * (UInt64(2) - AP0 * LInv);
  Result := UInt64(0) - LInv;
end;

class procedure TCTFieldArithBase.MontMul(APR, APA, APB, APCtx: PUInt64);
var
  Lt: array [0 .. 19] of UInt64;
  Ld: array [0 .. 9] of UInt64;
  LPMod: PUInt64;
  LN, LI, LJ: Int32;
  LN0, LM, LHi, LLo, LC, LS, LX, LBorrowIn, LB1, LB2, LMask: UInt64;
begin
  LN0 := APCtx[0];
  LN := Int32(APCtx[1]);
  LPMod := APCtx;
  Inc(LPMod, 2);
  for LI := 0 to LN + 1 do
    Lt[LI] := 0;
  for LI := 0 to LN - 1 do
  begin
    LC := 0;
    for LJ := 0 to LN - 1 do
    begin
      Mul64(APA[LJ], APB[LI], LHi, LLo);
      LLo := LLo + Lt[LJ]; if LLo < Lt[LJ] then Inc(LHi);
      LLo := LLo + LC;     if LLo < LC     then Inc(LHi);
      Lt[LJ] := LLo; LC := LHi;
    end;
    LS := Lt[LN] + LC; Lt[LN] := LS; if LS < LC then Lt[LN + 1] := 1 else Lt[LN + 1] := 0;
    LM := Lt[0] * LN0;
    Mul64(LM, LPMod[0], LHi, LLo);
    LLo := LLo + Lt[0]; if LLo < Lt[0] then Inc(LHi);
    LC := LHi;
    for LJ := 1 to LN - 1 do
    begin
      Mul64(LM, LPMod[LJ], LHi, LLo);
      LLo := LLo + Lt[LJ]; if LLo < Lt[LJ] then Inc(LHi);
      LLo := LLo + LC;     if LLo < LC     then Inc(LHi);
      Lt[LJ - 1] := LLo; LC := LHi;
    end;
    LS := Lt[LN] + LC; Lt[LN - 1] := LS;
    if LS < LC then Lt[LN] := Lt[LN + 1] + 1 else Lt[LN] := Lt[LN + 1];
  end;
  // constant-time final reduce: mask-select between t and (t - p)
  LBorrowIn := 0;
  for LI := 0 to LN - 1 do
  begin
    LX := Lt[LI] - LBorrowIn; LB1 := Ord(Lt[LI] < LBorrowIn);
    Ld[LI] := LX - LPMod[LI]; LB2 := Ord(LX < LPMod[LI]);
    LBorrowIn := LB1 + LB2;
  end;
  LMask := UInt64(0) - UInt64(Ord(Lt[LN] < LBorrowIn)); // all-ones if t < p (keep t)
  for LI := 0 to LN - 1 do
    APR[LI] := (Lt[LI] and LMask) or (Ld[LI] and (not LMask));
end;

class procedure TCTFieldArithBase.Mul(const AX, AY: TFe; var AZ: TFe; var ATT: TFeExt);
var
  LP: PMontParams;
begin
  LP := MontParams;
  if not TFpKernelSimd.TryMontMul(PUInt64(@ATT.W[0]), PUInt64(@AX.W[0]),
    PUInt64(@AY.W[0]), PUInt64(@LP^.CtxData[0])) then
    MontMul(PUInt64(@ATT.W[0]), PUInt64(@AX.W[0]), PUInt64(@AY.W[0]),
      PUInt64(@LP^.CtxData[0]));
  Move(ATT.W[0], AZ.W[0], (Int32(LP^.CtxData[1]) * 2) * SizeOf(UInt32));
end;

class procedure TCTFieldArithBase.Sqr(const AX: TFe; var AZ: TFe; var ATT: TFeExt);
begin
  Mul(AX, AX, AZ, ATT); // dedicated MontSqr is a later perf layer
end;

class procedure TCTFieldArithBase.MulByB3(const AX: TFe; var AZ: TFe; var ATT: TFeExt);
begin
  Mul(AX, MontParams^.Fb3, AZ, ATT);
end;

class procedure TCTFieldArithBase.SetOne(var AZ: TFe);
begin
  AZ := MontParams^.MontOne;
end;

class procedure TCTFieldArithBase.ToMont(const AX: TFe; var AZ: TFe; var ATT: TFeExt);
begin
  Mul(AX, MontParams^.R2, AZ, ATT); // AX * R^2 * R^-1 = AX * R
end;

class procedure TCTFieldArithBase.FromMont(const AX: TFe; var AZ: TFe; var ATT: TFeExt);
var
  LOne: TFe;
begin
  FillChar(LOne, SizeOf(LOne), 0);
  LOne.W[0] := 1;
  Mul(AX, LOne, AZ, ATT); // AX * 1 * R^-1 = AX * R^-1
end;

class procedure TCTFieldArithBase.Add(const AX, AY: TFe; var AZ: TFe);
var
  LP: PMontParams;
begin
  LP := MontParams;
  if not TFpKernelSimd.TryModAdd(PUInt64(@AZ.W[0]), PUInt64(@AX.W[0]),
    PUInt64(@AY.W[0]), PUInt64(@LP^.CtxData[0])) then
    ModAdd(PUInt64(@AZ.W[0]), PUInt64(@AX.W[0]), PUInt64(@AY.W[0]),
      PUInt64(@LP^.CtxData[0]));
end;

class procedure TCTFieldArithBase.Sub(const AX, AY: TFe; var AZ: TFe);
var
  LP: PMontParams;
begin
  LP := MontParams;
  if not TFpKernelSimd.TryModSub(PUInt64(@AZ.W[0]), PUInt64(@AX.W[0]),
    PUInt64(@AY.W[0]), PUInt64(@LP^.CtxData[0])) then
    ModSub(PUInt64(@AZ.W[0]), PUInt64(@AX.W[0]), PUInt64(@AY.W[0]),
      PUInt64(@LP^.CtxData[0]));
end;

class procedure TCTFieldArithBase.MulByMinusThree(const AX: TFe; var AZ: TFe);
var
  LT, LZero: TFe;
begin
  Add(AX, AX, LT);   // 2*AX
  Add(LT, AX, LT);   // 3*AX
  FillChar(LZero, SizeOf(LZero), 0);
  Sub(LZero, LT, AZ); // -3*AX
end;

class procedure TCTFieldArithBase.ModAdd(APR, APA, APB, APCtx: PUInt64);
var
  Ld: array [0 .. 9] of UInt64;
  LPMod: PUInt64;
  LN, LI: Int32;
  LC, LS, LX, LBorrow, LB1, LB2, LMask: UInt64;
begin
  LN := Int32(APCtx[1]);
  LPMod := APCtx;
  Inc(LPMod, 2);
  LC := 0;
  for LI := 0 to LN - 1 do
  begin
    LS := APA[LI] + APB[LI]; LX := Ord(LS < APA[LI]);
    LS := LS + LC; LX := LX + Ord(LS < LC);
    APR[LI] := LS; LC := LX;
  end;
  // constant-time: subtract p into Ld, mask-select if (carry) or (no borrow)
  LBorrow := 0;
  for LI := 0 to LN - 1 do
  begin
    LS := APR[LI] - LBorrow; LB1 := Ord(APR[LI] < LBorrow);
    Ld[LI] := LS - LPMod[LI]; LB2 := Ord(LS < LPMod[LI]);
    LBorrow := LB1 + LB2;
  end;
  LMask := UInt64(0) - (UInt64(Ord(LC <> 0)) or UInt64(Ord(LBorrow = 0)));
  for LI := 0 to LN - 1 do
    APR[LI] := (Ld[LI] and LMask) or (APR[LI] and (not LMask));
end;

class procedure TCTFieldArithBase.ModSub(APR, APA, APB, APCtx: PUInt64);
var
  LPMod: PUInt64;
  LN, LI: Int32;
  LC, LS, LX, LBorrow, LB1, LB2, LMask: UInt64;
begin
  LN := Int32(APCtx[1]);
  LPMod := APCtx;
  Inc(LPMod, 2);
  LBorrow := 0;
  for LI := 0 to LN - 1 do
  begin
    LS := APA[LI] - LBorrow; LB1 := Ord(APA[LI] < LBorrow);
    APR[LI] := LS - APB[LI]; LB2 := Ord(LS < APB[LI]);
    LBorrow := LB1 + LB2;
  end;
  LMask := UInt64(0) - LBorrow; // all-ones if A < B (add p back)
  LC := 0;
  for LI := 0 to LN - 1 do
  begin
    LS := APR[LI] + (LPMod[LI] and LMask); LX := Ord(LS < APR[LI]);
    LS := LS + LC; LX := LX + Ord(LS < LC);
    APR[LI] := LS; LC := LX;
  end;
end;

end.
