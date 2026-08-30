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
  ClpMontKernelSimd,
  ClpCTFieldValue,
  ClpBinaryPrimitives,
  ClpCryptoLibTypes;

type
  /// <summary>Form of the curve coefficient a, selecting which RCB2016 complete
  /// group law a curve runs: <c>MinusThree</c> uses the a=-3 formulas
  /// (Algorithms 4/6), <c>Zero</c> the a=0 formulas (Algorithms 7/9), and
  /// <c>General</c> the general-a Algorithms 1/3.</summary>
  TCTACoeff = (General, MinusThree, Zero);

  /// <summary>The Montgomery-domain constants a curve supplies to the shared field
  /// arithmetic: the CIOS context plus the fixed operands the domain ops need.</summary>
  TMontParams = record
    CtxData: array [0 .. 10] of UInt64; // [n0', N, p0..p(N-1)] (N in [1], max N = 9)
    R2: TFe;      // R^2 mod p       (ToMont operand)
    MontOne: TFe; // R mod p         (Montgomery form of 1)
  end;

  PMontParams = ^TMontParams;

  /// <summary>
  /// Per-curve prime-field arithmetic for the value-type constant-time ladder. The
  /// ladder runs in the Montgomery domain (every field element is x*R mod p); the
  /// domain ops (<c>Mul</c>/<c>Sqr</c>/<c>SetOne</c>/<c>ToMont</c>/
  /// <c>FromMont</c>) are implemented ONCE here and are identical for every curve -
  /// a curve only supplies its constants (<c>MontParams</c>) and the genuinely
  /// curve-specific ops (<c>Add</c>/<c>Sub</c>, which depend on p).
  /// The generic <c>TCTJacPoint&lt;TOps: TCTFieldArithBase&gt;</c> dispatches to it with
  /// no interface dispatch and every temporary a stack <see cref="TFe"/>.
  /// </summary>
  TCTFieldArithBase = class
  strict private
    /// <summary>128-bit product APHi:APLo := AX * AY.</summary>
    class procedure Mul64(AX, AY: UInt64; out APHi, APLo: UInt64); static;
    /// <summary>Read the AIdx-th 64-bit limb from a uint32-limb array
    /// (limb = W[2*AIdx] + W[2*AIdx+1] * 2^32).</summary>
    class function LoadLimb(AP: PCardinal; AIdx: Int32): UInt64; static; inline;
    /// <summary>Write AVal into the AIdx-th uint32 limb pair.</summary>
    class procedure StoreLimb(AP: PCardinal; AIdx: Int32; AVal: UInt64); static; inline;
  public
    // ---- curve-specific providers ----
    /// <summary>uint32 limb count N for this curve (P-256 = 8).</summary>
    class function FieldLimbs: Int32; virtual; abstract;
    /// <summary>Pointer to this curve's Montgomery constants.</summary>
    class function MontParams: PMontParams; virtual; abstract;
    /// <summary>Form of the coefficient a. Default <c>General</c>; a=-3 curves
    /// override to <c>MinusThree</c> to take the faster complete formulas.</summary>
    class function ACoeff: TCTACoeff; virtual;
    /// <summary>Optional fused incomplete-Jacobian doubling: APR := 2*APA (Jacobian).
    /// Default False -> generic per-op Jacobian formula.</summary>
    class function TryFusedJacPointDouble(APR, APA: PUInt64): Boolean; virtual;
    /// <summary>Optional fused incomplete-Jacobian addition. APScratch is a
    /// <c>TJacAddScratch</c> base receiving the masked-infinity-completed sum in R and
    /// the predicate operands H (= U2-U1) and RS (= S2-S1); the caller owns the P=Q
    /// detect-and-double. APA/APQ are <c>TFePoint</c> bases. Default False.</summary>
    class function TryFusedJacPointAdd(APScratch, APA, APQ: PUInt64): Boolean; virtual;
    /// <summary>Optional fused mixed incomplete-Jacobian addition: APQ is a
    /// <c>TFeAffine</c> base (implicit Z2=1). Default False.</summary>
    class function TryFusedJacPointAddMixed(APScratch, APA, APQ: PUInt64): Boolean; virtual;
    /// <summary>
    /// Montgomery-domain modular inverse AZ := AX^-1 mod p (input and output
    /// Montgomery-domain, AX non-zero) via a curve-specific Fermat addition
    /// chain over the field kernels. False when the curve has no dedicated
    /// chain; the caller then uses its generic inverse.
    /// </summary>
    class function TryInvMont(const AX: TFe; var AZ: TFe; var ATT: TFeExt): Boolean; virtual;

    // ---- shared ops (one implementation for every curve) ----
    /// <summary>AZ := MontMul(AX, AY) = AX*AY*R^-1 mod p. ATT is caller-owned scratch.</summary>
    class procedure Mul(const AX, AY: TFe; var AZ: TFe; var ATT: TFeExt); virtual;
    /// <summary>AZ := MontMul(AX, AX).</summary>
    class procedure Sqr(const AX: TFe; var AZ: TFe; var ATT: TFeExt); virtual;
    /// <summary>AZ := AX + AY mod p (domain-agnostic; modulus from MontParams).</summary>
    class procedure Add(const AX, AY: TFe; var AZ: TFe); virtual;
    /// <summary>AZ := AX - AY mod p (domain-agnostic; modulus from MontParams).</summary>
    class procedure Sub(const AX, AY: TFe; var AZ: TFe); virtual;
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
    /// <summary>Pack ALimbs32 uint32 modulus limbs at AP into ceil(ALimbs32/2)
    /// 64-bit limbs at APCtx (the CIOS ctx p[] slots).</summary>
    class procedure LoadModulus(AP: PCardinal; ALimbs32: Int32; APCtx: PUInt64); static;
    /// <summary>Width-general CIOS Montgomery multiply. The field operands APR/APA/APB
    /// are uint32-limb arrays read through <c>LoadLimb</c>; APCtx = [n0', N, p[0..N-1]]
    /// (64-bit limbs). APR receives the reduced N-limb result (needs N+2 scratch limbs
    /// of headroom).</summary>
    class procedure MontMul(APR, APA, APB: PCardinal; APCtx: PUInt64); static;
    /// <summary>Width-general constant-time modular add/sub. Operands are uint32-limb
    /// arrays; APCtx = [n0'(unused), N, p[0..N-1]]; inputs < p.</summary>
    class procedure ModAdd(APR, APA, APB: PCardinal; APCtx: PUInt64); static;
    class procedure ModSub(APR, APA, APB: PCardinal; APCtx: PUInt64); static;
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

class function TCTFieldArithBase.LoadLimb(AP: PCardinal; AIdx: Int32): UInt64;
begin
  Result := UInt64(TBinaryPrimitives.LoadUInt32(@AP[2 * AIdx])) or
    (UInt64(TBinaryPrimitives.LoadUInt32(@AP[2 * AIdx + 1])) shl 32);
end;

class procedure TCTFieldArithBase.StoreLimb(AP: PCardinal; AIdx: Int32; AVal: UInt64);
begin
  TBinaryPrimitives.StoreUInt32(@AP[2 * AIdx], UInt32(AVal));
  TBinaryPrimitives.StoreUInt32(@AP[2 * AIdx + 1], UInt32(AVal shr 32));
end;

class procedure TCTFieldArithBase.LoadModulus(AP: PCardinal; ALimbs32: Int32; APCtx: PUInt64);
var
  LI: Int32;
  LHi: UInt32;
begin
  LI := 0;
  while (LI * 2) < ALimbs32 do
  begin
    if (LI * 2 + 1) < ALimbs32 then
      LHi := TBinaryPrimitives.LoadUInt32(@AP[LI * 2 + 1])
    else
      LHi := 0;
    APCtx[LI] := UInt64(TBinaryPrimitives.LoadUInt32(@AP[LI * 2])) or (UInt64(LHi) shl 32);
    Inc(LI);
  end;
end;

class procedure TCTFieldArithBase.MontMul(APR, APA, APB: PCardinal; APCtx: PUInt64);
var
  LA, LB: array [0 .. 9] of UInt64;
  Lt: array [0 .. 19] of UInt64;
  LD: array [0 .. 9] of UInt64;
  LPMod: PUInt64;
  LN, LI, LJ: Int32;
  LN0, LM, LHi, LLo, LC, LS, LX, LBorrowIn, LB1, LB2, LMask, LBI: UInt64;
begin
  LN0 := APCtx[0];
  LN := Int32(APCtx[1]);
  LPMod := APCtx;
  Inc(LPMod, 2);
  for LI := 0 to LN - 1 do
  begin
    LA[LI] := LoadLimb(APA, LI);
    LB[LI] := LoadLimb(APB, LI);
  end;
  for LI := 0 to LN + 1 do
    Lt[LI] := 0;
  for LI := 0 to LN - 1 do
  begin
    LBI := LB[LI];
    LC := 0;
    for LJ := 0 to LN - 1 do
    begin
      Mul64(LA[LJ], LBI, LHi, LLo);
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
    LD[LI] := LX - LPMod[LI]; LB2 := Ord(LX < LPMod[LI]);
    LBorrowIn := LB1 + LB2;
  end;
  LMask := UInt64(0) - UInt64(Ord(Lt[LN] < LBorrowIn)); // all-ones if t < p (keep t)
  for LI := 0 to LN - 1 do
    StoreLimb(APR, LI, (Lt[LI] and LMask) or (LD[LI] and (not LMask)));
end;

class procedure TCTFieldArithBase.Mul(const AX, AY: TFe; var AZ: TFe; var ATT: TFeExt);
var
  LP: PMontParams;
begin
  LP := MontParams;
  if not TMontKernelSimd.TryMontMul(PUInt64(@ATT.W[0]), PUInt64(@AX.W[0]),
    PUInt64(@AY.W[0]), PUInt64(@LP^.CtxData[0])) then
    MontMul(PCardinal(@ATT.W[0]), PCardinal(@AX.W[0]), PCardinal(@AY.W[0]),
      PUInt64(@LP^.CtxData[0]));
  Move(ATT.W[0], AZ.W[0], (Int32(LP^.CtxData[1]) * 2) * SizeOf(UInt32));
end;

class procedure TCTFieldArithBase.Sqr(const AX: TFe; var AZ: TFe; var ATT: TFeExt);
begin
  Mul(AX, AX, AZ, ATT);
end;

class function TCTFieldArithBase.ACoeff: TCTACoeff;
begin
  Result := TCTACoeff.General;
end;

class function TCTFieldArithBase.TryInvMont(const AX: TFe; var AZ: TFe; var ATT: TFeExt): Boolean;
begin
  Result := False; // no dedicated inversion chain; caller uses its generic inverse
end;

class function TCTFieldArithBase.TryFusedJacPointDouble(APR, APA: PUInt64): Boolean;
begin
  Result := False; // generic curves run the per-op Jacobian formula
end;

class function TCTFieldArithBase.TryFusedJacPointAdd(APScratch, APA, APQ: PUInt64): Boolean;
begin
  Result := False; // generic curves run the per-op Jacobian formula
end;

class function TCTFieldArithBase.TryFusedJacPointAddMixed(APScratch, APA, APQ: PUInt64): Boolean;
begin
  Result := False; // generic curves run the per-op Jacobian formula
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
  if not TMontKernelSimd.TryModAdd(PUInt64(@AZ.W[0]), PUInt64(@AX.W[0]),
    PUInt64(@AY.W[0]), PUInt64(@LP^.CtxData[0])) then
    ModAdd(PCardinal(@AZ.W[0]), PCardinal(@AX.W[0]), PCardinal(@AY.W[0]),
      PUInt64(@LP^.CtxData[0]));
end;

class procedure TCTFieldArithBase.Sub(const AX, AY: TFe; var AZ: TFe);
var
  LP: PMontParams;
begin
  LP := MontParams;
  if not TMontKernelSimd.TryModSub(PUInt64(@AZ.W[0]), PUInt64(@AX.W[0]),
    PUInt64(@AY.W[0]), PUInt64(@LP^.CtxData[0])) then
    ModSub(PCardinal(@AZ.W[0]), PCardinal(@AX.W[0]), PCardinal(@AY.W[0]),
      PUInt64(@LP^.CtxData[0]));
end;

class procedure TCTFieldArithBase.ModAdd(APR, APA, APB: PCardinal; APCtx: PUInt64);
var
  LR, LD: array [0 .. 9] of UInt64;
  LPMod: PUInt64;
  LN, LI: Int32;
  LC, LS, LX, LA, LBorrow, LB1, LB2, LMask: UInt64;
begin
  LN := Int32(APCtx[1]);
  LPMod := APCtx;
  Inc(LPMod, 2);
  LC := 0;
  for LI := 0 to LN - 1 do
  begin
    LA := LoadLimb(APA, LI);
    LS := LA + LoadLimb(APB, LI); LX := Ord(LS < LA);
    LS := LS + LC; LX := LX + Ord(LS < LC);
    LR[LI] := LS; LC := LX;
  end;
  // constant-time: subtract p into LD, mask-select if (carry) or (no borrow)
  LBorrow := 0;
  for LI := 0 to LN - 1 do
  begin
    LS := LR[LI] - LBorrow; LB1 := Ord(LR[LI] < LBorrow);
    LD[LI] := LS - LPMod[LI]; LB2 := Ord(LS < LPMod[LI]);
    LBorrow := LB1 + LB2;
  end;
  LMask := UInt64(0) - (UInt64(Ord(LC <> 0)) or UInt64(Ord(LBorrow = 0)));
  for LI := 0 to LN - 1 do
    StoreLimb(APR, LI, (LD[LI] and LMask) or (LR[LI] and (not LMask)));
end;

class procedure TCTFieldArithBase.ModSub(APR, APA, APB: PCardinal; APCtx: PUInt64);
var
  LR: array [0 .. 9] of UInt64;
  LPMod: PUInt64;
  LN, LI: Int32;
  LC, LS, LX, LA, LB, LBorrow, LB1, LB2, LMask: UInt64;
begin
  LN := Int32(APCtx[1]);
  LPMod := APCtx;
  Inc(LPMod, 2);
  LBorrow := 0;
  for LI := 0 to LN - 1 do
  begin
    LA := LoadLimb(APA, LI); LB := LoadLimb(APB, LI);
    LS := LA - LBorrow; LB1 := Ord(LA < LBorrow);
    LR[LI] := LS - LB; LB2 := Ord(LS < LB);
    LBorrow := LB1 + LB2;
  end;
  LMask := UInt64(0) - LBorrow; // all-ones if A < B (add p back)
  LC := 0;
  for LI := 0 to LN - 1 do
  begin
    LS := LR[LI] + (LPMod[LI] and LMask); LX := Ord(LS < LR[LI]);
    LS := LS + LC; LX := LX + Ord(LS < LC);
    StoreLimb(APR, LI, LS); LC := LX;
  end;
end;

end.
