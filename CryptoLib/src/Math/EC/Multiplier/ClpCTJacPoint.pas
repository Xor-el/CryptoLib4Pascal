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

unit ClpCTJacPoint;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpNat,
  ClpBitOperations,
  ClpIFpFieldOps,
  ClpIECFieldElement,
  ClpCTFieldValue,
  ClpCTFieldArith,
  ClpCryptoLibTypes;

type
  /// <summary>Coordinate-neutral helpers shared by every value-type point engine:
  /// the full-table masked gathers. These touch only the flat limb layout of a
  /// point/affine record, so they are independent of the coordinate system (RCB
  /// homogeneous or incomplete Jacobian) and of the curve.</summary>
  TCTPointCommon = class sealed
  public
    /// <summary>Constant-time masked lookup: AR := ATable[AIndex], scanning all
    /// ACount entries so the access pattern is scalar-independent.</summary>
    class procedure SelectEntry(const AFieldOps: IFpFieldOps;
      const ATable: array of TFePoint; ACount, AIndex: Int32; var AR: TFePoint); static;
    /// <summary>Constant-time masked lookup over a flat affine table: AR :=
    /// ATable[ABase + AIndex], scanning ACount entries. AIndex outside
    /// [0, ACount) selects nothing, leaving AR zero.</summary>
    class procedure SelectAffineEntry(const AFieldOps: IFpFieldOps;
      const ATable: array of TFeAffine; ABase, ACount, AIndex: Int32;
      var AR: TFeAffine); static;
  end;

  /// <summary>
  /// Generic constant-time value-type point operations for Fp short-Weierstrass
  /// curves in Jacobian coordinates (x = X/Z^2, y = Y/Z^3, infinity = Z=0): the
  /// incomplete group law (fewer field muls than the RCB2016 complete law) made
  /// complete on the secret path by masked-cmov handling of the point-at-infinity
  /// cases and a detect-and-double branch for the P=Q case. One body
  /// serves every curve; the doubling is a-parameterised through
  /// <see cref="TCTFieldArithBase.ACoeff"/> (a=-3 trick for the NIST prime curves,
  /// the lean a=0 form for secp256k1) and the addition is a-independent.
  /// <c>TOps</c> supplies the Montgomery field arithmetic with no interface
  /// dispatch and every temporary a stack <see cref="TFe"/>.
  /// </summary>
  TCTJacPoint<TOps: TCTFieldArithBase> = class sealed
  strict private
    /// <summary>Incomplete Jacobian addition assuming both operands finite. Also
    /// returns the equal-affine predicate limbs: AHZero = -1 iff U1=U2, ARZero = -1
    /// iff S1=S2 (their conjunction is P=Q).</summary>
    class procedure AddIncomplete(const AP, AQ: TFePoint; var AR: TFePoint;
      out AHZero, ARZero: UInt32); static;
    class procedure MixedAddIncomplete(const AP: TFePoint; const AQ: TFeAffine;
      var AR: TFePoint; out AHZero, ARZero: UInt32); static;
    class procedure DoubleM3(const AP: TFePoint; var AR: TFePoint); static;
    class procedure DoubleZero(const AP: TFePoint; var AR: TFePoint); static;
    /// <summary>Branch-free masked-infinity completion of an incomplete full-add sum
    /// held in AR: AR := AIn1 ? AQ : (AIn2 ? AP : AR). Matches the fused kernel.</summary>
    class procedure CompleteInfinity(AIn1, AIn2: UInt32;
      const AP, AQ: TFePoint; var AR: TFePoint); static;
    /// <summary>uint32 limb count for the curve (2 * the CIOS 64-bit width). Read from
    /// MontParams rather than FieldLimbs: a virtual class method reached through the
    /// generic type parameter does not dispatch to the override under FPC.</summary>
    class function LimbCount: Int32; static; inline;
    /// <summary>-1 when AF is zero over the curve's N limbs, else 0 (branch-free).</summary>
    class function ZeroMask(const AF: TFe): UInt32; static;
    /// <summary>-1 when the Jacobian point is at infinity (Z=0), else 0.</summary>
    class function InfMask(const AP: TFePoint): UInt32; static;
  public
    /// <summary>AR := 2*AP. a=-3 curves take the dbl-2001-b trick, a=0 curves the
    /// lean dbl-2009-l form. Infinity (Z=0) maps to infinity with no branch. AR may
    /// alias AP.</summary>
    class procedure PointDouble(const AP: TFePoint; var AR: TFePoint); static;
    /// <summary>AR := AP + AQ (incomplete add + masked-infinity cmov + P=Q
    /// detect-and-double backstop). AR may alias AP or AQ.</summary>
    class procedure PointAdd(const AP, AQ: TFePoint; var AR: TFePoint); static;
    /// <summary>AR := AP + AQ with AQ affine (Z2=1). Same hybrid contract.</summary>
    class procedure PointAddMixed(const AP: TFePoint; const AQ: TFeAffine;
      var AR: TFePoint); static;
    class procedure OneFe(const AFieldOps: IFpFieldOps; var AZ: TFe); static;
    class procedure Infinity(const AFieldOps: IFpFieldOps; var AR: TFePoint); static;
    class procedure FromAffine(const AFieldOps: IFpFieldOps;
      const AXa, AYa: TCryptoLibUInt32Array; var AR: TFePoint); static;
    class procedure FromAffineElt(const AFieldOps: IFpFieldOps;
      const AX, AY: IECFieldElement; var AR: TFePoint); static;
    class procedure ToAffine(const AFieldOps: IFpFieldOps; const AP: TFePoint;
      const AXa, AYa: TCryptoLibUInt32Array; out AIsInfinity: Boolean); static;
    class procedure SelectEntry(const AFieldOps: IFpFieldOps;
      const ATable: array of TFePoint; ACount, AIndex: Int32; var AR: TFePoint); static;
    /// <summary>Randomized-Z rescale for the single-trace defense: (X*l^2, Y*l^3,
    /// Z*l) keeps the same affine point. ALambda is Montgomery-domain.</summary>
    class procedure ScaleRandom(const AP: TFePoint; const ALambda: TFe;
      var AR: TFePoint); static;
  end;

implementation

{ TCTPointCommon }

class procedure TCTPointCommon.SelectEntry(const AFieldOps: IFpFieldOps;
  const ATable: array of TFePoint; ACount, AIndex: Int32; var AR: TFePoint);
var
  LN, LI, LJ: Int32;
  LMask: UInt32;
  LEntry: ^TFePoint;
begin
  LN := AFieldOps.GetFieldInts;
  FillChar(AR, SizeOf(AR), 0);
  for LI := 0 to ACount - 1 do
  begin
    LEntry := @ATable[LI];
    LMask := UInt32(TBitOperations.Asr32(((LI xor AIndex) - 1), 31));
    for LJ := 0 to LN - 1 do
    begin
      AR.X.W[LJ] := AR.X.W[LJ] xor (LEntry^.X.W[LJ] and LMask);
      AR.Y.W[LJ] := AR.Y.W[LJ] xor (LEntry^.Y.W[LJ] and LMask);
      AR.Z.W[LJ] := AR.Z.W[LJ] xor (LEntry^.Z.W[LJ] and LMask);
    end;
  end;
end;

class procedure TCTPointCommon.SelectAffineEntry(const AFieldOps: IFpFieldOps;
  const ATable: array of TFeAffine; ABase, ACount, AIndex: Int32; var AR: TFeAffine);
var
  LN, LI, LJ: Int32;
  LMask: UInt32;
  LEntry: ^TFeAffine;
begin
  LN := AFieldOps.GetFieldInts;
  FillChar(AR, SizeOf(AR), 0);
  for LI := 0 to ACount - 1 do
  begin
    LEntry := @ATable[ABase + LI];
    LMask := UInt32(TBitOperations.Asr32(((LI xor AIndex) - 1), 31));
    for LJ := 0 to LN - 1 do
    begin
      AR.X.W[LJ] := AR.X.W[LJ] xor (LEntry^.X.W[LJ] and LMask);
      AR.Y.W[LJ] := AR.Y.W[LJ] xor (LEntry^.Y.W[LJ] and LMask);
    end;
  end;
end;

{ TCTJacPoint<TOps> }

class function TCTJacPoint<TOps>.LimbCount: Int32;
begin
  Result := Int32(TOps.MontParams^.CtxData[1]) shl 1;
end;

class function TCTJacPoint<TOps>.ZeroMask(const AF: TFe): UInt32;
var
  LN, LI: Int32;
  LAcc: UInt32;
begin
  LN := LimbCount;
  LAcc := 0;
  for LI := 0 to LN - 1 do
    LAcc := LAcc or AF.W[LI];
  Result := UInt32(0) - UInt32(Ord(LAcc = 0)); // all ones iff AF = 0, else 0
end;

class function TCTJacPoint<TOps>.InfMask(const AP: TFePoint): UInt32;
begin
  Result := ZeroMask(AP.Z);
end;

class procedure TCTJacPoint<TOps>.DoubleM3(const AP: TFePoint; var AR: TFePoint);
var
  LDelta, LGamma, LBeta, LAlpha, LT, LU, LX3, LY3, LZ3, LTmp: TFe;
  LTT: TFeExt;
begin
  // dbl-2001-b (a=-3): alpha = 3*(X-Z^2)*(X+Z^2) = 3X^2 - 3Z^4.
  TOps.Sqr(AP.Z, LDelta, LTT);        // delta = Z^2
  TOps.Sqr(AP.Y, LGamma, LTT);        // gamma = Y^2
  TOps.Mul(AP.X, LGamma, LBeta, LTT); // beta = X*gamma
  TOps.Sub(AP.X, LDelta, LT);         // X - delta
  TOps.Add(AP.X, LDelta, LU);         // X + delta
  TOps.Mul(LT, LU, LTmp, LTT);        // (X-delta)(X+delta)
  TOps.Add(LTmp, LTmp, LAlpha);
  TOps.Add(LAlpha, LTmp, LAlpha);     // alpha = 3*(...)
  // X3 = alpha^2 - 8*beta
  TOps.Sqr(LAlpha, LX3, LTT);
  TOps.Add(LBeta, LBeta, LTmp);
  TOps.Add(LTmp, LTmp, LTmp);
  TOps.Add(LTmp, LTmp, LTmp);         // 8*beta
  TOps.Sub(LX3, LTmp, LX3);
  // Z3 = (Y+Z)^2 - gamma - delta
  TOps.Add(AP.Y, AP.Z, LZ3);
  TOps.Sqr(LZ3, LZ3, LTT);
  TOps.Sub(LZ3, LGamma, LZ3);
  TOps.Sub(LZ3, LDelta, LZ3);
  // Y3 = alpha*(4*beta - X3) - 8*gamma^2
  TOps.Add(LBeta, LBeta, LTmp);
  TOps.Add(LTmp, LTmp, LTmp);         // 4*beta
  TOps.Sub(LTmp, LX3, LTmp);
  TOps.Mul(LAlpha, LTmp, LY3, LTT);
  TOps.Sqr(LGamma, LTmp, LTT);        // gamma^2
  TOps.Add(LTmp, LTmp, LTmp);
  TOps.Add(LTmp, LTmp, LTmp);
  TOps.Add(LTmp, LTmp, LTmp);         // 8*gamma^2
  TOps.Sub(LY3, LTmp, LY3);
  AR.X := LX3;
  AR.Y := LY3;
  AR.Z := LZ3;
end;

class procedure TCTJacPoint<TOps>.DoubleZero(const AP: TFePoint; var AR: TFePoint);
var
  LA, LB, LC, LD, LE, LX3, LY3, LZ3, LTmp: TFe;
  LTT: TFeExt;
begin
  // dbl-2009-l (a=0): alpha = 3*X^2 directly (no a*Z^4, no Z^4).
  TOps.Sqr(AP.X, LA, LTT);            // A = X^2
  TOps.Sqr(AP.Y, LB, LTT);            // B = Y^2
  TOps.Sqr(LB, LC, LTT);             // C = B^2
  // D = 2*((X+B)^2 - A - C)
  TOps.Add(AP.X, LB, LTmp);
  TOps.Sqr(LTmp, LTmp, LTT);
  TOps.Sub(LTmp, LA, LTmp);
  TOps.Sub(LTmp, LC, LTmp);
  TOps.Add(LTmp, LTmp, LD);
  // E = 3*A
  TOps.Add(LA, LA, LE);
  TOps.Add(LE, LA, LE);
  // X3 = E^2 - 2*D
  TOps.Sqr(LE, LX3, LTT);
  TOps.Add(LD, LD, LTmp);
  TOps.Sub(LX3, LTmp, LX3);
  // Y3 = E*(D - X3) - 8*C
  TOps.Sub(LD, LX3, LTmp);
  TOps.Mul(LE, LTmp, LY3, LTT);
  TOps.Add(LC, LC, LTmp);
  TOps.Add(LTmp, LTmp, LTmp);
  TOps.Add(LTmp, LTmp, LTmp);         // 8*C
  TOps.Sub(LY3, LTmp, LY3);
  // Z3 = 2*Y*Z (Z=0 -> Z3=0: infinity maps to infinity, no branch)
  TOps.Mul(AP.Y, AP.Z, LZ3, LTT);
  TOps.Add(LZ3, LZ3, LZ3);
  AR.X := LX3;
  AR.Y := LY3;
  AR.Z := LZ3;
end;

class procedure TCTJacPoint<TOps>.PointDouble(const AP: TFePoint; var AR: TFePoint);
begin
  // Fused Jacobian doubling when the curve has a gated kernel; the asm copies the
  // input into its frame before writing, so AR may alias AP. Generic fallback is
  // the bit-identical per-op formula (a-parameterised).
  if TOps.TryFusedJacPointDouble(PUInt64(@AR), PUInt64(@AP)) then
    Exit;
  if TOps.ACoeff = TCTACoeff.MinusThree then
    DoubleM3(AP, AR)
  else
    DoubleZero(AP, AR);
end;

class procedure TCTJacPoint<TOps>.CompleteInfinity(AIn1, AIn2: UInt32;
  const AP, AQ: TFePoint; var AR: TFePoint);
var
  LN, LJ: Int32;
  LInner: UInt32;
begin
  // Branch-free masked-infinity completion, identical to the fused kernel:
  // R = in1 ? Q : (in2 ? P : incomplete-sum). Restores completeness for the
  // point-at-infinity operands without a data-dependent branch.
  LN := LimbCount;
  for LJ := 0 to LN - 1 do
  begin
    LInner := (AP.X.W[LJ] and AIn2) or (AR.X.W[LJ] and (not AIn2));
    AR.X.W[LJ] := (AQ.X.W[LJ] and AIn1) or (LInner and (not AIn1));
    LInner := (AP.Y.W[LJ] and AIn2) or (AR.Y.W[LJ] and (not AIn2));
    AR.Y.W[LJ] := (AQ.Y.W[LJ] and AIn1) or (LInner and (not AIn1));
    LInner := (AP.Z.W[LJ] and AIn2) or (AR.Z.W[LJ] and (not AIn2));
    AR.Z.W[LJ] := (AQ.Z.W[LJ] and AIn1) or (LInner and (not AIn1));
  end;
end;

class procedure TCTJacPoint<TOps>.AddIncomplete(const AP, AQ: TFePoint;
  var AR: TFePoint; out AHZero, ARZero: UInt32);
var
  LZ1Z1, LZ2Z2, LU1, LU2, LS1, LS2, LH, LRs, LR, LI, LJ, LV, LX3, LY3, LZ3, LT: TFe;
  LTT: TFeExt;
begin
  // add-2007-bl (a-independent), 11M + 5S.
  TOps.Sqr(AP.Z, LZ1Z1, LTT);
  TOps.Sqr(AQ.Z, LZ2Z2, LTT);
  TOps.Mul(AP.X, LZ2Z2, LU1, LTT);       // U1 = X1*Z2^2
  TOps.Mul(AQ.X, LZ1Z1, LU2, LTT);       // U2 = X2*Z1^2
  TOps.Mul(AP.Y, AQ.Z, LT, LTT);
  TOps.Mul(LT, LZ2Z2, LS1, LTT);         // S1 = Y1*Z2^3
  TOps.Mul(AQ.Y, AP.Z, LT, LTT);
  TOps.Mul(LT, LZ1Z1, LS2, LTT);         // S2 = Y2*Z1^3
  TOps.Sub(LU2, LU1, LH);                // H = U2 - U1
  AHZero := ZeroMask(LH);
  TOps.Sub(LS2, LS1, LRs);               // S2 - S1
  ARZero := ZeroMask(LRs);
  TOps.Add(LRs, LRs, LR);                // r = 2*(S2-S1)
  TOps.Add(LH, LH, LT);
  TOps.Sqr(LT, LI, LTT);                 // I = (2H)^2
  TOps.Mul(LH, LI, LJ, LTT);             // J = H*I
  TOps.Mul(LU1, LI, LV, LTT);            // V = U1*I
  // X3 = r^2 - J - 2V
  TOps.Sqr(LR, LX3, LTT);
  TOps.Sub(LX3, LJ, LX3);
  TOps.Add(LV, LV, LT);
  TOps.Sub(LX3, LT, LX3);
  // Y3 = r*(V - X3) - 2*S1*J
  TOps.Sub(LV, LX3, LT);
  TOps.Mul(LR, LT, LY3, LTT);
  TOps.Mul(LS1, LJ, LT, LTT);
  TOps.Add(LT, LT, LT);
  TOps.Sub(LY3, LT, LY3);
  // Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2) * H
  TOps.Add(AP.Z, AQ.Z, LZ3);
  TOps.Sqr(LZ3, LZ3, LTT);
  TOps.Sub(LZ3, LZ1Z1, LZ3);
  TOps.Sub(LZ3, LZ2Z2, LZ3);
  TOps.Mul(LZ3, LH, LZ3, LTT);
  AR.X := LX3;
  AR.Y := LY3;
  AR.Z := LZ3;
end;

class procedure TCTJacPoint<TOps>.MixedAddIncomplete(const AP: TFePoint;
  const AQ: TFeAffine; var AR: TFePoint; out AHZero, ARZero: UInt32);
var
  LZ1Z1, LU2, LS2, LH, LRs, LR, LI, LJ, LV, LX3, LY3, LZ3, LT, LOne: TFe;
  LTT: TFeExt;
begin
  // madd-2007-bl (Z2 = 1), 7M + 4S. U1 = X1, S1 = Y1.
  TOps.SetOne(LOne);
  TOps.Sqr(AP.Z, LZ1Z1, LTT);
  TOps.Mul(AQ.X, LZ1Z1, LU2, LTT);       // U2 = X2*Z1^2
  TOps.Mul(AQ.Y, AP.Z, LT, LTT);
  TOps.Mul(LT, LZ1Z1, LS2, LTT);         // S2 = Y2*Z1^3
  TOps.Sub(LU2, AP.X, LH);               // H = U2 - X1
  AHZero := ZeroMask(LH);
  TOps.Sub(LS2, AP.Y, LRs);              // S2 - Y1
  ARZero := ZeroMask(LRs);
  TOps.Add(LRs, LRs, LR);                // r = 2*(S2 - Y1)
  TOps.Add(LH, LH, LT);
  TOps.Sqr(LT, LI, LTT);                 // I = (2H)^2
  TOps.Mul(LH, LI, LJ, LTT);             // J = H*I
  TOps.Mul(AP.X, LI, LV, LTT);           // V = X1*I
  TOps.Sqr(LR, LX3, LTT);
  TOps.Sub(LX3, LJ, LX3);
  TOps.Add(LV, LV, LT);
  TOps.Sub(LX3, LT, LX3);
  TOps.Sub(LV, LX3, LT);
  TOps.Mul(LR, LT, LY3, LTT);
  TOps.Mul(AP.Y, LJ, LT, LTT);
  TOps.Add(LT, LT, LT);
  TOps.Sub(LY3, LT, LY3);                // Y3 = r*(V-X3) - 2*Y1*J
  // Z3 = ((Z1+1)^2 - Z1Z1 - 1) * H
  TOps.Add(AP.Z, LOne, LZ3);
  TOps.Sqr(LZ3, LZ3, LTT);
  TOps.Sub(LZ3, LZ1Z1, LZ3);
  TOps.Sub(LZ3, LOne, LZ3);
  TOps.Mul(LZ3, LH, LZ3, LTT);
  AR.X := LX3;
  AR.Y := LY3;
  AR.Z := LZ3;
end;

class procedure TCTJacPoint<TOps>.PointAdd(const AP, AQ: TFePoint; var AR: TFePoint);
var
  LScr: TJacAddScratch;
  LRtmp: TFePoint;
  LIn1, LIn2, LHz, LRz: UInt32;
begin
  LIn1 := InfMask(AP);
  LIn2 := InfMask(AQ);
  if TOps.TryFusedJacPointAdd(PUInt64(@LScr), PUInt64(@AP), PUInt64(@AQ)) then
  begin
    // The fused kernel already applied the masked-infinity completion and exposed
    // the raw predicate operands; derive the P=Q flags from them.
    LRtmp := LScr.R;
    LHz := ZeroMask(LScr.H);
    LRz := ZeroMask(LScr.RS);
  end
  else
  begin
    AddIncomplete(AP, AQ, LRtmp, LHz, LRz);
    CompleteInfinity(LIn1, LIn2, AP, AQ, LRtmp);
  end;

  // P=Q backstop: a detect-and-double BRANCH, isolated here so a
  // later fully-masked-cmov double is a swap of this block. Only when both operands
  // are finite and equal (U1=U2 and S1=S2). Never taken on an honest ephemeral
  // [d]Q, so no secret-dependent timing there; correctness is guaranteed always.
  if ((LIn1 or LIn2) = 0) and (LHz <> 0) and (LRz <> 0) then
  begin
    PointDouble(AP, AR);
    Exit;
  end;

  AR := LRtmp;
end;

class procedure TCTJacPoint<TOps>.PointAddMixed(const AP: TFePoint;
  const AQ: TFeAffine; var AR: TFePoint);
var
  LScr: TJacAddScratch;
  LRtmp: TFePoint;
  LOne: TFe;
  LIn1, LHz, LRz: UInt32;
  LN, LJ: Int32;
begin
  LIn1 := InfMask(AP);
  if TOps.TryFusedJacPointAddMixed(PUInt64(@LScr), PUInt64(@AP), PUInt64(@AQ)) then
  begin
    LRtmp := LScr.R;
    LHz := ZeroMask(LScr.H);
    LRz := ZeroMask(LScr.RS);
  end
  else
  begin
    MixedAddIncomplete(AP, AQ, LRtmp, LHz, LRz);
    // R = in1 ? (X2, Y2, 1) : incomplete-sum. Affine Q is always finite (in2 = 0).
    TOps.SetOne(LOne);
    LN := LimbCount;
    for LJ := 0 to LN - 1 do
    begin
      LRtmp.X.W[LJ] := (AQ.X.W[LJ] and LIn1) or (LRtmp.X.W[LJ] and (not LIn1));
      LRtmp.Y.W[LJ] := (AQ.Y.W[LJ] and LIn1) or (LRtmp.Y.W[LJ] and (not LIn1));
      LRtmp.Z.W[LJ] := (LOne.W[LJ] and LIn1) or (LRtmp.Z.W[LJ] and (not LIn1));
    end;
  end;

  if (LIn1 = 0) and (LHz <> 0) and (LRz <> 0) then
  begin
    PointDouble(AP, AR);
    Exit;
  end;

  AR := LRtmp;
end;

class procedure TCTJacPoint<TOps>.OneFe(const AFieldOps: IFpFieldOps; var AZ: TFe);
begin
  TOps.SetOne(AZ);
end;

class procedure TCTJacPoint<TOps>.Infinity(const AFieldOps: IFpFieldOps; var AR: TFePoint);
begin
  // Jacobian infinity is Z = 0; the all-zero record carries it (X,Y are ignored).
  FillChar(AR, SizeOf(AR), 0);
end;

class procedure TCTJacPoint<TOps>.FromAffine(const AFieldOps: IFpFieldOps;
  const AXa, AYa: TCryptoLibUInt32Array; var AR: TFePoint);
var
  LN: Int32;
  LTT: TFeExt;
begin
  LN := AFieldOps.GetFieldInts;
  FillChar(AR, SizeOf(AR), 0);
  Move(AXa[0], AR.X.W[0], LN * SizeOf(UInt32));
  Move(AYa[0], AR.Y.W[0], LN * SizeOf(UInt32));
  TOps.ToMont(AR.X, AR.X, LTT);
  TOps.ToMont(AR.Y, AR.Y, LTT);
  TOps.SetOne(AR.Z); // Z = 1 -> affine (X, Y) as Jacobian
end;

class procedure TCTJacPoint<TOps>.FromAffineElt(const AFieldOps: IFpFieldOps;
  const AX, AY: IECFieldElement; var AR: TFePoint);
var
  LN: Int32;
  LXa, LYa: TCryptoLibUInt32Array;
begin
  LN := AFieldOps.GetFieldInts;
  LXa := TNat.Create(LN);
  LYa := TNat.Create(LN);
  AFieldOps.FieldFromBigInteger(AX.ToBigInteger(), LXa);
  AFieldOps.FieldFromBigInteger(AY.ToBigInteger(), LYa);
  FromAffine(AFieldOps, LXa, LYa, AR);
end;

class procedure TCTJacPoint<TOps>.ToAffine(const AFieldOps: IFpFieldOps;
  const AP: TFePoint; const AXa, AYa: TCryptoLibUInt32Array; out AIsInfinity: Boolean);
var
  LN: Int32;
  LZn, LXn, LYn: TFe;
  LTT: TFeExt;
  LZarr, LZInv, LZInv2, LZInv3, LXn0, LYn0: TCryptoLibUInt32Array;
begin
  LN := AFieldOps.GetFieldInts;
  // Bring each coordinate out of the Montgomery domain, then do the x = X/Z^2,
  // y = Y/Z^3 division in the normal domain (one modular inverse of Z).
  TOps.FromMont(AP.Z, LZn, LTT);
  LZarr := TNat.Create(LN);
  Move(LZn.W[0], LZarr[0], LN * SizeOf(UInt32));
  AIsInfinity := AFieldOps.IsZero(LZarr);
  if AIsInfinity then
    Exit;
  TOps.FromMont(AP.X, LXn, LTT);
  TOps.FromMont(AP.Y, LYn, LTT);
  LXn0 := TNat.Create(LN);
  LYn0 := TNat.Create(LN);
  Move(LXn.W[0], LXn0[0], LN * SizeOf(UInt32));
  Move(LYn.W[0], LYn0[0], LN * SizeOf(UInt32));
  LZInv := TNat.Create(LN);
  LZInv2 := TNat.Create(LN);
  LZInv3 := TNat.Create(LN);
  AFieldOps.Inv(LZarr, LZInv);
  AFieldOps.Mul(LZInv, LZInv, LZInv2);   // Z^-2
  AFieldOps.Mul(LZInv2, LZInv, LZInv3);  // Z^-3
  AFieldOps.Mul(LXn0, LZInv2, AXa);      // x = X * Z^-2
  AFieldOps.Mul(LYn0, LZInv3, AYa);      // y = Y * Z^-3
end;

class procedure TCTJacPoint<TOps>.SelectEntry(const AFieldOps: IFpFieldOps;
  const ATable: array of TFePoint; ACount, AIndex: Int32; var AR: TFePoint);
begin
  TCTPointCommon.SelectEntry(AFieldOps, ATable, ACount, AIndex, AR);
end;

class procedure TCTJacPoint<TOps>.ScaleRandom(const AP: TFePoint; const ALambda: TFe;
  var AR: TFePoint);
var
  LL2, LL3: TFe;
  LTT: TFeExt;
begin
  TOps.Mul(ALambda, ALambda, LL2, LTT); // lambda^2
  TOps.Mul(LL2, ALambda, LL3, LTT);     // lambda^3
  TOps.Mul(AP.X, LL2, AR.X, LTT);       // X * lambda^2
  TOps.Mul(AP.Y, LL3, AR.Y, LTT);       // Y * lambda^3
  TOps.Mul(AP.Z, ALambda, AR.Z, LTT);   // Z * lambda
end;

end.
