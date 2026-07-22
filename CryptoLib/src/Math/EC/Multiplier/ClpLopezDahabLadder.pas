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

unit ClpLopezDahabLadder;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpNat,
  ClpIF2mFieldOps,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// A point in López–Dahab x-only projective coordinates (X : Z), x = X/Z,
  /// point at infinity = (X : 0) with X != 0. Value aggregate over the limb arrays.
  /// </summary>
  TLDPoint = record
    X, Z: TCryptoLibUInt64Array;
  end;

  /// <summary>
  /// López–Dahab (1999) Montgomery-ladder x-only formulas over GF(2^m):
  /// Mdouble, differential Madd, and Mxy y-recovery. See ClpLopezDahabLadder /
  /// binary-ct plan for the exact formulas and the batched single-inversion
  /// recovery. Exception-free through the infinity representation.
  /// </summary>
  TLopezDahabLadder = class sealed(TObject)
  strict private
    class procedure Sel(const AFO: IF2mFieldOps; AMask: UInt64;
      const AIfTrue, AIfFalse, AZ: TCryptoLibUInt64Array); static;
  public
    // Mdouble: (X:Z) -> 2*(X:Z);  Z' = X^2 Z^2,  X' = X^4 + b Z^4
    class function MDouble(const AFO: IF2mFieldOps; const AP: TLDPoint): TLDPoint; static;
    // Madd: differential add of (X1:Z1),(X2:Z2) whose difference is the base point x.
    // Z' = (X1 Z2 + X2 Z1)^2,  X' = x Z' + (X1 Z2)(X2 Z1)
    class function MAdd(const AFO: IF2mFieldOps; const AP1, AP2: TLDPoint;
      const ABaseX: TCryptoLibUInt64Array): TLDPoint; static;
    // Recover affine (x_k) and lambda (lambda_k) of the result from the final
    // ladder state (Q1 = x(kP), Q2 = x((k+1)P)) and the base affine (x, y).
    // Returns infinity when Z1 = 0. Batched single secret-path inversion.
    class procedure Recover(const AFO: IF2mFieldOps; const AP1, AP2: TLDPoint;
      const ABaseX, ABaseY: TCryptoLibUInt64Array;
      const AXOut, ALOut: TCryptoLibUInt64Array; out AIsInfinity: Boolean); static;
  end;

implementation

{ TLopezDahabLadder }

class procedure TLopezDahabLadder.Sel(const AFO: IF2mFieldOps; AMask: UInt64;
  const AIfTrue, AIfFalse, AZ: TCryptoLibUInt64Array);
var
  LN, LI: Int32;
begin
  // constant-time: AZ := AMask ? AIfTrue : AIfFalse  (AMask is 0 or all-ones)
  LN := AFO.GetFieldLongs;
  for LI := 0 to LN - 1 do
    AZ[LI] := (AIfTrue[LI] and AMask) or (AIfFalse[LI] and (not AMask));
end;

class function TLopezDahabLadder.MDouble(const AFO: IF2mFieldOps; const AP: TLDPoint): TLDPoint;
var
  LN: Int32;
  Lt0, Lt1, LX3, LZ3: TCryptoLibUInt64Array;
begin
  LN := AFO.GetFieldLongs;
  Lt0 := TNat.Create64(LN); Lt1 := TNat.Create64(LN);
  LX3 := TNat.Create64(LN); LZ3 := TNat.Create64(LN);

  AFO.Square(AP.X, Lt0);      // t0 = X^2
  AFO.Square(AP.Z, Lt1);      // t1 = Z^2
  AFO.Mul(Lt0, Lt1, LZ3);     // Z3 = X^2 Z^2
  AFO.Square(Lt0, Lt0);       // t0 = X^4
  AFO.Square(Lt1, Lt1);       // t1 = Z^4
  AFO.MulByB(Lt1, Lt1);       // t1 = b Z^4
  AFO.Add(Lt0, Lt1, LX3);     // X3 = X^4 + b Z^4

  Result.X := LX3; Result.Z := LZ3;
end;

class function TLopezDahabLadder.MAdd(const AFO: IF2mFieldOps; const AP1, AP2: TLDPoint;
  const ABaseX: TCryptoLibUInt64Array): TLDPoint;
var
  LN: Int32;
  LA, LB, LC, LD, LX3, LZ3: TCryptoLibUInt64Array;
begin
  LN := AFO.GetFieldLongs;
  LA := TNat.Create64(LN); LB := TNat.Create64(LN); LC := TNat.Create64(LN);
  LD := TNat.Create64(LN); LX3 := TNat.Create64(LN); LZ3 := TNat.Create64(LN);

  AFO.Mul(AP1.X, AP2.Z, LA);  // A = X1 Z2
  AFO.Mul(AP2.X, AP1.Z, LB);  // B = X2 Z1
  AFO.Mul(LA, LB, LC);        // C = A B
  AFO.Add(LA, LB, LD);        // D = A + B
  AFO.Square(LD, LZ3);        // Z3 = D^2
  AFO.Mul(ABaseX, LZ3, LX3);  // X3 = x Z3
  AFO.Add(LX3, LC, LX3);      // X3 = x Z3 + C

  Result.X := LX3; Result.Z := LZ3;
end;

class procedure TLopezDahabLadder.Recover(const AFO: IF2mFieldOps; const AP1, AP2: TLDPoint;
  const ABaseX, ABaseY: TCryptoLibUInt64Array;
  const AXOut, ALOut: TCryptoLibUInt64Array; out AIsInfinity: Boolean);
var
  LN: Int32;
  LZ1Z2, LP1, LU, LUinv, LInvP1, LInvZ1, LInvX1, LTmp, LTmp2: TCryptoLibUInt64Array;
  LxZ1, LxZ2, Lxk, Ls, Lt, LN2, Lx2y, Lfrac, Lyk, LinvXk, Llamk: TCryptoLibUInt64Array;
  LInvX, LxNeg, LlamNeg: TCryptoLibUInt64Array;
  LmaskZ2: UInt64;
begin
  LN := AFO.GetFieldLongs;
  AIsInfinity := AFO.IsZeroMask(AP1.Z) <> 0;
  if AIsInfinity then
    Exit; // kP = infinity (k == 0 mod ord P) - excluded for valid ECDH scalars

  LZ1Z2 := TNat.Create64(LN); LP1 := TNat.Create64(LN); LU := TNat.Create64(LN);
  LUinv := TNat.Create64(LN); LInvP1 := TNat.Create64(LN); LInvZ1 := TNat.Create64(LN);
  LInvX1 := TNat.Create64(LN); LTmp := TNat.Create64(LN); LTmp2 := TNat.Create64(LN);
  LxZ1 := TNat.Create64(LN); LxZ2 := TNat.Create64(LN); Lxk := TNat.Create64(LN);
  Ls := TNat.Create64(LN); Lt := TNat.Create64(LN); LN2 := TNat.Create64(LN);
  Lx2y := TNat.Create64(LN); Lfrac := TNat.Create64(LN); Lyk := TNat.Create64(LN);
  LinvXk := TNat.Create64(LN); Llamk := TNat.Create64(LN);
  LInvX := TNat.Create64(LN); LxNeg := TNat.Create64(LN); LlamNeg := TNat.Create64(LN);

  // --- batched inversion: U = x*Z1*Z2*X1 (secret path, single guard-free inverse) ---
  AFO.Mul(AP1.Z, AP2.Z, LZ1Z2);       // Z1 Z2
  AFO.Mul(ABaseX, LZ1Z2, LP1);        // P1 = x Z1 Z2
  AFO.Mul(LP1, AP1.X, LU);            // U  = P1 X1
  AFO.Inv(LU, LUinv);                 // 1/U (0 if U = 0; only in the Z2=0 edge, selected away)
  AFO.Mul(AP1.X, LUinv, LInvP1);      // 1/(x Z1 Z2) = X1/U
  AFO.Mul(ABaseX, AP2.Z, LTmp);       // x Z2
  AFO.Mul(LTmp, AP1.X, LTmp2);        // x Z2 X1
  AFO.Mul(LTmp2, LUinv, LInvZ1);      // 1/Z1
  AFO.Mul(LP1, LUinv, LInvX1);        // 1/X1

  // --- normal recovery ---
  AFO.Mul(AP1.X, LInvZ1, Lxk);        // x_k = X1/Z1
  AFO.Mul(ABaseX, AP1.Z, LxZ1);       // x Z1
  AFO.Mul(ABaseX, AP2.Z, LxZ2);       // x Z2
  AFO.Add(AP1.X, LxZ1, Ls);           // s = X1 + x Z1
  AFO.Add(AP2.X, LxZ2, Lt);           // t = X2 + x Z2
  AFO.Mul(Ls, Lt, LN2);               // s t
  AFO.Square(ABaseX, Lx2y);           // x^2
  AFO.Add(Lx2y, ABaseY, Lx2y);        // x^2 + y
  AFO.Mul(Lx2y, LZ1Z2, LTmp);         // (x^2+y) Z1 Z2
  AFO.Add(LN2, LTmp, LN2);            // N = s t + (x^2+y) Z1 Z2
  AFO.Mul(LN2, LInvP1, Lfrac);        // N / (x Z1 Z2)
  AFO.Add(LxK, ABaseX, LTmp);         // x_k + x
  AFO.Mul(LTmp, Lfrac, Lyk);          // (x_k+x) * frac
  AFO.Add(Lyk, ABaseY, Lyk);          // y_k = ... + y
  AFO.Mul(AP1.Z, LInvX1, LinvXk);     // 1/x_k = Z1/X1
  AFO.Mul(Lyk, LinvXk, Llamk);        // y_k / x_k
  AFO.Add(Llamk, LxK, Llamk);         // lambda_k = y_k/x_k + x_k

  // --- -P candidate (public base; independent of the collapsed U) ---
  AFO.Inv(ABaseX, LInvX);             // 1/x  (x is public, nonzero validated)
  AFO.Add(ABaseX, ABaseY, LxNeg);     // x + y  (affine y of -P)
  AFO.Mul(LxNeg, LInvX, LlamNeg);     // (x+y)/x
  AFO.Add(LlamNeg, ABaseX, LlamNeg);  // lambda(-P) = (x+y)/x + x
  // x-coordinate of -P is x itself; reuse ABaseX below.

  // --- CT select the Z2=0 edge (result = -P) ---
  LmaskZ2 := AFO.IsZeroMask(AP2.Z);
  Sel(AFO, LmaskZ2, ABaseX, LxK, AXOut);
  Sel(AFO, LmaskZ2, LlamNeg, Llamk, ALOut);
end;

end.
