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

unit ClpCTPoint;

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
  /// <summary>
  /// Generic constant-time value-type point operations for Fp short-Weierstrass
  /// curves in homogeneous coordinates: the RCB2016 complete group law (addition
  /// = Algorithm 1, doubling = Algorithm 3) plus the representation helpers
  /// (affine &lt;-&gt; projective conversion and the masked table lookup) that the
  /// multipliers build on. One body serves every curve; <c>TOps</c> supplies the
  /// field arithmetic via the <see cref="TCTFieldArithBase"/> virtual class
  /// methods, so the formulas run with no interface dispatch and every temporary
  /// is a stack <see cref="TFe"/>. The curve context needed by the conversions
  /// (field width, one, is-zero, inverse) comes from the <c>IFpFieldOps</c>
  /// adapter threaded in as a parameter. The windowed/comb scalar loops that
  /// drive these live in <c>TFpCTMultiplier</c> / <c>TFpCombMultiplier</c>.
  /// </summary>
  TCTPoint<TOps: TCTFieldArithBase> = class sealed
  public
    /// <summary>RCB2016 complete addition (Algorithm 1, explicit a and b3).
    /// AR := AP + AQ in homogeneous coordinates; all temporaries are stack
    /// records. AR may alias AP or AQ.</summary>
    class procedure PointAdd(const AP, AQ: TFePoint; var AR: TFePoint); static;
    /// <summary>RCB2016 complete doubling (Algorithm 3). AR := 2*AP.</summary>
    class procedure PointDouble(const AP: TFePoint; var AR: TFePoint); static;
    class procedure OneFe(const AFieldOps: IFpFieldOps; var AZ: TFe); static;
    class procedure Infinity(const AFieldOps: IFpFieldOps; var AR: TFePoint); static;
    class procedure FromAffine(const AFieldOps: IFpFieldOps;
      const AXa, AYa: TCryptoLibUInt32Array; var AR: TFePoint); static;
    class procedure FromAffineElt(const AFieldOps: IFpFieldOps;
      const AX, AY: IECFieldElement; var AR: TFePoint); static;
    class procedure ToAffine(const AFieldOps: IFpFieldOps; const AP: TFePoint;
      const AXa, AYa: TCryptoLibUInt32Array; out AIsInfinity: Boolean); static;
    /// <summary>Constant-time masked lookup: AR := ATable[AIndex], scanning all
    /// ACount entries so the access pattern is scalar-independent.</summary>
    class procedure SelectEntry(const AFieldOps: IFpFieldOps;
      const ATable: array of TFePoint; ACount, AIndex: Int32; var AR: TFePoint); static;
  end;

implementation

class procedure TCTPoint<TOps>.PointAdd(const AP, AQ: TFePoint; var AR: TFePoint);
var
  Lt0, Lt1, Lt2, Lt3, Lt4, Lt5, LX3, LY3, LZ3: TFe;
  LTT: TFeExt;
begin
  TOps.Mul(AP.X, AQ.X, Lt0, LTT);   // t0 = X1*X2
  TOps.Mul(AP.Y, AQ.Y, Lt1, LTT);   // t1 = Y1*Y2
  TOps.Mul(AP.Z, AQ.Z, Lt2, LTT);   // t2 = Z1*Z2
  TOps.Add(AP.X, AP.Y, Lt3);        // t3 = X1+Y1
  TOps.Add(AQ.X, AQ.Y, Lt4);        // t4 = X2+Y2
  TOps.Mul(Lt3, Lt4, Lt3, LTT);     // t3 = t3*t4
  TOps.Add(Lt0, Lt1, Lt4);          // t4 = t0+t1
  TOps.Sub(Lt3, Lt4, Lt3);          // t3 = t3-t4
  TOps.Add(AP.X, AP.Z, Lt4);        // t4 = X1+Z1
  TOps.Add(AQ.X, AQ.Z, Lt5);        // t5 = X2+Z2
  TOps.Mul(Lt4, Lt5, Lt4, LTT);     // t4 = t4*t5
  TOps.Add(Lt0, Lt2, Lt5);          // t5 = t0+t2
  TOps.Sub(Lt4, Lt5, Lt4);          // t4 = t4-t5
  TOps.Add(AP.Y, AP.Z, Lt5);        // t5 = Y1+Z1
  TOps.Add(AQ.Y, AQ.Z, LX3);        // X3 = Y2+Z2
  TOps.Mul(Lt5, LX3, Lt5, LTT);     // t5 = t5*X3
  TOps.Add(Lt1, Lt2, LX3);          // X3 = t1+t2
  TOps.Sub(Lt5, LX3, Lt5);          // t5 = t5-X3
  TOps.MulByA(Lt4, LZ3, LTT);       // Z3 = a*t4
  TOps.MulByB3(Lt2, LX3, LTT);      // X3 = b3*t2
  TOps.Add(LX3, LZ3, LZ3);          // Z3 = X3+Z3
  TOps.Sub(Lt1, LZ3, LX3);          // X3 = t1-Z3
  TOps.Add(Lt1, LZ3, LZ3);          // Z3 = t1+Z3
  TOps.Mul(LX3, LZ3, LY3, LTT);     // Y3 = X3*Z3
  TOps.Add(Lt0, Lt0, Lt1);          // t1 = t0+t0
  TOps.Add(Lt1, Lt0, Lt1);          // t1 = t1+t0
  TOps.MulByA(Lt2, Lt2, LTT);       // t2 = a*t2
  TOps.MulByB3(Lt4, Lt4, LTT);      // t4 = b3*t4
  TOps.Add(Lt1, Lt2, Lt1);          // t1 = t1+t2
  TOps.Sub(Lt0, Lt2, Lt2);          // t2 = t0-t2
  TOps.MulByA(Lt2, Lt2, LTT);       // t2 = a*t2
  TOps.Add(Lt4, Lt2, Lt4);          // t4 = t4+t2
  TOps.Mul(Lt1, Lt4, Lt0, LTT);     // t0 = t1*t4
  TOps.Add(LY3, Lt0, LY3);          // Y3 = Y3+t0
  TOps.Mul(Lt5, Lt4, Lt0, LTT);     // t0 = t5*t4
  TOps.Mul(Lt3, LX3, LX3, LTT);     // X3 = t3*X3
  TOps.Sub(LX3, Lt0, LX3);          // X3 = X3-t0
  TOps.Mul(Lt3, Lt1, Lt0, LTT);     // t0 = t3*t1
  TOps.Mul(Lt5, LZ3, LZ3, LTT);     // Z3 = t5*Z3
  TOps.Add(LZ3, Lt0, LZ3);          // Z3 = Z3+t0
  AR.X := LX3;
  AR.Y := LY3;
  AR.Z := LZ3;
end;

class procedure TCTPoint<TOps>.PointDouble(const AP: TFePoint; var AR: TFePoint);
var
  Lt0, Lt1, Lt2, Lt3, LX3, LY3, LZ3: TFe;
  LTT: TFeExt;
begin
  TOps.Sqr(AP.X, Lt0, LTT);         // t0 = X*X
  TOps.Sqr(AP.Y, Lt1, LTT);         // t1 = Y*Y
  TOps.Sqr(AP.Z, Lt2, LTT);         // t2 = Z*Z
  TOps.Mul(AP.X, AP.Y, Lt3, LTT);   // t3 = X*Y
  TOps.Add(Lt3, Lt3, Lt3);          // t3 = t3+t3
  TOps.Mul(AP.X, AP.Z, LZ3, LTT);   // Z3 = X*Z
  TOps.Add(LZ3, LZ3, LZ3);          // Z3 = Z3+Z3
  TOps.MulByA(LZ3, LX3, LTT);       // X3 = a*Z3
  TOps.MulByB3(Lt2, LY3, LTT);      // Y3 = b3*t2
  TOps.Add(LX3, LY3, LY3);          // Y3 = X3+Y3
  TOps.Sub(Lt1, LY3, LX3);          // X3 = t1-Y3
  TOps.Add(Lt1, LY3, LY3);          // Y3 = t1+Y3
  TOps.Mul(LX3, LY3, LY3, LTT);     // Y3 = X3*Y3
  TOps.Mul(Lt3, LX3, LX3, LTT);     // X3 = t3*X3
  TOps.MulByB3(LZ3, LZ3, LTT);      // Z3 = b3*Z3
  TOps.MulByA(Lt2, Lt2, LTT);       // t2 = a*t2
  TOps.Sub(Lt0, Lt2, Lt3);          // t3 = t0-t2
  TOps.MulByA(Lt3, Lt3, LTT);       // t3 = a*t3
  TOps.Add(Lt3, LZ3, Lt3);          // t3 = t3+Z3
  TOps.Add(Lt0, Lt0, LZ3);          // Z3 = t0+t0
  TOps.Add(LZ3, Lt0, Lt0);          // t0 = Z3+t0
  TOps.Add(Lt0, Lt2, Lt0);          // t0 = t0+t2
  TOps.Mul(Lt0, Lt3, Lt0, LTT);     // t0 = t0*t3
  TOps.Add(LY3, Lt0, LY3);          // Y3 = Y3+t0
  TOps.Mul(AP.Y, AP.Z, Lt2, LTT);   // t2 = Y*Z
  TOps.Add(Lt2, Lt2, Lt2);          // t2 = t2+t2
  TOps.Mul(Lt2, Lt3, Lt0, LTT);     // t0 = t2*t3
  TOps.Sub(LX3, Lt0, LX3);          // X3 = X3-t0
  TOps.Mul(Lt2, Lt1, LZ3, LTT);     // Z3 = t2*t1
  TOps.Add(LZ3, LZ3, LZ3);          // Z3 = Z3+Z3
  TOps.Add(LZ3, LZ3, LZ3);          // Z3 = Z3+Z3
  AR.X := LX3;
  AR.Y := LY3;
  AR.Z := LZ3;
end;

class procedure TCTPoint<TOps>.OneFe(const AFieldOps: IFpFieldOps; var AZ: TFe);
var
  LArr: TCryptoLibUInt32Array;
begin
  LArr := TNat.Create(AFieldOps.GetFieldInts);
  AFieldOps.FieldOne(LArr);
  FillChar(AZ, SizeOf(AZ), 0);
  Move(LArr[0], AZ.W[0], AFieldOps.GetFieldInts * SizeOf(UInt32));
end;

class procedure TCTPoint<TOps>.Infinity(const AFieldOps: IFpFieldOps; var AR: TFePoint);
begin
  FillChar(AR, SizeOf(AR), 0);
  OneFe(AFieldOps, AR.Y);
end;

class procedure TCTPoint<TOps>.FromAffine(const AFieldOps: IFpFieldOps;
  const AXa, AYa: TCryptoLibUInt32Array; var AR: TFePoint);
var
  LN: Int32;
begin
  LN := AFieldOps.GetFieldInts;
  FillChar(AR, SizeOf(AR), 0);
  Move(AXa[0], AR.X.W[0], LN * SizeOf(UInt32));
  Move(AYa[0], AR.Y.W[0], LN * SizeOf(UInt32));
  OneFe(AFieldOps, AR.Z);
end;

class procedure TCTPoint<TOps>.FromAffineElt(const AFieldOps: IFpFieldOps;
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

class procedure TCTPoint<TOps>.ToAffine(const AFieldOps: IFpFieldOps;
  const AP: TFePoint; const AXa, AYa: TCryptoLibUInt32Array; out AIsInfinity: Boolean);
var
  LN: Int32;
  LZarr, LZInvArr: TCryptoLibUInt32Array;
  LZInv, LTmp: TFe;
  LTT: TFeExt;
begin
  LN := AFieldOps.GetFieldInts;
  LZarr := TNat.Create(LN);
  Move(AP.Z.W[0], LZarr[0], LN * SizeOf(UInt32));
  AIsInfinity := AFieldOps.IsZero(LZarr);
  if AIsInfinity then
    Exit;
  LZInvArr := TNat.Create(LN);
  AFieldOps.Inv(LZarr, LZInvArr);
  FillChar(LZInv, SizeOf(LZInv), 0);
  Move(LZInvArr[0], LZInv.W[0], LN * SizeOf(UInt32));
  TOps.Mul(AP.X, LZInv, LTmp, LTT);
  Move(LTmp.W[0], AXa[0], LN * SizeOf(UInt32));
  TOps.Mul(AP.Y, LZInv, LTmp, LTT);
  Move(LTmp.W[0], AYa[0], LN * SizeOf(UInt32));
end;

class procedure TCTPoint<TOps>.SelectEntry(const AFieldOps: IFpFieldOps;
  const ATable: array of TFePoint; ACount, AIndex: Int32; var AR: TFePoint);
var
  LN, LI, LJ: Int32;
  LMask: UInt32;
  LEntry: TFePoint;
begin
  LN := AFieldOps.GetFieldInts;
  FillChar(AR, SizeOf(AR), 0);
  for LI := 0 to ACount - 1 do
  begin
    LEntry := ATable[LI];
    LMask := UInt32(TBitOperations.Asr32(((LI xor AIndex) - 1), 31));
    for LJ := 0 to LN - 1 do
    begin
      AR.X.W[LJ] := AR.X.W[LJ] xor (LEntry.X.W[LJ] and LMask);
      AR.Y.W[LJ] := AR.Y.W[LJ] xor (LEntry.Y.W[LJ] and LMask);
      AR.Z.W[LJ] := AR.Z.W[LJ] xor (LEntry.Z.W[LJ] and LMask);
    end;
  end;
end;

end.
