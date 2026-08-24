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
  strict private
    /// <summary>RCB2016 general-a complete addition (Algorithm 1).</summary>
    class procedure PointAddGeneral(const AP, AQ: TFePoint; var AR: TFePoint); static;
    /// <summary>RCB2016 a=-3 complete addition (Algorithm 4).</summary>
    class procedure PointAddM3(const AP, AQ: TFePoint; var AR: TFePoint); static;
    /// <summary>RCB2016 a=0 complete addition (Algorithm 7).</summary>
    class procedure PointAddZero(const AP, AQ: TFePoint; var AR: TFePoint); static;
    /// <summary>RCB2016 general-a complete doubling (Algorithm 3).</summary>
    class procedure PointDoubleGeneral(const AP: TFePoint; var AR: TFePoint); static;
    /// <summary>RCB2016 a=-3 complete doubling (Algorithm 6).</summary>
    class procedure PointDoubleM3(const AP: TFePoint; var AR: TFePoint); static;
    /// <summary>RCB2016 a=0 complete doubling (Algorithm 9).</summary>
    class procedure PointDoubleZero(const AP: TFePoint; var AR: TFePoint); static;
  public
    /// <summary>RCB2016 complete addition. AR := AP + AQ in homogeneous
    /// coordinates; all temporaries are stack records. AR may alias AP or AQ.
    /// a=-3 curves take Algorithm 4, a=0 Algorithm 7, others Algorithm 1.</summary>
    class procedure PointAdd(const AP, AQ: TFePoint; var AR: TFePoint); static;
    /// <summary>RCB2016 complete doubling. AR := 2*AP (a=-3 Algorithm 6, a=0
    /// Algorithm 9, else Algorithm 3).</summary>
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
begin
  if TOps.ACoeff = TCTACoeff.Zero then
    PointAddZero(AP, AQ, AR)
  else if TOps.ACoeff = TCTACoeff.MinusThree then
    PointAddM3(AP, AQ, AR)
  else
    PointAddGeneral(AP, AQ, AR);
end;

class procedure TCTPoint<TOps>.PointAddGeneral(const AP, AQ: TFePoint; var AR: TFePoint);
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

class procedure TCTPoint<TOps>.PointAddM3(const AP, AQ: TFePoint; var AR: TFePoint);
var
  Lt0, Lt1, Lt2, Lt3, Lt4, LX3, LY3, LZ3: TFe;
  LTT: TFeExt;
begin
  // RCB2016 Algorithm 4 (complete addition, a=-3); 12M + 2 mul_b, no mul_a.
  TOps.Mul(AP.X, AQ.X, Lt0, LTT);   // t0 = X1*X2
  TOps.Mul(AP.Y, AQ.Y, Lt1, LTT);   // t1 = Y1*Y2
  TOps.Mul(AP.Z, AQ.Z, Lt2, LTT);   // t2 = Z1*Z2
  TOps.Add(AP.X, AP.Y, Lt3);        // t3 = X1+Y1
  TOps.Add(AQ.X, AQ.Y, Lt4);        // t4 = X2+Y2
  TOps.Mul(Lt3, Lt4, Lt3, LTT);     // t3 = t3*t4
  TOps.Add(Lt0, Lt1, Lt4);          // t4 = t0+t1
  TOps.Sub(Lt3, Lt4, Lt3);          // t3 = t3-t4
  TOps.Add(AP.Y, AP.Z, Lt4);        // t4 = Y1+Z1
  TOps.Add(AQ.Y, AQ.Z, LX3);        // X3 = Y2+Z2
  TOps.Mul(Lt4, LX3, Lt4, LTT);     // t4 = t4*X3
  TOps.Add(Lt1, Lt2, LX3);          // X3 = t1+t2
  TOps.Sub(Lt4, LX3, Lt4);          // t4 = t4-X3
  TOps.Add(AP.X, AP.Z, LX3);        // X3 = X1+Z1
  TOps.Add(AQ.X, AQ.Z, LY3);        // Y3 = X2+Z2
  TOps.Mul(LX3, LY3, LX3, LTT);     // X3 = X3*Y3
  TOps.Add(Lt0, Lt2, LY3);          // Y3 = t0+t2
  TOps.Sub(LX3, LY3, LY3);          // Y3 = X3-Y3
  TOps.MulByB(Lt2, LZ3, LTT);       // Z3 = b*t2
  TOps.Sub(LY3, LZ3, LX3);          // X3 = Y3-Z3
  TOps.Add(LX3, LX3, LZ3);          // Z3 = X3+X3
  TOps.Add(LX3, LZ3, LX3);          // X3 = X3+Z3
  TOps.Sub(Lt1, LX3, LZ3);          // Z3 = t1-X3
  TOps.Add(Lt1, LX3, LX3);          // X3 = t1+X3
  TOps.MulByB(LY3, LY3, LTT);       // Y3 = b*Y3
  TOps.Add(Lt2, Lt2, Lt1);          // t1 = t2+t2
  TOps.Add(Lt1, Lt2, Lt2);          // t2 = t1+t2
  TOps.Sub(LY3, Lt2, LY3);          // Y3 = Y3-t2
  TOps.Sub(LY3, Lt0, LY3);          // Y3 = Y3-t0
  TOps.Add(LY3, LY3, Lt1);          // t1 = Y3+Y3
  TOps.Add(Lt1, LY3, LY3);          // Y3 = t1+Y3
  TOps.Add(Lt0, Lt0, Lt1);          // t1 = t0+t0
  TOps.Add(Lt1, Lt0, Lt0);          // t0 = t1+t0
  TOps.Sub(Lt0, Lt2, Lt0);          // t0 = t0-t2
  TOps.Mul(Lt4, LY3, Lt1, LTT);     // t1 = t4*Y3
  TOps.Mul(Lt0, LY3, Lt2, LTT);     // t2 = t0*Y3
  TOps.Mul(LX3, LZ3, LY3, LTT);     // Y3 = X3*Z3
  TOps.Add(LY3, Lt2, LY3);          // Y3 = Y3+t2
  TOps.Mul(Lt3, LX3, LX3, LTT);     // X3 = t3*X3
  TOps.Sub(LX3, Lt1, LX3);          // X3 = X3-t1
  TOps.Mul(Lt4, LZ3, LZ3, LTT);     // Z3 = t4*Z3
  TOps.Mul(Lt3, Lt0, Lt1, LTT);     // t1 = t3*t0
  TOps.Add(LZ3, Lt1, LZ3);          // Z3 = Z3+t1
  AR.X := LX3;
  AR.Y := LY3;
  AR.Z := LZ3;
end;

class procedure TCTPoint<TOps>.PointAddZero(const AP, AQ: TFePoint; var AR: TFePoint);
var
  Lt0, Lt1, Lt2, Lt3, Lt4, LX3, LY3, LZ3: TFe;
  LTT: TFeExt;
begin
  // RCB2016 Algorithm 7 (complete addition, a=0); 12M + 2 mul_b3, no mul_a.
  TOps.Mul(AP.X, AQ.X, Lt0, LTT);   // t0 = X1*X2
  TOps.Mul(AP.Y, AQ.Y, Lt1, LTT);   // t1 = Y1*Y2
  TOps.Mul(AP.Z, AQ.Z, Lt2, LTT);   // t2 = Z1*Z2
  TOps.Add(AP.X, AP.Y, Lt3);        // t3 = X1+Y1
  TOps.Add(AQ.X, AQ.Y, Lt4);        // t4 = X2+Y2
  TOps.Mul(Lt3, Lt4, Lt3, LTT);     // t3 = t3*t4
  TOps.Add(Lt0, Lt1, Lt4);          // t4 = t0+t1
  TOps.Sub(Lt3, Lt4, Lt3);          // t3 = t3-t4
  TOps.Add(AP.Y, AP.Z, Lt4);        // t4 = Y1+Z1
  TOps.Add(AQ.Y, AQ.Z, LX3);        // X3 = Y2+Z2
  TOps.Mul(Lt4, LX3, Lt4, LTT);     // t4 = t4*X3
  TOps.Add(Lt1, Lt2, LX3);          // X3 = t1+t2
  TOps.Sub(Lt4, LX3, Lt4);          // t4 = t4-X3
  TOps.Add(AP.X, AP.Z, LX3);        // X3 = X1+Z1
  TOps.Add(AQ.X, AQ.Z, LY3);        // Y3 = X2+Z2
  TOps.Mul(LX3, LY3, LX3, LTT);     // X3 = X3*Y3
  TOps.Add(Lt0, Lt2, LY3);          // Y3 = t0+t2
  TOps.Sub(LX3, LY3, LY3);          // Y3 = X3-Y3
  TOps.Add(Lt0, Lt0, LX3);          // X3 = t0+t0
  TOps.Add(LX3, Lt0, Lt0);          // t0 = X3+t0
  TOps.MulByB3(Lt2, Lt2, LTT);      // t2 = b3*t2
  TOps.Add(Lt1, Lt2, LZ3);          // Z3 = t1+t2
  TOps.Sub(Lt1, Lt2, Lt1);          // t1 = t1-t2
  TOps.MulByB3(LY3, LY3, LTT);      // Y3 = b3*Y3
  TOps.Mul(Lt4, LY3, LX3, LTT);     // X3 = t4*Y3
  TOps.Mul(Lt3, Lt1, Lt2, LTT);     // t2 = t3*t1
  TOps.Sub(Lt2, LX3, LX3);          // X3 = t2-X3
  TOps.Mul(LY3, Lt0, LY3, LTT);     // Y3 = Y3*t0
  TOps.Mul(Lt1, LZ3, Lt1, LTT);     // t1 = t1*Z3
  TOps.Add(Lt1, LY3, LY3);          // Y3 = t1+Y3
  TOps.Mul(Lt0, Lt3, Lt0, LTT);     // t0 = t0*t3
  TOps.Mul(LZ3, Lt4, LZ3, LTT);     // Z3 = Z3*t4
  TOps.Add(LZ3, Lt0, LZ3);          // Z3 = Z3+t0
  AR.X := LX3;
  AR.Y := LY3;
  AR.Z := LZ3;
end;

class procedure TCTPoint<TOps>.PointDouble(const AP: TFePoint; var AR: TFePoint);
begin
  if TOps.ACoeff = TCTACoeff.Zero then
    PointDoubleZero(AP, AR)
  else if TOps.ACoeff = TCTACoeff.MinusThree then
    PointDoubleM3(AP, AR)
  else
    PointDoubleGeneral(AP, AR);
end;

class procedure TCTPoint<TOps>.PointDoubleGeneral(const AP: TFePoint; var AR: TFePoint);
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

class procedure TCTPoint<TOps>.PointDoubleM3(const AP: TFePoint; var AR: TFePoint);
var
  Lt0, Lt1, Lt2, Lt3, LX3, LY3, LZ3: TFe;
  LTT: TFeExt;
begin
  // RCB2016 Algorithm 6 (exception-free doubling, a=-3); 8M + 3S + 2 mul_b, no mul_a.
  TOps.Sqr(AP.X, Lt0, LTT);         // t0 = X*X
  TOps.Sqr(AP.Y, Lt1, LTT);         // t1 = Y*Y
  TOps.Sqr(AP.Z, Lt2, LTT);         // t2 = Z*Z
  TOps.Mul(AP.X, AP.Y, Lt3, LTT);   // t3 = X*Y
  TOps.Add(Lt3, Lt3, Lt3);          // t3 = t3+t3
  TOps.Mul(AP.X, AP.Z, LZ3, LTT);   // Z3 = X*Z
  TOps.Add(LZ3, LZ3, LZ3);          // Z3 = Z3+Z3
  TOps.MulByB(Lt2, LY3, LTT);       // Y3 = b*t2
  TOps.Sub(LY3, LZ3, LY3);          // Y3 = Y3-Z3
  TOps.Add(LY3, LY3, LX3);          // X3 = Y3+Y3
  TOps.Add(LX3, LY3, LY3);          // Y3 = X3+Y3
  TOps.Sub(Lt1, LY3, LX3);          // X3 = t1-Y3
  TOps.Add(Lt1, LY3, LY3);          // Y3 = t1+Y3
  TOps.Mul(LX3, LY3, LY3, LTT);     // Y3 = X3*Y3
  TOps.Mul(LX3, Lt3, LX3, LTT);     // X3 = X3*t3
  TOps.Add(Lt2, Lt2, Lt3);          // t3 = t2+t2
  TOps.Add(Lt2, Lt3, Lt2);          // t2 = t2+t3
  TOps.MulByB(LZ3, LZ3, LTT);       // Z3 = b*Z3
  TOps.Sub(LZ3, Lt2, LZ3);          // Z3 = Z3-t2
  TOps.Sub(LZ3, Lt0, LZ3);          // Z3 = Z3-t0
  TOps.Add(LZ3, LZ3, Lt3);          // t3 = Z3+Z3
  TOps.Add(LZ3, Lt3, LZ3);          // Z3 = Z3+t3
  TOps.Add(Lt0, Lt0, Lt3);          // t3 = t0+t0
  TOps.Add(Lt3, Lt0, Lt0);          // t0 = t3+t0
  TOps.Sub(Lt0, Lt2, Lt0);          // t0 = t0-t2
  TOps.Mul(Lt0, LZ3, Lt0, LTT);     // t0 = t0*Z3
  TOps.Add(LY3, Lt0, LY3);          // Y3 = Y3+t0
  TOps.Mul(AP.Y, AP.Z, Lt0, LTT);   // t0 = Y*Z
  TOps.Add(Lt0, Lt0, Lt0);          // t0 = t0+t0
  TOps.Mul(Lt0, LZ3, LZ3, LTT);     // Z3 = t0*Z3
  TOps.Sub(LX3, LZ3, LX3);          // X3 = X3-Z3
  TOps.Mul(Lt0, Lt1, LZ3, LTT);     // Z3 = t0*t1
  TOps.Add(LZ3, LZ3, LZ3);          // Z3 = Z3+Z3
  TOps.Add(LZ3, LZ3, LZ3);          // Z3 = Z3+Z3
  AR.X := LX3;
  AR.Y := LY3;
  AR.Z := LZ3;
end;

class procedure TCTPoint<TOps>.PointDoubleZero(const AP: TFePoint; var AR: TFePoint);
var
  Lt0, Lt1, Lt2, LX3, LY3, LZ3: TFe;
  LTT: TFeExt;
begin
  // RCB2016 Algorithm 9 (exception-free doubling, a=0); 6M + 2S + 1 mul_b3, no mul_a.
  TOps.Sqr(AP.Y, Lt0, LTT);         // t0 = Y*Y
  TOps.Add(Lt0, Lt0, LZ3);          // Z3 = t0+t0
  TOps.Add(LZ3, LZ3, LZ3);          // Z3 = Z3+Z3
  TOps.Add(LZ3, LZ3, LZ3);          // Z3 = Z3+Z3
  TOps.Mul(AP.Y, AP.Z, Lt1, LTT);   // t1 = Y*Z
  TOps.Sqr(AP.Z, Lt2, LTT);         // t2 = Z*Z
  TOps.MulByB3(Lt2, Lt2, LTT);      // t2 = b3*t2
  TOps.Mul(Lt2, LZ3, LX3, LTT);     // X3 = t2*Z3
  TOps.Add(Lt0, Lt2, LY3);          // Y3 = t0+t2
  TOps.Mul(Lt1, LZ3, LZ3, LTT);     // Z3 = t1*Z3
  TOps.Add(Lt2, Lt2, Lt1);          // t1 = t2+t2
  TOps.Add(Lt1, Lt2, Lt2);          // t2 = t1+t2
  TOps.Sub(Lt0, Lt2, Lt0);          // t0 = t0-t2
  TOps.Mul(Lt0, LY3, LY3, LTT);     // Y3 = t0*Y3
  TOps.Add(LX3, LY3, LY3);          // Y3 = X3+Y3
  TOps.Mul(AP.X, AP.Y, Lt1, LTT);   // t1 = X*Y
  TOps.Mul(Lt0, Lt1, LX3, LTT);     // X3 = t0*t1
  TOps.Add(LX3, LX3, LX3);          // X3 = X3+X3
  AR.X := LX3;
  AR.Y := LY3;
  AR.Z := LZ3;
end;

class procedure TCTPoint<TOps>.OneFe(const AFieldOps: IFpFieldOps; var AZ: TFe);
begin
  // Montgomery form of 1 (= R mod p); AFieldOps retained for signature parity.
  TOps.SetOne(AZ);
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
  LTT: TFeExt;
begin
  LN := AFieldOps.GetFieldInts;
  FillChar(AR, SizeOf(AR), 0);
  Move(AXa[0], AR.X.W[0], LN * SizeOf(UInt32));
  Move(AYa[0], AR.Y.W[0], LN * SizeOf(UInt32));
  // normal affine coords -> Montgomery domain; Z := Mont(1)
  TOps.ToMont(AR.X, AR.X, LTT);
  TOps.ToMont(AR.Y, AR.Y, LTT);
  TOps.SetOne(AR.Z);
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
  LZInv, LTmp, LZNorm: TFe;
  LTT: TFeExt;
begin
  LN := AFieldOps.GetFieldInts;
  LZarr := TNat.Create(LN);
  // Z is in the Montgomery domain; take it out before the normal-domain inverse.
  // The subsequent TOps.Mul(X_mont, Zinv_normal) then yields the normal affine coord.
  TOps.FromMont(AP.Z, LZNorm, LTT);
  Move(LZNorm.W[0], LZarr[0], LN * SizeOf(UInt32));
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
  LEntry: ^TFePoint;
begin
  LN := AFieldOps.GetFieldInts;
  FillChar(AR, SizeOf(AR), 0);
  // Scan every entry (scalar-independent access pattern); read straight from the
  // table (no per-entry struct copy) and only the N live limbs.
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

end.
