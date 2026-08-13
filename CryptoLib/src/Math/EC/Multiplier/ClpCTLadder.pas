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

unit ClpCTLadder;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpCTFieldValue,
  ClpCTFieldOps;

type
  /// <summary>
  /// Generic constant-time point arithmetic over a per-curve ops class: the
  /// RCB2016 complete addition (Algorithm 1) and doubling (Algorithm 3) for Fp
  /// short-Weierstrass curves in homogeneous coordinates. One body serves every
  /// curve; <c>TOps</c> supplies the field arithmetic via the
  /// <see cref="TCTFieldOpsBase"/> virtual class methods, so the formulas run
  /// with no interface dispatch and every temporary is a stack
  /// <see cref="TFe"/>. The windowed scalar loop that drives these lives in
  /// <c>TFpCTMultiplier</c>.
  /// </summary>
  TCTLadder<TOps: TCTFieldOpsBase> = class sealed
  public
    /// <summary>RCB2016 complete addition (Algorithm 1, explicit a and b3).
    /// AR := AP + AQ in homogeneous coordinates; all temporaries are stack
    /// records. AR may alias AP or AQ.</summary>
    class procedure PointAdd(const AP, AQ: TFePoint; var AR: TFePoint); static;
    /// <summary>RCB2016 complete doubling (Algorithm 3). AR := 2*AP.</summary>
    class procedure PointDouble(const AP: TFePoint; var AR: TFePoint); static;
  end;

implementation

class procedure TCTLadder<TOps>.PointAdd(const AP, AQ: TFePoint; var AR: TFePoint);
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

class procedure TCTLadder<TOps>.PointDouble(const AP: TFePoint; var AR: TFePoint);
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

end.
