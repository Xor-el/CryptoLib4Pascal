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

unit ClpHomogeneousPoint;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpNat,
  ClpICTFieldOps,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// A point in homogeneous projective coordinates (X : Y : Z), x = X/Z, y = Y/Z,
  /// identity = (0 : 1 : 0). Value aggregate over the three limb arrays.
  /// </summary>
  TCTHomogPoint = record
    X, Y, Z: TCryptoLibUInt32Array;
  end;

  /// <summary>
  /// Renes-Costello-Batina (EUROCRYPT 2016) complete addition formulas,
  /// a = -3 specialization (Algorithms 4 and 6), homogeneous coordinates.
  /// Exception-free for prime-order (cofactor 1) short-Weierstrass curves.
  /// </summary>
  TCTHomogeneousMath = class sealed(TObject)
  public
    class function Infinity(const AFO: ICTFieldOps): TCTHomogPoint; static;
    class function FromAffine(const AFO: ICTFieldOps;
      const AX, AY: TCryptoLibUInt32Array): TCTHomogPoint; static;
    class function ScaleRandom(const AFO: ICTFieldOps; const AP: TCTHomogPoint;
      const ALambda: TCryptoLibUInt32Array): TCTHomogPoint; static;
    class function Add(const AFO: ICTFieldOps; const AP, AQ: TCTHomogPoint): TCTHomogPoint; static;
    class function Double(const AFO: ICTFieldOps; const AP: TCTHomogPoint): TCTHomogPoint; static;
    class procedure ToAffine(const AFO: ICTFieldOps; const AP: TCTHomogPoint;
      out AX, AY: TCryptoLibUInt32Array; out AIsInfinity: Boolean); static;
  end;

implementation

{ TCTHomogeneousMath }

class function TCTHomogeneousMath.Infinity(const AFO: ICTFieldOps): TCTHomogPoint;
var
  LN: Int32;
  LX, LY, LZ: TCryptoLibUInt32Array;
begin
  LN := AFO.GetFieldInts;
  LX := TNat.Create(LN);
  LY := TNat.Create(LN);
  LZ := TNat.Create(LN);
  AFO.FieldOne(LY);
  Result.X := LX;
  Result.Y := LY;
  Result.Z := LZ;
end;

class function TCTHomogeneousMath.FromAffine(const AFO: ICTFieldOps;
  const AX, AY: TCryptoLibUInt32Array): TCTHomogPoint;
var
  LN: Int32;
  LX, LY, LZ: TCryptoLibUInt32Array;
begin
  LN := AFO.GetFieldInts;
  LX := TNat.Copy(LN, AX);
  LY := TNat.Copy(LN, AY);
  LZ := TNat.Create(LN);
  AFO.FieldOne(LZ);
  Result.X := LX;
  Result.Y := LY;
  Result.Z := LZ;
end;

class function TCTHomogeneousMath.ScaleRandom(const AFO: ICTFieldOps;
  const AP: TCTHomogPoint; const ALambda: TCryptoLibUInt32Array): TCTHomogPoint;
var
  LN: Int32;
begin
  LN := AFO.GetFieldInts;
  Result.X := TNat.Create(LN);
  Result.Y := TNat.Create(LN);
  Result.Z := TNat.Create(LN);
  AFO.Mul(AP.X, ALambda, Result.X);
  AFO.Mul(AP.Y, ALambda, Result.Y);
  AFO.Mul(AP.Z, ALambda, Result.Z);
end;

class function TCTHomogeneousMath.Add(const AFO: ICTFieldOps;
  const AP, AQ: TCTHomogPoint): TCTHomogPoint;
var
  LN: Int32;
  Lt0, Lt1, Lt2, Lt3, Lt4, Lt5, LX3, LY3, LZ3: TCryptoLibUInt32Array;
  LX1, LY1, LZ1, LX2, LY2, LZ2: TCryptoLibUInt32Array;
begin
  LN := AFO.GetFieldInts;
  LX1 := AP.X; LY1 := AP.Y; LZ1 := AP.Z;
  LX2 := AQ.X; LY2 := AQ.Y; LZ2 := AQ.Z;

  Lt0 := TNat.Create(LN); Lt1 := TNat.Create(LN); Lt2 := TNat.Create(LN);
  Lt3 := TNat.Create(LN); Lt4 := TNat.Create(LN); Lt5 := TNat.Create(LN);
  LX3 := TNat.Create(LN); LY3 := TNat.Create(LN); LZ3 := TNat.Create(LN);

  // RCB2016 complete addition (Algorithm 1), explicit a and b3 = 3b
  AFO.Mul(LX1, LX2, Lt0);   // t0 = X1*X2
  AFO.Mul(LY1, LY2, Lt1);   // t1 = Y1*Y2
  AFO.Mul(LZ1, LZ2, Lt2);   // t2 = Z1*Z2
  AFO.Add(LX1, LY1, Lt3);   // t3 = X1+Y1
  AFO.Add(LX2, LY2, Lt4);   // t4 = X2+Y2
  AFO.Mul(Lt3, Lt4, Lt3);   // t3 = t3*t4
  AFO.Add(Lt0, Lt1, Lt4);   // t4 = t0+t1
  AFO.Sub(Lt3, Lt4, Lt3);   // t3 = t3-t4
  AFO.Add(LX1, LZ1, Lt4);   // t4 = X1+Z1
  AFO.Add(LX2, LZ2, Lt5);   // t5 = X2+Z2
  AFO.Mul(Lt4, Lt5, Lt4);   // t4 = t4*t5
  AFO.Add(Lt0, Lt2, Lt5);   // t5 = t0+t2
  AFO.Sub(Lt4, Lt5, Lt4);   // t4 = t4-t5
  AFO.Add(LY1, LZ1, Lt5);   // t5 = Y1+Z1
  AFO.Add(LY2, LZ2, LX3);   // X3 = Y2+Z2
  AFO.Mul(Lt5, LX3, Lt5);   // t5 = t5*X3
  AFO.Add(Lt1, Lt2, LX3);   // X3 = t1+t2
  AFO.Sub(Lt5, LX3, Lt5);   // t5 = t5-X3
  AFO.MulByA(Lt4, LZ3);     // Z3 = a*t4
  AFO.MulByB3(Lt2, LX3);    // X3 = b3*t2
  AFO.Add(LX3, LZ3, LZ3);   // Z3 = X3+Z3
  AFO.Sub(Lt1, LZ3, LX3);   // X3 = t1-Z3
  AFO.Add(Lt1, LZ3, LZ3);   // Z3 = t1+Z3
  AFO.Mul(LX3, LZ3, LY3);   // Y3 = X3*Z3
  AFO.Add(Lt0, Lt0, Lt1);   // t1 = t0+t0
  AFO.Add(Lt1, Lt0, Lt1);   // t1 = t1+t0
  AFO.MulByA(Lt2, Lt2);     // t2 = a*t2
  AFO.MulByB3(Lt4, Lt4);    // t4 = b3*t4
  AFO.Add(Lt1, Lt2, Lt1);   // t1 = t1+t2
  AFO.Sub(Lt0, Lt2, Lt2);   // t2 = t0-t2
  AFO.MulByA(Lt2, Lt2);     // t2 = a*t2
  AFO.Add(Lt4, Lt2, Lt4);   // t4 = t4+t2
  AFO.Mul(Lt1, Lt4, Lt0);   // t0 = t1*t4
  AFO.Add(LY3, Lt0, LY3);   // Y3 = Y3+t0
  AFO.Mul(Lt5, Lt4, Lt0);   // t0 = t5*t4
  AFO.Mul(Lt3, LX3, LX3);   // X3 = t3*X3
  AFO.Sub(LX3, Lt0, LX3);   // X3 = X3-t0
  AFO.Mul(Lt3, Lt1, Lt0);   // t0 = t3*t1
  AFO.Mul(Lt5, LZ3, LZ3);   // Z3 = t5*Z3
  AFO.Add(LZ3, Lt0, LZ3);   // Z3 = Z3+t0

  Result.X := LX3; Result.Y := LY3; Result.Z := LZ3;
end;

class function TCTHomogeneousMath.Double(const AFO: ICTFieldOps;
  const AP: TCTHomogPoint): TCTHomogPoint;
var
  LN: Int32;
  Lt0, Lt1, Lt2, Lt3, LX3, LY3, LZ3: TCryptoLibUInt32Array;
  LX, LY, LZ: TCryptoLibUInt32Array;
begin
  LN := AFO.GetFieldInts;
  LX := AP.X; LY := AP.Y; LZ := AP.Z;

  Lt0 := TNat.Create(LN); Lt1 := TNat.Create(LN); Lt2 := TNat.Create(LN);
  Lt3 := TNat.Create(LN);
  LX3 := TNat.Create(LN); LY3 := TNat.Create(LN); LZ3 := TNat.Create(LN);

  // RCB2016 complete doubling (Algorithm 3), explicit a and b3 = 3b
  AFO.Square(LX, Lt0);      // t0 = X*X
  AFO.Square(LY, Lt1);      // t1 = Y*Y
  AFO.Square(LZ, Lt2);      // t2 = Z*Z
  AFO.Mul(LX, LY, Lt3);     // t3 = X*Y
  AFO.Add(Lt3, Lt3, Lt3);   // t3 = t3+t3
  AFO.Mul(LX, LZ, LZ3);     // Z3 = X*Z
  AFO.Add(LZ3, LZ3, LZ3);   // Z3 = Z3+Z3
  AFO.MulByA(LZ3, LX3);     // X3 = a*Z3
  AFO.MulByB3(Lt2, LY3);    // Y3 = b3*t2
  AFO.Add(LX3, LY3, LY3);   // Y3 = X3+Y3
  AFO.Sub(Lt1, LY3, LX3);   // X3 = t1-Y3
  AFO.Add(Lt1, LY3, LY3);   // Y3 = t1+Y3
  AFO.Mul(LX3, LY3, LY3);   // Y3 = X3*Y3
  AFO.Mul(Lt3, LX3, LX3);   // X3 = t3*X3
  AFO.MulByB3(LZ3, LZ3);    // Z3 = b3*Z3
  AFO.MulByA(Lt2, Lt2);     // t2 = a*t2
  AFO.Sub(Lt0, Lt2, Lt3);   // t3 = t0-t2
  AFO.MulByA(Lt3, Lt3);     // t3 = a*t3
  AFO.Add(Lt3, LZ3, Lt3);   // t3 = t3+Z3
  AFO.Add(Lt0, Lt0, LZ3);   // Z3 = t0+t0
  AFO.Add(LZ3, Lt0, Lt0);   // t0 = Z3+t0
  AFO.Add(Lt0, Lt2, Lt0);   // t0 = t0+t2
  AFO.Mul(Lt0, Lt3, Lt0);   // t0 = t0*t3
  AFO.Add(LY3, Lt0, LY3);   // Y3 = Y3+t0
  AFO.Mul(LY, LZ, Lt2);     // t2 = Y*Z
  AFO.Add(Lt2, Lt2, Lt2);   // t2 = t2+t2
  AFO.Mul(Lt2, Lt3, Lt0);   // t0 = t2*t3
  AFO.Sub(LX3, Lt0, LX3);   // X3 = X3-t0
  AFO.Mul(Lt2, Lt1, LZ3);   // Z3 = t2*t1
  AFO.Add(LZ3, LZ3, LZ3);   // Z3 = Z3+Z3
  AFO.Add(LZ3, LZ3, LZ3);   // Z3 = Z3+Z3

  Result.X := LX3; Result.Y := LY3; Result.Z := LZ3;
end;

class procedure TCTHomogeneousMath.ToAffine(const AFO: ICTFieldOps;
  const AP: TCTHomogPoint; out AX, AY: TCryptoLibUInt32Array; out AIsInfinity: Boolean);
var
  LN: Int32;
  LZInv: TCryptoLibUInt32Array;
begin
  LN := AFO.GetFieldInts;
  AIsInfinity := AFO.IsZero(AP.Z);
  AX := TNat.Create(LN);
  AY := TNat.Create(LN);
  if AIsInfinity then
    Exit;
  LZInv := TNat.Create(LN);
  AFO.Inv(AP.Z, LZInv);
  AFO.Mul(AP.X, LZInv, AX);
  AFO.Mul(AP.Y, LZInv, AY);
end;

end.
