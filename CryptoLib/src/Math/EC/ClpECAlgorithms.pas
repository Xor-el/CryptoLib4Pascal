{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpECAlgorithms;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Math,
  ClpCryptoLibTypes,
  ClpBits,
  ClpBigInteger,
  ClpWNafUtilities,
  ClpIPolynomialExtensionField,
  ClpIGlvEndomorphism,
  ClpIWNafPreCompInfo,
  ClpIECInterface,
  ClpIECFieldElement,
  ClpIFiniteField;

resourcestring
  SInvalidArray =
    'Point and Scalar Arrays Should be Non-Null, and of Equal, Non-Zero, Length';
  SInvalidPointLocation = 'Point Must be on the Same Curve';
  SInvalidPoint = 'Invalid Point, "P"';
  SInvalidResult = 'Invalid Result';

type
  TECAlgorithms = class sealed(TObject)

  strict private
    class function ImplShamirsTrickWNaf(const preCompP,
      preCompNegP: TCryptoLibGenericArray<IECPoint>;
      const wnafP: TCryptoLibByteArray;
      const preCompQ, preCompNegQ: TCryptoLibGenericArray<IECPoint>;
      const wnafQ: TCryptoLibByteArray): IECPoint; overload; static;

    class function ImplSumOfMultiplies(const negs: TCryptoLibBooleanArray;
      const infos: TCryptoLibGenericArray<IWNafPreCompInfo>;
      const wnafs: TCryptoLibMatrixByteArray): IECPoint; overload; static;

  public
    class function IsF2mCurve(const c: IECCurve): Boolean; static;
    class function IsF2mField(const field: IFiniteField): Boolean; static;
    class function IsFpCurve(const c: IECCurve): Boolean; static;
    class function IsFpField(const field: IFiniteField): Boolean; static;

    class function SumOfMultiplies(const ps: TCryptoLibGenericArray<IECPoint>;
      const ks: TCryptoLibGenericArray<TBigInteger>): IECPoint; static;

    class function SumOfTwoMultiplies(const P: IECPoint; const a: TBigInteger;
      const Q: IECPoint; const b: TBigInteger): IECPoint; static;

    // /*
    // * "Shamir's Trick", originally due to E. G. Straus
    // * (Addition chains of vectors. American Mathematical Monthly,
    // * 71(7):806-808, Aug./Sept. 1964)
    // *
    // * Input: The points P, Q, scalar k = (km?, ... , k1, k0)
    // * and scalar l = (lm?, ... , l1, l0).
    // * Output: R = k * P + l * Q.
    // * 1: Z <- P + Q
    // * 2: R <- O
    // * 3: for i from m-1 down to 0 do
    // * 4:        R <- R + R        {point doubling}
    // * 5:        if (ki = 1) and (li = 0) then R <- R + P end if
    // * 6:        if (ki = 0) and (li = 1) then R <- R + Q end if
    // * 7:        if (ki = 1) and (li = 1) then R <- R + Z end if
    // * 8: end for
    // * 9: return R
    // */
    class function ShamirsTrick(const P: IECPoint; const k: TBigInteger;
      const Q: IECPoint; const l: TBigInteger): IECPoint; static;

    class function ImportPoint(const c: IECCurve; const P: IECPoint)
      : IECPoint; static;

    class procedure MontgomeryTrick(const zs
      : TCryptoLibGenericArray<IECFieldElement>; off, len: Int32); overload;
      static; inline;

    class procedure MontgomeryTrick(const zs
      : TCryptoLibGenericArray<IECFieldElement>; off, len: Int32;
      const scale: IECFieldElement); overload; static;

    // /**
    // * Simple shift-and-add multiplication. Serves as reference implementation
    // * to verify (possibly faster) implementations, and for very small scalars.
    // *
    // * @param p
    // *            The point to multiply.
    // * @param k
    // *            The multiplier.
    // * @return The result of the point multiplication <code>kP</code>.
    // */
    class function ReferenceMultiply(const P: IECPoint; const k: TBigInteger)
      : IECPoint; static;

    class function ImplCheckResult(const P: IECPoint): IECPoint; static;

    class function ValidatePoint(const P: IECPoint): IECPoint; static;

    class function CleanPoint(const c: IECCurve; const P: IECPoint)
      : IECPoint; static;

    class function ImplShamirsTrickJsf(const P: IECPoint; const k: TBigInteger;
      const Q: IECPoint; const l: TBigInteger): IECPoint; static;

    class function ImplShamirsTrickWNaf(const P: IECPoint; const k: TBigInteger;
      const Q: IECPoint; const l: TBigInteger): IECPoint; overload; static;

    class function ImplShamirsTrickWNaf(const P: IECPoint; const k: TBigInteger;
      const pointMapQ: IECPointMap; const l: TBigInteger): IECPoint;
      overload; static;

    class function ImplSumOfMultiplies
      (const ps: TCryptoLibGenericArray<IECPoint>;
      const ks: TCryptoLibGenericArray<TBigInteger>): IECPoint;
      overload; static;

    class function ImplSumOfMultipliesGlv
      (const ps: TCryptoLibGenericArray<IECPoint>;
      const ks: TCryptoLibGenericArray<TBigInteger>;
      const glvEndomorphism: IGlvEndomorphism): IECPoint; static;

    class function ImplSumOfMultiplies
      (const ps: TCryptoLibGenericArray<IECPoint>; const pointMap: IECPointMap;
      const ks: TCryptoLibGenericArray<TBigInteger>): IECPoint;
      overload; static;

  end;

implementation

{ TECAlgorithms }

class function TECAlgorithms.ImplCheckResult(const P: IECPoint): IECPoint;
begin
  if (not(P.IsValidPartial())) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidResult);
  end;

  result := P;
end;

class function TECAlgorithms.CleanPoint(const c: IECCurve; const P: IECPoint)
  : IECPoint;
var
  cp: IECCurve;
begin
  cp := P.Curve;
  if (not c.Equals(cp)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidPointLocation);
  end;

  result := c.DecodePoint(P.getEncoded(false));
end;

class function TECAlgorithms.ValidatePoint(const P: IECPoint): IECPoint;
begin
  if (not P.IsValid()) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidPoint);
  end;

  result := P;
end;

class function TECAlgorithms.ImplShamirsTrickJsf(const P: IECPoint;
  const k: TBigInteger; const Q: IECPoint; const l: TBigInteger): IECPoint;
var
  Curve: IECCurve;
  infinity, R: IECPoint;
  PaddQ, PsubQ: IECPoint;
  points, table: TCryptoLibGenericArray<IECPoint>;
  jsf: TCryptoLibByteArray;
  i, jsfi, kDigit, lDigit, index: Int32;
begin
  Curve := P.Curve;
  infinity := Curve.infinity;

  // TODO conjugate co-Z addition (ZADDC) can return both of these
  PaddQ := P.Add(Q);
  PsubQ := P.Subtract(Q);

  points := TCryptoLibGenericArray<IECPoint>.Create(Q, PsubQ, P, PaddQ);
  Curve.NormalizeAll(points);

  table := TCryptoLibGenericArray<IECPoint>.Create(points[3].Negate(),
    points[2].Negate(), points[1].Negate(), points[0].Negate(), infinity,
    points[0], points[1], points[2], points[3]);

  jsf := TWNafUtilities.GenerateJsf(k, l);

  R := infinity;

  i := System.Length(jsf);
  System.Dec(i);
  while (i >= 0) do
  begin
    jsfi := jsf[i];

    // NOTE: The shifting ensures the sign is extended correctly
    kDigit := (TBits.Asr32((jsfi shl 24), 28));
    lDigit := (TBits.Asr32((jsfi shl 28), 28));

    index := 4 + (kDigit * 3) + lDigit;
    R := R.TwicePlus(table[index]);
    System.Dec(i);
  end;

  result := R;
end;

class function TECAlgorithms.ImplShamirsTrickWNaf(const P: IECPoint;
  const k: TBigInteger; const pointMapQ: IECPointMap; const l: TBigInteger)
  : IECPoint;
var
  negK, negL: Boolean;
  width: Int32;
  Q: IECPoint;
  infoP, infoQ: IWNafPreCompInfo;
  preCompP, preCompQ, preCompNegP, preCompNegQ
    : TCryptoLibGenericArray<IECPoint>;
  wnafP, wnafQ: TCryptoLibByteArray;
  LK, LL: TBigInteger;
begin
  LK := k;
  LL := l;
  negK := LK.SignValue < 0;
  negL := LL.SignValue < 0;

  LK := LK.Abs();
  LL := LL.Abs();

  width := Max(2, Min(16, TWNafUtilities.GetWindowSize(Max(LK.BitLength,
    LL.BitLength))));

  Q := TWNafUtilities.MapPointWithPrecomp(P, width, true, pointMapQ);
  infoP := TWNafUtilities.GetWNafPreCompInfo(P);
  infoQ := TWNafUtilities.GetWNafPreCompInfo(Q);

  case negK of
    true:
      preCompP := infoP.PreCompNeg;
    false:
      preCompP := infoP.PreComp;
  end;

  case negL of
    true:
      preCompQ := infoQ.PreCompNeg;
    false:
      preCompQ := infoQ.PreComp
  end;

  case negK of
    true:
      preCompNegP := infoP.PreComp;
    false:
      preCompNegP := infoP.PreCompNeg;
  end;

  case negL of
    true:
      preCompNegQ := infoQ.PreComp;
    false:
      preCompNegQ := infoQ.PreCompNeg
  end;

  wnafP := TWNafUtilities.GenerateWindowNaf(width, LK);
  wnafQ := TWNafUtilities.GenerateWindowNaf(width, LL);

  result := ImplShamirsTrickWNaf(preCompP, preCompNegP, wnafP, preCompQ,
    preCompNegQ, wnafQ);

  infoP.PreComp := Nil; // Review
  infoP.PreCompNeg := Nil; // Review
  infoQ.PreComp := Nil; // Review
  infoQ.PreCompNeg := Nil; // Review

end;

class function TECAlgorithms.ImplShamirsTrickWNaf(const P: IECPoint;
  const k: TBigInteger; const Q: IECPoint; const l: TBigInteger): IECPoint;
var
  negK, negL: Boolean;
  widthP, widthQ: Int32;
  infoP, infoQ: IWNafPreCompInfo;
  preCompP, preCompQ, preCompNegP, preCompNegQ
    : TCryptoLibGenericArray<IECPoint>;
  wnafP, wnafQ: TCryptoLibByteArray;
  LK, LL: TBigInteger;
begin
  LK := k;
  LL := l;
  negK := LK.SignValue < 0;
  negL := LL.SignValue < 0;

  LK := LK.Abs();
  LL := LL.Abs();

  widthP := Max(2, Min(16, TWNafUtilities.GetWindowSize(LK.BitLength)));
  widthQ := Max(2, Min(16, TWNafUtilities.GetWindowSize(LL.BitLength)));

  infoP := TWNafUtilities.Precompute(P, widthP, true);
  infoQ := TWNafUtilities.Precompute(Q, widthQ, true);

  if negK then
  begin
    preCompP := infoP.PreCompNeg
  end
  else
  begin
    preCompP := infoP.PreComp
  end;

  if negL then
  begin
    preCompQ := infoQ.PreCompNeg
  end
  else
  begin
    preCompQ := infoQ.PreComp
  end;

  if negK then
  begin
    preCompNegP := infoP.PreComp
  end
  else
  begin
    preCompNegP := infoP.PreCompNeg
  end;

  if negL then
  begin
    preCompNegQ := infoQ.PreComp
  end
  else
  begin
    preCompNegQ := infoQ.PreCompNeg
  end;

  wnafP := TWNafUtilities.GenerateWindowNaf(widthP, LK);
  wnafQ := TWNafUtilities.GenerateWindowNaf(widthQ, LL);

  result := ImplShamirsTrickWNaf(preCompP, preCompNegP, wnafP, preCompQ,
    preCompNegQ, wnafQ);
  infoP.PreComp := Nil; // Review
  infoP.PreCompNeg := Nil; // Review
  infoQ.PreComp := Nil; // Review
  infoQ.PreCompNeg := Nil; // Review
end;

class function TECAlgorithms.ImplShamirsTrickWNaf(const preCompP,
  preCompNegP: TCryptoLibGenericArray<IECPoint>;
  const wnafP: TCryptoLibByteArray;
  const preCompQ, preCompNegQ: TCryptoLibGenericArray<IECPoint>;
  const wnafQ: TCryptoLibByteArray): IECPoint;
var
  len, zeroes, i, wiP, wiQ, nP, nQ: Int32;
  Curve: IECCurve;
  infinity, R, point: IECPoint;
  tableP, tableQ: TCryptoLibGenericArray<IECPoint>;
begin
  len := Math.Max(System.Length(wnafP), System.Length(wnafQ));

  Curve := preCompP[0].Curve;
  infinity := Curve.infinity;

  R := infinity;
  zeroes := 0;

  i := len - 1;
  while (i >= 0) do
  begin

    if i < System.Length(wnafP) then
    begin
      wiP := Int32(ShortInt(wnafP[i]));
    end
    else
    begin
      wiP := 0;
    end;

    if i < System.Length(wnafQ) then
    begin
      wiQ := Int32(ShortInt(wnafQ[i]));
    end
    else
    begin
      wiQ := 0;
    end;

    if ((wiP or wiQ) = 0) then
    begin
      System.Inc(zeroes);
      System.Dec(i);
      continue;
    end;

    point := infinity;
    if (wiP <> 0) then
    begin
      nP := System.Abs(wiP);
      if wiP < 0 then
      begin
        tableP := preCompNegP;
      end
      else
      begin
        tableP := preCompP;
      end;

      point := point.Add(tableP[TBits.Asr32(nP, 1)]);
    end;
    if (wiQ <> 0) then
    begin

      nQ := System.Abs(wiQ);
      if wiQ < 0 then
      begin
        tableQ := preCompNegQ;
      end
      else
      begin
        tableQ := preCompQ;
      end;

      point := point.Add(tableQ[TBits.Asr32(nQ, 1)]);

    end;

    if (zeroes > 0) then
    begin
      R := R.TimesPow2(zeroes);
      zeroes := 0;
    end;

    R := R.TwicePlus(point);
    System.Dec(i);
  end;

  if (zeroes > 0) then
  begin
    R := R.TimesPow2(zeroes);
  end;

  result := R;
end;

class function TECAlgorithms.ImplSumOfMultiplies
  (const ps: TCryptoLibGenericArray<IECPoint>; const pointMap: IECPointMap;
  const ks: TCryptoLibGenericArray<TBigInteger>): IECPoint;
var
  halfCount, fullCount: Int32;
  negs: TCryptoLibBooleanArray;
  infos: TCryptoLibGenericArray<IWNafPreCompInfo>;
  wnafs: TCryptoLibMatrixByteArray;
  i, j0, j1, width: Int32;
  kj0, kj1: TBigInteger;
  P, Q: IECPoint;
begin
  halfCount := System.Length(ps);
  fullCount := halfCount shl 1;
  System.SetLength(negs, fullCount);
  System.SetLength(infos, fullCount);
  System.SetLength(wnafs, fullCount);

  for i := 0 to System.Pred(halfCount) do
  begin
    j0 := i shl 1;
    j1 := j0 + 1;

    kj0 := ks[j0];
    negs[j0] := kj0.SignValue < 0;
    kj0 := kj0.Abs();
    kj1 := ks[j1];
    negs[j1] := kj1.SignValue < 0;
    kj1 := kj1.Abs();

    width := Max(2, Min(16, TWNafUtilities.GetWindowSize(Max(kj0.BitLength,
      kj1.BitLength))));

    P := ps[i];
    Q := TWNafUtilities.MapPointWithPrecomp(P, width, true, pointMap);
    infos[j0] := TWNafUtilities.GetWNafPreCompInfo(P);
    infos[j1] := TWNafUtilities.GetWNafPreCompInfo(Q);
    wnafs[j0] := TWNafUtilities.GenerateWindowNaf(width, kj0);
    wnafs[j1] := TWNafUtilities.GenerateWindowNaf(width, kj1);
  end;

  result := ImplSumOfMultiplies(negs, infos, wnafs);

  for i := System.Low(infos) to System.High(infos) do
  begin
    infos[i].PreComp := Nil; // Review
    infos[i].PreCompNeg := Nil; // Review
  end;

end;

class function TECAlgorithms.ImplSumOfMultiplies
  (const ps: TCryptoLibGenericArray<IECPoint>;
  const ks: TCryptoLibGenericArray<TBigInteger>): IECPoint;
var
  count, i, width: Int32;
  negs: TCryptoLibBooleanArray;
  infos: TCryptoLibGenericArray<IWNafPreCompInfo>;
  wnafs: TCryptoLibMatrixByteArray;
  ki: TBigInteger;
begin
  count := System.Length(ps);
  System.SetLength(negs, count);

  System.SetLength(infos, count);

  System.SetLength(wnafs, count);

  for i := 0 to System.Pred(count) do
  begin
    ki := ks[i];
    negs[i] := ki.SignValue < 0;
    ki := ki.Abs();

    width := Max(2, Min(16, TWNafUtilities.GetWindowSize(ki.BitLength)));
    infos[i] := TWNafUtilities.Precompute(ps[i], width, true);
    wnafs[i] := TWNafUtilities.GenerateWindowNaf(width, ki);
  end;

  result := ImplSumOfMultiplies(negs, infos, wnafs);

  for i := System.Low(infos) to System.High(infos) do
  begin
    infos[i].PreComp := Nil; // Review
    infos[i].PreCompNeg := Nil; // Review
  end;

end;

class function TECAlgorithms.ImplSumOfMultiplies
  (const negs: TCryptoLibBooleanArray;
  const infos: TCryptoLibGenericArray<IWNafPreCompInfo>;
  const wnafs: TCryptoLibMatrixByteArray): IECPoint;
var
  len, count, zeroes: Int32;
  i, J, wi, n: Int32;
  Curve: IECCurve;
  infinity, R, point: IECPoint;
  wnaf: TCryptoLibByteArray;
  info: IWNafPreCompInfo;
  table: TCryptoLibGenericArray<IECPoint>;
begin
  len := 0;
  count := System.Length(wnafs);

  for i := 0 to System.Pred(count) do
  begin
    len := Max(len, System.Length(wnafs[i]));
  end;

  Curve := infos[0].PreComp[0].Curve;
  infinity := Curve.infinity;

  R := infinity;
  zeroes := 0;

  i := len - 1;
  while (i >= 0) do
  begin
    point := infinity;

    for J := 0 to System.Pred(count) do
    begin
      wnaf := wnafs[J];
      if i < System.Length(wnaf) then
      begin
        wi := Int32(ShortInt(wnaf[i]));
      end
      else
      begin
        wi := 0;
      end;

      if (wi <> 0) then
      begin
        n := System.Abs(wi);
        info := infos[J];
        if (wi < 0 = negs[J]) then
        begin
          table := info.PreComp;
        end
        else
        begin
          table := info.PreCompNeg;
        end;

        point := point.Add(table[TBits.Asr32(n, 1)]);
      end;
    end;

    if (point = infinity) then
    begin
      System.Inc(zeroes);
      System.Dec(i);
      continue;
    end;

    if (zeroes > 0) then
    begin
      R := R.TimesPow2(zeroes);
      zeroes := 0;
    end;

    R := R.TwicePlus(point);

    System.Dec(i);
  end;

  if (zeroes > 0) then
  begin
    R := R.TimesPow2(zeroes);
  end;

  result := R;

end;

class function TECAlgorithms.ImplSumOfMultipliesGlv
  (const ps: TCryptoLibGenericArray<IECPoint>;
  const ks: TCryptoLibGenericArray<TBigInteger>;
  const glvEndomorphism: IGlvEndomorphism): IECPoint;
var
  n: TBigInteger;
  len, i, J: Int32;
  &abs, ab: TCryptoLibGenericArray<TBigInteger>;
  pointMap: IECPointMap;
  pqs: TCryptoLibGenericArray<IECPoint>;
  P, Q: IECPoint;
begin
  n := ps[0].Curve.Order;

  len := System.Length(ps);

  System.SetLength(Abs, len shl 1);

  i := 0;
  J := 0;

  while (i < len) do
  begin
    ab := glvEndomorphism.DecomposeScalar(ks[i].&Mod(n));

    Abs[J] := ab[0];
    System.Inc(J);
    Abs[J] := ab[1];
    System.Inc(J);
    System.Inc(i);
  end;

  pointMap := glvEndomorphism.pointMap;
  if (glvEndomorphism.HasEfficientPointMap) then
  begin
    result := TECAlgorithms.ImplSumOfMultiplies(ps, pointMap, Abs);
    Exit;
  end;

  System.SetLength(pqs, len shl 1);

  i := 0;
  J := 0;

  while (i < len) do
  begin
    P := ps[i];
    Q := pointMap.Map(P);

    pqs[J] := P;
    System.Inc(J);
    pqs[J] := Q;
    System.Inc(J);
    System.Inc(i);
  end;

  result := TECAlgorithms.ImplSumOfMultiplies(pqs, Abs);
end;

class function TECAlgorithms.ImportPoint(const c: IECCurve; const P: IECPoint)
  : IECPoint;
var
  cp: IECCurve;
begin
  cp := P.Curve;
  if (not c.Equals(cp)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidPointLocation);
  end;

  result := c.ImportPoint(P);
end;

class function TECAlgorithms.IsF2mField(const field: IFiniteField): Boolean;
begin
  result := (field.Dimension > 1) and
    (field.Characteristic.Equals(TBigInteger.Two)) and
    (Supports(field, IPolynomialExtensionField));
end;

class function TECAlgorithms.IsF2mCurve(const c: IECCurve): Boolean;
begin
  result := IsF2mField(c.field);
end;

class function TECAlgorithms.IsFpField(const field: IFiniteField): Boolean;
begin
  result := field.Dimension = 1;
end;

class function TECAlgorithms.IsFpCurve(const c: IECCurve): Boolean;
begin
  result := IsFpField(c.field);
end;

class procedure TECAlgorithms.MontgomeryTrick
  (const zs: TCryptoLibGenericArray<IECFieldElement>; off, len: Int32;
  const scale: IECFieldElement);
var
  c: TCryptoLibGenericArray<IECFieldElement>;
  i, J: Int32;
  u, tmp: IECFieldElement;
begin
  // /*
  // * Uses the "Montgomery Trick" to invert many field elements, with only a single actual
  // * field inversion. See e.g. the paper:
  // * "Fast Multi-scalar Multiplication Methods on Elliptic Curves with Precomputation Strategy Using Montgomery Trick"
  // * by Katsuyuki Okeya, Kouichi Sakurai.
  // */

  System.SetLength(c, len);

  c[0] := zs[off];

  i := 0;
  System.Inc(i);
  while (i < len) do
  begin
    c[i] := c[i - 1].Multiply(zs[off + i]);
    System.Inc(i);
  end;
  System.Dec(i);

  if (scale <> Nil) then
  begin
    c[i] := c[i].Multiply(scale);
  end;

  u := c[i].Invert();

  while (i > 0) do
  begin
    J := off + i;
    System.Dec(i);
    tmp := zs[J];
    zs[J] := c[i].Multiply(u);
    u := u.Multiply(tmp);
  end;

  zs[off] := u;
end;

class procedure TECAlgorithms.MontgomeryTrick
  (const zs: TCryptoLibGenericArray<IECFieldElement>; off, len: Int32);
begin
  MontgomeryTrick(zs, off, len, Nil);
end;

class function TECAlgorithms.ReferenceMultiply(const P: IECPoint;
  const k: TBigInteger): IECPoint;
var
  x: TBigInteger;
  Q, LP: IECPoint;
  t, i: Int32;
begin
  LP := P;
  x := k.Abs();
  Q := LP.Curve.infinity;
  t := x.BitLength;
  if (t > 0) then
  begin
    if (x.TestBit(0)) then
    begin
      Q := LP;
    end;
    i := 1;
    while (i < t) do
    begin
      LP := LP.Twice();
      if (x.TestBit(i)) then
      begin
        Q := Q.Add(LP);
      end;
      System.Inc(i);
    end;

  end;

  if k.SignValue < 0 then
  begin
    result := Q.Negate();
  end
  else
  begin
    result := Q;
  end;

end;

class function TECAlgorithms.ShamirsTrick(const P: IECPoint;
  const k: TBigInteger; const Q: IECPoint; const l: TBigInteger): IECPoint;
var
  cp: IECCurve;
  LQ: IECPoint;
begin
  cp := P.Curve;
  LQ := Q;
  LQ := ImportPoint(cp, LQ);

  result := ImplCheckResult(ImplShamirsTrickJsf(P, k, LQ, l));
end;

class function TECAlgorithms.SumOfMultiplies
  (const ps: TCryptoLibGenericArray<IECPoint>;
  const ks: TCryptoLibGenericArray<TBigInteger>): IECPoint;
var
  count: Int32;
  P: IECPoint;
  c: IECCurve;
  i: Int32;
  imported: TCryptoLibGenericArray<IECPoint>;
  glvEndomorphism: IGlvEndomorphism;
begin
  if ((ps = Nil) or (ks = Nil) or (System.Length(ps) <> System.Length(ks)) or
    (System.Length(ps) < 1)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidArray);
  end;

  count := System.Length(ps);

  case count of
    1:
      begin
        result := ps[0].Multiply(ks[0]);
        Exit;
      end;

    2:
      begin
        result := SumOfTwoMultiplies(ps[0], ks[0], ps[1], ks[1]);
        Exit;
      end;

  end;

  P := ps[0];
  c := P.Curve;
  System.SetLength(imported, count);
  imported[0] := P;

  for i := 1 to System.Pred(count) do
  begin
    imported[i] := ImportPoint(c, ps[i]);
  end;

  if Supports(c.GetEndomorphism(), IGlvEndomorphism, glvEndomorphism) then
  begin
    result := ImplCheckResult(ImplSumOfMultipliesGlv(imported, ks,
      glvEndomorphism));
    Exit;
  end;

  result := ImplCheckResult(ImplSumOfMultiplies(imported, ks));
end;

class function TECAlgorithms.SumOfTwoMultiplies(const P: IECPoint;
  const a: TBigInteger; const Q: IECPoint; const b: TBigInteger): IECPoint;
var
  cp: IECCurve;
  f2mCurve: IAbstractF2mCurve;
  glvEndomorphism: IGlvEndomorphism;
  LQ: IECPoint;
begin
  cp := P.Curve;
  LQ := Q;
  LQ := ImportPoint(cp, LQ);

  // Point multiplication for Koblitz curves (using WTNAF) beats Shamir's trick

  if (Supports(cp, IAbstractF2mCurve, f2mCurve) and (f2mCurve.IsKoblitz)) then
  begin
    result := ImplCheckResult(P.Multiply(a).Add(LQ.Multiply(b)));
    Exit;
  end;

  if Supports(cp.GetEndomorphism(), IGlvEndomorphism, glvEndomorphism) then
  begin
    result := ImplCheckResult
      (ImplSumOfMultipliesGlv(TCryptoLibGenericArray<IECPoint>.Create(P, LQ),
      TCryptoLibGenericArray<TBigInteger>.Create(a, b), glvEndomorphism));
    Exit;
  end;

  result := ImplCheckResult(ImplShamirsTrickWNaf(P, a, LQ, b));
end;

end.
