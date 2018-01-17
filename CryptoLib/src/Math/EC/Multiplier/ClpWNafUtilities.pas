{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                    Copyright (c) 2018 Ugochukwu Mmaduekwe                       * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *        Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring        * }
{ *                        the development of this library                          * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpWNafUtilities;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  Math,
  SysUtils,
  ClpBigInteger,
  ClpBits,
  ClpWNafPreCompInfo,
  ClpIPreCompInfo,
  ClpIWNafPreCompInfo,
  ClpIECInterface,
  ClpIECFieldElement,
  ClpCryptoLibTypes;

resourcestring
  SInvalidBitLength = 'Must have BitLength < 2^16, "k"';
  SInvalidRange = 'Must be in the Range [2, 16], "width"';
  SInvalidRange2 = 'Must be in the Range [2, 8], "width"';

type
  TWNafUtilities = class abstract(TObject)

  strict private

  class var
    FDEFAULT_WINDOW_SIZE_CUTOFFS, FEMPTY_INTS: TCryptoLibInt32Array;

    FEMPTY_BYTES: TCryptoLibByteArray;

    FEMPTY_POINTS: TCryptoLibGenericArray<IECPoint>;

    class function Trim(a: TCryptoLibByteArray; length: Int32)
      : TCryptoLibByteArray; overload; static; inline;

    class function Trim(a: TCryptoLibInt32Array; length: Int32)
      : TCryptoLibInt32Array; overload; static; inline;

    class function ResizeTable(a: TCryptoLibGenericArray<IECPoint>;
      length: Int32): TCryptoLibGenericArray<IECPoint>; static; inline;

    class constructor WNafUtilities();

  public

    const
    PRECOMP_NAME = 'bc_wnaf';

    class function GenerateCompactNaf(k: TBigInteger)
      : TCryptoLibInt32Array; static;
    class function GenerateCompactWindowNaf(width: Int32; k: TBigInteger)
      : TCryptoLibInt32Array; static;

    class function GenerateJsf(g, h: TBigInteger): TCryptoLibByteArray; static;
    class function GenerateNaf(k: TBigInteger): TCryptoLibByteArray; static;
    // /**
    // * Computes the Window NAF (non-adjacent Form) of an integer.
    // * @param width The width <code>w</code> of the Window NAF. The width is
    // * defined as the minimal number <code>w</code>, such that for any
    // * <code>w</code> consecutive digits in the resulting representation, at
    // * most one is non-zero.
    // * @param k The integer of which the Window NAF is computed.
    // * @return The Window NAF of the given width, such that the following holds:
    // * <code>k = &amp;sum;<sub>i=0</sub><sup>l-1</sup> k<sub>i</sub>2<sup>i</sup>
    // * </code>, where the <code>k<sub>i</sub></code> denote the elements of the
    // * returned <code>byte[]</code>.
    // */
    class function GenerateWindowNaf(width: Int32; k: TBigInteger)
      : TCryptoLibByteArray; static;

    class function GetNafWeight(k: TBigInteger): Int32; static; inline;

    class function GetWNafPreCompInfo(p: IECPoint): IWNafPreCompInfo; overload;
      static; inline;

    class function GetWNafPreCompInfo(preCompInfo: IPreCompInfo)
      : IWNafPreCompInfo; overload; static; inline;

    /// <summary>
    /// Determine window width to use for a scalar multiplication of the
    /// given size.
    /// </summary>
    /// <param name="bits">
    /// the bit-length of the scalar to multiply by
    /// </param>
    /// <returns>
    /// the window size to use
    /// </returns>
    class function GetWindowSize(bits: Int32): Int32; overload; static; inline;

    /// <summary>
    /// Determine window width to use for a scalar multiplication of the
    /// given size.
    /// </summary>
    /// <param name="bits">
    /// the bit-length of the scalar to multiply by
    /// </param>
    /// <param name="windowSizeCutoffs">
    /// a monotonically increasing list of bit sizes at which to increment
    /// the window width
    /// </param>
    /// <returns>
    /// the window size to use
    /// </returns>
    class function GetWindowSize(bits: Int32;
      windowSizeCutoffs: TCryptoLibInt32Array): Int32; overload; static; inline;

    class function MapPointWithPrecomp(p: IECPoint; width: Int32;
      includeNegated: Boolean; pointMap: IECPointMap): IECPoint; static;

    class function Precompute(p: IECPoint; width: Int32;
      includeNegated: Boolean): IWNafPreCompInfo; static;

  end;

implementation

uses
  ClpECCurve,
  ClpECAlgorithms; // included here to avoid circular dependency :)

{ TWNafUtilities }

class function TWNafUtilities.ResizeTable(a: TCryptoLibGenericArray<IECPoint>;
  length: Int32): TCryptoLibGenericArray<IECPoint>;
begin
  // Result := System.Copy(a, 0, System.length(a));
  if a <> Nil then
  begin
    Result := System.Copy(a);
  end;
  System.SetLength(Result, length);
end;

class function TWNafUtilities.Trim(a: TCryptoLibInt32Array; length: Int32)
  : TCryptoLibInt32Array;
begin
  Result := System.Copy(a, 0, length);
end;

class function TWNafUtilities.Trim(a: TCryptoLibByteArray; length: Int32)
  : TCryptoLibByteArray;
begin
  Result := System.Copy(a, 0, length);
end;

class function TWNafUtilities.GenerateCompactNaf(k: TBigInteger)
  : TCryptoLibInt32Array;
var
  _3k, diff: TBigInteger;
  bits, highBit, &length, zeroes, I, digit: Int32;
  naf: TCryptoLibInt32Array;
begin
  if ((TBits.Asr32(k.BitLength, 16)) <> 0) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidBitLength);
  end;
  if (k.SignValue = 0) then
  begin
    Result := FEMPTY_INTS;
    Exit;
  end;

  _3k := k.ShiftLeft(1).Add(k);

  bits := _3k.BitLength;
  System.SetLength(naf, TBits.Asr32(bits, 1));

  diff := _3k.&Xor(k);

  highBit := bits - 1;
  &length := 0;
  zeroes := 0;

  I := 1;

  while (I < highBit) do
  begin
    if (not diff.TestBit(I)) then
    begin
      System.Inc(zeroes);
      System.Inc(I);
      continue;
    end;

    if k.TestBit(I) then
    begin
      digit := -1;
    end
    else
    begin
      digit := 1;
    end;

    naf[length] := (digit shl 16) or zeroes;
    System.Inc(length);
    zeroes := 1;

    System.Inc(I, 2);

  end;

  naf[length] := (1 shl 16) or zeroes;
  System.Inc(length);

  if (System.length(naf) > length) then
  begin
    naf := Trim(naf, length);
  end;

  Result := naf;
end;

class function TWNafUtilities.GenerateCompactWindowNaf(width: Int32;
  k: TBigInteger): TCryptoLibInt32Array;
var
  wnaf: TCryptoLibInt32Array;
  pow2, mask, sign, &length, &pos, digit, zeroes: Int32;
  carry: Boolean;
begin
  if (width = 2) then
  begin
    Result := GenerateCompactNaf(k);
    Exit;
  end;

  if ((width < 2) or (width > 16)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidRange);
  end;
  if ((TBits.Asr32(k.BitLength, 16)) <> 0) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidBitLength);
  end;
  if (k.SignValue = 0) then
  begin
    Result := FEMPTY_INTS;
    Exit;
  end;

  System.SetLength(wnaf, (k.BitLength div width) + 1);

  // 2^width and a mask and sign bit set accordingly
  pow2 := 1 shl width;
  mask := pow2 - 1;
  sign := TBits.Asr32(pow2, 1);

  carry := false;
  length := 0;
  pos := 0;

  while (pos <= k.BitLength) do
  begin
    if (k.TestBit(pos) = carry) then
    begin
      System.Inc(pos);
      continue;
    end;

    k := k.ShiftRight(pos);

    digit := k.Int32Value and mask;
    if (carry) then
    begin
      System.Inc(digit);
    end;

    carry := (digit and sign) <> 0;
    if (carry) then
    begin
      digit := digit - pow2;
    end;

    if length > 0 then
    begin
      zeroes := pos - 1;
    end
    else
    begin
      zeroes := pos;
    end;

    wnaf[length] := (digit shl 16) or zeroes;
    System.Inc(length);
    pos := width;
  end;

  // Reduce the WNAF array to its actual length
  if (System.length(wnaf) > length) then
  begin
    wnaf := Trim(wnaf, length);
  end;

  Result := wnaf;
end;

class function TWNafUtilities.GenerateJsf(g, h: TBigInteger)
  : TCryptoLibByteArray;
var
  digits, j, d0, d1, offset, n0, n1, u0, u1: Int32;
  jsf: TCryptoLibByteArray;
  k0, k1: TBigInteger;
begin
  digits := Max(g.BitLength, h.BitLength) + 1;

  System.SetLength(jsf, digits);

  k0 := g;
  k1 := h;
  j := 0;
  d0 := 0;
  d1 := 0;

  offset := 0;

  while (((d0 or d1) <> 0) or (k0.BitLength > offset) or
    (k1.BitLength > offset)) do
  begin
    n0 := (Int32(UInt32(k0.Int32Value) shr offset) + d0) and 7;
    n1 := (Int32(UInt32(k1.Int32Value) shr offset) + d1) and 7;

    u0 := n0 and 1;
    if (u0 <> 0) then
    begin
      u0 := u0 - (n0 and 2);
      if (((n0 + u0) = 4) and ((n1 and 3) = 2)) then
      begin
        u0 := -u0;
      end;
    end;

    u1 := n1 and 1;
    if (u1 <> 0) then
    begin
      u1 := u1 - (n1 and 2);
      if (((n1 + u1) = 4) and ((n0 and 3) = 2)) then
      begin
        u1 := -u1;
      end;
    end;

    if ((d0 shl 1) = (1 + u0)) then
    begin
      d0 := d0 xor 1;
    end;
    if ((d1 shl 1) = (1 + u1)) then
    begin
      d1 := d1 xor 1;
    end;

    System.Inc(offset);
    if (offset = 30) then
    begin
      offset := 0;
      k0 := k0.ShiftRight(30);
      k1 := k1.ShiftRight(30);
    end;

    jsf[j] := Byte((u0 shl 4) or (u1 and $F));
    System.Inc(j);
  end;

  // Reduce the JSF array to its actual length
  if (System.length(jsf) > j) then
  begin
    jsf := Trim(jsf, j);
  end;

  Result := jsf;
end;

class function TWNafUtilities.GenerateNaf(k: TBigInteger): TCryptoLibByteArray;
var
  _3k, diff: TBigInteger;
  digits, I: Int32;
  naf: TCryptoLibByteArray;
begin
  if (k.SignValue = 0) then
  begin
    Result := FEMPTY_BYTES;
    Exit;
  end;

  _3k := k.ShiftLeft(1).Add(k);

  digits := _3k.BitLength - 1;
  System.SetLength(naf, digits);

  diff := _3k.&Xor(k);

  I := 1;

  while I < digits do
  begin
    if (diff.TestBit(I)) then
    begin
      if k.TestBit(I) then
      begin
        naf[I - 1] := Byte(-1);
      end
      else
      begin
        naf[I - 1] := Byte(1);
      end;

      System.Inc(I);
    end;
    System.Inc(I);
  end;

  naf[digits - 1] := 1;

  Result := naf;
end;

class function TWNafUtilities.GenerateWindowNaf(width: Int32; k: TBigInteger)
  : TCryptoLibByteArray;
var
  wnaf: TCryptoLibByteArray;
  pow2, mask, sign, &length, &pos, digit: Int32;
  carry: Boolean;
begin
  if (width = 2) then
  begin
    Result := GenerateNaf(k);
    Exit;
  end;

  if ((width < 2) or (width > 8)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidRange2);
  end;
  if (k.SignValue = 0) then
  begin
    Result := FEMPTY_BYTES;
    Exit;
  end;

  System.SetLength(wnaf, k.BitLength + 1);

  // 2^width and a mask and sign bit set accordingly
  pow2 := 1 shl width;
  mask := pow2 - 1;
  sign := TBits.Asr32(pow2, 1);

  carry := false;
  length := 0;
  pos := 0;

  while (pos <= k.BitLength) do
  begin
    if (k.TestBit(pos) = carry) then
    begin
      System.Inc(pos);
      continue;
    end;

    k := k.ShiftRight(pos);

    digit := k.Int32Value and mask;
    if (carry) then
    begin
      System.Inc(digit);
    end;

    carry := (digit and sign) <> 0;
    if (carry) then
    begin
      digit := digit - pow2;
    end;

    if length > 0 then
    begin
      length := length + (pos - 1);
    end
    else
    begin
      length := length + (pos);
    end;

    wnaf[length] := Byte(digit);
    System.Inc(length);
    pos := width;
  end;

  // Reduce the WNAF array to its actual length
  if (System.length(wnaf) > length) then
  begin
    wnaf := Trim(wnaf, length);
  end;

  Result := wnaf;
end;

class function TWNafUtilities.GetNafWeight(k: TBigInteger): Int32;
var
  _3k, diff: TBigInteger;
begin
  if (k.SignValue = 0) then
  begin
    Result := 0;
    Exit;
  end;

  _3k := k.ShiftLeft(1).Add(k);
  diff := _3k.&Xor(k);

  Result := diff.BitCount;
end;

class function TWNafUtilities.GetWindowSize(bits: Int32;
  windowSizeCutoffs: TCryptoLibInt32Array): Int32;
var
  w: Int32;
begin
  w := 0;
  while (w < System.length(windowSizeCutoffs)) do
  begin
    if (bits < windowSizeCutoffs[w]) then
    begin
      break;
    end;
    System.Inc(w);
  end;

  Result := w + 2;
end;

class function TWNafUtilities.GetWindowSize(bits: Int32): Int32;
begin
  Result := GetWindowSize(bits, FDEFAULT_WINDOW_SIZE_CUTOFFS);
end;

class function TWNafUtilities.GetWNafPreCompInfo(p: IECPoint): IWNafPreCompInfo;
begin
  Result := GetWNafPreCompInfo(p.Curve.GetPreCompInfo(p, PRECOMP_NAME));
end;

class function TWNafUtilities.GetWNafPreCompInfo(preCompInfo: IPreCompInfo)
  : IWNafPreCompInfo;
begin
  if (Supports(preCompInfo, IWNafPreCompInfo, Result)) then
  begin
    Exit;
  end;

  Result := TWNafPreCompInfo.Create();
end;

class function TWNafUtilities.MapPointWithPrecomp(p: IECPoint; width: Int32;
  includeNegated: Boolean; pointMap: IECPointMap): IECPoint;
var
  c: IECCurve;
  wnafPreCompP, wnafPreCompQ: IWNafPreCompInfo;
  q, twiceP, twiceQ: IECPoint;
  preCompP, preCompQ, preCompNegQ: TCryptoLibGenericArray<IECPoint>;
  I: Int32;
begin
  c := p.Curve;
  wnafPreCompP := Precompute(p, width, includeNegated);

  q := pointMap.Map(p);
  wnafPreCompQ := GetWNafPreCompInfo(c.GetPreCompInfo(q, PRECOMP_NAME));

  twiceP := wnafPreCompP.Twice;
  if (twiceP <> Nil) then
  begin
    twiceQ := pointMap.Map(twiceP);
    wnafPreCompQ.Twice := twiceQ;
  end;

  preCompP := wnafPreCompP.PreComp;
  System.SetLength(preCompQ, System.length(preCompP));
  for I := 0 to System.Pred(System.length(preCompP)) do
  begin
    preCompQ[I] := pointMap.Map(preCompP[I]);
  end;

  wnafPreCompQ.PreComp := preCompQ;

  if (includeNegated) then
  begin

    System.SetLength(preCompNegQ, System.length(preCompQ));

    for I := 0 to System.Pred(System.length(preCompNegQ)) do
    begin
      preCompNegQ[I] := preCompQ[I].Negate();
    end;

    wnafPreCompQ.PreCompNeg := preCompNegQ;
  end;

  c.SetPreCompInfo(q, PRECOMP_NAME, wnafPreCompQ);

  Result := q;

end;

class function TWNafUtilities.Precompute(p: IECPoint; width: Int32;
  includeNegated: Boolean): IWNafPreCompInfo;
var
  c: IECCurve;
  wnafPreCompInfo: IWNafPreCompInfo;
  iniPreCompLen, reqPreCompLen, curPreCompLen, &pos: Int32;
  PreComp, PreCompNeg: TCryptoLibGenericArray<IECPoint>;
  iso, iso2, iso3: IECFieldElement;
  twiceP, last: IECPoint;
begin
  c := p.Curve;
  wnafPreCompInfo := GetWNafPreCompInfo(c.GetPreCompInfo(p, PRECOMP_NAME));

  iniPreCompLen := 0;
  reqPreCompLen := 1 shl Max(0, width - 2);

  PreComp := wnafPreCompInfo.PreComp;
  if (PreComp = Nil) then
  begin
    PreComp := FEMPTY_POINTS;
  end
  else
  begin
    iniPreCompLen := System.length(PreComp);
  end;

  if (iniPreCompLen < reqPreCompLen) then
  begin
    PreComp := ResizeTable(PreComp, reqPreCompLen);

    if (reqPreCompLen = 1) then
    begin
      PreComp[0] := p.Normalize();
    end
    else
    begin
      curPreCompLen := iniPreCompLen;
      if (curPreCompLen = 0) then
      begin
        PreComp[0] := p;
        curPreCompLen := 1;
      end;

      iso := Nil;

      if (reqPreCompLen = 2) then
      begin
        PreComp[1] := p.ThreeTimes();
      end
      else
      begin
        twiceP := wnafPreCompInfo.Twice;
        last := PreComp[curPreCompLen - 1];
        if (twiceP = Nil) then
        begin
          twiceP := PreComp[0].Twice();
          wnafPreCompInfo.Twice := twiceP;

          // /*
          // * For Fp curves with Jacobian projective coordinates, use a (quasi-)isomorphism
          // * where 'twiceP' is "affine", so that the subsequent additions are cheaper. This
          // * also requires scaling the initial point's X, Y coordinates, and reversing the
          // * isomorphism as part of the subsequent normalization.
          // *
          // *  NOTE: The correctness of this optimization depends on:
          // *      1) additions do not use the curve's A, B coefficients.
          // *      2) no special cases (i.e. Q +/- Q) when calculating 1P, 3P, 5P, ...
          // */
          if ((not twiceP.IsInfinity) and (TECAlgorithms.IsFpCurve(c)) and
            (c.FieldSize >= 64)) then
          begin
            case (c.CoordinateSystem) of

              // TECCurve.COORD_JACOBIAN .. TECCurve.COORD_JACOBIAN_MODIFIED:
              TECCurve.COORD_JACOBIAN, TECCurve.COORD_JACOBIAN_CHUDNOVSKY,
                TECCurve.COORD_JACOBIAN_MODIFIED:
                begin
                  iso := twiceP.GetZCoord(0);
                  twiceP := c.CreatePoint(twiceP.XCoord.ToBigInteger(),
                    twiceP.YCoord.ToBigInteger());

                  iso2 := iso.Square();
                  iso3 := iso2.Multiply(iso);
                  last := last.ScaleX(iso2).ScaleY(iso3);

                  if (iniPreCompLen = 0) then
                  begin
                    PreComp[0] := last;
                  end;

                end;
            end;
          end;
        end;

        while (curPreCompLen < reqPreCompLen) do
        begin
          // /*
          // * Compute the new ECPoints for the precomputation array. The values 1, 3,
          // * 5, ..., 2^(width-1)-1 times p are computed
          // */

          last := last.Add(twiceP);
          PreComp[curPreCompLen] := last;
          System.Inc(curPreCompLen);
        end;
      end;

      // /*
      // * Having oft-used operands in affine form makes operations faster.
      // */
      c.NormalizeAll(PreComp, iniPreCompLen,
        reqPreCompLen - iniPreCompLen, iso);
    end;
  end;

  wnafPreCompInfo.PreComp := PreComp;

  if (includeNegated) then
  begin
    PreCompNeg := wnafPreCompInfo.PreCompNeg;

    if (PreCompNeg = Nil) then
    begin
      pos := 0;
      System.SetLength(PreCompNeg, reqPreCompLen);

    end
    else
    begin
      pos := System.length(PreCompNeg);
      if (pos < reqPreCompLen) then
      begin
        PreCompNeg := ResizeTable(PreCompNeg, reqPreCompLen);
      end
    end;

    while (pos < reqPreCompLen) do
    begin
      PreCompNeg[pos] := PreComp[pos].Negate();
      System.Inc(pos);
    end;

    wnafPreCompInfo.PreCompNeg := PreCompNeg;
  end;

  c.SetPreCompInfo(p, PRECOMP_NAME, wnafPreCompInfo);

  Result := wnafPreCompInfo;
end;

class constructor TWNafUtilities.WNafUtilities;
begin
  FDEFAULT_WINDOW_SIZE_CUTOFFS := TCryptoLibInt32Array.Create(13, 41, 121, 337,
    897, 2305);
  System.SetLength(FEMPTY_BYTES, 0);
  System.SetLength(FEMPTY_INTS, 0);
  System.SetLength(FEMPTY_POINTS, 0);
end;

end.
