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

unit ClpWNafL2RMultiplier;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  Math,
  ClpBits,
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpIECC,
  ClpIWNafPreCompInfo,
  ClpECAlgorithms,
  ClpAbstractECMultiplier,
  ClpIWNafL2RMultiplier;

type

  /// <summary>
  /// Class implementing the WNAF (Window Non-Adjacent Form) multiplication
  /// algorithm.
  /// </summary>
  TWNafL2RMultiplier = class(TAbstractECMultiplier, IWNafL2RMultiplier)

  strict protected
    // /**
    // * Multiplies <code>this</code> by an integer <code>k</code> using the
    // * Window NAF method.
    // * @param k The integer by which <code>this</code> is multiplied.
    // * @return A new <code>ECPoint</code> which equals <code>this</code>
    // * multiplied by <code>k</code>.
    // */
    function MultiplyPositive(const p: IECPoint; const k: TBigInteger)
      : IECPoint; override;

  public

    constructor Create();
    destructor Destroy; override;

  end;

implementation

{ TWNafL2RMultiplier }

constructor TWNafL2RMultiplier.Create;
begin
  Inherited Create();
end;

destructor TWNafL2RMultiplier.Destroy;
begin
  inherited Destroy;
end;

function TWNafL2RMultiplier.MultiplyPositive(const p: IECPoint;
  const k: TBigInteger): IECPoint;
var
  width, minWidth, i, wi, digit, zeroes, n, highest, scale, lowBits, i1,
    i2: Int32;
  info: IWNafPreCompInfo;
  preComp, preCompNeg, table: TCryptoLibGenericArray<IECPoint>;
  wnaf: TCryptoLibInt32Array;
  R, lr: IECPoint;
begin
  minWidth := TWNafUtilities.GetWindowSize(k.BitLength);

  info := TWNafUtilities.Precompute(p, minWidth, true);
  preComp := info.preComp;
  preCompNeg := info.preCompNeg;
  width := info.width;

  wnaf := TWNafUtilities.GenerateCompactWindowNaf(width, k);

  R := p.Curve.Infinity;

  i := System.Length(wnaf);

  // /*
  // * NOTE: We try to optimize the first window using the precomputed points to substitute an
  // * addition for 2 or more doublings.
  // */
  if (i > 1) then
  begin
    System.Dec(i);
    wi := wnaf[i];
    digit := TBits.Asr32(wi, 16);
    zeroes := wi and $FFFF;

    n := System.Abs(digit);
    if digit < 0 then
    begin
      table := preCompNeg;
    end
    else
    begin
      table := preComp;
    end;

    // Optimization can only be used for values in the lower half of the table
    if ((n shl 2) < (1 shl width)) then
    begin
      highest := 32 - TBits.NumberOfLeadingZeros(n);

      // TODO Get addition/doubling cost ratio from curve and compare to 'scale' to see if worth substituting?
      scale := width - highest;
      lowBits := n xor (1 shl (highest - 1));

      i1 := ((1 shl (width - 1)) - 1);
      i2 := (lowBits shl scale) + 1;
      R := table[TBits.Asr32(i1, 1)].Add(table[TBits.Asr32(i2, 1)]);

      zeroes := zeroes - scale;

      // Console.WriteLine("Optimized: 2^" + scale + " * " + n + " = " + i1 + " + " + i2);
    end
    else
    begin
      R := table[TBits.Asr32(n, 1)];
    end;

    R := R.TimesPow2(zeroes);
  end;

  while (i > 0) do
  begin
    System.Dec(i);
    wi := wnaf[i];
    digit := TBits.Asr32(wi, 16);
    zeroes := wi and $FFFF;

    n := System.Abs(digit);
    if digit < 0 then
    begin
      table := preCompNeg;
    end
    else
    begin
      table := preComp;
    end;

    lr := table[TBits.Asr32(n, 1)];

    R := R.TwicePlus(lr);
    R := R.TimesPow2(zeroes);
  end;

  Result := R;

  info.preComp := Nil; // Review
  info.preCompNeg := Nil; // Review

end;

end.
