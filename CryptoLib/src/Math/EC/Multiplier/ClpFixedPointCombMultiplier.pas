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

unit ClpFixedPointCombMultiplier;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpIECInterface,
  ClpFixedPointUtilities,
  ClpIFixedPointPreCompInfo,
  ClpAbstractECMultiplier,
  ClpIFixedPointCombMultiplier;

resourcestring
  SInvalidComputation =
    'Fixed-Point Comb Doesn''t Support Scalars Larger Than The Curve Order';

type
  TFixedPointCombMultiplier = class sealed(TAbstractECMultiplier,
    IFixedPointCombMultiplier)

  strict protected
    function MultiplyPositive(const p: IECPoint; const k: TBigInteger)
      : IECPoint; override;
    function GetWidthForCombSize(combSize: Int32): Int32; virtual;

  end;

implementation

{ TFixedPointCombMultiplier }

function TFixedPointCombMultiplier.GetWidthForCombSize(combSize: Int32): Int32;
begin
  if (combSize > 257) then
  begin
    Result := 6
  end
  else
  begin
    Result := 5;
  end;
end;

function TFixedPointCombMultiplier.MultiplyPositive(const p: IECPoint;
  const k: TBigInteger): IECPoint;
var
  c: IECCurve;
  R: IECPoint;
  size, minWidth, width, d, top, i, j, index: Int32;
  info: IFixedPointPreCompInfo;
  lookupTable: TCryptoLibGenericArray<IECPoint>;
begin
  c := p.Curve;
  size := TFixedPointUtilities.GetCombSize(c);
  if (k.BitLength > size) then
  begin
    // /*
    // * TODO The comb works best when the scalars are less than the (possibly unknown) order.
    // * Still, if we want to handle larger scalars, we could allow customization of the comb
    // * size, or alternatively we could deal with the 'extra' bits either by running the comb
    // * multiple times as necessary, or by using an alternative multiplier as prelude.
    // */
    raise EInvalidOperationCryptoLibException.CreateRes(@SInvalidComputation);
  end;

  minWidth := GetWidthForCombSize(size);

  info := TFixedPointUtilities.Precompute(p, minWidth);
  lookupTable := info.PreComp;
  width := info.width;

  d := (size + width - 1) div width;

  R := c.Infinity;

  top := d * width - 1;

  for i := 0 to System.Pred(d) do
  begin

    index := 0;

    j := (top - i);

    while j >= 0 do
    begin

      index := index shl 1;
      if (k.TestBit(j)) then
      begin
        index := index or 1;
      end;

      System.Dec(j, d);
    end;

    R := R.TwicePlus(lookupTable[index]);

  end;

  Result := R.Add(info.Offset);

end;

end.
