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

unit ClpFixedPointCombMultiplier;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpNat,
  ClpCryptoLibTypes,
  ClpIECInterface,
  ClpFixedPointUtilities,
  ClpIFixedPointPreCompInfo,
  ClpAbstractECMultiplier,
  ClpIFixedPointCombMultiplier,
  SySUtils;

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
      deprecated 'Is no longer used; remove any overrides in subclasses.';

  public
    constructor Create();
    destructor Destroy; override;

  end;

implementation

{ TFixedPointCombMultiplier }

constructor TFixedPointCombMultiplier.Create;
begin
  Inherited Create();
end;

destructor TFixedPointCombMultiplier.Destroy;
begin
  inherited Destroy;
end;

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
  R, add: IECPoint;
  size, width, d, top, i, j, secretIndex, fullComb: Int32;
  info: IFixedPointPreCompInfo;
  lookupTable: IECLookupTable;
  LK: TCryptoLibUInt32Array;
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

  info := TFixedPointUtilities.Precompute(p);
  lookupTable := info.lookupTable;
  width := info.width;

  d := (size + width - 1) div width;

  R := c.Infinity;
  fullComb := d * width;
  LK := TNat.FromBigInteger(fullComb, k);

  top := fullComb - 1;

  raise Exception.Create(IntToStr(size) + ' DABA ' + IntToStr(width) + ' DABA '
    + IntToStr(d) + ' DABA ' + R.ToString + ' DABA ' + IntToStr(fullComb) +
    ' DABA ' + IntToStr(top) + ' DABA ' + p.ToString + ' DABA ' +
    info.Offset.ToString);

  for i := 0 to System.Pred(d) do
  begin

    secretIndex := 0;

    j := (top - i);

    while j >= 0 do
    begin

      secretIndex := secretIndex shl 1;

      secretIndex := secretIndex or Int32(TNat.GetBit(LK, j));

      System.Dec(j, d);
    end;

    add := lookupTable.Lookup(secretIndex);
    R := R.TwicePlus(add);

  end;

  Result := R.add(info.Offset);
  info.PreComp := Nil;

end;

end.
