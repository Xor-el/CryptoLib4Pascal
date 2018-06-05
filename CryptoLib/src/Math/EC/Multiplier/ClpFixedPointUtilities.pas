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

unit ClpFixedPointUtilities;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpIPreCompInfo,
  ClpFixedPointPreCompInfo,
  ClpIFixedPointPreCompInfo,
  ClpIECInterface;

type
  TFixedPointUtilities = class sealed(TObject)
  strict private
  const
    PRECOMP_NAME: String = 'bc_fixed_point';

  public
    class function GetCombSize(const c: IECCurve): Int32; static; inline;
    class function GetFixedPointPreCompInfo(const preCompInfo: IPreCompInfo)
      : IFixedPointPreCompInfo; static; inline;
    class function Precompute(const p: IECPoint): IFixedPointPreCompInfo;
      overload; static;
    class function Precompute(const p: IECPoint; minWidth: Int32)
      : IFixedPointPreCompInfo; overload; static;
      deprecated
      'Use "Precompute(ECPoint)" instead, as minWidth parameter is now ignored';
  end;

implementation

{ TFixedPointUtilities }

class function TFixedPointUtilities.GetCombSize(const c: IECCurve): Int32;
var
  order: TBigInteger;
begin
  order := c.order;
  if (not(order.IsInitialized)) then
  begin
    Result := c.FieldSize + 1;
  end
  else
  begin
    Result := order.BitLength;
  end;
end;

class function TFixedPointUtilities.GetFixedPointPreCompInfo(const preCompInfo
  : IPreCompInfo): IFixedPointPreCompInfo;
begin
  if (Supports(preCompInfo, IFixedPointPreCompInfo, Result)) then
  begin
    Exit;
  end;

  Result := TFixedPointPreCompInfo.Create();
end;

class function TFixedPointUtilities.Precompute(const p: IECPoint)
  : IFixedPointPreCompInfo;
var
  c: IECCurve;
  n, bit, bits, d, i, step, minWidth: Int32;
  info: IFixedPointPreCompInfo;
  pow2: IECPoint;
  lookupTable, pow2Table: TCryptoLibGenericArray<IECPoint>;
begin
  c := p.Curve;

  if GetCombSize(c) > 257 then
  begin
    minWidth := 6
  end
  else
  begin
    minWidth := 5
  end;

  n := 1 shl minWidth;
  info := GetFixedPointPreCompInfo(c.GetPreCompInfo(p, PRECOMP_NAME));

  lookupTable := info.PreComp;

  if ((lookupTable = Nil) or (System.Length(lookupTable) < n)) then
  begin
    bits := GetCombSize(c);
    d := (bits + minWidth - 1) div minWidth;

    raise Exception.Create(IntToStr(c.order) + ' DABA ' + IntToStr(bits) +
      ' DABA ' + IntToStr(d));

    System.SetLength(pow2Table, minWidth + 1);

    pow2Table[0] := p;
    for i := 1 to System.Pred(minWidth) do
    begin
      pow2Table[i] := pow2Table[i - 1].TimesPow2(d);
    end;

    // This will be the 'offset' value
    pow2Table[minWidth] := pow2Table[0].Subtract(pow2Table[1]);

    c.NormalizeAll(pow2Table);

    System.SetLength(lookupTable, n);

    lookupTable[0] := pow2Table[0];

    bit := minWidth - 1;
    while bit >= 0 do
    begin
      pow2 := pow2Table[bit];

      step := 1 shl bit;

      i := step;

      while i < n do
      begin
        lookupTable[i] := lookupTable[i - step].Add(pow2);

        System.Inc(i, step shl 1);
      end;

      System.Dec(bit);
    end;

    c.NormalizeAll(lookupTable);

    info.lookupTable := c.CreateCacheSafeLookupTable(lookupTable, 0,
      System.Length(lookupTable));
    info.Offset := pow2Table[minWidth];
    info.PreComp := lookupTable;
    info.Width := minWidth;

    c.SetPreCompInfo(p, PRECOMP_NAME, info);
  end;
  Result := info;
end;

class function TFixedPointUtilities.Precompute(const p: IECPoint;
  minWidth: Int32): IFixedPointPreCompInfo;
begin
  Result := Precompute(p);
end;

end.
