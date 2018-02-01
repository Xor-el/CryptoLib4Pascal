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

unit ClpWTauNafMultiplier;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBits,
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpTNaf,
  ClpAbstractECMultiplier,
  ClpIWTauNafPreCompInfo,
  ClpWTauNafPreCompInfo,
  ClpIECInterface,
  ClpIZTauElement,
  ClpIPreCompInfo,
  ClpIWTauNafMultiplier;

resourcestring
  SInCompatiblePoint = 'Only AbstractF2mPoint can be used in WTauNafMultiplier';

type
  /// **
  // * Class implementing the WTNAF (Window
  // * <code>&#964;</code>-adic Non-Adjacent Form) algorithm.
  // */
  TWTauNafMultiplier = class(TAbstractECMultiplier, IWTauNafMultiplier)

  strict private
    // TODO Create WTauNafUtilities class and move various functionality into it
  const
    PRECOMP_NAME = 'bc_wtnaf';

    // /**
    // * Multiplies a {@link org.bouncycastle.math.ec.AbstractF2mPoint AbstractF2mPoint}
    // * by an element <code>&#955;</code> of <code><b>Z</b>[&#964;]</code> using
    // * the <code>&#964;</code>-adic NAF (TNAF) method.
    // * @param p The AbstractF2mPoint to multiply.
    // * @param lambda The element <code>&#955;</code> of
    // * <code><b>Z</b>[&#964;]</code> of which to compute the
    // * <code>[&#964;]</code>-adic NAF.
    // * @return <code>p</code> multiplied by <code>&#955;</code>.
    // */
    function MultiplyWTnaf(const p: IAbstractF2mPoint;
      const lambda: IZTauElement; const preCompInfo: IPreCompInfo;
      a, mu: ShortInt): IAbstractF2mPoint; inline;

    // /**
    // * Multiplies a {@link org.bouncycastle.math.ec.AbstractF2mPoint AbstractF2mPoint}
    // * by an element <code>&#955;</code> of <code><b>Z</b>[&#964;]</code>
    // * using the window <code>&#964;</code>-adic NAF (TNAF) method, given the
    // * WTNAF of <code>&#955;</code>.
    // * @param p The AbstractF2mPoint to multiply.
    // * @param u The the WTNAF of <code>&#955;</code>..
    // * @return <code>&#955; * p</code>
    // */
    class function MultiplyFromWTnaf(const p: IAbstractF2mPoint;
      u: TCryptoLibShortIntArray; const preCompInfo: IPreCompInfo)
      : IAbstractF2mPoint; static;

  strict protected
    // /**
    // * Multiplies a {@link org.bouncycastle.math.ec.AbstractF2mPoint AbstractF2mPoint}
    // * by <code>k</code> using the reduced <code>&#964;</code>-adic NAF (RTNAF)
    // * method.
    // * @param p The AbstractF2mPoint to multiply.
    // * @param k The integer by which to multiply <code>k</code>.
    // * @return <code>p</code> multiplied by <code>k</code>.
    // */
    function MultiplyPositive(const point: IECPoint; const k: TBigInteger)
      : IECPoint; override;

  public
    constructor Create();
    destructor Destroy; override;

  end;

implementation

{ TWTauNafMultiplier }

constructor TWTauNafMultiplier.Create;
begin
  Inherited Create();
end;

destructor TWTauNafMultiplier.Destroy;
begin
  inherited Destroy;
end;

class function TWTauNafMultiplier.MultiplyFromWTnaf(const p: IAbstractF2mPoint;
  u: TCryptoLibShortIntArray; const preCompInfo: IPreCompInfo)
  : IAbstractF2mPoint;
var
  curve: IAbstractF2mCurve;
  a: ShortInt;
  i, tauCount, ui: Int32;
  pu, puNeg: TCryptoLibGenericArray<IAbstractF2mPoint>;
  pre: IWTauNafPreCompInfo;
  q: IAbstractF2mPoint;
  x: IECPoint;
begin
  curve := p.curve as IAbstractF2mCurve;
  a := ShortInt(curve.a.ToBigInteger().Int32Value);

  // if ((preCompInfo = Nil) or (not(Supports(preCompInfo, IWTauNafPreCompInfo))))
  // then
  // begin
  pu := TTnaf.GetPreComp(p, a);

  pre := TWTauNafPreCompInfo.Create();
  pre.PreComp := pu;
  curve.SetPreCompInfo(p, PRECOMP_NAME, pre);
  // end
  // else
  // begin
  // pu := (preCompInfo as IWTauNafPreCompInfo).PreComp;
  // end;

  // TODO Include negations in precomp (optionally) and use from here
  System.SetLength(puNeg, System.Length(pu));
  for i := 0 to System.Pred(System.Length(pu)) do

  begin
    puNeg[i] := pu[i].Negate() as IAbstractF2mPoint;
  end;

  // q = infinity
  q := p.curve.Infinity as IAbstractF2mPoint;
  tauCount := 0;
  i := System.Length(u) - 1;
  while i >= 0 do
  begin
    System.Inc(tauCount);
    ui := u[i];
    if (ui <> 0) then
    begin
      q := q.TauPow(tauCount);
      tauCount := 0;

      if ui > 0 then
      begin
        x := pu[TBits.Asr32(ui, 1)];
      end
      else
      begin
        x := puNeg[TBits.Asr32(-ui, 1)];
      end;

      q := q.Add(x) as IAbstractF2mPoint;
    end;
    System.Dec(i);
  end;
  if (tauCount > 0) then
  begin
    q := q.TauPow(tauCount);
  end;
  result := q;
  pre.PreComp := Nil;
end;

function TWTauNafMultiplier.MultiplyWTnaf(const p: IAbstractF2mPoint;
  const lambda: IZTauElement; const preCompInfo: IPreCompInfo; a, mu: ShortInt)
  : IAbstractF2mPoint;
var
  alpha: TCryptoLibGenericArray<IZTauElement>;
  tw: TBigInteger;
  u: TCryptoLibShortIntArray;
begin
  if a = 0 then
  begin
    alpha := TTnaf.Alpha0;
  end
  else
  begin
    alpha := TTnaf.Alpha1;
  end;

  tw := TTnaf.GetTw(mu, TTnaf.Width);

  u := TTnaf.TauAdicWNaf(mu, lambda, TTnaf.Width,
    TBigInteger.ValueOf(TTnaf.Pow2Width), tw, alpha);

  result := MultiplyFromWTnaf(p, u, preCompInfo);
end;

function TWTauNafMultiplier.MultiplyPositive(const point: IECPoint;
  const k: TBigInteger): IECPoint;
var
  p: IAbstractF2mPoint;
  curve: IAbstractF2mCurve;
  m: Int32;
  a, mu: ShortInt;
  s: TCryptoLibGenericArray<TBigInteger>;
  rho: IZTauElement;
begin
  if (not(Supports(point, IAbstractF2mPoint))) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInCompatiblePoint);
  end;

  p := point as IAbstractF2mPoint;
  curve := p.curve as IAbstractF2mCurve;
  m := curve.FieldSize;
  a := ShortInt(curve.a.ToBigInteger().Int32Value);
  mu := TTnaf.GetMu(a);
  s := curve.GetSi();

  rho := TTnaf.PartModReduction(k, m, a, s, mu, ShortInt(10));

  result := MultiplyWTnaf(p, rho, curve.GetPreCompInfo(p, PRECOMP_NAME), a, mu);

end;

end.
