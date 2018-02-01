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

unit ClpIWTauNafMultiplier;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIECInterface,
  ClpIPreCompInfo,
  ClpIZTauElement,
  ClpIAbstractECMultiplier;

type
  IWTauNafMultiplier = interface(IAbstractECMultiplier)
    ['{B71E75E5-FB6D-4A54-BE8A-820FC9A1E509}']

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
      a, mu: ShortInt): IAbstractF2mPoint;

    // /**
    // * Multiplies a {@link org.bouncycastle.math.ec.AbstractF2mPoint AbstractF2mPoint}
    // * by <code>k</code> using the reduced <code>&#964;</code>-adic NAF (RTNAF)
    // * method.
    // * @param p The AbstractF2mPoint to multiply.
    // * @param k The integer by which to multiply <code>k</code>.
    // * @return <code>p</code> multiplied by <code>k</code>.
    // */
    function MultiplyPositive(const point: IECPoint; const k: TBigInteger)
      : IECPoint;

  end;

implementation

end.
