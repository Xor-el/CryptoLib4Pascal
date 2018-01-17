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

unit ClpIWNafL2RMultiplier;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIECInterface,
  ClpIAbstractECMultiplier;

type
  IWNafL2RMultiplier = interface(IAbstractECMultiplier)

    ['{E2A5E4EF-C092-4F83-ACCF-0FC8731FB274}']

    // /**
    // * Multiplies <code>this</code> by an integer <code>k</code> using the
    // * Window NAF method.
    // * @param k The integer by which <code>this</code> is multiplied.
    // * @return A new <code>ECPoint</code> which equals <code>this</code>
    // * multiplied by <code>k</code>.
    // */
    function MultiplyPositive(p: IECPoint; k: TBigInteger): IECPoint;

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
    function GetWindowSize(bits: Int32): Int32;

  end;

implementation

end.
