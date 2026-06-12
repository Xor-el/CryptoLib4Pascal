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

unit ClpIBinPolyInv;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Multiplicative inversion in the field GF(2^n) = GF(2)[x] / f(x).
  /// </summary>
  /// <remarks>
  /// <para>
  /// Instances are produced by the static factories on <c>TBinPolys.TBinPolysInv</c>.
  /// Inversion is only well-defined when the reduction polynomial backing the supplied
  /// <c>IBinPolyMul</c> is irreducible, so that the quotient ring is a field. The binomial
  /// reducer (<c>x^n + 1</c>) is always reducible (<c>x = 1</c> is a root over GF(2)) and
  /// must not be used. Irreducibility is the caller's attestation — it is not checked, and
  /// a reducible polynomial yields a meaningless result (or stumbles on a non-invertible
  /// element).
  /// </para>
  /// <para>
  /// Polynomials use the same bit-packed <c>TCryptoLibUInt64Array</c> representation as
  /// <c>IBinPolyMul</c>.
  /// </para>
  /// </remarks>
  IBinPolyInv = interface(IInterface)
    ['{C1D2E3F4-A5B6-4789-ABCD-EF0123456703}']
    /// <summary>Polynomial bit-length n.</summary>
    function GetN: Int32;
    /// <summary>Number of UInt64 limbs required to hold a polynomial of length <c>N</c>.</summary>
    function GetSize: Int32;
    /// <summary>
    /// Compute <c>AZ = AX^{-1} mod f(x)</c>. By convention 0 maps to 0 — there is no
    /// special case for it (nor for 1); both fall out of the computation, so the running cost
    /// is independent of the element value. <c>AX</c> may alias <c>AZ</c>.
    /// </summary>
    procedure Invert(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32);
    property N: Int32 read GetN;
    property Size: Int32 read GetSize;
  end;

implementation

end.
