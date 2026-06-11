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

unit ClpIBinPolyMul;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Reduction of an extended binary polynomial product into the quotient ring.
  /// </summary>
  /// <remarks>
  /// <para>
  /// Reduces the extended product in <c>Att[AttOff..AttOff + 2*Size - 1]</c> into
  /// <c>Az[AzOff..AzOff + Size - 1]</c>. The reducer knows its own field size.
  /// </para>
  /// <para>
  /// Post-condition on <c>Att</c>: arbitrary. The reducer may freely mutate any limb in
  /// its window, and individual implementations are free not to write some limbs at all
  /// (fully-unrolled and direct-to-<c>Az</c> variants do exactly this). Callers must
  /// not read <c>Att</c> after <c>Reduce</c> returns, and if <c>Att</c> held
  /// secret-bearing material they remain responsible for wiping it (see
  /// <c>TBinPolys.Clear</c>).
  /// </para>
  /// </remarks>
  IBinPolyReduce = interface(IInterface)
    ['{C1D2E3F4-A5B6-4789-ABCD-EF0123456701}']
    /// <summary>
    /// Reduce an extended product buffer into a result buffer.
    /// </summary>
    /// <param name="Att">Extended product buffer (2 * Size limbs).</param>
    /// <param name="AttOff">Offset into <paramref name="Att"/>.</param>
    /// <param name="Az">Output buffer (Size limbs).</param>
    /// <param name="AzOff">Offset into <paramref name="Az"/>.</param>
    procedure Reduce(const Att: TCryptoLibUInt64Array; AttOff: Int32;
      const Az: TCryptoLibUInt64Array; AzOff: Int32);
  end;

  /// <summary>
  /// Binary polynomial arithmetic in GF(2)[x] / r(x), where r(x) is a binomial,
  /// trinomial, or pentanomial.
  /// </summary>
  /// <remarks>
  /// <para>
  /// Instances are produced by the static factories on <c>TBinPolys.TBinPolysMul</c>.
  /// Polynomials are stored bit-packed in <c>TCryptoLibUInt64Array</c> with little-endian
  /// word order. Each arithmetic method operates on a <c>Size</c>-limb slice of every array
  /// argument starting at the supplied offset; the caller is responsible for ensuring those
  /// slices are in-bounds.
  /// </para>
  /// <para><b>Aliasing contract.</b> The output buffer (<c>AZ</c>) may alias at most one
  /// input, and only the first input. Specifically:</para>
  /// <list type="bullet">
  /// <item><description><c>Multiply</c>: <c>AX</c> may alias <c>AZ</c> (in-place
  /// <c>AZ = AZ * AY</c>); <c>AY</c> must NOT alias <c>AZ</c>.</description></item>
  /// <item><description><c>Square</c> / <c>SquareN</c>: <c>AX</c> may alias <c>AZ</c>
  /// (in-place squaring).</description></item>
  /// </list>
  /// <para>
  /// Implementations may rely on the disallowed cases NOT occurring; consumers passing
  /// disallowed aliases may produce arbitrary results.
  /// </para>
  /// </remarks>
  IBinPolyMul = interface(IInterface)
    ['{C1D2E3F4-A5B6-4789-ABCD-EF0123456702}']
    /// <summary>Polynomial bit-length n.</summary>
    function GetN: Int32;
    /// <summary>Number of UInt64 limbs required to hold a polynomial of length <c>N</c>.</summary>
    function GetSize: Int32;
    /// <summary>
    /// Compute <c>AZ = AX * AY mod r(x)</c>. <c>AX</c> may alias <c>AZ</c>; <c>AY</c> must
    /// not alias <c>AZ</c>. See the interface remarks for the full aliasing contract.
    /// </summary>
    procedure Multiply(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AY: TCryptoLibUInt64Array; AYOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32);
    /// <summary>
    /// Compute <c>AZ = AX^2 mod r(x)</c>. <c>AX</c> may alias <c>AZ</c> (in-place squaring).
    /// </summary>
    procedure Square(const AX: TCryptoLibUInt64Array; AXOff: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32);
    /// <summary>
    /// Compute <c>AZ = AX^(2^AN) mod r(x)</c>, i.e. repeated squarings.
    /// <c>AX</c> may alias <c>AZ</c> (in-place repeated squaring).
    /// </summary>
    /// <param name="AN">Number of squarings (must be positive).</param>
    procedure SquareN(const AX: TCryptoLibUInt64Array; AXOff: Int32; AN: Int32;
      const AZ: TCryptoLibUInt64Array; AZOff: Int32);
    property N: Int32 read GetN;
    property Size: Int32 read GetSize;
  end;

implementation

end.
