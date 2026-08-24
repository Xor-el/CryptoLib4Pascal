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

unit ClpIScalarFieldOps;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger;

type
  /// <summary>
  /// Constant-time fixed-width arithmetic in the scalar field of a curve (mod the
  /// group order n), riding the Montgomery kernel. Used by ECDSA nonce math to
  /// replace the heap <c>TBigInteger</c> inverse/multiply with an allocation-free,
  /// side-channel-hardened path. Inputs/outputs are normal-domain residues in
  /// [0, n); the modular reduction and Montgomery conversions are internal.
  /// </summary>
  IScalarFieldOps = interface(IInterface)
    ['{4E9D1B27-8C6A-4F03-B5D1-9A7C2E6F0483}']

    /// <summary>AX^-1 mod n (Fermat: AX^(n-2), constant-time in AX).</summary>
    function InvModN(const AX: TBigInteger): TBigInteger;
    /// <summary>AX * AY mod n.</summary>
    function MulModN(const AX, AY: TBigInteger): TBigInteger;
    /// <summary>AX + AY mod n.</summary>
    function AddModN(const AX, AY: TBigInteger): TBigInteger;
    /// <summary>The ECDSA s value AK^-1 * (AE + AD*AR) mod n, computed entirely in
    /// the Montgomery domain (one nonce inversion, no intermediate heap residues).</summary>
    function ComputeS(const AK, AE, AD, AR: TBigInteger): TBigInteger;
  end;

implementation

end.
