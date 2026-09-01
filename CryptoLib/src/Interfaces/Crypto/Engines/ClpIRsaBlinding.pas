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

unit ClpIRsaBlinding;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpRsaBlindingTypes;

type

  /// <summary>
  /// Per-key RSA blinding cache: a blinding pair advanced by squaring on every
  /// signature and periodically refreshed, so the modular inverse is amortized rather
  /// than paid per signature. Bound to the private key and shared by every signature,
  /// so implementations must be safe under concurrent use.
  /// </summary>
  IRsaBlinding = interface(IInterface)
    ['{DFBF42EF-B39D-43E2-8927-B39DE76B9FC2}']
    /// <summary>Advance the cached pair (square, or refresh at the interval) and
    /// return this signature's pair. Locked.</summary>
    procedure Acquire(out APair: TRsaBlindingPair);
    function Blind(const APair: TRsaBlindingPair; const AInput: TBigInteger): TBigInteger;
    function Unblind(const APair: TRsaBlindingPair; const AResult: TBigInteger): TBigInteger;
  end;

implementation

end.
