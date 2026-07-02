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

unit ClpPoly1305State;

{$I ..\..\Include\CryptoLib.inc}

interface

type
  /// <summary>
  /// Poly1305 algorithm state in radix-2^26 form (72 bytes; same layout on
  /// every architecture).
  /// <list type="bullet">
  /// <item>R0..R4 - clamped 130-bit r split into five 26-bit limbs</item>
  /// <item>S1..S4 - precomputed 5 * R1..R4 wraparound multipliers</item>
  /// <item>H0..H4 - 130-bit accumulator in five 26-bit limbs (plus a few carry bits)</item>
  /// <item>K0..K3 - the Poly1305 "s" key (second half of the 32-byte key)</item>
  /// </list>
  /// </summary>
  TPoly1305State = record
    R0, R1, R2, R3, R4: UInt32;
    S1, S2, S3, S4: UInt32;
    H0, H1, H2, H3, H4: UInt32;
    K0, K1, K2, K3: UInt32;
  end;

implementation

end.
