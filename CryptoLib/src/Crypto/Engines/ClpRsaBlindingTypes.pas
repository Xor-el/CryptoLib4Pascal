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

unit ClpRsaBlindingTypes;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpCryptoLibTypes;

type

  /// <summary>
  /// The blinding pair for one signature: <c>Blind</c> = r^e mod n applied to the
  /// input, <c>Unblind</c> = r^-1 mod n applied to the result. Snapshotted from the
  /// cache under lock so each signature gets its own pair. Under the kernel strategy the
  /// pair carries the Montgomery-form factors as its own copies plus a private scratch,
  /// so a signature runs entirely on thread-local buffers once it leaves the lock.
  /// </summary>
  TRsaBlindingPair = record
    Blind, Unblind: TBigInteger;
    BlindMont, UnblindMont, Scratch: TCryptoLibUInt64Array;
  end;

implementation

end.
