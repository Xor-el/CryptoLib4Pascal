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

unit ClpIRawKeyedCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type
  /// <summary>
  ///   Raw-key (re)init for a keyed cipher engine: (re)build the key schedule
  ///   from a raw key byte span, with a compare-only same-key fast path - no
  ///   parameter object and no key copy on the reuse path. Lets a one-shot /
  ///   packet caller re-key across messages without constructing an
  ///   IKeyParameter each time. AKey must be non-nil (nil-key "reuse" is a
  ///   mode-level convention, handled by the calling mode, not the engine).
  /// </summary>
  IRawKeyedCipher = interface
    ['{5C1D9E48-2A73-4F60-B18E-6D4A0F92C7B3}']

    procedure InitRaw(AForEncryption: Boolean;
      const AKey: TCryptoLibByteArray);
  end;

implementation

end.
