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

unit ClpIRawInitBlockCipherMode;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type
  /// <summary>
  ///   Zero-allocation re-init for a block-cipher mode (CTR / CBC) driven from a
  ///   one-shot packet cipher: the caller passes the key and the per-message IV
  ///   as raw byte spans, avoiding the per-message TParametersWithIV wrapper (and
  ///   the copy-on-read GetIV) that Init needs. The IV is copied in place (no
  ///   allocation when the length is unchanged); the key routes to the engine's
  ///   raw-key compare-only same-key gate (no key copy on reuse). AKey = nil
  ///   reuses the engine's established schedule (raises if it was never keyed).
  ///   Validation is identical to Init.
  /// </summary>
  IRawInitBlockCipherMode = interface
    ['{3F8A1C05-9D42-4E7B-8A16-2B5C9E0D7F31}']

    procedure InitRaw(AForEncryption: Boolean;
      const AKey, AIv: TCryptoLibByteArray);
  end;

implementation

end.
