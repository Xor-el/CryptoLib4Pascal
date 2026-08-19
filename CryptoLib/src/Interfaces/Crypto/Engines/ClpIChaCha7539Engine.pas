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

unit ClpIChaCha7539Engine;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpISalsa20Engine,
  ClpCryptoLibTypes;

type

  IChaCha7539Engine = interface(ISalsa20Engine)
    ['{3E8B7A2D-C4F1-4D9E-A6B0-7F2E5D8C1A94}']

    procedure DoFinal(const AInBuf: TCryptoLibByteArray; AInOff, AInLen: Int32;
      const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);

    procedure ProcessBlock(const AInBytes: TCryptoLibByteArray; AInOff: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32);

    /// <summary>Pointer to the engine's 16 x UInt32 block state (constants[0..3],
    /// key[4..11], counter word 12 at byte offset 48, nonce[13..15]; DJB engine:
    /// 64-bit counter, words 12-13, nonce words 14-15). For the accelerated fused
    /// ChaCha20-Poly1305 kernel, which advances the counter in place. The state
    /// array is allocated once at construction and never reallocated (re-Init only
    /// rewrites the words), so the pointer is stable for the engine's lifetime -
    /// a kernel may capture it once at construction.</summary>
    function GetEngineStatePtr: PUInt32;

  end;

implementation

end.
