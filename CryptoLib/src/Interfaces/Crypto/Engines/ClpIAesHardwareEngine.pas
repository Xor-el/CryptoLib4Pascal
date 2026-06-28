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

unit ClpIAesHardwareEngine;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBulkBlockCipher,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Architecture-neutral capability interface for hardware-accelerated AES
  /// engines (AES-NI on x86 via <c>TAesEngineX86</c> today; a NEON/Crypto-Ext
  /// ARMv8 engine could implement the same surface tomorrow). It exposes the
  /// fixed-width 4-/8-block batch entry points and the raw-pointer single-block
  /// overload that sit beneath the generic <see cref="IBulkBlockCipher" />
  /// ladder. The aliasing contract for every overload here is identical to
  /// IBulkBlockCipher: AInput / AOutput MUST be either identical pointers
  /// (in-place) or reference fully disjoint ranges of the stated size.
  /// </summary>
  /// <remarks>
  /// This interface is the shared surface that engine-agnostic test suites and
  /// future cross-architecture callers bind to, so the same coverage runs
  /// against any hardware AES engine without referencing a concrete class.
  /// </remarks>
  IAesHardwareEngine = interface(IBulkBlockCipher)
    ['{6D5C4B3A-2E1F-4A8B-9C7D-0E1F2A3B4C5D}']

    /// <summary>
    /// Transform a single 16-byte block (raw pointers). Skips the array
    /// overload's length validation; the caller guarantees 16 valid bytes
    /// behind each pointer and the standard identical-or-disjoint aliasing.
    /// </summary>
    function ProcessBlock(AInput, AOutput: PByte): Int32; overload;

    /// <summary>
    /// Four consecutive 16-byte blocks (64 bytes) from AInput[AInOff] into
    /// AOutput[AOutOff].
    /// </summary>
    function ProcessFourBlocks(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload;

    /// <summary>
    /// Four consecutive 16-byte blocks (64 bytes) via raw pointers.
    /// </summary>
    function ProcessFourBlocks(AInput, AOutput: PByte): Int32; overload;

    /// <summary>
    /// Eight consecutive 16-byte blocks (128 bytes) from AInput[AInOff] into
    /// AOutput[AOutOff].
    /// </summary>
    function ProcessEightBlocks(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload;

    /// <summary>
    /// Eight consecutive 16-byte blocks (128 bytes) via raw pointers.
    /// </summary>
    function ProcessEightBlocks(AInput, AOutput: PByte): Int32; overload;
  end;

implementation

end.
