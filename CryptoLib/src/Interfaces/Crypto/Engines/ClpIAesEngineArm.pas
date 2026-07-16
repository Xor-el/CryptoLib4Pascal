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

unit ClpIAesEngineArm;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAesHardwareEngine;

type
  /// <summary>
  /// AES ARMv8 Crypto Extensions engine interface. Extends the
  /// architecture-neutral <see cref="IAesHardwareEngine" /> with the AES
  /// round-key schedule pointers required by the concrete fused AES kernels.
  /// Internal-use: only TAesEngineArm implements it in-tree. Modes wanting
  /// plain multi-block batching should query IBulkBlockCipher instead to stay
  /// cipher-agnostic.
  /// </summary>
  IAesEngineArm = interface(IAesHardwareEngine)
    ['{5D9C7E24-6B1F-4A83-9E57-2C8A0F4B6D31}']

    /// <summary>
    /// Returns the encrypt round-key schedule pointer and round count when
    /// the engine is currently initialized for encryption (round count in
    /// {10,12,14}); False otherwise. The pointer MUST NOT be retained past
    /// the current engine init.
    /// </summary>
    function TryGetEncKeysPtr(out AKeysPtr: PByte; out ANumRounds: Int32): Boolean;

    /// <summary>
    /// Returns the decrypt round-key schedule (inverse MixColumns already
    /// applied, slots in consumption order) when the engine is currently
    /// initialized for decryption; False otherwise. Same lifetime contract
    /// as TryGetEncKeysPtr.
    /// </summary>
    function TryGetDecKeysPtr(out AKeysPtr: PByte; out ANumRounds: Int32): Boolean;
  end;

implementation

end.
