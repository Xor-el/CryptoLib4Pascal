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

unit ClpIAesEngineX86;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBulkBlockCipher;

type
  /// <summary>
  /// AES-NI engine interface. Surfaces the AES round-key schedule pointers
  /// required by the concrete fused AES-NI AEAD kernels. Internal-use: only
  /// TAesEngineX86 implements it in-tree. Modes wanting plain multi-block
  /// batching should query IBulkBlockCipher instead to stay cipher-agnostic.
  /// </summary>
  IAesEngineX86 = interface(IBulkBlockCipher)
    ['{B2F8C4A1-9E3D-4F6B-8C0D-1A2B3C4D5E6F}']

    /// <summary>
    /// Returns the AES-NI encrypt round-key schedule pointer and round
    /// count when the engine is currently initialized for encryption
    /// (round count in {10,12,14}); False otherwise. The pointer MUST NOT
    /// be retained past the current engine init.
    /// </summary>
    function TryGetEncKeysPtr(out AKeysPtr: PByte; out ANumRounds: Int32): Boolean;

    /// <summary>
    /// Returns the AES-NI decrypt round-key schedule (inverse MixColumns
    /// already applied) when the engine is currently initialized for
    /// decryption; False otherwise. Same lifetime contract as
    /// TryGetEncKeysPtr.
    /// </summary>
    function TryGetDecKeysPtr(out AKeysPtr: PByte; out ANumRounds: Int32): Boolean;
  end;

implementation

end.
