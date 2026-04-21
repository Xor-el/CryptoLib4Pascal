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

unit ClpIFusedCcmKernel;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipher,
  ClpFusedKernelTypes;

type
  /// <summary>
  ///   Mode-specific contract for a fused CCM body kernel running the
  ///   CTR keystream and CBC-MAC lanes together per iteration.
  ///   Direction-bound at construction: encrypt and decrypt take
  ///   different paths through the inner MAC dependency chain. The
  ///   kernel owns the inner loop over ABlockCount; the mode calls
  ///   ProcessBody once per Init / Reset cycle covering the full bulk
  ///   body.
  /// </summary>
  IFusedCcmKernel = interface
    ['{BEAAEA01-DF32-441F-96AB-77D07C19578D}']

    /// <summary>Minimum number of 16-byte body blocks the kernel can
    /// usefully process. If the mode has fewer than MinimumBlockCount
    /// bulk blocks it stays on the scalar path.</summary>
    function MinimumBlockCount: Int32;

    /// <summary>
    ///   Process ABlockCount (>= MinimumBlockCount) body blocks in a
    ///   single call. The mode has already folded B_0 + AAD + padding
    ///   into ACbcMacState during the scalar header pass and advanced
    ///   ACtrState past the keystream block reserved for the
    ///   authentication tag. On return ACtrState has advanced by
    ///   exactly ABlockCount keystream blocks and ACbcMacState has
    ///   absorbed the corresponding plaintext (always plaintext, even
    ///   when decrypting - the decrypt kernel recovers plaintext
    ///   internally and folds it). AOutPtr may alias AInPtr; both must
    ///   cover ABlockCount * 16 contiguous bytes.
    /// </summary>
    procedure ProcessBody(AInPtr, AOutPtr, ACtrState,
      ACbcMacState: Pointer; ABlockCount: Int32);
  end;

  IFusedCcmKernelFactory = interface
    ['{F30B4F47-0546-4212-A00D-850F2AF4FF5F}']

    function ProviderName: String;
    function Priority: TFusedKernelPriority;

    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TFusedModeDirection;
      out AKernel: IFusedCcmKernel): Boolean;
  end;

implementation

end.
