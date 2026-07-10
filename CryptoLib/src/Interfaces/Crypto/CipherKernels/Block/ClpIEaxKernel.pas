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

unit ClpIEaxKernel;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipher,
  ClpCipherKernelTypes,
  ClpICipherKernelFactory;

type
  /// <summary>
  ///   Mode-specific contract for an accelerated EAX body kernel running the
  ///   CTR keystream and OMAC lanes together per iteration. Direction-
  ///   bound at construction: encrypt and decrypt take different paths
  ///   through the inner MAC dependency chain. The kernel owns the
  ///   inner loop over ABlockCount; the mode seeds AOmacState to the
  ///   running OMAC pre-body state (OMAC of TagC only on first call,
  ///   CBC-MAC running thereafter) and handles nonce-OMAC, header-OMAC,
  ///   and the final-block OMAC subkey XOR.
  /// </summary>
  IEaxKernel = interface
    ['{3D87A0D4-7375-453F-BF72-CA3CA191CDCB}']

    /// <summary>Minimum number of 16-byte body blocks the kernel can
    /// usefully process. If the mode has fewer than MinimumBlockCount
    /// bulk blocks it stays on the scalar path.</summary>
    function MinimumBlockCount: Int32;

    /// <summary>
    ///   Process ABlockCount (>= MinimumBlockCount) body blocks in a
    ///   single call. ACtrState holds the pre-body counter; AOmacState
    ///   holds the running OMAC / CBC-MAC state. On return ACtrState
    ///   has advanced by ABlockCount keystream blocks and AOmacState
    ///   has absorbed the corresponding ciphertext (always ciphertext,
    ///   the MAC substrate under EAX, regardless of direction). AOutPtr
    ///   may alias AInPtr; both must cover ABlockCount * 16 contiguous
    ///   bytes.
    /// </summary>
    procedure ProcessBody(AInPtr, AOutPtr, ACtrState,
      AOmacState: Pointer; ABlockCount: Int32);
  end;

  IEaxKernelFactory = interface(ICipherKernelFactory)
    ['{E3DDE544-91EF-4E41-B707-7ACD366FDB0A}']

    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TCipherKernelDirection;
      out AKernel: IEaxKernel): Boolean;
  end;

implementation

end.
