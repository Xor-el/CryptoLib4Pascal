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

unit ClpIFusedGcmSivKernel;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipher,
  ClpFusedModeDirection;

type
  /// <summary>
  ///   Mode-specific contract for a fused GCM-SIV POLYVAL batch kernel.
  ///   GCM-SIV's fused path is authentication-only and does not touch
  ///   the cipher's key schedule; the kernel is therefore intrinsically
  ///   cipher-agnostic, but is still registered through the shared
  ///   factory registry for uniformity with the other fused AEAD
  ///   kernels.
  /// </summary>
  IFusedGcmSivKernel = interface
    ['{5FA774F0-42CC-407C-9410-1D5D66421F66}']

    /// <summary>Number of 16-byte blocks absorbed per
    /// ProcessPolyvalBatch invocation.</summary>
    function MinimumBlockCount: Int32;

    /// <summary>
    ///   Fold exactly MinimumBlockCount 16-byte blocks of AInPtr into
    ///   the running POLYVAL accumulator at AAccumulator. The kernel
    ///   consumes its pre-computed H-power table from private state
    ///   seeded at construction. ABlockCount MUST equal
    ///   MinimumBlockCount.
    /// </summary>
    procedure ProcessPolyvalBatch(AInPtr, AAccumulator: Pointer;
      ABlockCount: Int32);
  end;

  /// <summary>
  ///   Factory contract for GCM-SIV POLYVAL kernel providers. AHPowers
  ///   points at the caller's pre-computed H-power table, captured by
  ///   reference by the returned kernel; the table MUST outlive the
  ///   kernel. ADirection is accepted for registry uniformity but
  ///   POLYVAL is direction-agnostic and it is typically ignored.
  /// </summary>
  IFusedGcmSivKernelFactory = interface
    ['{5EA5178B-93BD-4E96-B19E-C09B04B32655}']

    function ProviderName: String;
    function Priority: TFusedKernelPriority;

    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TFusedModeDirection;
      AHPowers: Pointer;
      out AKernel: IFusedGcmSivKernel): Boolean;
  end;

implementation

end.
