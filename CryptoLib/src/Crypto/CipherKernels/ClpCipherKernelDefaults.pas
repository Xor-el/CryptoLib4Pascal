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

unit ClpCipherKernelDefaults;

{$I ..\..\Include\CryptoLib.inc}

// Aggregator for CryptoLib's in-tree cipher kernel factories.
// Listed factory units self-gate on their own CPU/arch defines, so
// this file is a plain, platform-agnostic list: adding a new in-tree
// accelerator is one `uses` line here, mode units are never touched.
// External / third-party factories live in the consumer's own unit
// tree and register via the same mechanism -- no edit to this file.

interface

implementation

uses
  ClpAesNiGcmKernel,
  ClpAesNiOcbKernel,
  ClpAesNiCcmKernel,
  ClpAesNiEaxKernel,
  ClpAesNiCtrKernel,
  ClpAesNiCbcKernel,
  ClpAesCryptoExtCtrKernel,
  ClpAesCryptoExtCbcKernel,
  ClpAesCryptoExtGcmKernel,
  ClpAesCryptoExtOcbKernel,
  ClpAesCryptoExtCcmKernel,
  ClpAesCryptoExtEaxKernel,
  ClpPclmulGcmSivKernel,
  ClpPmullGcmSivKernel,
  // ChaCha20-Poly1305 fused kernels: only the aarch64 (NEON) arm is registered.
  // On Intel x86-64 the scalar-poly mulx competes with ChaCha for ports 1/5 and
  // on i386 the radix-2^26 poly is register-starved, so both lose to the
  // vectorized two-pass and are intentionally NOT registered (the units and
  // are preserved for reference).
  ClpChaCha20Poly1305ArmKernel;

end.
