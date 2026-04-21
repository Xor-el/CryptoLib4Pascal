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

unit ClpFusedKernelDefaults;

{$I ..\..\..\Include\CryptoLib.inc}

// Aggregator for CryptoLib's in-tree fused AEAD kernel factories.
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
  ClpPclmulGcmSivKernel;

end.
