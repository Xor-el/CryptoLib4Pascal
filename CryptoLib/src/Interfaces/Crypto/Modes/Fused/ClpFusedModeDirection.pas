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

unit ClpFusedModeDirection;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

type
  /// <summary>
  ///   Direction a fused AEAD kernel is being constructed for. Modes
  ///   whose hot path is direction-agnostic may pass Encrypt for both
  ///   cases.
  /// </summary>
  TFusedModeDirection = (Encrypt, Decrypt);

  /// <summary>
  ///   Quality-of-service tier used to order factories in the fused
  ///   AEAD kernel registry. Higher ordinal wins; equal priorities
  ///   retain registration order.
  ///     Fallback     - opt-in experimental / diagnostic kernel; loses
  ///                    to anything else.
  ///     Baseline     - in-tree built-in accelerators.
  ///     Accelerated  - external plug-in targeting a newer ISA
  ///                    extension than the in-tree baseline.
  ///     UserOverride - last-resort explicit override wired in by the
  ///                    consumer (application or test harness).
  /// </summary>
  TFusedKernelPriority = (Fallback, Baseline, Accelerated, UserOverride);

implementation

end.
