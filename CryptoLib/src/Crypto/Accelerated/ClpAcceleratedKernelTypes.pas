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

unit ClpAcceleratedKernelTypes;

{$I ..\..\Include\CryptoLib.inc}

interface

type
  /// <summary>
  ///   Direction an accelerated kernel is being constructed for. Modes
  ///   whose hot path is direction-agnostic may pass Encrypt for both
  ///   cases.
  /// </summary>
  TAcceleratedKernelDirection = (Encrypt, Decrypt);

  /// <summary>
  ///   Priority class used to order factories in the accelerated kernel
  ///   registry. Higher ordinal wins; equal priorities retain registration
  ///   order (first registered wins), which is why UserOverride sits above
  ///   Preferred - it keeps the consumer's explicit choice the final word
  ///   regardless of plug-in load order.
  ///     Fallback     - opt-in experimental / diagnostic kernel; loses
  ///                    to anything else (never wins over a real kernel).
  ///     Baseline     - in-tree built-in accelerators.
  ///     Preferred    - a self-registering kernel that should outrank the
  ///                    in-tree baseline when present (e.g. an external
  ///                    plug-in for a newer ISA extension), yet still yield
  ///                    to the consumer's explicit override.
  ///     UserOverride - last-resort explicit override wired in by the
  ///                    consumer (application or test harness); beats all.
  /// </summary>
  TAcceleratedKernelPriority = (Fallback, Baseline, Preferred, UserOverride);

implementation

end.
