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

unit ClpIAcceleratedKernelFactory;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpAcceleratedKernelTypes;

type
  /// <summary>
  ///   Family-agnostic base contract shared by every accelerated kernel factory
  ///   (block-cipher AEAD modes and stream-cipher AEADs alike). It carries only
  ///   the identity and ordering a factory needs to live in the registry; the
  ///   actual TryCreate lives on each derived factory interface with its own
  ///   strongly-typed cipher parameter. The registry stores factories through
  ///   this base and rediscovers a concrete family with Supports(); an external
  ///   consumer can therefore register an accelerated kernel for an algorithm the
  ///   framework never enumerated, with no framework edit.
  /// </summary>
  IAcceleratedKernelFactory = interface
    ['{006B1103-17E9-43C6-9A7A-EB515B120325}']

    /// <summary>Stable human-readable provider label (diagnostics / tests).</summary>
    function ProviderName: String;

    /// <summary>Priority class controlling factory order inside the registry;
    /// see TAcceleratedKernelPriority. Higher wins; equal priorities keep
    /// registration order.</summary>
    function Priority: TAcceleratedKernelPriority;
  end;

implementation

end.
