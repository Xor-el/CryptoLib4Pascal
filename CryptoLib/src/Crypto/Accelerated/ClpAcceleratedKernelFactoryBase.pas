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

unit ClpAcceleratedKernelFactoryBase;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAcceleratedKernelTypes;

type
  /// <summary>
  ///   Shared base for accelerated-kernel factory classes. ProviderName is
  ///   abstract - each concrete factory must declare its own provider identity
  ///   (there is no generic default). Priority defaults to Baseline, a neutral
  ///   value a factory overrides only when it should out- or under-rank peers.
  ///   The base intentionally declares no interface - each concrete factory
  ///   lists its own IAccelerated&lt;Mode&gt;KernelFactory, and these members
  ///   satisfy the base slice of that contract.
  /// </summary>
  TAcceleratedKernelFactoryBase = class abstract(TInterfacedObject)
  public
    function ProviderName: String; virtual; abstract;
    function Priority: TAcceleratedKernelPriority; virtual;
  end;

implementation

{ TAcceleratedKernelFactoryBase }

function TAcceleratedKernelFactoryBase.Priority: TAcceleratedKernelPriority;
begin
  Result := TAcceleratedKernelPriority.Baseline;
end;

end.
