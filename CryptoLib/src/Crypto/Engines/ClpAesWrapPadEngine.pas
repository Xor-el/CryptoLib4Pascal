{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpAesWrapPadEngine;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAesWrapPadEngine,
  ClpIAesEngine,
  ClpIWrapper,
  ClpAesEngine,
  ClpRfc5649WrapEngine;

type
  /// <summary>
  /// An implementation of the AES Key Wrap with Padding as described in RFC 5649.
  /// </summary>
  TAesWrapPadEngine = class sealed(TRfc5649WrapEngine, IAesWrapPadEngine, IWrapper)

  public
    constructor Create();

  end;

implementation

{ TAesWrapPadEngine }

constructor TAesWrapPadEngine.Create();
begin
  inherited Create(TAesEngine.Create() as IAesEngine);
end;

end.
