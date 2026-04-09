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

unit ClpAesWrapEngine;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAesWrapEngine,
  ClpIWrapper,
  ClpAesUtilities,
  ClpRfc3394WrapEngine;

type
  /// <summary>
  /// An implementation of the AES Key Wrapper from the NIST Key Wrap
  /// Specification as described in RFC 3394.
  /// </summary>
  TAesWrapEngine = class sealed(TRfc3394WrapEngine, IAesWrapEngine, IWrapper)

  public
    constructor Create(); overload;
    constructor Create(AUseReverseDirection: Boolean); overload;

  end;

implementation

{ TAesWrapEngine }

constructor TAesWrapEngine.Create();
begin
  inherited Create(TAesUtilities.CreateEngine());
end;

constructor TAesWrapEngine.Create(AUseReverseDirection: Boolean);
begin
  inherited Create(TAesUtilities.CreateEngine(), AUseReverseDirection);
end;

end.
