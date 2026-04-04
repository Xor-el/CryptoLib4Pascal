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

unit ClpIX931Signer;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpISigner;

type
  /// <summary>
  /// Interface for X9.31 signer.
  /// </summary>
  IX931Signer = interface(ISigner)
    ['{B3C4D5E6-F7A8-9B0C-1D2E-3F4A5B6C7D8E}']
  end;

implementation

end.
