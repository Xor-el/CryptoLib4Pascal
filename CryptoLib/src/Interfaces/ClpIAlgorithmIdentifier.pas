{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIAlgorithmIdentifier;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects;

type
  IAlgorithmIdentifier = interface(IAsn1Encodable)
    ['{D7B8C4E1-8A2F-4B5C-9D3E-1F6A7B8C9D0E}']
    function GetAlgorithm: IDerObjectIdentifier;
    function GetParameters: IAsn1Encodable;

    property Algorithm: IDerObjectIdentifier read GetAlgorithm;
    property Parameters: IAsn1Encodable read GetParameters;
  end;

implementation

end.
