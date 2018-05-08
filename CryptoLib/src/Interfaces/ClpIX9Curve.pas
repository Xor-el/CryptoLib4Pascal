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

unit ClpIX9Curve;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIECInterface,
  ClpCryptoLibTypes,
  ClpIProxiedInterface;

type
  IX9Curve = interface(IAsn1Encodable)
    ['{BD78E2A1-C079-461C-8962-C4834DFA1478}']

    function GetCurve: IECCurve;

    function GetSeed(): TCryptoLibByteArray;

    property curve: IECCurve read GetCurve;

  end;

implementation

end.
