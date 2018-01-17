{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                    Copyright (c) 2018 Ugochukwu Mmaduekwe                       * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *        Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring        * }
{ *                        the development of this library                          * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIDerOctetStringParser;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpIAsn1OctetStringParser,
  ClpIProxiedInterface;

type
  IDerOctetStringParser = interface(IAsn1OctetStringParser)
    ['{49664C03-CD81-423F-A93D-025D3116B066}']

    function GetOctetStream(): TStream;
    function ToAsn1Object(): IAsn1Object;
  end;

implementation

end.
