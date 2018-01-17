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

unit ClpIBerOctetStringParser;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpIAsn1OctetStringParser,
  ClpIProxiedInterface;

type
  IBerOctetStringParser = interface(IAsn1OctetStringParser)
    ['{27698DDF-3584-45F6-8B6D-0AD85AA63F10}']

    function GetOctetStream(): TStream;
    function ToAsn1Object(): IAsn1Object;
  end;

implementation

end.
