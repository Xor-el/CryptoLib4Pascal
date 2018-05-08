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

unit ClpIAsn1TaggedObjectParser;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIProxiedInterface;

type
  IAsn1TaggedObjectParser = interface(IAsn1Convertible)

    ['{AB221E2D-A78A-46F7-85AE-B642D904B705}']

    function GetTagNo: Int32;
    property TagNo: Int32 read GetTagNo;
    function GetObjectParser(tag: Int32; isExplicit: Boolean): IAsn1Convertible;
  end;

implementation

end.
