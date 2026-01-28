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

unit ClpIX509Attribute;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Class for carrying the values in an X.509 Attribute.
  /// </summary>
  IX509Attribute = interface
    ['{B1C2D3E4-F5A6-7890-BCDE-F12345678901}']

    function GetOid: String;
    function GetValues: TCryptoLibGenericArray<IAsn1Encodable>;
    function ToAsn1Object: IAsn1Object;

    property Oid: String read GetOid;
  end;

implementation

end.

