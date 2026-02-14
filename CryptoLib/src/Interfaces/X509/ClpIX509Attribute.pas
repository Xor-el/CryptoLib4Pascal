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
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Class for carrying the values in an X.509 Attribute.
  /// </summary>
  IX509Attribute = interface
    ['{B43958A4-2E0A-4F18-A7AC-0DF88F32B6B3}']

    function GetOid: String;
    function GetValues: TCryptoLibGenericArray<IAsn1Encodable>;
    function ToAsn1Object: IAsn1Object;

    property Oid: String read GetOid;
  end;

implementation

end.

