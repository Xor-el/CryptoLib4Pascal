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

unit ClpIDerApplicationSpecific;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpIProxiedInterface;

type
  IDerApplicationSpecific = interface(IAsn1Object)
    ['{87EE7482-8D8B-4593-85B7-B5B286B43195}']

    function GetApplicationTag: Int32;
    function GetLengthOfHeader(const data: TCryptoLibByteArray): Int32;

    function isConstructed(): Boolean;
    function GetContents(): TCryptoLibByteArray;

    function GetObject(): IAsn1Object; overload;

    function GetObject(derTagNo: Int32): IAsn1Object; overload;

    property ApplicationTag: Int32 read GetApplicationTag;

  end;

implementation

end.
