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
    function GetLengthOfHeader(data: TCryptoLibByteArray): Int32;

    function Asn1Equals(asn1Object: IAsn1Object): Boolean;
    function Asn1GetHashCode(): Int32;

    function isConstructed(): Boolean;
    function GetContents(): TCryptoLibByteArray;

    function GetObject(): IAsn1Object; overload;

    function GetObject(derTagNo: Int32): IAsn1Object; overload;

    procedure Encode(derOut: IDerOutputStream);

    property ApplicationTag: Int32 read GetApplicationTag;

  end;

implementation

end.
