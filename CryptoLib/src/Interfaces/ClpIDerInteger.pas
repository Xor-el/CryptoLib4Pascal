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

unit ClpIDerInteger;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIProxiedInterface,
  ClpCryptoLibTypes,
  ClpBigInteger;

type

  IDerInteger = interface(IAsn1Object)
    ['{B968152A-5A16-4C1D-95E1-3B5F416D2C75}']

    function GetBytes: TCryptoLibByteArray;
    function GetPositiveValue: TBigInteger;
    function GetValue: TBigInteger;

    function ToString(): String;

    property value: TBigInteger read GetValue;
    property PositiveValue: TBigInteger read GetPositiveValue;
    property bytes: TCryptoLibByteArray read GetBytes;

  end;

implementation

end.
