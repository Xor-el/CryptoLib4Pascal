{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIAeadParameters;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpICipherParameters,
  ClpIKeyParameter,
  ClpCryptoLibTypes;

type
  IAeadParameters = interface(ICipherParameters)
    ['{B8E0DFD2-4055-4795-B3A1-AD539257C89A}']

    function GetKey(): IKeyParameter;
    function GetMacSize(): Int32;
    function GetNonce(): TCryptoLibByteArray;
    function GetAssociatedText(): TCryptoLibByteArray;

    property Key: IKeyParameter read GetKey;
    property MacSize: Int32 read GetMacSize;
  end;

implementation

end.
