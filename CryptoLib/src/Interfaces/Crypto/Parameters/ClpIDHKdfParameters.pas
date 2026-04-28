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

unit ClpIDHKdfParameters;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIDerivationParameters,
  ClpCryptoLibTypes;

type
  IDHKdfParameters = interface(IDerivationParameters)
    ['{333F2D1B-44A6-49A9-A659-CBBC78484675}']

    function GetAlgorithm(): IDerObjectIdentifier;
    function GetKeySize(): Int32;
    function GetZ(): TCryptoLibByteArray;
    function GetExtraInfo(): TCryptoLibByteArray;

    property Algorithm: IDerObjectIdentifier read GetAlgorithm;
    property KeySize: Int32 read GetKeySize;
    property Z: TCryptoLibByteArray read GetZ;
    property ExtraInfo: TCryptoLibByteArray read GetExtraInfo;
  end;

implementation

end.
