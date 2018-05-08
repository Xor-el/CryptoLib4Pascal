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

unit ClpIDerBitString;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpIDerStringBase;

type
  IDerBitString = interface(IDerStringBase)

    ['{2EBCCC24-BF14-4EB1-BADA-C521439682BE}']

    function GetmData: TCryptoLibByteArray;
    property mData: TCryptoLibByteArray read GetmData;

    function GetmPadBits: Int32;
    property mPadBits: Int32 read GetmPadBits;

    function GetOctets(): TCryptoLibByteArray;

    function GetBytes(): TCryptoLibByteArray;

    function GetInt32Value: Int32;
    property Int32Value: Int32 read GetInt32Value;

  end;

implementation

end.
