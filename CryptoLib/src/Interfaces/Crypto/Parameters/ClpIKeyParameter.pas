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

unit ClpIKeyParameter;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpICipherParameters,
  ClpCryptoLibTypes;

type

  IKeyParameter = interface(ICipherParameters)
    ['{92E7D4F7-40E5-4DC1-8058-23BE60848CC3}']

    function GetKey(): TCryptoLibByteArray;
    function GetKeyLength(): Int32;
    procedure Clear();
    function FixedTimeEquals(const AOther: TCryptoLibByteArray): Boolean;
    procedure CopyKeyTo(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32);
    function Reverse(): IKeyParameter;

    property KeyLength: Int32 read GetKeyLength;
  end;

implementation

end.
