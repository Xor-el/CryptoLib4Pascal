{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIRandom;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type

  IRandom = interface(IInterface)
    ['{509F9F51-2FC4-40E6-8E4A-68B59808BF5A}']

    procedure NextBytes(const ABuf: TCryptoLibByteArray); overload;

    function NextDouble(): Double;

    function Next(): Int32; overload;
    function Next(AMaxValue: Int32): Int32; overload;
    function Next(AMinValue, AMaxValue: Int32): Int32; overload;

  end;

implementation

end.
