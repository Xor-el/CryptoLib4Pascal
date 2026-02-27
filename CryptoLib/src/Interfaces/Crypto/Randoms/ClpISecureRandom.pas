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

unit ClpISecureRandom;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIRandom,
  ClpCryptoLibTypes;

type

  ISecureRandom = interface(IRandom)
    ['{BF2E135B-E889-4B2F-837E-6B2049213C83}']

    function GenerateSeed(ALength: Int32): TCryptoLibByteArray;
    procedure SetSeed(const ASeed: TCryptoLibByteArray); overload;
    procedure SetSeed(ASeed: Int64); overload;

    procedure NextBytes(const ABuf: TCryptoLibByteArray;
      AOff, ALen: Int32); overload;
    function NextInt32(): Int32;
    function NextInt64(): Int64;

  end;

implementation

end.
