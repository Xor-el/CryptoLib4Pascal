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

unit ClpIAeadBlockCipher;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipher,
  ClpIAeadCipher;

type
  IAeadBlockCipher = interface(IAeadCipher)
    ['{E85409BF-5446-4324-86A8-A70BF4067C11}']

    function GetBlockSize(): Int32;
    function GetUnderlyingCipher(): IBlockCipher;

    property UnderlyingCipher: IBlockCipher read GetUnderlyingCipher;
  end;

implementation

end.
