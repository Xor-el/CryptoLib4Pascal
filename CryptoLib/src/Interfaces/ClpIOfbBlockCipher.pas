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

unit ClpIOfbBlockCipher;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipher;

type
  IOfbBlockCipher = interface(IBlockCipher)

    ['{17D4977F-C9D8-466D-8E46-7E23A03471FC}']

    /// <summary>
    /// return the underlying block cipher that we are wrapping.
    /// </summary>
    /// <returns>
    /// return the underlying block cipher that we are wrapping.
    /// </returns>
    function GetUnderlyingCipher(): IBlockCipher;

  end;

implementation

end.
