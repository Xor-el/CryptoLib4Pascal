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

unit ClpICfbBlockCipher;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipher;

type
  ICfbBlockCipher = interface(IBlockCipher)

    ['{A58FD8F1-EECF-402F-9007-4E884FF7D325}']

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
