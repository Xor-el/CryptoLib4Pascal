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

unit ClpIAesEngine;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipher;

type

  /// <summary>AES <see cref="IBlockCipher"/>: 128-bit blocks, 128/192/256-bit keys.</summary>
  IAesEngine = interface(IBlockCipher)
    ['{984D6EC6-DBFC-4CEC-88B6-29B1C0BEA6CD}']

  end;

implementation

end.
