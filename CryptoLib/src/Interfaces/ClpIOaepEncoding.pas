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

unit ClpIOaepEncoding;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIAsymmetricBlockCipher;

type
  /// <summary>
  /// Interface for OAEP encoding.
  /// </summary>
  IOaepEncoding = interface(IAsymmetricBlockCipher)
    ['{C9D0E1F2-A3B4-5678-9012-3456789ABCDE}']

    function GetUnderlyingCipher: IAsymmetricBlockCipher;
    property UnderlyingCipher: IAsymmetricBlockCipher read GetUnderlyingCipher;

  end;

implementation

end.
