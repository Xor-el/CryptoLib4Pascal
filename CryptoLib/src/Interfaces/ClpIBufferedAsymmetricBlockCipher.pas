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

unit ClpIBufferedAsymmetricBlockCipher;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIBufferedCipher;

type
  /// <summary>
  /// Interface for a buffer wrapper for an asymmetric block cipher.
  /// </summary>
  IBufferedAsymmetricBlockCipher = interface(IBufferedCipher)
    ['{B2C4D6E8-F0A2-4B3C-9D5E-7F0A2B4C6D8E}']
  end;

implementation

end.
