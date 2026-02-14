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

unit ClpIRsaBlindedEngine;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsymmetricBlockCipher;

type
  /// <summary>
  /// Interface for blinded RSA engine implementing IAsymmetricBlockCipher.
  /// Wraps IRsa with random blinding for side-channel protection.
  /// </summary>
  IRsaBlindedEngine = interface(IAsymmetricBlockCipher)
    ['{14EA4B56-B8CF-4D6E-BE9C-1C6D522A06E8}']
  end;

implementation

end.
