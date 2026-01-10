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

unit ClpIRsaBlindingEngine;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIAsymmetricBlockCipher;

type
  /// <summary>
  /// Interface for RSA Blinding Engine - used for Chaum's blind signatures.
  /// </summary>
  IRsaBlindingEngine = interface(IAsymmetricBlockCipher)
    ['{A1B3C5D7-E9F1-4A3B-8C5D-7E9F1A3B5C7D}']
  end;

implementation

end.
