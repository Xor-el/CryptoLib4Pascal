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

unit ClpIISO9796d1Encoding;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIAsymmetricBlockCipher;

type
  /// <summary>
  /// Interface for ISO 9796-1 encoding.
  /// </summary>
  IISO9796d1Encoding = interface(IAsymmetricBlockCipher)
    ['{E1F2A3B4-C5D6-7890-1234-56789ABCDEF0}']

    function GetUnderlyingCipher: IAsymmetricBlockCipher;
    procedure SetPadBits(padBits: Int32);
    function GetPadBits: Int32;

    property UnderlyingCipher: IAsymmetricBlockCipher read GetUnderlyingCipher;
    property PadBits: Int32 read GetPadBits write SetPadBits;

  end;

implementation

end.
