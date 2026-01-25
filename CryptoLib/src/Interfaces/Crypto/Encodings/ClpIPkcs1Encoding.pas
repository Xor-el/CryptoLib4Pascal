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

unit ClpIPkcs1Encoding;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsymmetricBlockCipher;

type
  /// <summary>
  /// Interface for PKCS#1 v1.5 encoding.
  /// </summary>
  IPkcs1Encoding = interface(IAsymmetricBlockCipher)
    ['{B8C9D0E1-F2A3-4567-8901-23456789ABCD}']

    function GetUnderlyingCipher: IAsymmetricBlockCipher;
    property UnderlyingCipher: IAsymmetricBlockCipher read GetUnderlyingCipher;

  end;

implementation

end.
