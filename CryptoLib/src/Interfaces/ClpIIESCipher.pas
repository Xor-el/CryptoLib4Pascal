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

unit ClpIIESCipher;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpICipherParameters,
  ClpISecureRandom,
  ClpIIESWithCipherParameters,
  ClpCryptoLibTypes;

type
  IIESCipher = interface(IInterface)
    ['{DD112FD3-844A-4EF0-B9B8-22AFAEFB0881}']

    procedure Init(ForEncryption: Boolean; const Key: ICipherParameters;
      const params: IIESWithCipherParameters; const Random: ISecureRandom);

    procedure ProcessBytes(input: TCryptoLibByteArray); overload;
    procedure ProcessBytes(input: TCryptoLibByteArray;
      inputOffset, inputLen: Int32); overload;

    function DoFinal(input: TCryptoLibByteArray): TCryptoLibByteArray; overload;

    function DoFinal(input: TCryptoLibByteArray; inputOffset, inputLen: Int32)
      : TCryptoLibByteArray; overload;

    function DoFinal(input: TCryptoLibByteArray; inputOffset, inputLen: Int32;
      output: TCryptoLibByteArray; outputOffset: Int32): Int32; overload;
  end;

implementation

end.
