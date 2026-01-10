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

unit ClpIRsa;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpICipherParameters,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Base interface for RSA engine implementations.
  /// </summary>
  IRsa = interface(IInterface)
    ['{D4E5F6A7-B8C9-0123-4567-89ABCDEF0123}']

    procedure Init(forEncryption: Boolean; const parameters: ICipherParameters);
    function GetInputBlockSize: Int32;
    function GetOutputBlockSize: Int32;
    function ConvertInput(const buf: TCryptoLibByteArray; off, len: Int32): TBigInteger;
    function ProcessBlock(const input: TBigInteger): TBigInteger;
    function ConvertOutput(const result: TBigInteger): TCryptoLibByteArray;

    property InputBlockSize: Int32 read GetInputBlockSize;
    property OutputBlockSize: Int32 read GetOutputBlockSize;

  end;

implementation

end.
