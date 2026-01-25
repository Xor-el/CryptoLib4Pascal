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

unit ClpIAsymmetricBlockCipher;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpICipherParameters,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Base interface for a public/private key block cipher.
  /// </summary>
  IAsymmetricBlockCipher = interface(IInterface)
    ['{D4E5F6A7-B8C9-0123-DEF0-123456789ABC}']

    /// <summary>
    /// The name of the algorithm this cipher implements.
    /// </summary>
    function GetAlgorithmName: String;

    /// <summary>
    /// Initialise the cipher.
    /// </summary>
    /// <param name="forEncryption">
    /// Initialise for encryption if true, for decryption if false.
    /// </param>
    /// <param name="parameters">
    /// The key or other data required by the cipher.
    /// </param>
    procedure Init(forEncryption: Boolean; const parameters: ICipherParameters);

    /// <summary>
    /// The maximum size, in bytes, an input block may be.
    /// </summary>
    function GetInputBlockSize: Int32;

    /// <summary>
    /// The maximum size, in bytes, an output block will be.
    /// </summary>
    function GetOutputBlockSize: Int32;

    /// <summary>
    /// Process a block.
    /// </summary>
    /// <param name="inBuf">The input buffer.</param>
    /// <param name="inOff">The offset into inBuf that the input block begins.</param>
    /// <param name="inLen">The length of the input block.</param>
    /// <returns>The processed block.</returns>
    function ProcessBlock(const inBuf: TCryptoLibByteArray;
      inOff, inLen: Int32): TCryptoLibByteArray;

    property AlgorithmName: String read GetAlgorithmName;
    property InputBlockSize: Int32 read GetInputBlockSize;
    property OutputBlockSize: Int32 read GetOutputBlockSize;

  end;

implementation

end.
