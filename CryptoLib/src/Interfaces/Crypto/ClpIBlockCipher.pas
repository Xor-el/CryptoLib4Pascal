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

unit ClpIBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpICipherParameters,
  ClpCryptoLibTypes;

type
  /// <summary>Base interface for a symmetric block cipher keyed by algorithm-specific parameters.</summary>
  IBlockCipher = interface(IInterface)
    ['{0D2145AA-9D1E-4955-A55E-645CC8DEBE6F}']

    /// <summary>The name of the algorithm this cipher implements.</summary>
    function GetAlgorithmName: String;
    property AlgorithmName: String read GetAlgorithmName;

    /// <summary>Initialise the cipher.</summary>
    /// <param name="AForEncryption">Initialise for encryption if true, for decryption if false.</param>
    /// <param name="AParameters">The key or other data required by the cipher.</param>
    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters);

    /// <summary>Return the block size for this cipher, in bytes.</summary>
    /// <returns>The block size for this cipher, in bytes.</returns>
    function GetBlockSize(): Int32;

    /// <summary>Process a single block.</summary>
    /// <param name="AInBuf">The input buffer.</param>
    /// <param name="AInOff">The offset into <paramref name="AInBuf"/> that the input block begins.</param>
    /// <param name="AOutBuf">The output buffer.</param>
    /// <param name="AOutOff">The offset into <paramref name="AOutBuf"/> to write the output block.</param>
    /// <exception cref="EDataLengthCryptoLibException">If the input slice is shorter than one block or the output buffer is too small.</exception>
    /// <exception cref="EArgumentCryptoLibException">From some implementations if the cipher is not initialised or parameters are inconsistent.</exception>
    /// <returns>The number of bytes processed and produced.</returns>
    function ProcessBlock(const AInBuf: TCryptoLibByteArray; AInOff: Int32;
      const AOutBuf: TCryptoLibByteArray; AOutOff: Int32): Int32;

  end;

implementation

end.
