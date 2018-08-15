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

unit ClpIBufferedCipher;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpICipherParameters,
  ClpCryptoLibTypes;

type
  /// <remarks>Block cipher engines are expected to conform to this interface.</remarks>
  IBufferedCipher = interface(IInterface)
    ['{44FE589C-EDAE-4FDC-90AE-90C0935B4BC7}']
    /// <summary>The name of the algorithm this cipher implements.</summary>
    function GetAlgorithmName: String;
    property AlgorithmName: String read GetAlgorithmName;

    /// <summary>Initialise the cipher.</summary>
    /// <param name="forEncryption">If true the cipher is initialised for encryption,
    /// if false for decryption.</param>
    /// <param name="parameters">The key and other data required by the cipher.</param>
    procedure Init(forEncryption: Boolean; const parameters: ICipherParameters);

    function GetBlockSize(): Int32;

    function GetOutputSize(inputLen: Int32): Int32;

    function GetUpdateOutputSize(inputLen: Int32): Int32;

    function ProcessByte(input: Byte): TCryptoLibByteArray; overload;
    function ProcessByte(input: Byte; const output: TCryptoLibByteArray;
      outOff: Int32): Int32; overload;

    function ProcessBytes(const input: TCryptoLibByteArray)
      : TCryptoLibByteArray; overload;
    function ProcessBytes(const input: TCryptoLibByteArray;
      inOff, length: Int32): TCryptoLibByteArray; overload;
    function ProcessBytes(const input, output: TCryptoLibByteArray;
      outOff: Int32): Int32; overload;
    function ProcessBytes(const input: TCryptoLibByteArray;
      inOff, length: Int32; const output: TCryptoLibByteArray; outOff: Int32)
      : Int32; overload;

    function DoFinal(): TCryptoLibByteArray; overload;
    function DoFinal(const input: TCryptoLibByteArray)
      : TCryptoLibByteArray; overload;
    function DoFinal(const input: TCryptoLibByteArray; inOff, length: Int32)
      : TCryptoLibByteArray; overload;
    function DoFinal(const output: TCryptoLibByteArray; outOff: Int32)
      : Int32; overload;
    function DoFinal(const input, output: TCryptoLibByteArray; outOff: Int32)
      : Int32; overload;
    function DoFinal(const input: TCryptoLibByteArray; inOff, length: Int32;
      const output: TCryptoLibByteArray; outOff: Int32): Int32; overload;

    /// <summary>
    /// Reset the cipher. After resetting the cipher is in the same state
    /// as it was after the last init (if there was one).
    /// </summary>
    procedure Reset();
  end;

implementation

end.
