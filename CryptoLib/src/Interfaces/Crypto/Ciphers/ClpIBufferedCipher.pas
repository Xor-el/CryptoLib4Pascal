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

{$I ..\..\..\Include\CryptoLib.inc}

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
    /// <param name="AForEncryption">If true the cipher is initialised for encryption,
    /// if false for decryption.</param>
    /// <param name="AParameters">The key and other data required by the cipher.</param>
    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters);

    function GetBlockSize(): Int32;

    function GetOutputSize(AInputLen: Int32): Int32;

    function GetUpdateOutputSize(AInputLen: Int32): Int32;

    function ProcessByte(AInput: Byte): TCryptoLibByteArray; overload;
    function ProcessByte(AInput: Byte; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload;

    function ProcessBytes(const AInput: TCryptoLibByteArray): TCryptoLibByteArray; overload;
    function ProcessBytes(const AInput: TCryptoLibByteArray; AInOff, ALength: Int32): TCryptoLibByteArray; overload;
    function ProcessBytes(const AInput, AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload;
    function ProcessBytes(const AInput: TCryptoLibByteArray; AInOff, ALength: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload;

    function DoFinal(): TCryptoLibByteArray; overload;
    function DoFinal(const AInput: TCryptoLibByteArray): TCryptoLibByteArray; overload;
    function DoFinal(const AInput: TCryptoLibByteArray; AInOff, ALength: Int32): TCryptoLibByteArray; overload;
    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload;
    function DoFinal(const AInput, AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload;
    function DoFinal(const AInput: TCryptoLibByteArray; AInOff, ALength: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload;

    /// <summary>
    /// Reset the cipher. After resetting the cipher is in the same state
    /// as it was after the last init (if there was one).
    /// </summary>
    procedure Reset();
  end;

implementation

end.
