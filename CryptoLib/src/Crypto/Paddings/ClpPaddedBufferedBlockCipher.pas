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

unit ClpPaddedBufferedBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCheck,
  ClpIBlockCipher,
  ClpIBlockCipherMode,
  ClpEcbBlockCipher,
  ClpPkcs7Padding,
  ClpIPkcs7Padding,
  ClpBufferedBlockCipher,
  ClpIPaddedBufferedBlockCipher,
  ClpIBlockCipherPadding,
  ClpICipherParameters,
  ClpParameterUtilities,
  ClpISecureRandom,
  ClpCryptoLibTypes;

resourcestring
  SOutputBufferTooSmall = 'output buffer too short';
  SIncompleteLastBlockInDecryption = 'last block incomplete in decryption';
  SBufOffInvariant = 'BufOff invariant violated: expected [0..blockSize-1] before AddPadding';
type

  /// <summary>
  /// <para>
  /// A wrapper class that allows block ciphers to be used to process
  /// data in a piecemeal fashion with padding.
  /// </para>
  /// <para>
  /// The PaddedBufferedBlockCipher outputs a block only when the buffer
  /// is full and more data is being added, or on a doFinal (unless the
  /// current block in the buffer is a pad block). <br />The default
  /// padding mechanism used is the one outlined in Pkcs5/Pkcs7. <br />
  /// </para>
  /// </summary>
  TPaddedBufferedBlockCipher = class sealed(TBufferedBlockCipher,
    IPaddedBufferedBlockCipher)

  strict private
    FPadding: IBlockCipherPadding;

  strict protected
    /// <summary>
    /// Padded cipher must retain the last block in FBuf so DoFinal can
    /// apply (encrypting) or strip (decrypting) the padding.
    /// </summary>
    function IsFullBufferRetained: Boolean; override;

  public

    constructor Create(const ACipher: IBlockCipher;
      const APadding: IBlockCipherPadding); overload;

    /// <summary>
    /// Create a buffered block cipher with the desired padding.
    /// </summary>
    /// <param name="ACipherMode">
    /// the underlying block cipher mode this buffering object wraps.
    /// </param>
    /// <param name="APadding">
    /// the padding type.
    /// </param>
    constructor Create(const ACipherMode: IBlockCipherMode;
      const APadding: IBlockCipherPadding); overload;

    /// <summary>
    /// Create a buffered block cipher with Pkcs7 padding.
    /// </summary>
    /// <param name="ACipherMode">
    /// the underlying block cipher mode this buffering object wraps.
    /// </param>
    constructor Create(const ACipherMode: IBlockCipherMode); overload;

    /// <summary>
    /// initialise the cipher.
    /// </summary>
    /// <param name="AForEncryption">
    /// if true the cipher is initialised for encryption, if false for
    /// decryption.
    /// </param>
    /// <param name="AParameters">
    /// the key and other data required by the cipher.
    /// </param>
    /// <exception cref="EArgumentCryptoLibException">
    /// if the parameters argument is inappropriate.
    /// </exception>
    procedure Init(AForEncryption: Boolean;
      const AParameters: ICipherParameters); override;

    /// <summary>
    /// return the minimum size of the output buffer required for an update
    /// plus a doFinal with an input of len bytes.
    /// </summary>
    /// <param name="ALength">
    /// the length of the input.
    /// </param>
    /// <returns>
    /// the space required to accommodate a call to update and doFinal with
    /// len bytes of input.
    /// </returns>
    function GetOutputSize(ALength: Int32): Int32; override;

    /// <summary>
    /// return the size of the output buffer required for an update an input
    /// of len bytes.
    /// </summary>
    /// <param name="ALength">
    /// the length of the input.
    /// </param>
    /// <returns>
    /// the space required to accommodate a call to update with length bytes
    /// of input.
    /// </returns>
    function GetUpdateOutputSize(ALength: Int32): Int32; override;

    /// <summary>
    /// process an array of bytes, producing output if necessary.
    /// </summary>
    /// <param name="AInput">
    /// the input byte array.
    /// </param>
    /// <param name="AInOff">
    /// the offset at which the input data starts.
    /// </param>
    /// <param name="ALength">
    /// the number of bytes to be copied out of the input array.
    /// </param>
    /// <param name="AOutput">
    /// the space for any output that might be produced.
    /// </param>
    /// <param name="AOutOff">
    /// the offset from which the output will be copied.
    /// </param>
    /// <returns>
    /// the number of output bytes copied to output.
    /// </returns>
    /// <exception cref="EDataLengthCryptoLibException">
    /// if there isn't enough space in output.
    /// </exception>
    /// <exception cref="EInvalidOperationCryptoLibException">
    /// if the cipher isn't initialised.
    /// </exception>
    /// <summary>
    /// Process the last block in the buffer. If the buffer is currently full
    /// and padding needs to be added a call to doFinal will produce 2 *
    /// GetBlockSize() bytes.
    /// </summary>
    /// <param name="AOutput">
    /// the array the block currently being held is copied into.
    /// </param>
    /// <param name="AOutOff">
    /// the offset at which the copying starts.
    /// </param>
    /// <returns>
    /// the number of output bytes copied to output.
    /// </returns>
    /// <exception cref="EDataLengthCryptoLibException">
    /// if there is insufficient space in output for the output or we are
    /// decrypting and the input is not block size aligned.
    /// </exception>
    /// <exception cref="EInvalidOperationCryptoLibException">
    /// if the underlying cipher is not initialised.
    /// </exception>
    /// <exception cref="EInvalidCipherTextCryptoLibException">
    /// if padding is expected and not found.
    /// </exception>
    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32)
      : Int32; override;

  end;

implementation

{ TPaddedBufferedBlockCipher }

constructor TPaddedBufferedBlockCipher.Create(const ACipher: IBlockCipher;
  const APadding: IBlockCipherPadding);
begin
  Create(TEcbBlockCipher.GetBlockCipherMode(ACipher), APadding);
end;

constructor TPaddedBufferedBlockCipher.Create(const ACipherMode: IBlockCipherMode;
  const APadding: IBlockCipherPadding);
begin
  Inherited Create(ACipherMode);
  FPadding := APadding;
end;

constructor TPaddedBufferedBlockCipher.Create(const ACipherMode: IBlockCipherMode);
begin
  Create(ACipherMode, TPkcs7Padding.Create() as IPkcs7Padding);
end;

function TPaddedBufferedBlockCipher.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LBlockSize, LResultLen: Int32;
begin
  try
    LResultLen := 0;
    LBlockSize := System.Length(FBuf);

    if (FForEncryption) then
    begin
      if (FBufOff = LBlockSize) then
      begin
        TCheck.OutputLength(AOutput, AOutOff, LBlockSize * 2,
          SOutputBufferTooSmall);

        LResultLen := FCipherMode.ProcessBlock(FBuf, 0, AOutput, AOutOff);
        FBufOff := 0;
      end
      else
      begin
        TCheck.OutputLength(AOutput, AOutOff, LBlockSize,
          SOutputBufferTooSmall);
      end;

      // FBufOff must be in [0..LBlockSize-1] when AddPadding is called.
      // Block-aligned input is handled by the if-branch above, which flushes
      // the full block and resets FBufOff to 0 - so AddPadding always sees
      // a value in the valid range. The guard below is a tripwire for future
      // refactors of ProcessBytes / IsFullBufferRetained / DoFinal.
      if (FBufOff < 0) or (FBufOff >= LBlockSize) then
        raise EInvalidOperationCryptoLibException.CreateRes(@SBufOffInvariant);

      FPadding.AddPadding(FBuf, FBufOff);

      LResultLen := LResultLen + FCipherMode.ProcessBlock(FBuf, 0, AOutput,
        AOutOff + LResultLen);
    end
    else
    begin
      TCheck.DataLength(FBufOff <> LBlockSize,
        SIncompleteLastBlockInDecryption);

      LResultLen := FCipherMode.ProcessBlock(FBuf, 0, FBuf, 0);

      LResultLen := LResultLen - FPadding.PadCount(FBuf);

      TCheck.OutputLength(AOutput, AOutOff, LResultLen,
        SOutputBufferTooSmall);

      System.Move(FBuf[0], AOutput[AOutOff], LResultLen * System.SizeOf(Byte));
    end;

    Result := LResultLen;
  finally
    Reset();
  end;
end;

function TPaddedBufferedBlockCipher.GetOutputSize(ALength: Int32): Int32;
var
  LTotalSize, LBlockSize: Int32;
begin
  LTotalSize := FBufOff + ALength;
  LBlockSize := System.Length(FBuf);

  if FForEncryption then
    Result := GetFullBlocksSize(LTotalSize, LBlockSize) + LBlockSize
  else
    Result := GetFullBlocksSize(LTotalSize + LBlockSize - 1, LBlockSize);
end;

function TPaddedBufferedBlockCipher.GetUpdateOutputSize(ALength: Int32): Int32;
begin
  Result := GetFullBlocksSize(FBufOff + ALength - 1, System.Length(FBuf));
end;

procedure TPaddedBufferedBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LInitRandom: ISecureRandom;
  LParams: ICipherParameters;
begin
  LParams := TParameterUtilities.GetRandom(AParameters, LInitRandom);
  FPadding.Init(LInitRandom);
  inherited Init(AForEncryption, LParams);
end;

function TPaddedBufferedBlockCipher.IsFullBufferRetained: Boolean;
begin
  Result := True;
end;

end.
