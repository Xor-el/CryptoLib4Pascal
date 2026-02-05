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

unit ClpPaddedBufferedBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Math,
  ClpCheck,
  ClpIBlockCipher,
  ClpISO10126d2Padding,
  ClpIISO10126d2Padding,
  ClpISO7816d4Padding,
  ClpIISO7816d4Padding,
  ClpPkcs7Padding,
  ClpIPkcs7Padding,
  ClpTBCPadding,
  ClpITBCPadding,
  ClpX923Padding,
  ClpIX923Padding,
  ClpZeroBytePadding,
  ClpIZeroBytePadding,
  ClpBufferedBlockCipher,
  ClpIPaddedBufferedBlockCipher,
  ClpIBlockCipherPadding,
  ClpICipherParameters,
  ClpIParametersWithRandom,
  ClpISecureRandom,
  ClpCryptoLibTypes;

resourcestring
  SOutputBufferTooSmall = 'Output Buffer too Short';
  SIncompleteLastBlockInDecryption = 'Last Block Incomplete in Decryption';
  SNegativeInputLength = 'Can''t Have a Negative Input Length!';

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

  public

    /// <summary>
    /// Create a buffered block cipher with the desired padding.
    /// </summary>
    /// <param name="cipher">
    /// the underlying block cipher this buffering object wraps.
    /// </param>
    /// <param name="padding">
    /// the padding type.
    /// </param>
    constructor Create(const ACipher: IBlockCipher;
      const APadding: IBlockCipherPadding); overload;

    /// <summary>
    /// Create a buffered block cipher Pkcs7 padding
    /// </summary>
    /// <param name="ACipher">
    /// the underlying block cipher this buffering object wraps.
    /// </param>
    constructor Create(const ACipher: IBlockCipher); overload;

    /// <summary>
    /// initialise the cipher.
    /// </summary>
    /// <param name="forEncryption">
    /// if true the cipher is initialised for encryption, if false for
    /// decryption.
    /// </param>
    /// <param name="parameters">
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
    /// <param name="length">
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
    /// <param name="length">
    /// the length of the input.
    /// </param>
    /// <returns>
    /// the space required to accommodate a call to update with length bytes
    /// of input.
    /// </returns>
    function GetUpdateOutputSize(ALength: Int32): Int32; override;

    /// <summary>
    /// process a single byte, producing an output block if necessary.
    /// </summary>
    /// <param name="input">
    /// the input byte.
    /// </param>
    /// <param name="output">
    /// the space for any output that might be produced.
    /// </param>
    /// <param name="outOff">
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
    function ProcessByte(AInput: Byte; const AOutput: TCryptoLibByteArray;
      AOutOff: Int32): Int32; override;

    /// <summary>
    /// process an array of bytes, producing output if necessary.
    /// </summary>
    /// <param name="input">
    /// the input byte array.
    /// </param>
    /// <param name="inOff">
    /// the offset at which the input data starts.
    /// </param>
    /// <param name="length">
    /// the number of bytes to be copied out of the input array.
    /// </param>
    /// <param name="output">
    /// the space for any output that might be produced.
    /// </param>
    /// <param name="outOff">
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
    function ProcessBytes(const AInput: TCryptoLibByteArray;
      AInOff, ALength: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32)
      : Int32; override;

    /// <summary>
    /// Process the last block in the buffer. If the buffer is currently full
    /// and padding needs to be added a call to doFinal will produce 2 *
    /// GetBlockSize() bytes.
    /// </summary>
    /// <param name="output">
    /// the array the block currently being held is copied into.
    /// </param>
    /// <param name="outOff">
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
  Inherited Create();
  FCipher := ACipher;
  FPadding := APadding;

  System.SetLength(FBuf, ACipher.GetBlockSize());
  FBufOff := 0;
end;

constructor TPaddedBufferedBlockCipher.Create(const ACipher: IBlockCipher);
begin
  Create(ACipher, TPkcs7Padding.Create() as IPkcs7Padding);
end;

function TPaddedBufferedBlockCipher.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LBlockSize, LResultLen, LResultTotalLen: Int32;
begin
  LBlockSize := FCipher.GetBlockSize();
  LResultLen := 0;

  if (FForEncryption) then
  begin
    if (FBufOff = LBlockSize) then
    begin
      if ((AOutOff + 2 * LBlockSize) > System.Length(AOutput)) then
      begin
        Reset();

        raise EOutputLengthCryptoLibException.CreateRes(@SOutputBufferTooSmall);
      end;

      LResultLen := FCipher.ProcessBlock(FBuf, 0, AOutput, AOutOff);
      FBufOff := 0;
    end;

    FPadding.AddPadding(FBuf, FBufOff);

    LResultLen := LResultLen + FCipher.ProcessBlock(FBuf, 0, AOutput,
      AOutOff + LResultLen);

    Reset();
  end
  else
  begin
    if (FBufOff = LBlockSize) then
    begin
      LResultLen := FCipher.ProcessBlock(FBuf, 0, FBuf, 0);
      FBufOff := 0;
    end
    else
    begin
      Reset();

      raise EDataLengthCryptoLibException.CreateRes
        (@SIncompleteLastBlockInDecryption);
    end;

    try
      LResultLen := LResultLen - FPadding.PadCount(FBuf);
      LResultTotalLen := LResultLen * System.SizeOf(Byte);
      if LResultTotalLen > 0 then
      begin
        System.Move(FBuf[0], AOutput[AOutOff], LResultTotalLen);
      end;

    finally
      Reset();
    end;

  end;

  Result := LResultLen;
end;

function TPaddedBufferedBlockCipher.GetOutputSize(ALength: Int32): Int32;
var
  LTotal, LLeftOver: Int32;
begin
  LTotal := ALength + FBufOff;
  LLeftOver := LTotal mod System.Length(FBuf);

  if (LLeftOver = 0) then
  begin
    if (FForEncryption) then
    begin
      Result := LTotal + System.Length(FBuf);
      Exit;
    end;

    Result := LTotal;
    Exit;
  end;

  Result := LTotal - LLeftOver + System.Length(FBuf);
end;

function TPaddedBufferedBlockCipher.GetUpdateOutputSize(ALength: Int32): Int32;
var
  LTotal, LLeftOver: Int32;
begin
  LTotal := ALength + FBufOff;
  LLeftOver := LTotal mod System.Length(FBuf);

  if (LLeftOver = 0) then
  begin
    Result := Max(0, LTotal - System.Length(FBuf));
    Exit;
  end;

  Result := LTotal - LLeftOver;
end;

procedure TPaddedBufferedBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LInitRandom: ISecureRandom;
  LParameters: ICipherParameters;
  LP: IParametersWithRandom;
begin
  FForEncryption := AForEncryption;
  LParameters := AParameters;
  LInitRandom := nil;

  if Supports(LParameters, IParametersWithRandom, LP) then
  begin
    LInitRandom := LP.Random;
    LParameters := LP.Parameters;
  end;

  Reset();
  FPadding.Init(LInitRandom);
  FCipher.Init(AForEncryption, LParameters);
end;

function TPaddedBufferedBlockCipher.ProcessByte(AInput: Byte;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LResultLen: Int32;
begin
  LResultLen := 0;

  if (FBufOff = System.Length(FBuf)) then
  begin
    LResultLen := FCipher.ProcessBlock(FBuf, 0, AOutput, AOutOff);
    FBufOff := 0;
  end;

  FBuf[FBufOff] := AInput;
  System.Inc(FBufOff);

  Result := LResultLen;
end;

function TPaddedBufferedBlockCipher.ProcessBytes(const AInput
  : TCryptoLibByteArray; AInOff, ALength: Int32;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LBlockSize, LOutLength, LResultLen, LGapLen: Int32;
begin
  if (ALength < 0) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SNegativeInputLength);
  end;

  LBlockSize := GetBlockSize();
  LOutLength := GetUpdateOutputSize(ALength);

  if (LOutLength > 0) then
  begin
    TCheck.OutputLength(AOutput, AOutOff, LOutLength, SOutputBufferTooSmall);
  end;

  LResultLen := 0;
  LGapLen := System.Length(FBuf) - FBufOff;

  if (ALength > LGapLen) then
  begin
    System.Move(AInput[AInOff], FBuf[FBufOff], LGapLen * System.SizeOf(Byte));

    LResultLen := LResultLen + FCipher.ProcessBlock(FBuf, 0, AOutput, AOutOff);

    FBufOff := 0;
    ALength := ALength - LGapLen;
    AInOff := AInOff + LGapLen;

    while (ALength > System.Length(FBuf)) do
    begin
      LResultLen := LResultLen + FCipher.ProcessBlock(AInput, AInOff, AOutput,
        AOutOff + LResultLen);

      ALength := ALength - LBlockSize;
      AInOff := AInOff + LBlockSize;
    end;
  end;

  System.Move(AInput[AInOff], FBuf[FBufOff], ALength * System.SizeOf(Byte));

  FBufOff := FBufOff + ALength;

  Result := LResultLen;
end;

end.
