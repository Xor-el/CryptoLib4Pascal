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

unit ClpCfbBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpICfbBlockCipher,
  ClpICipherParameters,
  ClpIParametersWithIV,
  ClpCryptoLibTypes;

resourcestring
  SInputBufferTooShort = 'Input Buffer too Short';
  SOutputBufferTooShort = 'Output Buffer too Short';

type

  /// <summary>
  /// implements a Cipher-FeedBack (CFB) mode on top of a simple cipher.
  /// </summary>
  TCfbBlockCipher = class sealed(TInterfacedObject, ICfbBlockCipher,
    IBlockCipher)

  strict private

  var
    FIV, FcfbV, FcfbOutV: TCryptoLibByteArray;
    FblockSize: Int32;
    Fcipher: IBlockCipher;
    Fencrypting: Boolean;

    /// <summary>
    /// return the algorithm name and mode.
    /// </summary>
    /// <returns>
    /// return the name of the underlying algorithm followed by "/CFB"
    /// </returns>
    function GetAlgorithmName: String; inline;

    function GetIsPartialBlockOkay: Boolean; inline;

    /// <summary>
    /// Do the appropriate processing for CFB mode encryption.
    /// </summary>
    /// <param name="input">
    /// the array containing the data to be encrypted.
    /// </param>
    /// <param name="inOff">
    /// offset into the in array the data starts at.
    /// </param>
    /// <param name="outBytes">
    /// the array the encrypted data will be copied into.
    /// </param>
    /// <param name="outOff">
    /// the offset into the out array the output will start at.
    /// </param>
    /// <returns>
    /// the number of bytes processed and produced.
    /// </returns>
    /// <exception cref="EDataLengthCryptoLibException">
    /// if there isn't enough data in input, or space in output.
    /// </exception>
    /// <exception cref="EInvalidOperationCryptoLibException">
    /// if the cipher isn't initialised.
    /// </exception>
    function EncryptBlock(const input: TCryptoLibByteArray; inOff: Int32;
      const outBytes: TCryptoLibByteArray; outOff: Int32): Int32;

    /// <summary>
    /// Do the appropriate chaining step for CBC mode decryption.
    /// </summary>
    /// <param name="input">
    /// the array containing the data to be decrypted.
    /// </param>
    /// <param name="inOff">
    /// offset into the in array the data starts at.
    /// </param>
    /// <param name="outBytes">
    /// the array the decrypted data will be copied into.
    /// </param>
    /// <param name="outOff">
    /// the offset into the out array the output will start at.
    /// </param>
    /// <returns>
    /// the number of bytes processed and produced.
    /// </returns>
    /// <exception cref="EDataLengthCryptoLibException">
    /// if there isn't enough data in input, or space in output.
    /// </exception>
    /// <exception cref="EInvalidOperationCryptoLibException">
    /// if the cipher isn't initialised.
    /// </exception>
    function DecryptBlock(const input: TCryptoLibByteArray; inOff: Int32;
      const outBytes: TCryptoLibByteArray; outOff: Int32): Int32;

  public

    /// <summary>
    /// Basic constructor.
    /// </summary>
    /// <param name="cipher">
    /// the block cipher to be used as the basis of the feedback mode.
    /// </param>
    /// <param name="bitBlockSize">
    /// the block size in bits (note: a multiple of 8)
    /// </param>
    constructor Create(const cipher: IBlockCipher; bitBlockSize: Int32);

    /// <summary>
    /// return the underlying block cipher that we are wrapping.
    /// </summary>
    /// <returns>
    /// return the underlying block cipher that we are wrapping.
    /// </returns>
    function GetUnderlyingCipher(): IBlockCipher;

    /// <summary>
    /// Initialise the cipher and, possibly, the initialisation vector (IV). <br />
    /// If an IV isn't passed as part of the parameter, the IV will be all
    /// zeros.
    /// An IV which is too short is handled in FIPS compliant fashion.
    /// </summary>
    /// <param name="forEncryption">
    /// forEncryption if true the cipher is initialised for encryption, if
    /// false for decryption.
    /// </param>
    /// <param name="parameters">
    /// the key and other data required by the cipher.
    /// </param>
    procedure Init(forEncryption: Boolean; const parameters: ICipherParameters);

    /// <summary>
    /// return the block size we are operating at.
    /// </summary>
    /// <returns>
    /// the block size we are operating at (in bytes).
    /// </returns>
    function GetBlockSize(): Int32; inline;

    /// <summary>
    /// Process one block of input from the input array and write it to the
    /// output array.
    /// </summary>
    /// <param name="input">
    /// the array containing the input data.
    /// </param>
    /// <param name="inOff">
    /// offset into the input array the data starts at.
    /// </param>
    /// <param name="output">
    /// the array the output data will be copied into.
    /// </param>
    /// <param name="outOff">
    /// the offset into the output array the data starts at.
    /// </param>
    /// <returns>
    /// the number of bytes processed and produced.
    /// </returns>
    /// <exception cref="EDataLengthCryptoLibException">
    /// if there isn't enough data in input, or space in output.
    /// </exception>
    /// <exception cref="EInvalidOperationCryptoLibException">
    /// if the cipher isn't initialised.
    /// </exception>
    function ProcessBlock(const input: TCryptoLibByteArray; inOff: Int32;
      const output: TCryptoLibByteArray; outOff: Int32): Int32;

    /// <summary>
    /// reset the chaining vector back to the IV and reset the underlying
    /// cipher.
    /// </summary>
    procedure Reset(); inline;

    /// <summary>
    /// return the algorithm name and mode.
    /// </summary>
    /// <value>
    /// return the name of the underlying algorithm followed by "/CFB"
    /// </value>
    property AlgorithmName: String read GetAlgorithmName;

    property IsPartialBlockOkay: Boolean read GetIsPartialBlockOkay;

  end;

implementation

{ TCfbBlockCipher }

constructor TCfbBlockCipher.Create(const cipher: IBlockCipher;
  bitBlockSize: Int32);
begin
  inherited Create();
  Fcipher := cipher;
  FblockSize := bitBlockSize div 8;

  System.SetLength(FIV, Fcipher.GetBlockSize);
  System.SetLength(FcfbV, Fcipher.GetBlockSize);
  System.SetLength(FcfbOutV, Fcipher.GetBlockSize);
end;

function TCfbBlockCipher.DecryptBlock(const input: TCryptoLibByteArray;
  inOff: Int32; const outBytes: TCryptoLibByteArray; outOff: Int32): Int32;
var
  I: Int32;
begin
  if ((inOff + FblockSize) > System.length(input)) then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SInputBufferTooShort);
  end;

  if ((outOff + FblockSize) > System.length(outBytes)) then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooShort);
  end;

  Fcipher.ProcessBlock(FcfbV, 0, FcfbOutV, 0);

  //
  // change over the input block.
  //
  System.Move(FcfbV[FblockSize], FcfbV[0], (System.length(FcfbV) - FblockSize) *
    System.SizeOf(Byte));

  System.Move(input[inOff], FcfbV[(System.length(FcfbV) - FblockSize)],
    FblockSize * System.SizeOf(Byte));

  // XOR the FcfbV with the ciphertext producing the plaintext

  for I := 0 to System.Pred(FblockSize) do
  begin
    outBytes[outOff + I] := Byte(FcfbOutV[I] xor input[inOff + I]);
  end;

  result := FblockSize;
end;

function TCfbBlockCipher.EncryptBlock(const input: TCryptoLibByteArray;
  inOff: Int32; const outBytes: TCryptoLibByteArray; outOff: Int32): Int32;
var
  I: Int32;
begin
  if ((inOff + FblockSize) > System.length(input)) then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SInputBufferTooShort);
  end;

  if ((outOff + FblockSize) > System.length(outBytes)) then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooShort);
  end;

  Fcipher.ProcessBlock(FcfbV, 0, FcfbOutV, 0);

  // XOR the FcfbV with the plaintext producing the ciphertext

  for I := 0 to System.Pred(FblockSize) do
  begin
    outBytes[outOff + I] := Byte(FcfbOutV[I] xor input[inOff + I]);
  end;

  //
  // change over the input block.
  //
  System.Move(FcfbV[FblockSize], FcfbV[0], (System.length(FcfbV) - FblockSize) *
    System.SizeOf(Byte));

  System.Move(outBytes[outOff], FcfbV[(System.length(FcfbV) - FblockSize)],
    FblockSize * System.SizeOf(Byte));

  result := FblockSize;
end;

procedure TCfbBlockCipher.Reset;
begin
  System.Move(FIV[0], FcfbV[0], System.length(FIV));

  Fcipher.Reset();
end;

function TCfbBlockCipher.GetAlgorithmName: String;
begin
  result := Fcipher.AlgorithmName + '/CFB' + IntToStr(FblockSize * 8);
end;

function TCfbBlockCipher.GetBlockSize: Int32;
begin
  result := FblockSize;
end;

function TCfbBlockCipher.GetIsPartialBlockOkay: Boolean;
begin
  result := true;
end;

function TCfbBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  result := Fcipher;
end;

procedure TCfbBlockCipher.Init(forEncryption: Boolean;
  const parameters: ICipherParameters);
var
  ivParam: IParametersWithIV;
  iv: TCryptoLibByteArray;
  Lparameters: ICipherParameters;
  diff: Int32;
begin
  Fencrypting := forEncryption;
  Lparameters := parameters;

  if Supports(Lparameters, IParametersWithIV, ivParam) then
  begin
    iv := ivParam.GetIV();

    diff := System.length(FIV) - System.length(iv);

    System.Move(iv[0], FIV[diff], System.length(iv) * System.SizeOf(Byte));
    System.FillChar(FIV[0], diff, Byte(0));

    Lparameters := ivParam.parameters;
  end;

  Reset();

  // if it's Nil, key is to be reused.
  if (Lparameters <> Nil) then
  begin
    Fcipher.Init(true, Lparameters);
  end;

end;

function TCfbBlockCipher.ProcessBlock(const input: TCryptoLibByteArray;
  inOff: Int32; const output: TCryptoLibByteArray; outOff: Int32): Int32;
begin
  if Fencrypting then
  begin
    result := EncryptBlock(input, inOff, output, outOff);
  end
  else
  begin
    result := DecryptBlock(input, inOff, output, outOff);
  end;
end;

end.
