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

unit ClpCbcBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpICbcBlockCipher,
  ClpICipherParameters,
  ClpIParametersWithIV,
  ClpCryptoLibTypes;

resourcestring
  SInvalidIVLength =
    'Initialisation Vector Must be the Same Length as Block Size';
  SInvalidChangeState = 'Cannot Change Encrypting State Without Providing Key.';
  SInputBufferTooShort = 'Input Buffer too Short';

type

  /// <summary>
  /// implements Cipher-Block-Chaining (CBC) mode on top of a simple cipher.
  /// </summary>
  TCbcBlockCipher = class sealed(TInterfacedObject, ICbcBlockCipher,
    IBlockCipher)

  strict private

  var
    FIV, FcbcV, FcbcNextV: TCryptoLibByteArray;
    FblockSize: Int32;
    Fcipher: IBlockCipher;
    Fencrypting: Boolean;

    /// <summary>
    /// return the algorithm name and mode.
    /// </summary>
    /// <returns>
    /// return the name of the underlying algorithm followed by "/CBC"
    /// </returns>
    function GetAlgorithmName: String; inline;

    function GetIsPartialBlockOkay: Boolean; inline;

    /// <summary>
    /// Do the appropriate chaining step for CBC mode encryption.
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
    /// the block cipher to be used as the basis of chaining.
    /// </param>
    constructor Create(const cipher: IBlockCipher);

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
    /// </summary>
    /// <param name="forEncryption">
    /// forEncryption if true the cipher is initialised for encryption, if
    /// false for decryption.
    /// </param>
    /// <param name="parameters">
    /// the key and other data required by the cipher.
    /// </param>
    /// <exception cref="EArgumentCryptoLibException">
    /// if the parameters argument is inappropriate
    /// </exception>
    procedure Init(forEncryption: Boolean; const parameters: ICipherParameters);

    /// <summary>
    /// return the block size of the underlying cipher.
    /// </summary>
    /// <returns>
    /// return the block size of the underlying cipher.
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
    /// return the name of the underlying algorithm followed by "/CBC"
    /// </value>
    property AlgorithmName: String read GetAlgorithmName;

    property IsPartialBlockOkay: Boolean read GetIsPartialBlockOkay;

  end;

implementation

{ TCbcBlockCipher }

constructor TCbcBlockCipher.Create(const cipher: IBlockCipher);
begin
  inherited Create();
  Fcipher := cipher;
  FblockSize := cipher.GetBlockSize();

  System.SetLength(FIV, FblockSize);
  System.SetLength(FcbcV, FblockSize);
  System.SetLength(FcbcNextV, FblockSize);
end;

function TCbcBlockCipher.DecryptBlock(const input: TCryptoLibByteArray;
  inOff: Int32; const outBytes: TCryptoLibByteArray; outOff: Int32): Int32;
var
  length, I: Int32;
  tmp: TCryptoLibByteArray;
begin
  if ((inOff + FblockSize) > System.length(input)) then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SInputBufferTooShort);
  end;

  System.Move(input[inOff], FcbcNextV[0], FblockSize * System.SizeOf(Byte));

  length := Fcipher.ProcessBlock(input, inOff, outBytes, outOff);


  // XOR the FcbcV and the output

  for I := 0 to System.Pred(FblockSize) do
  begin
    outBytes[outOff + I] := outBytes[outOff + I] xor FcbcV[I];
  end;


  // swap the back up buffer into next position

  tmp := FcbcV;
  FcbcV := FcbcNextV;
  FcbcNextV := tmp;

  result := &length;
end;

function TCbcBlockCipher.EncryptBlock(const input: TCryptoLibByteArray;
  inOff: Int32; const outBytes: TCryptoLibByteArray; outOff: Int32): Int32;
var
  I, &length: Int32;
begin
  if ((inOff + FblockSize) > System.length(input)) then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SInputBufferTooShort);
  end;

  // XOR the FcbcV and the input, then encrypt the FcbcV

  for I := 0 to System.Pred(FblockSize) do
  begin
    FcbcV[I] := FcbcV[I] xor input[inOff + I];
  end;

  &length := Fcipher.ProcessBlock(FcbcV, 0, outBytes, outOff);


  // copy ciphertext to FcbcV

  System.Move(outBytes[outOff], FcbcV[0], System.length(FcbcV) *
    System.SizeOf(Byte));

  result := &length;
end;

procedure TCbcBlockCipher.Reset;
begin
  System.Move(FIV[0], FcbcV[0], System.length(FIV));
  System.FillChar(FcbcNextV[0], System.length(FcbcNextV) *
    System.SizeOf(Byte), Byte(0));

  Fcipher.Reset();
end;

function TCbcBlockCipher.GetAlgorithmName: String;
begin
  result := Fcipher.AlgorithmName + '/CBC';
end;

function TCbcBlockCipher.GetBlockSize: Int32;
begin
  result := Fcipher.GetBlockSize();
end;

function TCbcBlockCipher.GetIsPartialBlockOkay: Boolean;
begin
  result := false;
end;

function TCbcBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  result := Fcipher;
end;

procedure TCbcBlockCipher.Init(forEncryption: Boolean;
  const parameters: ICipherParameters);
var
  oldEncrypting: Boolean;
  ivParam: IParametersWithIV;
  iv: TCryptoLibByteArray;
  Lparameters: ICipherParameters;
begin
  oldEncrypting := Fencrypting;
  Fencrypting := forEncryption;
  Lparameters := parameters;

  if Supports(Lparameters, IParametersWithIV, ivParam) then
  begin
    iv := ivParam.GetIV();

    if (System.length(iv) <> FblockSize) then
    begin
      raise EArgumentCryptoLibException.CreateRes(@SInvalidIVLength);
    end;

    System.Move(iv[0], FIV[0], System.length(iv) * System.SizeOf(Byte));

    Lparameters := ivParam.parameters;
  end;

  Reset();

  // if Nil it's an IV changed only.
  if (Lparameters <> Nil) then
  begin
    Fcipher.Init(Fencrypting, Lparameters);
  end
  else if (oldEncrypting <> Fencrypting) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidChangeState);
  end;

end;

function TCbcBlockCipher.ProcessBlock(const input: TCryptoLibByteArray;
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
