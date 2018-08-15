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

unit ClpOfbBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIOfbBlockCipher,
  ClpICipherParameters,
  ClpIParametersWithIV,
  ClpCryptoLibTypes;

resourcestring
  SInputBufferTooShort = 'Input Buffer too Short';
  SOutputBufferTooShort = 'Output Buffer too Short';

type

  /// <summary>
  /// implements a Output-FeedBack (OFB) mode on top of a simple cipher.
  /// </summary>
  TOfbBlockCipher = class sealed(TInterfacedObject, IOfbBlockCipher,
    IBlockCipher)

  strict private

  var
    FIV, FofbV, FofbOutV: TCryptoLibByteArray;
    FblockSize: Int32;
    Fcipher: IBlockCipher;
    Fencrypting: Boolean;

    /// <summary>
    /// return the algorithm name and mode.
    /// </summary>
    /// <returns>
    /// return the name of the underlying algorithm followed by "/OFB"
    /// </returns>
    function GetAlgorithmName: String; inline;

    function GetIsPartialBlockOkay: Boolean; inline;

  public

    /// <summary>
    /// Basic constructor.
    /// </summary>
    /// <param name="cipher">
    /// the block cipher to be used as the basis of the feedback mode.
    /// </param>
    /// <param name="blockSize">
    /// the block size in bits (note: a multiple of 8)
    /// </param>
    constructor Create(const cipher: IBlockCipher; blockSize: Int32);

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
    /// ignored by this OFB mode though
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
    /// return the name of the underlying algorithm followed by "/OFB"
    /// </value>
    property AlgorithmName: String read GetAlgorithmName;

    property IsPartialBlockOkay: Boolean read GetIsPartialBlockOkay;

  end;

implementation

{ TOfbBlockCipher }

constructor TOfbBlockCipher.Create(const cipher: IBlockCipher;
  blockSize: Int32);
begin
  inherited Create();
  Fcipher := cipher;
  FblockSize := blockSize div 8;

  System.SetLength(FIV, Fcipher.GetBlockSize);
  System.SetLength(FofbV, Fcipher.GetBlockSize);
  System.SetLength(FofbOutV, Fcipher.GetBlockSize);
end;

procedure TOfbBlockCipher.Reset;
begin
  System.Move(FIV[0], FofbV[0], System.length(FIV));

  Fcipher.Reset();

end;

function TOfbBlockCipher.GetAlgorithmName: String;
begin
  result := Fcipher.AlgorithmName + '/OFB' + IntToStr(FblockSize * 8);
end;

function TOfbBlockCipher.GetBlockSize: Int32;
begin
  result := FblockSize;
end;

function TOfbBlockCipher.GetIsPartialBlockOkay: Boolean;
begin
  result := true;
end;

function TOfbBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  result := Fcipher;
end;

procedure TOfbBlockCipher.Init(forEncryption: Boolean;
  // forEncryption ignored by this OFB mode
  const parameters: ICipherParameters);
var
  ivParam: IParametersWithIV;
  iv: TCryptoLibByteArray;
  Lparameters: ICipherParameters;
  I: Int32;
begin
  Fencrypting := forEncryption;
  Lparameters := parameters;

  if Supports(Lparameters, IParametersWithIV, ivParam) then
  begin
    iv := ivParam.GetIV();

    if (System.length(iv) < System.length(FIV)) then
    begin
      // prepend the supplied IV with zeros (per FIPS PUB 81)
      System.Move(iv[0], FIV[System.length(FIV) - System.length(iv)],
        System.length(iv) * System.SizeOf(Byte));

      for I := 0 to System.Pred(System.length(FIV) - System.length(iv)) do
      begin
        FIV[I] := 0;
      end;

    end
    else
    begin
      System.Move(iv[0], FIV[0], System.length(FIV) * System.SizeOf(Byte));
    end;

    Lparameters := ivParam.parameters;
  end;

  Reset();

  // if it's Nil, key is to be reused.
  if (Lparameters <> Nil) then
  begin
    Fcipher.Init(true, Lparameters);
  end;

end;

function TOfbBlockCipher.ProcessBlock(const input: TCryptoLibByteArray;
  inOff: Int32; const output: TCryptoLibByteArray; outOff: Int32): Int32;
var
  I: Int32;
begin
  if ((inOff + FblockSize) > System.length(input)) then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SInputBufferTooShort);
  end;

  if ((outOff + FblockSize) > System.length(output)) then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooShort);
  end;

  Fcipher.ProcessBlock(FofbV, 0, FofbOutV, 0);

  //
  // XOR the ofbV with the plaintext producing the cipher text (and
  // the next input block).
  //

  for I := 0 to System.Pred(FblockSize) do
  begin
    output[outOff + I] := Byte(FofbOutV[I] xor input[inOff + I]);
  end;

  //
  // change over the input block.
  //
  System.Move(FofbV[FblockSize], FofbV[0], (System.length(FofbV) - FblockSize) *
    System.SizeOf(Byte));

  System.Move(FofbOutV[0], FofbV[(System.length(FofbV) - FblockSize)],
    FblockSize * System.SizeOf(Byte));

  result := FblockSize;
end;

end.
