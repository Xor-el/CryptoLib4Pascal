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

unit ClpSicBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Math,
  ClpIBlockCipher,
  ClpISicBlockCipher,
  ClpICipherParameters,
  ClpIParametersWithIV,
  ClpCryptoLibTypes;

resourcestring
  SInputBufferTooShort = 'Input Buffer too Short';
  SOutputBufferTooShort = 'Output Buffer too Short';
{$IFNDEF _FIXINSIGHT_}
  SInvalidParameterArgument = 'CTR/SIC Mode Requires ParametersWithIV';
  SInvalidTooLargeIVLength =
    'CTR/SIC mode requires IV no greater than: %u bytes';
  SInvalidTooSmallIVLength = 'CTR/SIC mode requires IV of at least: %u bytes';
{$ENDIF}

type

  /// <summary>
  /// Implements the Segmented Integer Counter (SIC) mode on top of a simple block cipher.
  /// </summary>
  TSicBlockCipher = class sealed(TInterfacedObject, ISicBlockCipher,
    IBlockCipher)

  strict private

  var
    FIV, Fcounter, FcounterOut: TCryptoLibByteArray;
    FblockSize: Int32;
    Fcipher: IBlockCipher;

    /// <summary>
    /// return the algorithm name and mode.
    /// </summary>
    /// <returns>
    /// return the name of the underlying algorithm followed by "/SIC"
    /// </returns>
    function GetAlgorithmName: String; inline;

    function GetIsPartialBlockOkay: Boolean; inline;

  public

    /// <summary>
    /// Basic constructor.
    /// </summary>
    /// <param name="cipher">
    /// the block cipher to be used.
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
    /// An IV which is required in this mode.
    /// </summary>
    /// <param name="forEncryption">
    /// forEncryption if true the cipher is initialised for encryption, if
    /// false for decryption.
    /// ignored by this CTR mode though
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
    /// return the name of the underlying algorithm followed by "/SIC"
    /// </value>
    property AlgorithmName: String read GetAlgorithmName;

    property IsPartialBlockOkay: Boolean read GetIsPartialBlockOkay;

  end;

implementation

{ TSicBlockCipher }

constructor TSicBlockCipher.Create(const cipher: IBlockCipher);
begin
  inherited Create();
  Fcipher := cipher;
  FblockSize := Fcipher.GetBlockSize;

  System.SetLength(Fcounter, FblockSize);
  System.SetLength(FcounterOut, FblockSize);
  System.SetLength(FIV, FblockSize);
end;

procedure TSicBlockCipher.Reset;
begin
  System.FillChar(Fcounter[0], System.Length(Fcounter) *
    System.SizeOf(Byte), Byte(0));
  System.Move(FIV[0], Fcounter[0], System.Length(FIV) * System.SizeOf(Byte));

  Fcipher.Reset();

end;

function TSicBlockCipher.GetAlgorithmName: String;
begin
  result := Fcipher.AlgorithmName + '/SIC';
end;

function TSicBlockCipher.GetBlockSize: Int32;
begin
  result := Fcipher.GetBlockSize();
end;

function TSicBlockCipher.GetIsPartialBlockOkay: Boolean;
begin
  result := true;
end;

function TSicBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  result := Fcipher;
end;

{$IFNDEF _FIXINSIGHT_}

procedure TSicBlockCipher.Init(forEncryption: Boolean;
  // forEncryption ignored by this CTR mode
  const parameters: ICipherParameters);
var
  ivParam: IParametersWithIV;
  Lparameters: ICipherParameters;
  maxCounterSize: Int32;
begin
  Lparameters := parameters;

  if Supports(Lparameters, IParametersWithIV, ivParam) then
  begin
    FIV := ivParam.GetIV();

    if (FblockSize < System.Length(FIV)) then
    begin
      raise EArgumentCryptoLibException.CreateResFmt(@SInvalidTooLargeIVLength,
        [FblockSize]);
    end;

    maxCounterSize := Min(8, FblockSize div 2);

    if ((FblockSize - System.Length(FIV)) > maxCounterSize) then
    begin
      raise EArgumentCryptoLibException.CreateResFmt(@SInvalidTooSmallIVLength,
        [FblockSize - maxCounterSize]);
    end;

    Lparameters := ivParam.parameters;
  end
  else
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidParameterArgument);
  end;

  // if it's Nil, key is to be reused.
  if (Lparameters <> Nil) then
  begin
    Fcipher.Init(true, Lparameters);
  end;

  Reset();

end;
{$ENDIF}

function TSicBlockCipher.ProcessBlock(const input: TCryptoLibByteArray;
  inOff: Int32; const output: TCryptoLibByteArray; outOff: Int32): Int32;
var
  I, J: Int32;
begin

  if ((inOff + FblockSize) > System.Length(input)) then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SInputBufferTooShort);
  end;

  if ((outOff + FblockSize) > System.Length(output)) then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooShort);
  end;

  Fcipher.ProcessBlock(Fcounter, 0, FcounterOut, 0);

  //
  // XOR the counterOut with the plaintext producing the cipher text
  //
  for I := 0 to System.Pred(System.Length(FcounterOut)) do
  begin

    output[outOff + I] := Byte(FcounterOut[I] xor input[inOff + I]);
  end;

  // Increment the counter
  J := System.Length(Fcounter);
  System.Dec(J);
  System.Inc(Fcounter[J]);
  while ((J >= 0) and (Fcounter[J] = 0)) do
  begin
    System.Dec(J);
    System.Inc(Fcounter[J]);
  end;

  result := System.Length(Fcounter);
end;

end.
