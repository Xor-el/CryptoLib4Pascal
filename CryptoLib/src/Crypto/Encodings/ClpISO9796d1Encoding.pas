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

unit ClpISO9796d1Encoding;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpICipherParameters,
  ClpParameterUtilities,
  ClpIRsaParameters,
  ClpIAsymmetricBlockCipher,
  ClpIISO9796d1Encoding,
  ClpCryptoLibTypes;

resourcestring
  SPadBitsOutOfRange = 'padBits out of range (0-7)';
  SInvalidForcingByte = 'Invalid forcing byte in block';
  SInvalidCongruence = 'Resulting integer is not congruent to 6 mod 16';
  SInvalidTsums = 'Invalid tsums in block';

type
  /// <summary>
  /// ISO 9796-1 padding.
  /// you should only use this with RSA and never use it with anything other than a hash.
  /// </summary>
  TISO9796d1Encoding = class(TInterfacedObject, IAsymmetricBlockCipher, IISO9796d1Encoding)

  strict private
  const
    Shadows: array[0..15] of Byte = (14, 3, 5, 8, 9, 4, 2, 15, 0, 13, 11, 6, 7, 10, 12, 1);
    Inverse: array[0..15] of Byte = (8, 15, 6, 1, 5, 2, 11, 12, 3, 4, 13, 10, 14, 9, 0, 7);

  var
    FCipher: IAsymmetricBlockCipher;
    FForEncryption: Boolean;
    FBitSize: Int32;
    FPadBits: Int32;
    FModulus: TBigInteger;

    function EncodeBlock(const input: TCryptoLibByteArray;
      inOff, inLen: Int32): TCryptoLibByteArray;
    function DecodeBlock(const input: TCryptoLibByteArray;
      inOff, inLen: Int32): TCryptoLibByteArray;

  strict protected
    function GetAlgorithmName: String;
    function GetInputBlockSize: Int32;
    function GetOutputBlockSize: Int32;
    function GetUnderlyingCipher: IAsymmetricBlockCipher;
    function GetPadBits: Int32;
    procedure SetPadBits(padBits: Int32);

  public
    constructor Create(const cipher: IAsymmetricBlockCipher);

    procedure Init(forEncryption: Boolean; const parameters: ICipherParameters);
    function ProcessBlock(const inBuf: TCryptoLibByteArray;
      inOff, inLen: Int32): TCryptoLibByteArray;

    property AlgorithmName: String read GetAlgorithmName;
    property InputBlockSize: Int32 read GetInputBlockSize;
    property OutputBlockSize: Int32 read GetOutputBlockSize;
    property UnderlyingCipher: IAsymmetricBlockCipher read GetUnderlyingCipher;
    property PadBits: Int32 read GetPadBits write SetPadBits;

  end;

implementation

{ TISO9796d1Encoding }

constructor TISO9796d1Encoding.Create(const cipher: IAsymmetricBlockCipher);
begin
  inherited Create();
  FCipher := cipher;
  FPadBits := 0;
end;

function TISO9796d1Encoding.GetAlgorithmName: String;
begin
  Result := FCipher.AlgorithmName + '/ISO9796-1Padding';
end;

function TISO9796d1Encoding.GetUnderlyingCipher: IAsymmetricBlockCipher;
begin
  Result := FCipher;
end;

function TISO9796d1Encoding.GetPadBits: Int32;
begin
  Result := FPadBits;
end;

procedure TISO9796d1Encoding.SetPadBits(padBits: Int32);
begin
  if (padBits < 0) or (padBits > 7) then
  begin
    raise EArgumentOutOfRangeCryptoLibException.CreateRes(@SPadBitsOutOfRange);
  end;
  FPadBits := padBits;
end;

procedure TISO9796d1Encoding.Init(forEncryption: Boolean;
  const parameters: ICipherParameters);
var
  kParam: IRsaKeyParameters;
  LParameters: ICipherParameters;
begin
  LParameters := parameters;

  FCipher.Init(forEncryption, LParameters);

  LParameters := TParameterUtilities.IgnoreRandom(LParameters);

  kParam := LParameters as IRsaKeyParameters;
  FModulus := kParam.Modulus;
  FBitSize := FModulus.BitLength;
  FForEncryption := forEncryption;
end;

function TISO9796d1Encoding.GetInputBlockSize: Int32;
begin
  if FForEncryption then
    Result := (FCipher.InputBlockSize + 1) div 2
  else
    Result := FCipher.InputBlockSize;
end;

function TISO9796d1Encoding.GetOutputBlockSize: Int32;
begin
  if FForEncryption then
    Result := FCipher.OutputBlockSize
  else
    Result := (FCipher.OutputBlockSize + 1) div 2;
end;

function TISO9796d1Encoding.ProcessBlock(const inBuf: TCryptoLibByteArray;
  inOff, inLen: Int32): TCryptoLibByteArray;
begin
  if FForEncryption then
    Result := EncodeBlock(inBuf, inOff, inLen)
  else
    Result := DecodeBlock(inBuf, inOff, inLen);
end;

function TISO9796d1Encoding.EncodeBlock(const input: TCryptoLibByteArray;
  inOff, inLen: Int32): TCryptoLibByteArray;
var
  block: TCryptoLibByteArray;
  r, z, t, i, maxBit, offset: Int32;
  val: Byte;
begin
  SetLength(block, (FBitSize + 7) div 8);
  r := FPadBits + 1;
  z := inLen;
  t := (FBitSize + 13) div 16;

  i := 0;
  while i < t do
  begin
    if i > t - z then
    begin
      Move(input[inOff + z - (t - i)],
        block[Length(block) - t], t - i);
    end
    else
    begin
      Move(input[inOff],
        block[Length(block) - (i + z)], z);
    end;
    Inc(i, z);
  end;

  i := Length(block) - 2 * t;
  while i < Length(block) do
  begin
    val := block[Length(block) - t + i div 2];
    block[i] := Byte((Shadows[val shr 4] shl 4) or Shadows[val and $0F]);
    block[i + 1] := val;
    Inc(i, 2);
  end;

  block[Length(block) - 2 * z] :=
    block[Length(block) - 2 * z] xor Byte(r);
  block[Length(block) - 1] :=
    Byte((block[Length(block) - 1] shl 4) or $06);

  maxBit := 8 - ((FBitSize - 1) mod 8);
  offset := 0;

  if maxBit <> 8 then
  begin
    block[0] := block[0] and Byte($FF shr maxBit);
    block[0] := block[0] or Byte($80 shr maxBit);
  end
  else
  begin
    block[0] := $00;
    block[1] := block[1] or $80;
    offset := 1;
  end;

  Result := FCipher.ProcessBlock(block, offset, Length(block) - offset);
end;

function TISO9796d1Encoding.DecodeBlock(const input: TCryptoLibByteArray;
  inOff, inLen: Int32): TCryptoLibByteArray;
var
  block, nblock: TCryptoLibByteArray;
  r, t, i, val, x, boundary: Int32;
  &iS, iR: TBigInteger;
  boundaryFound: Boolean;
begin
  block := FCipher.ProcessBlock(input, inOff, inLen);
  r := 1;
  t := (FBitSize + 13) div 16;

  &iS := TBigInteger.Create(1, block);

  if (&iS.Int32Value and 15) = 6 then
  begin
    iR := &iS;
  end
  else
  begin
    iR := FModulus.Subtract(&iS);
    if (iR.Int32Value and 15) <> 6 then
    begin
      raise EInvalidCipherTextCryptoLibException.CreateRes(@SInvalidCongruence);
    end;
  end;

  block := iR.ToByteArrayUnsigned();

  if (block[Length(block) - 1] and $F) <> $6 then
  begin
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SInvalidForcingByte);
  end;

  block[Length(block) - 1] := Byte(
    (block[Length(block) - 1] shr 4) or
    (Inverse[block[Length(block) - 2] shr 4] shl 4));

  block[0] := Byte(
    (Shadows[block[1] shr 4] shl 4) or
    Shadows[block[1] and $0F]);

  boundaryFound := False;
  boundary := 0;

  i := Length(block) - 1;
  while i >= Length(block) - 2 * t do
  begin
    val := (Shadows[block[i] shr 4] shl 4) or Shadows[block[i] and $0F];
    x := val xor block[i - 1];

    if x <> 0 then
    begin
      if boundaryFound then
      begin
        raise EInvalidCipherTextCryptoLibException.CreateRes(@SInvalidTsums);
      end;
      boundaryFound := True;
      r := x;
      boundary := i - 1;
    end;

    Dec(i, 2);
  end;

  block[boundary] := 0;

  SetLength(nblock, (Length(block) - boundary) div 2);
  for i := 0 to Length(nblock) - 1 do
  begin
    nblock[i] := block[2 * i + boundary + 1];
  end;

  FPadBits := r - 1;
  Result := nblock;
end;

end.
