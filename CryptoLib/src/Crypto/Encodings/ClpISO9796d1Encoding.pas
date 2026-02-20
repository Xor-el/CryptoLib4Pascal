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

    function EncodeBlock(const AInput: TCryptoLibByteArray;
      AInOff, AInLen: Int32): TCryptoLibByteArray;
    function DecodeBlock(const AInput: TCryptoLibByteArray;
      AInOff, AInLen: Int32): TCryptoLibByteArray;

  strict protected
    function GetAlgorithmName: String;
    function GetInputBlockSize: Int32;
    function GetOutputBlockSize: Int32;
    function GetUnderlyingCipher: IAsymmetricBlockCipher;
    function GetPadBits: Int32;
    procedure SetPadBits(APadBits: Int32);

  public
    constructor Create(const ACipher: IAsymmetricBlockCipher);

    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters);
    function ProcessBlock(const AInBuf: TCryptoLibByteArray;
      AInOff, AInLen: Int32): TCryptoLibByteArray;

    property AlgorithmName: String read GetAlgorithmName;
    property InputBlockSize: Int32 read GetInputBlockSize;
    property OutputBlockSize: Int32 read GetOutputBlockSize;
    property UnderlyingCipher: IAsymmetricBlockCipher read GetUnderlyingCipher;
    property PadBits: Int32 read GetPadBits write SetPadBits;

  end;

implementation

{ TISO9796d1Encoding }

constructor TISO9796d1Encoding.Create(const ACipher: IAsymmetricBlockCipher);
begin
  inherited Create();
  FCipher := ACipher;
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

procedure TISO9796d1Encoding.SetPadBits(APadBits: Int32);
begin
  if (APadBits < 0) or (APadBits > 7) then
  begin
    raise EArgumentOutOfRangeCryptoLibException.CreateRes(@SPadBitsOutOfRange);
  end;
  FPadBits := APadBits;
end;

procedure TISO9796d1Encoding.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LKeyParam: IRsaKeyParameters;
  LParameters: ICipherParameters;
begin
  LParameters := AParameters;

  FCipher.Init(AForEncryption, LParameters);

  LParameters := TParameterUtilities.IgnoreRandom(LParameters);

  if not Supports(LParameters, IRsaKeyParameters, LKeyParam) then
    raise EInvalidKeyCryptoLibException.Create('Expected RSA key parameter');
  FModulus := LKeyParam.Modulus;
  FBitSize := FModulus.BitLength;
  FForEncryption := AForEncryption;
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

function TISO9796d1Encoding.ProcessBlock(const AInBuf: TCryptoLibByteArray;
  AInOff, AInLen: Int32): TCryptoLibByteArray;
begin
  if FForEncryption then
    Result := EncodeBlock(AInBuf, AInOff, AInLen)
  else
    Result := DecodeBlock(AInBuf, AInOff, AInLen);
end;

function TISO9796d1Encoding.EncodeBlock(const AInput: TCryptoLibByteArray;
  AInOff, AInLen: Int32): TCryptoLibByteArray;
var
  LBlock: TCryptoLibByteArray;
  LR, LZ, LT, LI, LMaxBit, LOffset: Int32;
  LVal: Byte;
begin
  SetLength(LBlock, (FBitSize + 7) div 8);
  LR := FPadBits + 1;
  LZ := AInLen;
  LT := (FBitSize + 13) div 16;

  LI := 0;
  while LI < LT do
  begin
    if LI > LT - LZ then
    begin
      System.Move(AInput[AInOff + LZ - (LT - LI)],
        LBlock[System.Length(LBlock) - LT], LT - LI);
    end
    else
    begin
      System.Move(AInput[AInOff],
        LBlock[System.Length(LBlock) - (LI + LZ)], LZ);
    end;
    Inc(LI, LZ);
  end;

  LI := System.Length(LBlock) - 2 * LT;
  while LI < System.Length(LBlock) do
  begin
    LVal := LBlock[System.Length(LBlock) - LT + LI div 2];
    LBlock[LI] := Byte((Shadows[LVal shr 4] shl 4) or Shadows[LVal and $0F]);
    LBlock[LI + 1] := LVal;
    Inc(LI, 2);
  end;

  LBlock[System.Length(LBlock) - 2 * LZ] :=
    LBlock[System.Length(LBlock) - 2 * LZ] xor Byte(LR);
  LBlock[System.Length(LBlock) - 1] :=
    Byte((LBlock[System.Length(LBlock) - 1] shl 4) or $06);

  LMaxBit := 8 - ((FBitSize - 1) mod 8);
  LOffset := 0;

  if LMaxBit <> 8 then
  begin
    LBlock[0] := LBlock[0] and Byte($FF shr LMaxBit);
    LBlock[0] := LBlock[0] or Byte($80 shr LMaxBit);
  end
  else
  begin
    LBlock[0] := $00;
    LBlock[1] := LBlock[1] or $80;
    LOffset := 1;
  end;

  Result := FCipher.ProcessBlock(LBlock, LOffset, System.Length(LBlock) - LOffset);
end;

function TISO9796d1Encoding.DecodeBlock(const AInput: TCryptoLibByteArray;
  AInOff, AInLen: Int32): TCryptoLibByteArray;
var
  LBlock, LNBlock: TCryptoLibByteArray;
  LR, LT, LI, LVal, LX, LBoundary: Int32;
  LIS, LIR: TBigInteger;
  LBoundaryFound: Boolean;
begin
  LBlock := FCipher.ProcessBlock(AInput, AInOff, AInLen);
  LR := 1;
  LT := (FBitSize + 13) div 16;

  LIS := TBigInteger.Create(1, LBlock);

  if (LIS.Int32Value and 15) = 6 then
  begin
    LIR := LIS;
  end
  else
  begin
    LIR := FModulus.Subtract(LIS);
    if (LIR.Int32Value and 15) <> 6 then
    begin
      raise EInvalidCipherTextCryptoLibException.CreateRes(@SInvalidCongruence);
    end;
  end;

  LBlock := LIR.ToByteArrayUnsigned();

  if (LBlock[System.Length(LBlock) - 1] and $F) <> $6 then
  begin
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SInvalidForcingByte);
  end;

  LBlock[System.Length(LBlock) - 1] := Byte(
    (LBlock[System.Length(LBlock) - 1] shr 4) or
    (Inverse[LBlock[System.Length(LBlock) - 2] shr 4] shl 4));

  LBlock[0] := Byte(
    (Shadows[LBlock[1] shr 4] shl 4) or
    Shadows[LBlock[1] and $0F]);

  LBoundaryFound := False;
  LBoundary := 0;

  LI := System.Length(LBlock) - 1;
  while LI >= System.Length(LBlock) - 2 * LT do
  begin
    LVal := (Shadows[LBlock[LI] shr 4] shl 4) or Shadows[LBlock[LI] and $0F];
    LX := LVal xor LBlock[LI - 1];

    if LX <> 0 then
    begin
      if LBoundaryFound then
      begin
        raise EInvalidCipherTextCryptoLibException.CreateRes(@SInvalidTsums);
      end;
      LBoundaryFound := True;
      LR := LX;
      LBoundary := LI - 1;
    end;

    Dec(LI, 2);
  end;

  LBlock[LBoundary] := 0;

  SetLength(LNBlock, (System.Length(LBlock) - LBoundary) div 2);
  for LI := 0 to System.Length(LNBlock) - 1 do
  begin
    LNBlock[LI] := LBlock[2 * LI + LBoundary + 1];
  end;

  FPadBits := LR - 1;
  Result := LNBlock;
end;

end.
