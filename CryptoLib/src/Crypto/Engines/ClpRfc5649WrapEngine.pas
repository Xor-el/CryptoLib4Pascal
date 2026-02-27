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

unit ClpRfc5649WrapEngine;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIRfc5649WrapEngine,
  ClpIWrapper,
  ClpIBlockCipher,
  ClpICipherParameters,
  ClpIKeyParameter,
  ClpIParametersWithIV,
  ClpIParametersWithRandom,
  ClpIRfc3394WrapEngine,
  ClpRfc3394WrapEngine,
  ClpParametersWithIV,
  ClpArrayUtilities,
  ClpPack,
  ClpCryptoLibTypes;

resourcestring
  SNotSetForWrapping5649 = 'Not set for wrapping';
  SNotSetForUnwrapping5649 = 'Not set for unwrapping';
  SUnwrapDataMustBeMultipleOf8_5649 = 'Unwrap data must be a multiple of 8 bytes';
  SUnwrapDataMustBeAtLeast16_5649 = 'Unwrap data must be at least 16 bytes';
  SIVLengthNotEqualTo4 = 'IV length not equal to 4';
  SChecksumFailed5649 = 'Checksum failed';

type
  TRfc5649WrapEngine = class(TInterfacedObject, IRfc5649WrapEngine, IWrapper)

  strict private
  class var
    FDefaultIV: TCryptoLibByteArray;

  var
    FEngine: IBlockCipher;
    FPreIV: TCryptoLibByteArray;
    FKey: IKeyParameter;
    FForWrapping: Boolean;

    function Rfc3394UnwrapNoIvCheck(const AInput: TCryptoLibByteArray;
      AInOff, AInLen: Int32; const AExtractedAIV: TCryptoLibByteArray): TCryptoLibByteArray;

    class function PadPlaintext(const APlaintext: TCryptoLibByteArray): TCryptoLibByteArray; static;

    class constructor Create;

  strict protected
    function GetAlgorithmName: String; virtual;

  public
    constructor Create(const AEngine: IBlockCipher);

    procedure Init(AForWrapping: Boolean; const AParameters: ICipherParameters); virtual;

    function Wrap(const AInput: TCryptoLibByteArray; AInOff, ALength: Int32): TCryptoLibByteArray; virtual;

    function Unwrap(const AInput: TCryptoLibByteArray; AInOff, ALength: Int32): TCryptoLibByteArray; virtual;

    property AlgorithmName: String read GetAlgorithmName;

  end;

implementation

{ TRfc5649WrapEngine }

class constructor TRfc5649WrapEngine.Create;
begin
  FDefaultIV := TCryptoLibByteArray.Create($A6, $59, $59, $A6);
end;

constructor TRfc5649WrapEngine.Create(const AEngine: IBlockCipher);
begin
  inherited Create;
  FEngine := AEngine;
  System.SetLength(FPreIV, 4);
end;

function TRfc5649WrapEngine.GetAlgorithmName: String;
begin
  Result := FEngine.AlgorithmName;
end;

procedure TRfc5649WrapEngine.Init(AForWrapping: Boolean;
  const AParameters: ICipherParameters);
var
  LParameters: ICipherParameters;
  LWithRandom: IParametersWithRandom;
  LKeyParameter: IKeyParameter;
  LWithIV: IParametersWithIV;
  LIv: TCryptoLibByteArray;
begin
  FForWrapping := AForWrapping;

  LParameters := AParameters;

  if Supports(LParameters, IParametersWithRandom, LWithRandom) then
    LParameters := LWithRandom.Parameters;

  if Supports(LParameters, IKeyParameter, LKeyParameter) then
  begin
    FKey := LKeyParameter;
    System.Move(FDefaultIV[0], FPreIV[0], 4 * System.SizeOf(Byte));
  end
  else if Supports(LParameters, IParametersWithIV, LWithIV) then
  begin
    LIv := LWithIV.GetIV();
    if System.Length(LIv) <> 4 then
      raise EArgumentCryptoLibException.CreateRes(@SIVLengthNotEqualTo4);

    Supports(LWithIV.Parameters, IKeyParameter, FKey);
    System.Move(LIv[0], FPreIV[0], 4 * System.SizeOf(Byte));
  end;
end;

function TRfc5649WrapEngine.Wrap(const AInput: TCryptoLibByteArray;
  AInOff, ALength: Int32): TCryptoLibByteArray;
var
  LIv, LRelevantPlaintext, LPaddedPlaintext, LPaddedPlainTextWithIV: TCryptoLibByteArray;
  LI, LBlockSize: Int32;
  LWrapper: IRfc3394WrapEngine;
  LParamsWithIV: IParametersWithIV;
begin
  if not FForWrapping then
    raise EInvalidOperationCryptoLibException.CreateRes(@SNotSetForWrapping5649);

  System.SetLength(LIv, 8);
  System.Move(FPreIV[0], LIv[0], 4 * System.SizeOf(Byte));
  TPack.UInt32_To_BE(UInt32(ALength), LIv, 4);

  System.SetLength(LRelevantPlaintext, ALength);
  System.Move(AInput[AInOff], LRelevantPlaintext[0], ALength * System.SizeOf(Byte));
  LPaddedPlaintext := PadPlaintext(LRelevantPlaintext);

  if System.Length(LPaddedPlaintext) = 8 then
  begin
    System.SetLength(LPaddedPlainTextWithIV, System.Length(LPaddedPlaintext) + System.Length(LIv));
    System.Move(LIv[0], LPaddedPlainTextWithIV[0], System.Length(LIv) * System.SizeOf(Byte));
    System.Move(LPaddedPlaintext[0], LPaddedPlainTextWithIV[System.Length(LIv)],
      System.Length(LPaddedPlaintext) * System.SizeOf(Byte));

    FEngine.Init(True, FKey);
    LBlockSize := FEngine.GetBlockSize();
    LI := 0;
    while LI < System.Length(LPaddedPlainTextWithIV) do
    begin
      FEngine.ProcessBlock(LPaddedPlainTextWithIV, LI, LPaddedPlainTextWithIV, LI);
      Inc(LI, LBlockSize);
    end;

    Result := LPaddedPlainTextWithIV;
  end
  else
  begin
    LWrapper := TRfc3394WrapEngine.Create(FEngine);
    LParamsWithIV := TParametersWithIV.Create(FKey, LIv);
    LWrapper.Init(True, LParamsWithIV);
    Result := LWrapper.Wrap(LPaddedPlaintext, 0, System.Length(LPaddedPlaintext));
  end;
end;

function TRfc5649WrapEngine.Unwrap(const AInput: TCryptoLibByteArray;
  AInOff, ALength: Int32): TCryptoLibByteArray;
var
  LN, LI, LBlockSize, LMli, LUpperBound, LLowerBound, LExpectedZeros: Int32;
  LIsValid: Boolean;
  LRelevantCiphertext, LDecrypted, LPaddedPlaintext, LExtractedAIV,
    LExtractedHighOrderAIV, LZeros, LPad, LPlaintext: TCryptoLibByteArray;
begin
  if FForWrapping then
    raise EInvalidOperationCryptoLibException.CreateRes(@SNotSetForUnwrapping5649);

  LN := ALength div 8;

  if (LN * 8) <> ALength then
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SUnwrapDataMustBeMultipleOf8_5649);

  if LN <= 1 then
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SUnwrapDataMustBeAtLeast16_5649);

  System.SetLength(LRelevantCiphertext, ALength);
  System.Move(AInput[AInOff], LRelevantCiphertext[0], ALength * System.SizeOf(Byte));
  System.SetLength(LDecrypted, ALength);

  System.SetLength(LExtractedAIV, 8);

  if LN = 2 then
  begin
    FEngine.Init(False, FKey);
    LBlockSize := FEngine.GetBlockSize();
    LI := 0;
    while LI < System.Length(LRelevantCiphertext) do
    begin
      FEngine.ProcessBlock(LRelevantCiphertext, LI, LDecrypted, LI);
      Inc(LI, LBlockSize);
    end;

    System.Move(LDecrypted[0], LExtractedAIV[0], 8 * System.SizeOf(Byte));
    System.SetLength(LPaddedPlaintext, System.Length(LDecrypted) - 8);
    System.Move(LDecrypted[8], LPaddedPlaintext[0],
      System.Length(LPaddedPlaintext) * System.SizeOf(Byte));
  end
  else
  begin
    LDecrypted := Rfc3394UnwrapNoIvCheck(AInput, AInOff, ALength, LExtractedAIV);
    LPaddedPlaintext := LDecrypted;
  end;

  System.SetLength(LExtractedHighOrderAIV, 4);
  System.Move(LExtractedAIV[0], LExtractedHighOrderAIV[0], 4 * System.SizeOf(Byte));
  LMli := Int32(TPack.BE_To_UInt32(LExtractedAIV, 4));

  LIsValid := TArrayUtilities.FixedTimeEquals(LExtractedHighOrderAIV, FPreIV);

  LUpperBound := System.Length(LPaddedPlaintext);
  LLowerBound := LUpperBound - 8;
  if LMli <= LLowerBound then
    LIsValid := False;
  if LMli > LUpperBound then
    LIsValid := False;

  LExpectedZeros := LUpperBound - LMli;
  if (LExpectedZeros >= 8) or (LExpectedZeros < 0) then
  begin
    LIsValid := False;
    LExpectedZeros := 4;
  end;

  System.SetLength(LZeros, LExpectedZeros);
  System.SetLength(LPad, LExpectedZeros);
  System.Move(LPaddedPlaintext[System.Length(LPaddedPlaintext) - LExpectedZeros],
    LPad[0], LExpectedZeros * System.SizeOf(Byte));
  if not TArrayUtilities.FixedTimeEquals(LPad, LZeros) then
    LIsValid := False;

  if not LIsValid then
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SChecksumFailed5649);

  System.SetLength(LPlaintext, LMli);
  System.Move(LPaddedPlaintext[0], LPlaintext[0], System.Length(LPlaintext) * System.SizeOf(Byte));

  Result := LPlaintext;
end;

function TRfc5649WrapEngine.Rfc3394UnwrapNoIvCheck(
  const AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
  const AExtractedAIV: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LBlock, LBuf: TCryptoLibByteArray;
  LN, LI, LJ, LK: Int32;
  LT: UInt32;
begin
  System.SetLength(LBlock, AInLen - 8);
  System.SetLength(LBuf, 16);

  System.Move(AInput[AInOff], LBuf[0], 8 * System.SizeOf(Byte));
  System.Move(AInput[AInOff + 8], LBlock[0], (AInLen - 8) * System.SizeOf(Byte));

  FEngine.Init(False, FKey);

  LN := AInLen div 8;
  LN := LN - 1;

  for LJ := 5 downto 0 do
  begin
    for LI := LN downto 1 do
    begin
      System.Move(LBlock[8 * (LI - 1)], LBuf[8], 8 * System.SizeOf(Byte));

      LT := UInt32(LN * LJ + LI);
      LK := 1;
      while LT <> 0 do
      begin
        LBuf[8 - LK] := LBuf[8 - LK] xor Byte(LT);
        LT := LT shr 8;
        Inc(LK);
      end;

      FEngine.ProcessBlock(LBuf, 0, LBuf, 0);

      System.Move(LBuf[8], LBlock[8 * (LI - 1)], 8 * System.SizeOf(Byte));
    end;
  end;

  System.Move(LBuf[0], AExtractedAIV[0], 8 * System.SizeOf(Byte));

  Result := LBlock;
end;

class function TRfc5649WrapEngine.PadPlaintext(
  const APlaintext: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LPlaintextLength, LNumOfZerosToAppend: Int32;
  LPaddedPlaintext, LZeros: TCryptoLibByteArray;
begin
  LPlaintextLength := System.Length(APlaintext);
  LNumOfZerosToAppend := (8 - (LPlaintextLength mod 8)) mod 8;
  System.SetLength(LPaddedPlaintext, LPlaintextLength + LNumOfZerosToAppend);
  System.Move(APlaintext[0], LPaddedPlaintext[0], LPlaintextLength * System.SizeOf(Byte));
  if LNumOfZerosToAppend <> 0 then
  begin
    System.SetLength(LZeros, LNumOfZerosToAppend);
    System.Move(LZeros[0], LPaddedPlaintext[LPlaintextLength],
      LNumOfZerosToAppend * System.SizeOf(Byte));
  end;
  Result := LPaddedPlaintext;
end;

end.
