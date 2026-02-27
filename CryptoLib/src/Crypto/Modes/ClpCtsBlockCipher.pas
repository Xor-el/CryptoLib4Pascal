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

unit ClpCtsBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIBlockCipherMode,
  ClpICtsBlockCipher,
  ClpICbcBlockCipher,
  ClpIEcbBlockCipher,
  ClpEcbBlockCipher,
  ClpBufferedBlockCipher,
  ClpCryptoLibTypes;

resourcestring
  SUnsupportedCipher = 'CtsBlockCipher can only accept ECB, or CBC ciphers';
  SNegativeInputLength = 'Can''t Have a Negative Input Length!';
  SCTSDoFinalError = 'Need at Least One Block of Input For CTS';
  SOutputBufferTooShort = 'Output Buffer too Short';
  SOutputBufferTooSmallForDoFinal = 'Output Buffer too Short for DoFinal()';

type
  TCtsBlockCipher = class sealed(TBufferedBlockCipher, ICtsBlockCipher)

  strict private
  var
    FBlockSize: Int32;

  public
    constructor Create(const ACipher: IBlockCipher); overload;
    constructor Create(const ACipherMode: IBlockCipherMode); overload;
    function GetOutputSize(AInputLen: Int32): Int32; override;
    function GetUpdateOutputSize(AInputLen: Int32): Int32; override;
    function ProcessByte(AInput: Byte; const AOutput: TCryptoLibByteArray;
      AOutOff: Int32): Int32; override;
    function ProcessBytes(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; override;
    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
      override;
  end;

implementation

{ TCtsBlockCipher }

constructor TCtsBlockCipher.Create(const ACipher: IBlockCipher);
begin
  Create(TEcbBlockCipher.GetBlockCipherMode(ACipher));
end;

constructor TCtsBlockCipher.Create(const ACipherMode: IBlockCipherMode);
begin
  Inherited Create();
  if not (Supports(ACipherMode, ICbcBlockCipher) or
    Supports(ACipherMode, IEcbBlockCipher)) then
    raise EArgumentCryptoLibException.CreateRes(@SUnsupportedCipher);

  FCipherMode := ACipherMode;

  FBlockSize := ACipherMode.GetBlockSize();

  System.SetLength(FBuf, FBlockSize * 2);
  FBufOff := 0;
end;

function TCtsBlockCipher.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LBlockSize, LLen, LI: Int32;
  LBlock, LLastBlock: TCryptoLibByteArray;
begin
  if ((FBufOff + AOutOff) > System.Length(AOutput)) then
    raise EDataLengthCryptoLibException.CreateRes
      (@SOutputBufferTooSmallForDoFinal);

  LBlockSize := FCipherMode.GetBlockSize();
  LLen := FBufOff - LBlockSize;
  System.SetLength(LBlock, LBlockSize);

  if (FForEncryption) then
  begin
    if (FBufOff < LBlockSize) then
      raise EDataLengthCryptoLibException.CreateRes(@SCTSDoFinalError);

    FCipherMode.ProcessBlock(FBuf, 0, LBlock, 0);

    if (FBufOff > LBlockSize) then
    begin
      LI := FBufOff;
      while LI <> System.Length(FBuf) do
      begin
        FBuf[LI] := LBlock[LI - LBlockSize];
        System.Inc(LI);
      end;

      LI := LBlockSize;
      while LI <> FBufOff do
      begin
        FBuf[LI] := FBuf[LI] xor (LBlock[LI - LBlockSize]);
        System.Inc(LI);
      end;

      FCipherMode.UnderlyingCipher.ProcessBlock(FBuf, LBlockSize, AOutput, AOutOff);

      System.Move(LBlock[0], AOutput[AOutOff + LBlockSize],
        LLen * System.SizeOf(Byte));
    end
    else
      System.Move(LBlock[0], AOutput[AOutOff], LBlockSize * System.SizeOf(Byte));
  end
  else
  begin
    if (FBufOff < LBlockSize) then
      raise EDataLengthCryptoLibException.CreateRes(@SCTSDoFinalError);

    System.SetLength(LLastBlock, LBlockSize);

    if (FBufOff > LBlockSize) then
    begin
      FCipherMode.UnderlyingCipher.ProcessBlock(FBuf, 0, LBlock, 0);

      LI := LBlockSize;
      while LI <> FBufOff do
      begin
        LLastBlock[LI - LBlockSize] := Byte(LBlock[LI - LBlockSize] xor FBuf[LI]);
        System.Inc(LI);
      end;

      System.Move(FBuf[LBlockSize], LBlock[0], LLen * System.SizeOf(Byte));
      FCipherMode.ProcessBlock(LBlock, 0, AOutput, AOutOff);
      System.Move(LLastBlock[0], AOutput[AOutOff + LBlockSize],
        LLen * System.SizeOf(Byte));
    end
    else
    begin
      FCipherMode.ProcessBlock(FBuf, 0, LBlock, 0);
      System.Move(LBlock[0], AOutput[AOutOff], LBlockSize * System.SizeOf(Byte));
    end;
  end;

  Result := FBufOff;
  Reset();
end;

function TCtsBlockCipher.GetOutputSize(AInputLen: Int32): Int32;
begin
  Result := AInputLen + FBufOff;
end;

function TCtsBlockCipher.GetUpdateOutputSize(AInputLen: Int32): Int32;
var
  LTotal, LLeftOver: Int32;
begin
  LTotal := AInputLen + FBufOff;
  LLeftOver := LTotal mod System.Length(FBuf);

  if (LLeftOver = 0) then
  begin
    Result := LTotal - System.Length(FBuf);
    Exit;
  end;
  Result := LTotal - LLeftOver;
end;

function TCtsBlockCipher.ProcessByte(AInput: Byte;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  Result := 0;

  if (FBufOff = System.Length(FBuf)) then
  begin
    Result := FCipherMode.ProcessBlock(FBuf, 0, AOutput, AOutOff);
    System.Move(FBuf[FBlockSize], FBuf[0], FBlockSize * System.SizeOf(Byte));
    FBufOff := FBlockSize;
  end;

  FBuf[FBufOff] := AInput;
  System.Inc(FBufOff);
end;

function TCtsBlockCipher.ProcessBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LBlockSize, LLength, LGapLen: Int32;
begin
  if (ALen < 0) then
    raise EArgumentCryptoLibException.CreateRes(@SNegativeInputLength);

  LBlockSize := GetBlockSize();
  LLength := GetUpdateOutputSize(ALen);

  if (LLength > 0) then
  begin
    if ((AOutOff + LLength) > System.Length(AOutput)) then
      raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooShort);
  end;

  Result := 0;
  LGapLen := System.Length(FBuf) - FBufOff;

  if (ALen > LGapLen) then
  begin
    System.Move(AInput[AInOff], FBuf[FBufOff], LGapLen * System.SizeOf(Byte));

    Result := Result + FCipherMode.ProcessBlock(FBuf, 0, AOutput, AOutOff);
    System.Move(FBuf[LBlockSize], FBuf[0], LBlockSize * System.SizeOf(Byte));

    FBufOff := LBlockSize;

    ALen := ALen - LGapLen;
    AInOff := AInOff + LGapLen;

    while (ALen > LBlockSize) do
    begin
      System.Move(AInput[AInOff], FBuf[FBufOff], LBlockSize * System.SizeOf(Byte));
      Result := Result + FCipherMode.ProcessBlock(FBuf, 0, AOutput, AOutOff + Result);
      System.Move(FBuf[LBlockSize], FBuf[0], LBlockSize * System.SizeOf(Byte));

      ALen := ALen - LBlockSize;
      AInOff := AInOff + LBlockSize;
    end;
  end;

  System.Move(AInput[AInOff], FBuf[FBufOff], ALen * System.SizeOf(Byte));

  FBufOff := FBufOff + ALen;
end;

end.
