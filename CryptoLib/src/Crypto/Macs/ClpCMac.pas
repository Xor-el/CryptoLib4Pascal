{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpCMac;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCbcBlockCipher,
  ClpICMac,
  ClpIMac,
  ClpMac,
  ClpIBlockCipher,
  ClpIBlockCipherMode,
  ClpICipherParameters,
  ClpIKeyParameter,
  ClpISO7816d4Padding,
  ClpIISO7816d4Padding,
  ClpArrayUtilities,
  ClpBitOperations,
  ClpCryptoLibTypes;

resourcestring
  SMacSizeMultipleOf8 = 'MAC size must be multiple of 8';
  SMacSizeTooLarge = 'MAC size must be less or equal to %d';
  SBlockSizeInvalid = 'Block size must be either 64 or 128 bits';
  SNegativeInputLength = 'Can''t have a negative input length!';
  SCMacKeyOnly = 'CMac mode only permits key to be set.';

type
  TCMac = class sealed(TMac, ICMac, IMac)

  strict private
  const
    CONSTANT_128 = Byte($87);
    CONSTANT_64 = Byte($1B);

  var
    FZeroes: TCryptoLibByteArray;
    FMac: TCryptoLibByteArray;
    FBuf: TCryptoLibByteArray;
    FBufOff: Int32;
    FCipherMode: IBlockCipherMode;
    FMacSize: Int32;
    FL, FLu, FLu2: TCryptoLibByteArray;

    class function ShiftLeft(const ABlock: TCryptoLibByteArray;
      const AOutput: TCryptoLibByteArray): Int32; static;
    class function DoubleLu(const AInput: TCryptoLibByteArray)
      : TCryptoLibByteArray; static;

  strict protected
    function GetAlgorithmName: String; override;

  public
    constructor Create(const ACipher: IBlockCipher); overload;
    constructor Create(const ACipher: IBlockCipher;
      AMacSizeInBits: Int32); overload;

    function GetMacSize: Int32; override;
    procedure Update(AInput: Byte); override;
    procedure BlockUpdate(const AInput: TCryptoLibByteArray;
      AInOff, ALen: Int32); override;
    procedure Init(const AParameters: ICipherParameters); override;
    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32)
      : Int32; overload; override;
    procedure Reset(); override;

    property AlgorithmName: String read GetAlgorithmName;
  end;

implementation

{ TCMac }

constructor TCMac.Create(const ACipher: IBlockCipher);
begin
  Create(ACipher, ACipher.GetBlockSize() * 8);
end;

constructor TCMac.Create(const ACipher: IBlockCipher; AMacSizeInBits: Int32);
var
  LBlockSize: Int32;
begin
  inherited Create();

  if (AMacSizeInBits mod 8) <> 0 then
    raise EArgumentCryptoLibException.CreateRes(@SMacSizeMultipleOf8);

  LBlockSize := ACipher.GetBlockSize();

  if AMacSizeInBits > (LBlockSize * 8) then
    raise EArgumentCryptoLibException.CreateResFmt(@SMacSizeTooLarge,
      [LBlockSize * 8]);

  if (LBlockSize <> 8) and (LBlockSize <> 16) then
    raise EArgumentCryptoLibException.CreateRes(@SBlockSizeInvalid);

  FCipherMode := TCbcBlockCipher.Create(ACipher) as IBlockCipherMode;
  FMacSize := AMacSizeInBits div 8;

  System.SetLength(FMac, LBlockSize);
  System.SetLength(FBuf, LBlockSize);
  System.SetLength(FZeroes, LBlockSize);
  FBufOff := 0;
end;

function TCMac.GetAlgorithmName: String;
begin
  Result := FCipherMode.AlgorithmName;
end;

class function TCMac.ShiftLeft(const ABlock: TCryptoLibByteArray;
  const AOutput: TCryptoLibByteArray): Int32;
var
  LI: Int32;
  LBit, LB: UInt32;
begin
  LI := System.Length(ABlock);
  LBit := 0;
  while LI > 0 do
  begin
    System.Dec(LI);
    LB := ABlock[LI];
    AOutput[LI] := Byte((LB shl 1) or LBit);
    LBit := (LB shr 7) and 1;
  end;
  Result := Int32(LBit);
end;

class function TCMac.DoubleLu(const AInput: TCryptoLibByteArray)
  : TCryptoLibByteArray;
var
  LCarry, LXorVal: Int32;
begin
  System.SetLength(Result, System.Length(AInput));
  LCarry := ShiftLeft(AInput, Result);
  if System.Length(AInput) = 16 then
    LXorVal := CONSTANT_128
  else
    LXorVal := CONSTANT_64;

  Result[System.Length(AInput) - 1] :=
    Result[System.Length(AInput) - 1] xor Byte(TBitOperations.Asr32(LXorVal, (1 - LCarry) shl 3));
end;

procedure TCMac.Init(const AParameters: ICipherParameters);
var
  LKeyParam: IKeyParameter;
begin
  if Supports(AParameters, IKeyParameter, LKeyParam) then
  begin
    FCipherMode.Init(True, AParameters);

    System.SetLength(FL, System.Length(FZeroes));
    FCipherMode.ProcessBlock(FZeroes, 0, FL, 0);
    FLu := DoubleLu(FL);
    FLu2 := DoubleLu(FLu);
  end
  else if AParameters <> nil then
    raise EArgumentCryptoLibException.CreateRes(@SCMacKeyOnly);

  Reset();
end;

function TCMac.GetMacSize: Int32;
begin
  Result := FMacSize;
end;

procedure TCMac.Update(AInput: Byte);
begin
  if FBufOff = System.Length(FBuf) then
  begin
    FCipherMode.ProcessBlock(FBuf, 0, FMac, 0);
    FBufOff := 0;
  end;
  FBuf[FBufOff] := AInput;
  System.Inc(FBufOff);
end;

procedure TCMac.BlockUpdate(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32);
var
  LBlockSize, LGapLen: Int32;
begin
  if ALen < 0 then
    raise EArgumentCryptoLibException.CreateRes(@SNegativeInputLength);

  LBlockSize := FCipherMode.GetBlockSize();
  LGapLen := LBlockSize - FBufOff;

  if ALen > LGapLen then
  begin
    System.Move(AInput[AInOff], FBuf[FBufOff], LGapLen * System.SizeOf(Byte));
    FCipherMode.ProcessBlock(FBuf, 0, FMac, 0);
    FBufOff := 0;
    ALen := ALen - LGapLen;
    AInOff := AInOff + LGapLen;

    while ALen > LBlockSize do
    begin
      FCipherMode.ProcessBlock(AInput, AInOff, FMac, 0);
      ALen := ALen - LBlockSize;
      AInOff := AInOff + LBlockSize;
    end;
  end;

  System.Move(AInput[AInOff], FBuf[FBufOff], ALen * System.SizeOf(Byte));
  FBufOff := FBufOff + ALen;
end;

function TCMac.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LBlockSize, LI: Int32;
  LLu: TCryptoLibByteArray;
  LPadding: IISO7816d4Padding;
begin
  LBlockSize := FCipherMode.GetBlockSize();

  if FBufOff = LBlockSize then
  begin
    LLu := FLu;
  end
  else
  begin
    LPadding := TISO7816d4Padding.Create() as IISO7816d4Padding;
    LPadding.AddPadding(FBuf, FBufOff);
    LLu := FLu2;
  end;

  for LI := 0 to System.Pred(System.Length(FMac)) do
    FBuf[LI] := FBuf[LI] xor LLu[LI];

  FCipherMode.ProcessBlock(FBuf, 0, FMac, 0);
  System.Move(FMac[0], AOutput[AOutOff], FMacSize * System.SizeOf(Byte));
  Reset();
  Result := FMacSize;
end;

procedure TCMac.Reset();
begin
  TArrayUtilities.Fill<Byte>(FBuf, 0, System.Length(FBuf), Byte(0));
  FBufOff := 0;
  FCipherMode.Reset();
end;

end.
