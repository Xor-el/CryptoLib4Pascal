{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpCfbBlockCipherMac;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpICfbBlockCipherMac,
  ClpIMac,
  ClpMac,
  ClpIBlockCipher,
  ClpIBlockCipherMode,
  ClpIBlockCipherPadding,
  ClpICipherParameters,
  ClpIParametersWithIV,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SMacSizeMultipleOf8 = 'MAC size must be multiple of 8';
  SNegativeInputLength = 'Can''t have a negative input length!';
  SInputBufferTooShort = 'Input buffer too short';
  SOutputBufferTooShort = 'Output buffer too short';

type
  IMacCfbBlockCipher = interface(IBlockCipherMode)
    ['{23F5FB58-873D-4DB8-9A3C-5CB4E5F15B6F}']
    procedure GetMacBlock(const AMac: TCryptoLibByteArray);
  end;

  TMacCfbBlockCipher = class sealed(TInterfacedObject, IMacCfbBlockCipher, IBlockCipherMode, IBlockCipher)

  strict private
  var
    FIV: TCryptoLibByteArray;
    FCfbV: TCryptoLibByteArray;
    FCfbOutV: TCryptoLibByteArray;
    FBlockSize: Int32;
    FCipher: IBlockCipher;

    function GetAlgorithmName: String; inline;
    function GetIsPartialBlockOkay: Boolean; inline;

  public
    constructor Create(const ACipher: IBlockCipher; ACfbBitSize: Int32);

    function GetUnderlyingCipher(): IBlockCipher;
    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters);
    function GetBlockSize(): Int32; inline;
    function ProcessBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
    procedure Reset();

    procedure GetMacBlock(const AMac: TCryptoLibByteArray);

    property AlgorithmName: String read GetAlgorithmName;
    property IsPartialBlockOkay: Boolean read GetIsPartialBlockOkay;
  end;

type
  TCfbBlockCipherMac = class sealed(TMac, ICfbBlockCipherMac, IMac)

  strict private
  var
    FMac: TCryptoLibByteArray;
    FBuf: TCryptoLibByteArray;
    FBufOff: Int32;
    FCipher: IMacCfbBlockCipher;
    FPadding: IBlockCipherPadding;
    FMacSize: Int32;

  strict protected
    function GetAlgorithmName: String; override;

  public
    constructor Create(const ACipher: IBlockCipher); overload;
    constructor Create(const ACipher: IBlockCipher;
      const APadding: IBlockCipherPadding); overload;
    constructor Create(const ACipher: IBlockCipher;
      ACfbBitSize, AMacSizeInBits: Int32); overload;
    constructor Create(const ACipher: IBlockCipher;
      ACfbBitSize, AMacSizeInBits: Int32;
      const APadding: IBlockCipherPadding); overload;

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

{ TMacCfbBlockCipher }

constructor TMacCfbBlockCipher.Create(const ACipher: IBlockCipher;
  ACfbBitSize: Int32);
var
  LBlockSize: Int32;
begin
  inherited Create();
  FCipher := ACipher;
  FBlockSize := ACfbBitSize div 8;

  LBlockSize := ACipher.GetBlockSize();
  System.SetLength(FIV, LBlockSize);
  System.SetLength(FCfbV, LBlockSize);
  System.SetLength(FCfbOutV, LBlockSize);
end;

function TMacCfbBlockCipher.GetAlgorithmName: String;
begin
  Result := FCipher.AlgorithmName + '/CFB' + IntToStr(FBlockSize * 8);
end;

function TMacCfbBlockCipher.GetBlockSize: Int32;
begin
  Result := FBlockSize;
end;

function TMacCfbBlockCipher.GetIsPartialBlockOkay: Boolean;
begin
  Result := True;
end;

function TMacCfbBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  Result := FCipher;
end;

procedure TMacCfbBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LParameters: ICipherParameters;
  LIvParam: IParametersWithIV;
  LIv: TCryptoLibByteArray;
  LIvLen, LOffset: Int32;
begin
  LParameters := AParameters;
  if Supports(LParameters, IParametersWithIV, LIvParam) then
  begin
    LIv := LIvParam.GetIV();
    LIvLen := System.Length(LIv);
    if LIvLen < System.Length(FIV) then
    begin
      LOffset := System.Length(FIV) - LIvLen;
      TArrayUtilities.Fill<Byte>(FIV, 0, LOffset, Byte(0));
      System.Move(LIv[0], FIV[LOffset], LIvLen * System.SizeOf(Byte));
    end
    else
    begin
      System.Move(LIv[0], FIV[0], System.Length(FIV) * System.SizeOf(Byte));
    end;
    LParameters := LIvParam.Parameters;
  end;

  Reset();

  FCipher.Init(True, LParameters);
end;

function TMacCfbBlockCipher.ProcessBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LI: Int32;
  LBlockLen, LShiftLen: Int32;
begin
  if ((AInOff + FBlockSize) > System.Length(AInput)) then
    raise EDataLengthCryptoLibException.CreateRes(@SInputBufferTooShort);

  if ((AOutOff + FBlockSize) > System.Length(AOutput)) then
    raise EOutputLengthCryptoLibException.CreateRes(@SOutputBufferTooShort);

  FCipher.ProcessBlock(FCfbV, 0, FCfbOutV, 0);

  for LI := 0 to System.Pred(FBlockSize) do
  begin
    AOutput[AOutOff + LI] := Byte(FCfbOutV[LI] xor AInput[AInOff + LI]);
  end;

  LBlockLen := System.Length(FCfbV);
  LShiftLen := LBlockLen - FBlockSize;

  if LShiftLen > 0 then
  begin
    System.Move(FCfbV[FBlockSize], FCfbV[0], LShiftLen * System.SizeOf(Byte));
  end;

  System.Move(AOutput[AOutOff], FCfbV[LShiftLen], FBlockSize * System.SizeOf(Byte));

  Result := FBlockSize;
end;

procedure TMacCfbBlockCipher.Reset;
begin
  System.Move(FIV[0], FCfbV[0], System.Length(FIV) * System.SizeOf(Byte));
end;

procedure TMacCfbBlockCipher.GetMacBlock(const AMac: TCryptoLibByteArray);
begin
  FCipher.ProcessBlock(FCfbV, 0, AMac, 0);
end;

{ TCfbBlockCipherMac }

constructor TCfbBlockCipherMac.Create(const ACipher: IBlockCipher);
begin
  Create(ACipher, 8, (ACipher.GetBlockSize() * 8) div 2, nil);
end;

constructor TCfbBlockCipherMac.Create(const ACipher: IBlockCipher;
  const APadding: IBlockCipherPadding);
begin
  Create(ACipher, 8, (ACipher.GetBlockSize() * 8) div 2, APadding);
end;

constructor TCfbBlockCipherMac.Create(const ACipher: IBlockCipher;
  ACfbBitSize, AMacSizeInBits: Int32);
begin
  Create(ACipher, ACfbBitSize, AMacSizeInBits, nil);
end;

constructor TCfbBlockCipherMac.Create(const ACipher: IBlockCipher;
  ACfbBitSize, AMacSizeInBits: Int32; const APadding: IBlockCipherPadding);
begin
  inherited Create();
  if (AMacSizeInBits mod 8) <> 0 then
    raise EArgumentCryptoLibException.CreateRes(@SMacSizeMultipleOf8);

  System.SetLength(FMac, ACipher.GetBlockSize());

  FCipher := TMacCfbBlockCipher.Create(ACipher, ACfbBitSize);
  FPadding := APadding;
  FMacSize := AMacSizeInBits div 8;

  System.SetLength(FBuf, FCipher.GetBlockSize());
  FBufOff := 0;
end;

function TCfbBlockCipherMac.GetAlgorithmName: String;
begin
  Result := FCipher.AlgorithmName;
end;

procedure TCfbBlockCipherMac.Init(const AParameters: ICipherParameters);
begin
  Reset();
  FCipher.Init(True, AParameters);
end;

function TCfbBlockCipherMac.GetMacSize: Int32;
begin
  Result := FMacSize;
end;

procedure TCfbBlockCipherMac.Update(AInput: Byte);
begin
  if FBufOff = System.Length(FBuf) then
  begin
    FCipher.ProcessBlock(FBuf, 0, FMac, 0);
    FBufOff := 0;
  end;
  FBuf[FBufOff] := AInput;
  System.Inc(FBufOff);
end;

procedure TCfbBlockCipherMac.BlockUpdate(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32);
var
  LBlockSize, LGapLen: Int32;
begin
  if ALen < 0 then
    raise EArgumentCryptoLibException.CreateRes(@SNegativeInputLength);

  LBlockSize := FCipher.GetBlockSize();
  LGapLen := LBlockSize - FBufOff;

  if ALen > LGapLen then
  begin
    System.Move(AInput[AInOff], FBuf[FBufOff], LGapLen * System.SizeOf(Byte));
    FCipher.ProcessBlock(FBuf, 0, FMac, 0);
    FBufOff := 0;
    ALen := ALen - LGapLen;
    AInOff := AInOff + LGapLen;

    while ALen > LBlockSize do
    begin
      FCipher.ProcessBlock(AInput, AInOff, FMac, 0);
      ALen := ALen - LBlockSize;
      AInOff := AInOff + LBlockSize;
    end;
  end;

  System.Move(AInput[AInOff], FBuf[FBufOff], ALen * System.SizeOf(Byte));
  FBufOff := FBufOff + ALen;
end;

function TCfbBlockCipherMac.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LBlockSize: Int32;
begin
  LBlockSize := FCipher.GetBlockSize();

  if FPadding = nil then
  begin
    while FBufOff < LBlockSize do
    begin
      FBuf[FBufOff] := 0;
      System.Inc(FBufOff);
    end;
  end
  else
  begin
    if FBufOff = LBlockSize then
    begin
      FCipher.ProcessBlock(FBuf, 0, FMac, 0);
      FBufOff := 0;
    end;
    FPadding.AddPadding(FBuf, FBufOff);
  end;

  FCipher.ProcessBlock(FBuf, 0, FMac, 0);
  FCipher.GetMacBlock(FMac);

  System.Move(FMac[0], AOutput[AOutOff], FMacSize * System.SizeOf(Byte));
  Reset();
  Result := FMacSize;
end;

procedure TCfbBlockCipherMac.Reset;
begin
  TArrayUtilities.Fill<Byte>(FBuf, 0, System.Length(FBuf), Byte(0));
  FBufOff := 0;
  FCipher.Reset();
end;

end.

