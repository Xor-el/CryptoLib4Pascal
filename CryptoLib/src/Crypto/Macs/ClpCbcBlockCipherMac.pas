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

unit ClpCbcBlockCipherMac;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCbcBlockCipher,
  ClpICbcBlockCipherMac,
  ClpIMac,
  ClpMac,
  ClpIBlockCipher,
  ClpIBlockCipherMode,
  ClpIBlockCipherPadding,
  ClpICipherParameters,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SMacSizeMultipleOf8 = 'MAC size must be multiple of 8';
  SNegativeInputLength = 'Can''t have a negative input length!';

type
  TCbcBlockCipherMac = class sealed(TMac, ICbcBlockCipherMac, IMac)

  strict private
  var
    FBuf: TCryptoLibByteArray;
    FBufOff: Int32;
    FCipherMode: IBlockCipherMode;
    FPadding: IBlockCipherPadding;
    FMacSize: Int32;

  strict protected
    function GetAlgorithmName: String; override;

  public
    constructor Create(const ACipher: IBlockCipher); overload;
    constructor Create(const ACipher: IBlockCipher;
      const APadding: IBlockCipherPadding); overload;
    constructor Create(const ACipher: IBlockCipher;
      AMacSizeInBits: Int32); overload;
    constructor Create(const ACipher: IBlockCipher; AMacSizeInBits: Int32;
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

{ TCbcBlockCipherMac }

constructor TCbcBlockCipherMac.Create(const ACipher: IBlockCipher);
begin
  Create(ACipher, (ACipher.GetBlockSize() * 8) div 2, nil);
end;

constructor TCbcBlockCipherMac.Create(const ACipher: IBlockCipher;
  const APadding: IBlockCipherPadding);
begin
  Create(ACipher, (ACipher.GetBlockSize() * 8) div 2, APadding);
end;

constructor TCbcBlockCipherMac.Create(const ACipher: IBlockCipher;
  AMacSizeInBits: Int32);
begin
  Create(ACipher, AMacSizeInBits, nil);
end;

constructor TCbcBlockCipherMac.Create(const ACipher: IBlockCipher;
  AMacSizeInBits: Int32; const APadding: IBlockCipherPadding);
begin
  inherited Create();
  if (AMacSizeInBits mod 8) <> 0 then
    raise EArgumentCryptoLibException.CreateRes(@SMacSizeMultipleOf8);

  FCipherMode := TCbcBlockCipher.Create(ACipher) as IBlockCipherMode;
  FPadding := APadding;
  FMacSize := AMacSizeInBits div 8;
  System.SetLength(FBuf, ACipher.GetBlockSize());
  FBufOff := 0;
end;

function TCbcBlockCipherMac.GetAlgorithmName: String;
begin
  Result := FCipherMode.AlgorithmName;
end;

procedure TCbcBlockCipherMac.Init(const AParameters: ICipherParameters);
begin
  Reset();
  FCipherMode.Init(True, AParameters);
end;

function TCbcBlockCipherMac.GetMacSize: Int32;
begin
  Result := FMacSize;
end;

procedure TCbcBlockCipherMac.Update(AInput: Byte);
begin
  if FBufOff = System.Length(FBuf) then
  begin
    FCipherMode.ProcessBlock(FBuf, 0, FBuf, 0);
    FBufOff := 0;
  end;
  FBuf[FBufOff] := AInput;
  System.Inc(FBufOff);
end;

procedure TCbcBlockCipherMac.BlockUpdate(const AInput: TCryptoLibByteArray;
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
    FCipherMode.ProcessBlock(FBuf, 0, FBuf, 0);
    FBufOff := 0;
    ALen := ALen - LGapLen;
    AInOff := AInOff + LGapLen;

    while ALen > LBlockSize do
    begin
      FCipherMode.ProcessBlock(AInput, AInOff, FBuf, 0);
      ALen := ALen - LBlockSize;
      AInOff := AInOff + LBlockSize;
    end;
  end;

  System.Move(AInput[AInOff], FBuf[FBufOff], ALen * System.SizeOf(Byte));
  FBufOff := FBufOff + ALen;
end;

function TCbcBlockCipherMac.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LBlockSize: Int32;
begin
  LBlockSize := FCipherMode.GetBlockSize();

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
      FCipherMode.ProcessBlock(FBuf, 0, FBuf, 0);
      FBufOff := 0;
    end;
    FPadding.AddPadding(FBuf, FBufOff);
  end;

  FCipherMode.ProcessBlock(FBuf, 0, FBuf, 0);
  System.Move(FBuf[0], AOutput[AOutOff], FMacSize * System.SizeOf(Byte));
  Reset();
  Result := FMacSize;
end;

procedure TCbcBlockCipherMac.Reset();
begin
  TArrayUtilities.Fill<Byte>(FBuf, 0, System.Length(FBuf), Byte(0));
  FBufOff := 0;
  FCipherMode.Reset();
end;

end.
