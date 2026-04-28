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

unit ClpRfc3394WrapEngine;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIRfc3394WrapEngine,
  ClpIWrapper,
  ClpIBlockCipher,
  ClpICipherParameters,
  ClpIKeyParameter,
  ClpIParametersWithIV,
  ClpIParametersWithRandom,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SNotSetForWrapping = 'Not set for wrapping';
  SNotSetForUnwrapping = 'Not set for unwrapping';
  SWrapDataMustBeAtLeast8Bytes = 'Wrap data must be at least 8 bytes';
  SWrapDataMustBeMultipleOf8 = 'Wrap data must be a multiple of 8 bytes';
  SUnwrapDataTooShort = 'Unwrap data too short';
  SUnwrapDataMustBeMultipleOf8 = 'Unwrap data must be a multiple of 8 bytes';
  SIVLengthNotEqualTo8 = 'IV length not equal to 8';
  SChecksumFailed = 'Checksum failed';

type
  TRfc3394WrapEngine = class(TInterfacedObject, IRfc3394WrapEngine, IWrapper)

  strict private
  class var
    FDefaultIV: TCryptoLibByteArray;

  var
    FEngine: IBlockCipher;
    FWrapCipherMode: Boolean;
    FIv: TCryptoLibByteArray;
    FKey: IKeyParameter;
    FForWrapping: Boolean;

    class constructor Create;

  strict protected
    function GetAlgorithmName: String; virtual;

  public
    constructor Create(const AEngine: IBlockCipher); overload;
    constructor Create(const AEngine: IBlockCipher; AUseReverseDirection: Boolean); overload;

    procedure Init(AForWrapping: Boolean; const AParameters: ICipherParameters); virtual;

    function Wrap(const AInput: TCryptoLibByteArray; AInOff, AInLen: Int32): TCryptoLibByteArray; virtual;

    function Unwrap(const AInput: TCryptoLibByteArray; AInOff, AInLen: Int32): TCryptoLibByteArray; virtual;

    property AlgorithmName: String read GetAlgorithmName;

  end;

implementation

{ TRfc3394WrapEngine }

class constructor TRfc3394WrapEngine.Create;
begin
  FDefaultIV := TCryptoLibByteArray.Create($A6, $A6, $A6, $A6, $A6, $A6, $A6, $A6);
end;

constructor TRfc3394WrapEngine.Create(const AEngine: IBlockCipher);
begin
  Create(AEngine, False);
end;

constructor TRfc3394WrapEngine.Create(const AEngine: IBlockCipher;
  AUseReverseDirection: Boolean);
begin
  inherited Create;
  FEngine := AEngine;
  FWrapCipherMode := not AUseReverseDirection;
  System.SetLength(FIv, 8);
end;

function TRfc3394WrapEngine.GetAlgorithmName: String;
begin
  Result := FEngine.AlgorithmName;
end;

procedure TRfc3394WrapEngine.Init(AForWrapping: Boolean;
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
    System.Move(FDefaultIV[0], FIv[0], 8 * System.SizeOf(Byte));
  end
  else if Supports(LParameters, IParametersWithIV, LWithIV) then
  begin
    LIv := LWithIV.GetIV();
    if System.Length(LIv) <> 8 then
      raise EArgumentCryptoLibException.CreateRes(@SIVLengthNotEqualTo8);

    Supports(LWithIV.Parameters, IKeyParameter, FKey);
    System.Move(LIv[0], FIv[0], 8 * System.SizeOf(Byte));
  end;
end;

function TRfc3394WrapEngine.Wrap(const AInput: TCryptoLibByteArray;
  AInOff, AInLen: Int32): TCryptoLibByteArray;
var
  LN, LI, LJ, LK: Int32;
  LT: UInt32;
  LBlock, LBuf: TCryptoLibByteArray;
begin
  if not FForWrapping then
    raise EInvalidOperationCryptoLibException.CreateRes(@SNotSetForWrapping);
  if AInLen < 8 then
    raise EDataLengthCryptoLibException.CreateRes(@SWrapDataMustBeAtLeast8Bytes);

  LN := AInLen div 8;

  if (LN * 8) <> AInLen then
    raise EDataLengthCryptoLibException.CreateRes(@SWrapDataMustBeMultipleOf8);

  FEngine.Init(FWrapCipherMode, FKey);

  System.SetLength(LBlock, AInLen + 8);
  System.Move(FIv[0], LBlock[0], 8 * System.SizeOf(Byte));
  System.Move(AInput[AInOff], LBlock[8], AInLen * System.SizeOf(Byte));

  if LN = 1 then
  begin
    FEngine.ProcessBlock(LBlock, 0, LBlock, 0);
  end
  else
  begin
    System.SetLength(LBuf, 16);

    for LJ := 0 to 5 do
    begin
      for LI := 1 to LN do
      begin
        System.Move(LBlock[0], LBuf[0], 8 * System.SizeOf(Byte));
        System.Move(LBlock[8 * LI], LBuf[8], 8 * System.SizeOf(Byte));
        FEngine.ProcessBlock(LBuf, 0, LBuf, 0);

        LT := UInt32(LN * LJ + LI);
        LK := 1;
        while LT <> 0 do
        begin
          LBuf[8 - LK] := LBuf[8 - LK] xor Byte(LT);
          LT := LT shr 8;
          Inc(LK);
        end;

        System.Move(LBuf[0], LBlock[0], 8 * System.SizeOf(Byte));
        System.Move(LBuf[8], LBlock[8 * LI], 8 * System.SizeOf(Byte));
      end;
    end;
  end;

  Result := LBlock;
end;

function TRfc3394WrapEngine.Unwrap(const AInput: TCryptoLibByteArray;
  AInOff, AInLen: Int32): TCryptoLibByteArray;
var
  LN, LI, LJ, LK: Int32;
  LT: UInt32;
  LBlock, LA, LBuf: TCryptoLibByteArray;
begin
  if FForWrapping then
    raise EInvalidOperationCryptoLibException.CreateRes(@SNotSetForUnwrapping);
  if AInLen < 16 then
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SUnwrapDataTooShort);

  LN := AInLen div 8;

  if (LN * 8) <> AInLen then
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SUnwrapDataMustBeMultipleOf8);

  FEngine.Init(not FWrapCipherMode, FKey);

  System.SetLength(LBlock, AInLen - 8);
  System.SetLength(LA, 8);
  System.SetLength(LBuf, 16);

  LN := LN - 1;

  if LN = 1 then
  begin
    FEngine.ProcessBlock(AInput, AInOff, LBuf, 0);
    System.Move(LBuf[0], LA[0], 8 * System.SizeOf(Byte));
    System.Move(LBuf[8], LBlock[0], 8 * System.SizeOf(Byte));
  end
  else
  begin
    System.Move(AInput[AInOff], LA[0], 8 * System.SizeOf(Byte));
    System.Move(AInput[AInOff + 8], LBlock[0], (AInLen - 8) * System.SizeOf(Byte));

    for LJ := 5 downto 0 do
    begin
      for LI := LN downto 1 do
      begin
        System.Move(LA[0], LBuf[0], 8 * System.SizeOf(Byte));
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
        System.Move(LBuf[0], LA[0], 8 * System.SizeOf(Byte));
        System.Move(LBuf[8], LBlock[8 * (LI - 1)], 8 * System.SizeOf(Byte));
      end;
    end;
  end;

  if not TArrayUtilities.FixedTimeEquals(LA, FIv) then
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SChecksumFailed);

  Result := LBlock;
end;

end.
