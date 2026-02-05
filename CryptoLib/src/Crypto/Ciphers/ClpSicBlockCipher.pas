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
  Math,
  SysUtils,
  ClpIBlockCipher,
  ClpISicBlockCipher,
  ClpICipherParameters,
  ClpIParametersWithIV,
  ClpArrayUtilities,
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
  TSicBlockCipher = class sealed(TInterfacedObject, ISicBlockCipher,
    IBlockCipher)

  strict private
  var
    FIV, FCounter, FCounterOut: TCryptoLibByteArray;
    FBlockSize: Int32;
    FCipher: IBlockCipher;

    function GetAlgorithmName: String; inline;
    function GetIsPartialBlockOkay: Boolean; inline;

  public
    constructor Create(const ACipher: IBlockCipher);
    function GetUnderlyingCipher(): IBlockCipher;
    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters);
    function GetBlockSize(): Int32; inline;
    function ProcessBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
    procedure Reset(); inline;
    property AlgorithmName: String read GetAlgorithmName;
    property IsPartialBlockOkay: Boolean read GetIsPartialBlockOkay;
  end;

implementation

{ TSicBlockCipher }

constructor TSicBlockCipher.Create(const ACipher: IBlockCipher);
begin
  inherited Create();
  FCipher := ACipher;
  FBlockSize := FCipher.GetBlockSize();

  System.SetLength(FCounter, FBlockSize);
  System.SetLength(FCounterOut, FBlockSize);
  System.SetLength(FIV, FBlockSize);
end;

procedure TSicBlockCipher.Reset;
begin
  TArrayUtilities.Fill<Byte>(FCounter, 0, System.Length(FCounter), Byte(0));
  System.Move(FIV[0], FCounter[0], System.Length(FIV) * System.SizeOf(Byte));
  FCipher.Reset();
end;

function TSicBlockCipher.GetAlgorithmName: String;
begin
  Result := FCipher.AlgorithmName + '/SIC';
end;

function TSicBlockCipher.GetBlockSize: Int32;
begin
  Result := FCipher.GetBlockSize();
end;

function TSicBlockCipher.GetIsPartialBlockOkay: Boolean;
begin
  Result := True;
end;

function TSicBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  Result := FCipher;
end;

{$IFNDEF _FIXINSIGHT_}
procedure TSicBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LIvParam: IParametersWithIV;
  LParameters: ICipherParameters;
  LMaxCounterSize: Int32;
begin
  LParameters := AParameters;

  if Supports(LParameters, IParametersWithIV, LIvParam) then
  begin
    FIV := LIvParam.GetIV();

    if (FBlockSize < System.Length(FIV)) then
      raise EArgumentCryptoLibException.CreateResFmt(@SInvalidTooLargeIVLength,
        [FBlockSize]);

    LMaxCounterSize := Min(8, FBlockSize div 2);

    if ((FBlockSize - System.Length(FIV)) > LMaxCounterSize) then
      raise EArgumentCryptoLibException.CreateResFmt(@SInvalidTooSmallIVLength,
        [FBlockSize - LMaxCounterSize]);

    LParameters := LIvParam.Parameters;
  end
  else
    raise EArgumentCryptoLibException.CreateRes(@SInvalidParameterArgument);

  if (LParameters <> nil) then
    FCipher.Init(True, LParameters);

  Reset();
end;
{$ENDIF}

function TSicBlockCipher.ProcessBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LI, LJ: Int32;
begin
  if ((AInOff + FBlockSize) > System.Length(AInput)) then
    raise EDataLengthCryptoLibException.CreateRes(@SInputBufferTooShort);

  if ((AOutOff + FBlockSize) > System.Length(AOutput)) then
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooShort);

  FCipher.ProcessBlock(FCounter, 0, FCounterOut, 0);

  for LI := 0 to System.Pred(System.Length(FCounterOut)) do
    AOutput[AOutOff + LI] := Byte(FCounterOut[LI] xor AInput[AInOff + LI]);

  LJ := System.Length(FCounter);
  System.Dec(LJ);
  System.Inc(FCounter[LJ]);
  while ((LJ >= 0) and (FCounter[LJ] = 0)) do
  begin
    System.Dec(LJ);
    System.Inc(FCounter[LJ]);
  end;

  Result := System.Length(FCounter);
end;

end.
