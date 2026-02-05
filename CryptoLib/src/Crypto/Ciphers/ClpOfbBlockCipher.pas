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

unit ClpOfbBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIOfbBlockCipher,
  ClpICipherParameters,
  ClpIParametersWithIV,
  ClpCryptoLibTypes;

resourcestring
  SInputBufferTooShort = 'Input Buffer too Short';
  SOutputBufferTooShort = 'Output Buffer too Short';

type
  TOfbBlockCipher = class sealed(TInterfacedObject, IOfbBlockCipher,
    IBlockCipher)

  strict private
  var
    FIV, FOfbV, FOfbOutV: TCryptoLibByteArray;
    FBlockSize: Int32;
    FCipher: IBlockCipher;
    FEncrypting: Boolean;

    function GetAlgorithmName: String; inline;
    function GetIsPartialBlockOkay: Boolean; inline;

  public
    constructor Create(const ACipher: IBlockCipher; ABlockSize: Int32);
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

{ TOfbBlockCipher }

constructor TOfbBlockCipher.Create(const ACipher: IBlockCipher;
  ABlockSize: Int32);
begin
  inherited Create();
  FCipher := ACipher;
  FBlockSize := ABlockSize div 8;

  System.SetLength(FIV, FCipher.GetBlockSize());
  System.SetLength(FOfbV, FCipher.GetBlockSize());
  System.SetLength(FOfbOutV, FCipher.GetBlockSize());
end;

procedure TOfbBlockCipher.Reset;
begin
  System.Move(FIV[0], FOfbV[0], System.Length(FIV));
  FCipher.Reset();
end;

function TOfbBlockCipher.GetAlgorithmName: String;
begin
  Result := FCipher.AlgorithmName + '/OFB' + IntToStr(FBlockSize * 8);
end;

function TOfbBlockCipher.GetBlockSize: Int32;
begin
  Result := FBlockSize;
end;

function TOfbBlockCipher.GetIsPartialBlockOkay: Boolean;
begin
  Result := True;
end;

function TOfbBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  Result := FCipher;
end;

procedure TOfbBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LIvParam: IParametersWithIV;
  LIv: TCryptoLibByteArray;
  LParameters: ICipherParameters;
  LI: Int32;
begin
  FEncrypting := AForEncryption;
  LParameters := AParameters;

  if Supports(LParameters, IParametersWithIV, LIvParam) then
  begin
    LIv := LIvParam.GetIV();
    if (System.Length(LIv) < System.Length(FIV)) then
    begin
      System.Move(LIv[0], FIV[System.Length(FIV) - System.Length(LIv)],
        System.Length(LIv) * System.SizeOf(Byte));
      for LI := 0 to System.Pred(System.Length(FIV) - System.Length(LIv)) do
        FIV[LI] := 0;
    end
    else
      System.Move(LIv[0], FIV[0], System.Length(FIV) * System.SizeOf(Byte));
    LParameters := LIvParam.Parameters;
  end;

  Reset();
  if (LParameters <> nil) then
    FCipher.Init(True, LParameters);
end;

function TOfbBlockCipher.ProcessBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LI, LCount: Int32;
begin
  if ((AInOff + FBlockSize) > System.Length(AInput)) then
    raise EDataLengthCryptoLibException.CreateRes(@SInputBufferTooShort);

  if ((AOutOff + FBlockSize) > System.Length(AOutput)) then
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooShort);

  FCipher.ProcessBlock(FOfbV, 0, FOfbOutV, 0);

  for LI := 0 to System.Pred(FBlockSize) do
    AOutput[AOutOff + LI] := Byte(FOfbOutV[LI] xor AInput[AInOff + LI]);

  LCount := (System.Length(FOfbV) - FBlockSize) * System.SizeOf(Byte);
  if LCount > 0 then
    System.Move(FOfbV[FBlockSize], FOfbV[0], LCount);

  System.Move(FOfbOutV[0], FOfbV[(System.Length(FOfbV) - FBlockSize)],
    FBlockSize * System.SizeOf(Byte));

  Result := FBlockSize;
end;

end.
