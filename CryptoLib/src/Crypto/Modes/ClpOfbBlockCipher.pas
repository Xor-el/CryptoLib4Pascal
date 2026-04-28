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

unit ClpOfbBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIBlockCipherMode,
  ClpIOfbBlockCipher,
  ClpICipherParameters,
  ClpCipherModeParameterUtilities,
  ClpCryptoLibTypes;

resourcestring
  SInputBufferTooShort = 'Input Buffer Too Short';
  SOutputBufferTooShort = 'Output Buffer Too Short';

type
  TOfbBlockCipher = class sealed(TInterfacedObject, IOfbBlockCipher,
    IBlockCipherMode, IBlockCipher)

  strict private
  var
    FIV, FOfbV, FOfbOutV: TCryptoLibByteArray;
    FBlockSize: Int32;
    FCipher: IBlockCipher;

  strict protected
    function GetAlgorithmName: String; inline;
    function GetIsPartialBlockOkay: Boolean; inline;
    function GetUnderlyingCipher(): IBlockCipher; inline;

  public
    constructor Create(const ACipher: IBlockCipher; ABlockSize: Int32);
    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters);
    function GetBlockSize(): Int32; inline;
    function ProcessBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
    procedure Reset(); inline;

    property UnderlyingCipher: IBlockCipher read GetUnderlyingCipher;
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
  LParameters: ICipherParameters;
begin
  TCipherModeParameterUtilities.TryUnwrapIv(AParameters, FIV, LParameters);

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
