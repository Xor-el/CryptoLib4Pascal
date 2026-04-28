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

unit ClpBufferedAeadCipher;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBufferedCipherBase,
  ClpIBufferedAeadCipher,
  ClpIAeadCipher,
  ClpICipherParameters,
  ClpIParametersWithRandom,
  ClpCryptoLibTypes;

resourcestring
  SCipherNil = 'Cipher Instance Cannot be Nil';
  SInputNil = 'Input Cannot be Nil';

type
  TBufferedAeadCipher = class(TBufferedCipherBase, IBufferedAeadCipher)

  strict private
  var
    FCipher: IAeadCipher;

  strict protected
    function GetAlgorithmName: String; override;

  public
    constructor Create(const ACipher: IAeadCipher);

    procedure Init(AForEncryption: Boolean;
      const AParameters: ICipherParameters); override;

    function GetBlockSize(): Int32; override;
    function GetUpdateOutputSize(AInputLen: Int32): Int32; override;
    function GetOutputSize(AInputLen: Int32): Int32; override;

    function ProcessByte(AInput: Byte): TCryptoLibByteArray; overload; override;

    function ProcessByte(AInput: Byte; const AOutput: TCryptoLibByteArray;
      AOutOff: Int32): Int32; overload; override;

    function ProcessBytes(const AInput: TCryptoLibByteArray;
      AInOff, ALength: Int32): TCryptoLibByteArray; overload; override;

    function ProcessBytes(const AInput: TCryptoLibByteArray;
      AInOff, ALength: Int32; const AOutput: TCryptoLibByteArray;
      AOutOff: Int32): Int32; overload; override;

    function DoFinal(): TCryptoLibByteArray; overload; override;

    function DoFinal(const AInput: TCryptoLibByteArray;
      AInOff, AInLen: Int32): TCryptoLibByteArray; overload; override;

    function DoFinal(const AOutput: TCryptoLibByteArray;
      AOutOff: Int32): Int32; overload; override;

    procedure Reset(); override;

    property AlgorithmName: String read GetAlgorithmName;
  end;

implementation

{ TBufferedAeadCipher }

constructor TBufferedAeadCipher.Create(const ACipher: IAeadCipher);
begin
  Inherited Create();
  if ACipher = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SCipherNil);
  FCipher := ACipher;
end;

function TBufferedAeadCipher.GetAlgorithmName: String;
begin
  Result := FCipher.AlgorithmName;
end;

procedure TBufferedAeadCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LWithRandom: IParametersWithRandom;
  LParameters: ICipherParameters;
begin
  LParameters := AParameters;

  if Supports(LParameters, IParametersWithRandom, LWithRandom) then
  begin
    LParameters := LWithRandom.Parameters;
  end;

  FCipher.Init(AForEncryption, LParameters);
end;

function TBufferedAeadCipher.GetBlockSize: Int32;
begin
  Result := 0;
end;

function TBufferedAeadCipher.GetUpdateOutputSize(AInputLen: Int32): Int32;
begin
  Result := FCipher.GetUpdateOutputSize(AInputLen);
end;

function TBufferedAeadCipher.GetOutputSize(AInputLen: Int32): Int32;
begin
  Result := FCipher.GetOutputSize(AInputLen);
end;

function TBufferedAeadCipher.ProcessByte(AInput: Byte): TCryptoLibByteArray;
var
  LOutBytes, LTmp: TCryptoLibByteArray;
  LUpdateSize, LPos: Int32;
begin
  LUpdateSize := FCipher.GetUpdateOutputSize(1);

  if LUpdateSize > 0 then
    System.SetLength(LOutBytes, LUpdateSize)
  else
    LOutBytes := nil;

  LPos := FCipher.ProcessByte(AInput, LOutBytes, 0);

  if ((LUpdateSize > 0) and (LPos < LUpdateSize)) then
  begin
    System.SetLength(LTmp, LPos);
    if LPos > 0 then
      System.Move(LOutBytes[0], LTmp[0], LPos * System.SizeOf(Byte));
    LOutBytes := LTmp;
  end;

  Result := LOutBytes;
end;

function TBufferedAeadCipher.ProcessByte(AInput: Byte;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  Result := FCipher.ProcessByte(AInput, AOutput, AOutOff);
end;

function TBufferedAeadCipher.ProcessBytes(
  const AInput: TCryptoLibByteArray;
  AInOff, ALength: Int32): TCryptoLibByteArray;
var
  LOutBytes, LTmp: TCryptoLibByteArray;
  LUpdateSize, LPos: Int32;
begin
  if AInput = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SInputNil);
  if ALength < 1 then
  begin
    Result := nil;
    Exit;
  end;

  LUpdateSize := FCipher.GetUpdateOutputSize(ALength);

  if LUpdateSize > 0 then
    System.SetLength(LOutBytes, LUpdateSize)
  else
    LOutBytes := nil;

  LPos := FCipher.ProcessBytes(AInput, AInOff, ALength, LOutBytes, 0);

  if ((LUpdateSize > 0) and (LPos < LUpdateSize)) then
  begin
    System.SetLength(LTmp, LPos);
    if LPos > 0 then
      System.Move(LOutBytes[0], LTmp[0], LPos * System.SizeOf(Byte));
    LOutBytes := LTmp;
  end;

  Result := LOutBytes;
end;

function TBufferedAeadCipher.ProcessBytes(
  const AInput: TCryptoLibByteArray; AInOff, ALength: Int32;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  Result := FCipher.ProcessBytes(AInput, AInOff, ALength, AOutput, AOutOff);
end;

function TBufferedAeadCipher.DoFinal: TCryptoLibByteArray;
var
  LOutBytes, LTmp: TCryptoLibByteArray;
  LOutSize, LPos: Int32;
begin
  LOutSize := FCipher.GetOutputSize(0);

  if LOutSize > 0 then
    System.SetLength(LOutBytes, LOutSize)
  else
    LOutBytes := EmptyBuffer;

  LPos := FCipher.DoFinal(LOutBytes, 0);

  if ((LOutSize > 0) and (LPos < LOutSize)) then
  begin
    System.SetLength(LTmp, LPos);
    if LPos > 0 then
      System.Move(LOutBytes[0], LTmp[0], LPos * System.SizeOf(Byte));
    LOutBytes := LTmp;
  end;

  Result := LOutBytes;
end;

function TBufferedAeadCipher.DoFinal(const AInput: TCryptoLibByteArray;
  AInOff, AInLen: Int32): TCryptoLibByteArray;
var
  LOutBytes, LTmp: TCryptoLibByteArray;
  LOutSize, LPos: Int32;
begin
  if AInput = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SInputNil);
  LOutSize := FCipher.GetOutputSize(AInLen);

  if LOutSize > 0 then
    System.SetLength(LOutBytes, LOutSize)
  else
    LOutBytes := EmptyBuffer;

  LPos := 0;
  if AInLen > 0 then
    LPos := FCipher.ProcessBytes(AInput, AInOff, AInLen, LOutBytes, 0);

  LPos := LPos + FCipher.DoFinal(LOutBytes, LPos);

  if ((LOutSize > 0) and (LPos < LOutSize)) then
  begin
    System.SetLength(LTmp, LPos);
    if LPos > 0 then
      System.Move(LOutBytes[0], LTmp[0], LPos * System.SizeOf(Byte));
    LOutBytes := LTmp;
  end;

  Result := LOutBytes;
end;

function TBufferedAeadCipher.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
begin
  Result := FCipher.DoFinal(AOutput, AOutOff);
end;

procedure TBufferedAeadCipher.Reset;
begin
  FCipher.Reset();
end;

end.
