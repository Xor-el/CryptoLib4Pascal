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

unit ClpBufferedStreamCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIStreamCipher,
  ClpICipherParameters,
  ClpIParametersWithRandom,
  ClpIBufferedStreamCipher,
  ClpBufferedCipherBase,
  ClpCryptoLibTypes;

resourcestring
  SCipherNil = 'Cipher Instance Cannot be Nil';

type
  TBufferedStreamCipher = class(TBufferedCipherBase, IBufferedStreamCipher)

  strict private
  var
    FCipher: IStreamCipher;

  strict protected
    function GetAlgorithmName: String; override;

  public
    constructor Create(const ACipher: IStreamCipher);

    procedure Init(AForEncryption: Boolean;
      const AParameters: ICipherParameters); override;

    function GetBlockSize(): Int32; override;

    function GetOutputSize(AInputLen: Int32): Int32; override;

    function GetUpdateOutputSize(AInputLen: Int32): Int32; override;

    function ProcessByte(AInput: Byte): TCryptoLibByteArray; overload; override;
    function ProcessByte(AInput: Byte; const AOutput: TCryptoLibByteArray;
      AOutOff: Int32): Int32; overload; override;

    function ProcessBytes(const AInput: TCryptoLibByteArray;
      AInOff, ALength: Int32): TCryptoLibByteArray; overload; override;
    function ProcessBytes(const AInput: TCryptoLibByteArray;
      AInOff, ALength: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32)
      : Int32; overload; override;

    function DoFinal(): TCryptoLibByteArray; overload; override;
    function DoFinal(const AInput: TCryptoLibByteArray; AInOff, ALength: Int32)
      : TCryptoLibByteArray; overload; override;

    procedure Reset(); override;

    property AlgorithmName: String read GetAlgorithmName;

  end;

implementation

{ TBufferedStreamCipher }

constructor TBufferedStreamCipher.Create(const ACipher: IStreamCipher);
begin
  Inherited Create();
  if (ACipher = nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SCipherNil);
  end;

  FCipher := ACipher;
end;

function TBufferedStreamCipher.GetAlgorithmName: String;
begin
  Result := FCipher.AlgorithmName;
end;

function TBufferedStreamCipher.GetBlockSize: Int32;
begin
  Result := 0;
end;

function TBufferedStreamCipher.GetOutputSize(AInputLen: Int32): Int32;
begin
  Result := AInputLen;
end;

function TBufferedStreamCipher.GetUpdateOutputSize(AInputLen: Int32): Int32;
begin
  Result := AInputLen;
end;

procedure TBufferedStreamCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LParameters: ICipherParameters;
begin
  LParameters := AParameters;
  if Supports(LParameters, IParametersWithRandom) then
  begin
    LParameters := (LParameters as IParametersWithRandom).Parameters;
  end;
  FCipher.Init(AForEncryption, LParameters);
end;

function TBufferedStreamCipher.ProcessByte(AInput: Byte;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  if (AOutOff >= System.Length(AOutput)) then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooSmall);
  end;
  AOutput[AOutOff] := FCipher.ReturnByte(AInput);
  Result := 1;
end;

function TBufferedStreamCipher.ProcessByte(AInput: Byte): TCryptoLibByteArray;
begin
  Result := TCryptoLibByteArray.Create(FCipher.ReturnByte(AInput));
end;

function TBufferedStreamCipher.ProcessBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALength: Int32; const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
begin
  if (ALength < 1) then
  begin
    Result := 0;
    Exit;
  end;

  if (ALength > 0) then
  begin
    FCipher.ProcessBytes(AInput, AInOff, ALength, AOutput, AOutOff);
  end;

  Result := ALength;
end;

function TBufferedStreamCipher.ProcessBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALength: Int32): TCryptoLibByteArray;
begin
  if (ALength < 1) then
  begin
    Result := nil;
    Exit;
  end;
  System.SetLength(Result, ALength);
  FCipher.ProcessBytes(AInput, AInOff, ALength, Result, 0);
end;

function TBufferedStreamCipher.DoFinal: TCryptoLibByteArray;
begin
  Reset();
  Result := EmptyBuffer;
end;

function TBufferedStreamCipher.DoFinal(const AInput: TCryptoLibByteArray;
  AInOff, ALength: Int32): TCryptoLibByteArray;
begin
  if (ALength < 1) then
  begin
    Result := EmptyBuffer;
    Exit;
  end;
  Result := ProcessBytes(AInput, AInOff, ALength);
  Reset();
end;

procedure TBufferedStreamCipher.Reset;
begin
  FCipher.Reset();
end;

end.
