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

unit ClpBufferedIesCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Math,
  SysUtils,
  ClpICipherParameters,
  ClpIIESEngine,
  ClpIIesParameters,
  ClpBufferedCipherBase,
  ClpCryptoLibTypes;

resourcestring
  SEngineNil = 'Engine Cannot be Nil';
  SCipherNotInitialised = 'Cipher not initialised';
  SIesCipherParametersRequired = 'IIesCipherParameters required for Init';

type
  TBufferedIesCipher = class sealed(TBufferedCipherBase)

  strict private
  var
    FEngine: IIesEngine;
    FForEncryption: Boolean;
    FBuffer: TCryptoLibByteArray;
    FBufferLen: Int32;

  strict protected
    function GetAlgorithmName: String; override;

  public
    constructor Create(const AEngine: IIesEngine);

    procedure Init(AForEncryption: Boolean;
      const AParameters: ICipherParameters); override;

    function GetBlockSize(): Int32; override;
    function GetOutputSize(AInputLen: Int32): Int32; override;
    function GetUpdateOutputSize(AInputLen: Int32): Int32; override;

    function ProcessByte(AInput: Byte): TCryptoLibByteArray; override;
    function ProcessBytes(const AInput: TCryptoLibByteArray; AInOff,
      ALength: Int32): TCryptoLibByteArray; override;

    function DoFinal(): TCryptoLibByteArray; override;
    function DoFinal(const AInput: TCryptoLibByteArray; AInOff,
      ALength: Int32): TCryptoLibByteArray; override;

    procedure Reset(); override;
  end;

implementation

const
  SIESAlgorithmName = 'IES';
  SDefaultMacSize = 20;

{ TBufferedIesCipher }

constructor TBufferedIesCipher.Create(const AEngine: IIesEngine);
begin
  Inherited Create();
  if AEngine = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SEngineNil);
  FEngine := AEngine;
  FBufferLen := 0;
end;

procedure TBufferedIesCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LParams: IIesCipherParameters;
  LPriv, LPub: ICipherParameters;
  LIesParams: IIesParameters;
begin
  FForEncryption := AForEncryption;
  if AParameters = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SIesCipherParametersRequired);
  if not Supports(AParameters, IIesCipherParameters, LParams) then
    raise EArgumentCryptoLibException.CreateRes(@SIesCipherParametersRequired);
  LPriv := LParams.PrivateKey;
  LPub := LParams.PublicKey;
  LIesParams := LParams.IesParameters;
  FEngine.Init(AForEncryption, LPriv, LPub, LIesParams);
  FBufferLen := 0;
end;

function TBufferedIesCipher.GetAlgorithmName: String;
begin
  Result := SIESAlgorithmName;
end;

function TBufferedIesCipher.GetBlockSize: Int32;
begin
  Result := 0;
end;

function TBufferedIesCipher.GetOutputSize(AInputLen: Int32): Int32;
var
  LBaseLen: Int32;
begin
  if FEngine = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SCipherNotInitialised);
  LBaseLen := AInputLen + FBufferLen;
  if FForEncryption then
    Result := LBaseLen + SDefaultMacSize
  else
    Result := LBaseLen - SDefaultMacSize;
  if Result < 0 then
    Result := 0;
end;

function TBufferedIesCipher.GetUpdateOutputSize(AInputLen: Int32): Int32;
begin
  Result := 0;
end;

function TBufferedIesCipher.ProcessByte(AInput: Byte): TCryptoLibByteArray;
begin
  if FBufferLen >= System.Length(FBuffer) then
    System.SetLength(FBuffer, Math.Max(256, FBufferLen * 2));
  FBuffer[FBufferLen] := AInput;
  System.Inc(FBufferLen);
  Result := nil;
end;

function TBufferedIesCipher.ProcessBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALength: Int32): TCryptoLibByteArray;
var
  LNewLen: Int32;
begin
  if AInput = nil then
    raise EArgumentNilCryptoLibException.Create('input');
  if (AInOff < 0) or (ALength < 0) or
    (AInOff + ALength > System.Length(AInput)) then
    raise EArgumentCryptoLibException.Create('invalid offset/length');
  if ALength = 0 then
  begin
    Result := nil;
    Exit;
  end;
  LNewLen := FBufferLen + ALength;
  if LNewLen > System.Length(FBuffer) then
    System.SetLength(FBuffer, LNewLen);
  System.Move(AInput[AInOff], FBuffer[FBufferLen], ALength * System.SizeOf(Byte));
  FBufferLen := LNewLen;
  Result := nil;
end;

function TBufferedIesCipher.DoFinal: TCryptoLibByteArray;
var
  LBlock: TCryptoLibByteArray;
begin
  LBlock := FEngine.ProcessBlock(FBuffer, 0, FBufferLen);
  Reset();
  Result := LBlock;
end;

function TBufferedIesCipher.DoFinal(const AInput: TCryptoLibByteArray; AInOff,
  ALength: Int32): TCryptoLibByteArray;
begin
  ProcessBytes(AInput, AInOff, ALength);
  Result := DoFinal();
end;

procedure TBufferedIesCipher.Reset;
begin
  FBufferLen := 0;
end;

end.
