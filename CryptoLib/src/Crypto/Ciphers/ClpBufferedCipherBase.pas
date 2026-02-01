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

unit ClpBufferedCipherBase;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBufferedCipher,
  ClpICipherParameters,
  ClpIBufferedCipherBase,
  ClpCryptoLibTypes;

resourcestring
  SOutputBufferTooSmall = 'Output Buffer too Short';

type
  TBufferedCipherBase = class abstract(TInterfacedObject, IBufferedCipherBase, IBufferedCipher)

  strict private

    class function GetEmptyBuffer: TCryptoLibByteArray; static; inline;

  strict protected

    function GetAlgorithmName: String; virtual; abstract;

    class function GetFullBlocksSize(ATotalSize, ABlockSize: Int32): Int32; static;

    class property EmptyBuffer: TCryptoLibByteArray read GetEmptyBuffer;

  public

    constructor Create();

    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters); virtual; abstract;

    function GetBlockSize(): Int32; virtual; abstract;

    function GetOutputSize(AInputLen: Int32): Int32; virtual; abstract;
    function GetUpdateOutputSize(AInputLen: Int32): Int32; virtual; abstract;

    function ProcessByte(AInput: Byte): TCryptoLibByteArray; overload; virtual; abstract;

    function ProcessByte(AInput: Byte; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload; virtual;

    function ProcessBytes(const AInput: TCryptoLibByteArray): TCryptoLibByteArray; overload; virtual;

    function ProcessBytes(const AInput: TCryptoLibByteArray; AInOff, ALength: Int32): TCryptoLibByteArray; overload; virtual; abstract;

    function ProcessBytes(const AInput, AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload; virtual;

    function ProcessBytes(const AInput: TCryptoLibByteArray; AInOff: Int32; ALength: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload; virtual;

    function DoFinal(): TCryptoLibByteArray; overload; virtual; abstract;

    function DoFinal(const AInput: TCryptoLibByteArray): TCryptoLibByteArray; overload; virtual;

    function DoFinal(const AInput: TCryptoLibByteArray; AInOff, ALength: Int32): TCryptoLibByteArray; overload; virtual; abstract;

    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload; virtual;

    function DoFinal(const AInput, AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload; virtual;

    function DoFinal(const AInput: TCryptoLibByteArray; AInOff, ALength: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload; virtual;

    procedure Reset(); virtual; abstract;

    property AlgorithmName: String read GetAlgorithmName;

  end;

implementation

{ TBufferedCipherBase }

constructor TBufferedCipherBase.Create;
begin
  Inherited Create();
end;

function TBufferedCipherBase.DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LOutBytes: TCryptoLibByteArray;
begin
  LOutBytes := DoFinal();
  if ((AOutOff + System.Length(LOutBytes)) > System.Length(AOutput)) then
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooSmall);
  System.Move(LOutBytes[0], AOutput[AOutOff], System.Length(LOutBytes));
  Result := System.Length(LOutBytes);
end;

function TBufferedCipherBase.DoFinal(const AInput: TCryptoLibByteArray): TCryptoLibByteArray;
begin
  Result := DoFinal(AInput, 0, System.Length(AInput));
end;

function TBufferedCipherBase.DoFinal(const AInput: TCryptoLibByteArray; AInOff, ALength: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LLen: Int32;
begin
  LLen := ProcessBytes(AInput, AInOff, ALength, AOutput, AOutOff);
  LLen := LLen + DoFinal(AOutput, AOutOff + LLen);
  Result := LLen;
end;

function TBufferedCipherBase.DoFinal(const AInput, AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  Result := DoFinal(AInput, 0, System.Length(AInput), AOutput, AOutOff);
end;

class function TBufferedCipherBase.GetEmptyBuffer: TCryptoLibByteArray;
begin
  Result := nil;
end;

class function TBufferedCipherBase.GetFullBlocksSize(ATotalSize, ABlockSize: Int32): Int32;
var
  LBlockSizeMask: Int32;
begin
  if ABlockSize <= 0 then
  begin
    Result := 0;
    Exit;
  end;
  if ATotalSize < 0 then
  begin
    Result := 0;
    Exit;
  end;
  LBlockSizeMask := ABlockSize - 1;
  if ((ABlockSize and LBlockSizeMask) = 0) then
    Result := ATotalSize and (not LBlockSizeMask)
  else
    Result := ATotalSize - (ATotalSize mod ABlockSize);
end;

function TBufferedCipherBase.ProcessByte(AInput: Byte; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LOutBytes: TCryptoLibByteArray;
begin
  LOutBytes := ProcessByte(AInput);
  if (LOutBytes = nil) then
  begin
    Result := 0;
    Exit;
  end;
  if ((AOutOff + System.Length(LOutBytes)) > System.Length(AOutput)) then
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooSmall);
  System.Move(LOutBytes[0], AOutput[AOutOff], System.Length(LOutBytes));
  Result := System.Length(LOutBytes);
end;

function TBufferedCipherBase.ProcessBytes(const AInput: TCryptoLibByteArray): TCryptoLibByteArray;
begin
  Result := ProcessBytes(AInput, 0, System.Length(AInput));
end;

function TBufferedCipherBase.ProcessBytes(const AInput: TCryptoLibByteArray; AInOff, ALength: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LOutBytes: TCryptoLibByteArray;
begin
  LOutBytes := ProcessBytes(AInput, AInOff, ALength);
  if (LOutBytes = nil) then
  begin
    Result := 0;
    Exit;
  end;
  if ((AOutOff + System.Length(LOutBytes)) > System.Length(AOutput)) then
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooSmall);
  System.Move(LOutBytes[0], AOutput[AOutOff], System.Length(LOutBytes));
  Result := System.Length(LOutBytes);
end;

function TBufferedCipherBase.ProcessBytes(const AInput, AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  Result := ProcessBytes(AInput, 0, System.Length(AInput), AOutput, AOutOff);
end;

end.
