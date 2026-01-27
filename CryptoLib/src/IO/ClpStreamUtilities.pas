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

unit ClpStreamUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  ClpCryptoLibTypes,
  ClpStreams;

type
  /// <summary>
  /// Utility class with static methods for stream operations.
  /// </summary>
  TStreamUtilities = class sealed(TObject)

  strict private
  const
    MaxStackAlloc = Int32(4096);

  public
    class function DefaultBufferSize: Int32; static; inline;

    class procedure CopyTo(const ASource: TStream; const ADestination: TStream;
      ABufferSize: Int32); overload; static;
    class procedure CopyTo(const ASource: TStream;
      const ADestination: TStream); overload; static;

    class procedure Drain(const AInStr: TStream); static;

    class procedure PipeAll(const AInStr: TStream; const AOutStr: TStream;
      ABufferSize: Int32); overload; static;
    class procedure PipeAll(const AInStr: TStream;
      AOutStr: TStream); overload; static;

    class function PipeAllLimited(const AInStr: TStream; ALimit: Int64;
      const AOutStr: TStream; ABufferSize: Int32): Int64; overload; static;
    class function PipeAllLimited(const AInStr: TStream; ALimit: Int64;
      const AOutStr: TStream): Int64; overload; static;

    class function ReadAll(const AInStr: TStream): TCryptoLibByteArray; static;

    class function ReadAllLimited(const AInStr: TStream;
      ALimit: Int32): TCryptoLibByteArray; static;

    class function ReadFully(const AInStr: TStream;
      const ABuf: TCryptoLibByteArray; AOff, ALen: Int32): Int32; overload; static;
    class function ReadFully(const AInStr: TStream;
      const ABuf: TCryptoLibByteArray): Int32; overload; static;

    class procedure ValidateBufferArguments(const ABuffer: TCryptoLibByteArray;
      AOffset, ACount: Int32); static;

    class function WriteBufTo(const ABuf: TMemoryStream;
      const AOutput: TCryptoLibByteArray; AOffset: Int32): Int32; static;

  end;

type
  /// <summary>
  /// Class helper for TStream to add ReadByte, WriteByte, Flush, and capability properties.
  /// </summary>
  TStreamHelper = class helper for TStream
  public
    function ReadByte(): Int32;
    procedure WriteByte(AValue: Byte);
    procedure Flush;

    function GetCanRead: Boolean;
    function GetCanSeek: Boolean;
    function GetCanWrite: Boolean;

    property CanRead: Boolean read GetCanRead;
    property CanSeek: Boolean read GetCanSeek;
    property CanWrite: Boolean read GetCanWrite;
  end;

implementation

{ TStreamUtilities }

class function TStreamUtilities.DefaultBufferSize: Int32;
begin
  Result := MaxStackAlloc;
end;

class procedure TStreamUtilities.CopyTo(const ASource: TStream;
  const ADestination: TStream; ABufferSize: Int32);
var
  LBytesRead: Int32;
  LBuffer: TCryptoLibByteArray;
begin
  System.SetLength(LBuffer, ABufferSize);
  LBytesRead := ASource.Read(LBuffer, 0, ABufferSize);
  while LBytesRead <> 0 do
  begin
    ADestination.Write(LBuffer, 0, LBytesRead);
    LBytesRead := ASource.Read(LBuffer, 0, ABufferSize);
  end;
end;

class procedure TStreamUtilities.CopyTo(const ASource: TStream;
  const ADestination: TStream);
begin
  CopyTo(ASource, ADestination, DefaultBufferSize);
end;

class procedure TStreamUtilities.Drain(const AInStr: TStream);
var
  LBuffer: TCryptoLibByteArray;
  LBytesRead: Int32;
begin
  System.SetLength(LBuffer, DefaultBufferSize);
  LBytesRead := AInStr.Read(LBuffer, 0, DefaultBufferSize);
  while LBytesRead > 0 do
  begin
    // Discard the data
    LBytesRead := AInStr.Read(LBuffer, 0, DefaultBufferSize);
  end;
end;

class procedure TStreamUtilities.PipeAll(const AInStr: TStream; const AOutStr: TStream;
  ABufferSize: Int32);
begin
  CopyTo(AInStr, AOutStr, ABufferSize);
end;

class procedure TStreamUtilities.PipeAll(const AInStr: TStream;
  AOutStr: TStream);
begin
  PipeAll(AInStr, AOutStr, DefaultBufferSize);
end;

class function TStreamUtilities.PipeAllLimited(const AInStr: TStream;
  ALimit: Int64; const AOutStr: TStream; ABufferSize: Int32): Int64;
var
  LLimited: TLimitedInputStream;
begin
  LLimited := TLimitedInputStream.Create(AInStr, ALimit);
  try
    CopyTo(LLimited, AOutStr, ABufferSize);
    Result := ALimit - LLimited.CurrentLimit;
  finally
    LLimited.Free;
  end;
end;

class function TStreamUtilities.PipeAllLimited(const AInStr: TStream;
  ALimit: Int64; const AOutStr: TStream): Int64;
begin
  Result := PipeAllLimited(AInStr, ALimit, AOutStr, DefaultBufferSize);
end;

class function TStreamUtilities.ReadAll(const AInStr: TStream): TCryptoLibByteArray;
var
  LBuf: TMemoryStream;
begin
  LBuf := TMemoryStream.Create();
  try
    PipeAll(AInStr, LBuf);
    System.SetLength(Result, LBuf.Size);
    LBuf.Position := 0;
    LBuf.Read(Result, 0, LBuf.Size);
  finally
    LBuf.Free;
  end;
end;

class function TStreamUtilities.ReadAllLimited(const AInStr: TStream;
  ALimit: Int32): TCryptoLibByteArray;
var
  LBuf: TMemoryStream;
begin
  LBuf := TMemoryStream.Create();
  try
    PipeAllLimited(AInStr, ALimit, LBuf);
    System.SetLength(Result, LBuf.Size);
    LBuf.Position := 0;
    LBuf.Read(Result, 0, LBuf.Size);
  finally
    LBuf.Free;
  end;
end;

class function TStreamUtilities.ReadFully(const AInStr: TStream;
  const ABuf: TCryptoLibByteArray; AOff, ALen: Int32): Int32;
var
  LTotalRead, LNumRead: Int32;
begin
  LTotalRead := 0;
  while LTotalRead < ALen do
  begin
    LNumRead := AInStr.Read(ABuf, AOff + LTotalRead, ALen - LTotalRead);
    if LNumRead < 1 then
      break;
    LTotalRead := LTotalRead + LNumRead;
  end;
  Result := LTotalRead;
end;

class function TStreamUtilities.ReadFully(const AInStr: TStream;
  const ABuf: TCryptoLibByteArray): Int32;
begin
  Result := ReadFully(AInStr, ABuf, 0, System.Length(ABuf));
end;

class procedure TStreamUtilities.ValidateBufferArguments(const ABuffer
  : TCryptoLibByteArray; AOffset, ACount: Int32);
var
  LAvailable, LRemaining: Int32;
begin
  if ABuffer = nil then
    raise EArgumentNilCryptoLibException.Create('Buffer cannot be nil');
  LAvailable := System.Length(ABuffer) - AOffset;
  if ((AOffset or LAvailable) < 0) then
    raise EArgumentOutOfRangeCryptoLibException.Create('Offset out of range');
  LRemaining := LAvailable - ACount;
  if ((ACount or LRemaining) < 0) then
    raise EArgumentOutOfRangeCryptoLibException.Create('Count out of range');
end;

class function TStreamUtilities.WriteBufTo(const ABuf: TMemoryStream;
  const AOutput: TBytes; AOffset: Integer): Integer;
begin
  Result := ABuf.Size;

  if (AOffset < 0) or (AOffset + Result > Length(AOutput)) then
    raise ERangeError.Create('Output buffer too small');

  // Copy directly from stream buffer into the byte array
  Move(PByte(ABuf.Memory)^, AOutput[AOffset], Result);
end;

{ TStreamHelper }

function TStreamHelper.ReadByte(): Int32;
var
  LBuffer: TCryptoLibByteArray;
begin
  LBuffer := nil;
  if Self is TBaseStream then
    Result := (Self as TBaseStream).ReadByte
  else
  begin
    System.SetLength(LBuffer, 1);
    if Self.Read(LBuffer, 0, 1) = 0 then
      Result := -1
    else
      Result := Int32(LBuffer[0]);
  end;
end;

procedure TStreamHelper.WriteByte(AValue: Byte);
var
  LOneByteArray: TCryptoLibByteArray;
begin
  if Self is TBaseStream then
   (Self as TBaseStream).WriteByte(AValue)
  else
  begin
    System.SetLength(LOneByteArray, 1);
    LOneByteArray[0] := AValue;
    Self.Write(LOneByteArray, 0, 1);
  end;
end;

procedure TStreamHelper.Flush;
begin
  if Self is TBaseStream then
    (Self as TBaseStream).Flush
  else
  begin
   // For plain TStream, Flush is a no-op (do nothing)
  end;
end;

function TStreamHelper.GetCanRead: Boolean;
begin
  if Self is TBaseStream then
    Result := (Self as TBaseStream).CanRead
  else
    Result := True; // Default for TStream
end;

function TStreamHelper.GetCanSeek: Boolean;
begin
  if Self is TBaseStream then
    Result := (Self as TBaseStream).CanSeek
  else
    Result := True; // Default for TStream
end;

function TStreamHelper.GetCanWrite: Boolean;
begin
  if Self is TBaseStream then
    Result := (Self as TBaseStream).CanWrite
  else
    Result := True; // Default for TStream
end;

end.
