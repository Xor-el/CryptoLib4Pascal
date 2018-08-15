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

unit ClpDefiniteLengthInputStream;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  Math,
  ClpCryptoLibTypes,
  ClpLimitedInputStream;

resourcestring
  SInvalidLength = 'Negative Lengths not Allowed", "Length"';
  SEndOfStream = 'DEF Length  %d " TObject truncated by " %d';
  SInvalidBufferLength = 'Buffer Length Not Right For Data';

type
  TDefiniteLengthInputStream = class(TLimitedInputStream)

  strict private
    class var

      FEmptyBytes: TCryptoLibByteArray;

  var
    F_originalLength, F_remaining: Int32;

    function GetRemaining: Int32; reintroduce; inline;
    class function GetEmptyBytes: TCryptoLibByteArray; static; inline;

    class constructor DefiniteLengthInputStream();

  public

    constructor Create(inStream: TStream; length: Int32);

    function ReadByte(): Int32; override;

    function Read(buf: TCryptoLibByteArray; off, len: Int32): Int32; override;

    procedure ReadAllIntoByteArray(var buf: TCryptoLibByteArray);

    function ToArray: TCryptoLibByteArray;

    property Remaining: Int32 read GetRemaining;
    class property EmptyBytes: TCryptoLibByteArray read GetEmptyBytes;

  end;

implementation

uses
  ClpStreams,
  ClpStreamSorter; // included here to avoid circular dependency :)

{ TDefiniteLengthInputStream }

constructor TDefiniteLengthInputStream.Create(inStream: TStream; length: Int32);
begin
  Inherited Create(inStream, length);
  if (length < 0) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidLength);
  end;

  F_originalLength := length;
  F_remaining := length;

  if (length = 0) then
  begin
    SetParentEofDetect(true);
  end;
end;

class constructor TDefiniteLengthInputStream.DefiniteLengthInputStream;
begin
  System.SetLength(FEmptyBytes, 0);
end;

class function TDefiniteLengthInputStream.GetEmptyBytes: TCryptoLibByteArray;
begin
  result := FEmptyBytes;
end;

function TDefiniteLengthInputStream.GetRemaining: Int32;
begin
  result := F_remaining;
end;

function TDefiniteLengthInputStream.Read(buf: TCryptoLibByteArray;
  off, len: Int32): Int32;
var
  toRead, numRead: Int32;

begin
  if (F_remaining = 0) then
  begin
    result := 0;
    Exit;
  end;

  toRead := Min(len, F_remaining);

  numRead := TStreamSorter.Read(F_in, buf, off, toRead);

  if (numRead < 1) then
  begin
    raise EEndOfStreamCryptoLibException.CreateResFmt(@SEndOfStream,
      [F_originalLength, F_remaining]);
  end;
  F_remaining := F_remaining - numRead;

  if (F_remaining = 0) then
  begin
    SetParentEofDetect(true);
  end;

  result := numRead;
end;

procedure TDefiniteLengthInputStream.ReadAllIntoByteArray
  (var buf: TCryptoLibByteArray);
begin
  if (F_remaining <> System.length(buf)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidBufferLength);
  end;
  F_remaining := F_remaining - TStreams.ReadFully(F_in, buf);
  if ((F_remaining <> 0)) then
  begin
    raise EEndOfStreamCryptoLibException.CreateResFmt(@SEndOfStream,
      [F_originalLength, F_remaining]);
  end;
  SetParentEofDetect(true);
end;

function TDefiniteLengthInputStream.ReadByte: Int32;
begin
  if (F_remaining = 0) then
  begin
    result := -1;
    Exit;
  end;

  // result := F_in.ReadByte();
  result := TStreamSorter.ReadByte(F_in);

  if (result < 0) then
  begin
    raise EEndOfStreamCryptoLibException.CreateResFmt(@SEndOfStream,
      [F_originalLength, F_remaining]);
  end;

  System.Dec(F_remaining);
  if (F_remaining = 0) then
  begin
    SetParentEofDetect(true);
  end;

end;

function TDefiniteLengthInputStream.ToArray: TCryptoLibByteArray;
var
  bytes: TCryptoLibByteArray;
begin
  if (F_remaining = 0) then
  begin
    result := EmptyBytes;
    Exit;
  end;
  System.SetLength(bytes, F_remaining);
  F_remaining := F_remaining - TStreams.ReadFully(F_in, bytes);
  if (F_remaining <> 0) then
  begin
    raise EEndOfStreamCryptoLibException.CreateResFmt(@SEndOfStream,
      [F_originalLength, F_remaining]);
  end;
  SetParentEofDetect(true);
  result := bytes;
end;

end.
