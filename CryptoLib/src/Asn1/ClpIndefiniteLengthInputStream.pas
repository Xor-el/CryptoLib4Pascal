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

unit ClpIndefiniteLengthInputStream;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpCryptoLibTypes,
  ClpLimitedInputStream;

resourcestring
  SMalformedContent = 'Malformed End-of-Contents Marker';

type
  TIndefiniteLengthInputStream = class(TLimitedInputStream)

  strict private
  var
    F_lookAhead: Int32;
    F_eofOn00: Boolean;

    function CheckForEof(): Boolean; inline;
    function RequireByte(): Int32; inline;

  public
    constructor Create(inStream: TStream; limit: Int32);
    procedure SetEofOn00(eofOn00: Boolean);

    function Read(buffer: TCryptoLibByteArray; offset, count: Int32)
      : Int32; override;

    function ReadByte(): Int32; override;

  end;

implementation

uses
  ClpStreamSorter; // included here to avoid circular dependency :)

{ TIndefiniteLengthInputStream }

function TIndefiniteLengthInputStream.RequireByte: Int32;
begin

  // result := F_in.ReadByte();
  result := TStreamSorter.ReadByte(F_in);

  if (result < 0) then
  begin
    // Corrupted stream
    raise EEndOfStreamCryptoLibException.Create('');
  end;
end;

function TIndefiniteLengthInputStream.CheckForEof: Boolean;
var
  extra: Int32;
begin
  if (F_lookAhead = $00) then
  begin
    extra := RequireByte();
    if (extra <> 0) then
    begin
      raise EIOCryptoLibException.CreateRes(@SMalformedContent);
    end;

    F_lookAhead := -1;
    SetParentEofDetect(true);
    result := true;
    Exit;
  end;
  result := F_lookAhead < 0;
end;

constructor TIndefiniteLengthInputStream.Create(inStream: TStream;
  limit: Int32);
begin
  Inherited Create(inStream, limit);
  F_lookAhead := RequireByte();
  CheckForEof();
end;

function TIndefiniteLengthInputStream.Read(buffer: TCryptoLibByteArray;
  offset, count: Int32): Int32;
var
  numRead: Int32;
begin
  // Only use this optimisation if we aren't checking for 00
  if ((F_eofOn00) or (count <= 1)) then
  begin
    result := (Inherited Read(buffer, offset, count));
    Exit;
  end;

  if (F_lookAhead < 0) then
  begin
    result := 0;
    Exit;
  end;

  numRead := TStreamSorter.Read(F_in, buffer, offset + 1, count - 1);

  if (numRead <= 0) then
  begin
    // Corrupted stream
    raise EEndOfStreamCryptoLibException.Create('');
  end;

  buffer[offset] := Byte(F_lookAhead);
  F_lookAhead := RequireByte();

  result := numRead + 1;
end;

function TIndefiniteLengthInputStream.ReadByte: Int32;
begin
  if (F_eofOn00 and CheckForEof()) then
  begin
    result := -1;
    Exit;
  end;

  result := F_lookAhead;
  F_lookAhead := RequireByte();

end;

procedure TIndefiniteLengthInputStream.SetEofOn00(eofOn00: Boolean);
begin
  F_eofOn00 := eofOn00;
  if (F_eofOn00) then
  begin
    CheckForEof();
  end;
end;

end.
