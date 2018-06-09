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

unit ClpConstructedOctetStream;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  ClpCryptoLibTypes,
  ClpBaseInputStream,
  ClpIAsn1OctetStringParser,
  ClpIAsn1StreamParser;

type
  TConstructedOctetStream = class(TBaseInputStream)

  strict private
  var
    F_parser: IAsn1StreamParser;
    F_first: Boolean;
    F_currentStream: TStream;

  public
    constructor Create(const parser: IAsn1StreamParser);
    function Read(buffer: TCryptoLibByteArray; offset, count: Int32)
      : Int32; override;
    function ReadByte(): Int32; override;
  end;

implementation

uses
  ClpStreamSorter; // included here to avoid circular dependency :)

{ TConstructedOctetStream }

constructor TConstructedOctetStream.Create(const parser: IAsn1StreamParser);
begin
  Inherited Create();
  F_parser := parser;
  F_first := true;
end;

function TConstructedOctetStream.Read(buffer: TCryptoLibByteArray;
  offset, count: Int32): Int32;
var
  s, aos: IAsn1OctetStringParser;
  totalRead, numRead: Int32;
begin
  if (F_currentStream = Nil) then
  begin
    if (not F_first) then
    begin
      result := 0;
      Exit;
    end;

    if (not Supports(F_parser.ReadObject(), IAsn1OctetStringParser, s)) then
    begin
      result := 0;
      Exit;
    end;

    F_first := false;
    F_currentStream := s.GetOctetStream();
  end;

  totalRead := 0;

  while true do

  begin

    numRead := TStreamSorter.Read(F_currentStream, buffer, offset + totalRead,
      count - totalRead);

    if (numRead > 0) then
    begin
      totalRead := totalRead + numRead;

      if (totalRead = count) then
      begin
        result := totalRead;
        Exit;
      end;
    end
    else
    begin

      if (not Supports(F_parser.ReadObject(), IAsn1OctetStringParser, aos)) then
      begin
        F_currentStream := Nil;
        result := totalRead;
        Exit;
      end;

      F_currentStream := aos.GetOctetStream();
    end
  end;
  result := 0;
end;

function TConstructedOctetStream.ReadByte: Int32;
var
  s, aos: IAsn1OctetStringParser;
  b: Int32;
begin
  if (F_currentStream = Nil) then
  begin
    if (not F_first) then
    begin
      result := 0;
      Exit;
    end;

    if (not Supports(F_parser.ReadObject(), IAsn1OctetStringParser, s)) then
    begin
      result := 0;
      Exit;
    end;

    F_first := false;
    F_currentStream := s.GetOctetStream();
  end;

  while true do

  begin

    // b := F_currentStream.ReadByte();
    b := TStreamSorter.ReadByte(F_currentStream);

    if (b >= 0) then
    begin
      result := b;
      Exit;
    end;

    if (not Supports(F_parser.ReadObject(), IAsn1OctetStringParser, aos)) then
    begin
      F_currentStream := Nil;
      result := -1;
      Exit;
    end;

    F_currentStream := aos.GetOctetStream();
  end;

  result := 0;
end;

end.
