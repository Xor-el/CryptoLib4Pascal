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

unit ClpPemReader;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Classes,
  Generics.Collections,
  ClpIPemReader,
  ClpIPemHeader,
  ClpIPemObject,
  ClpPemHeader,
  ClpPemObject,
  ClpCryptoLibTypes,
  ClpEncoders,
  ClpStringUtilities,
  ClpStreamUtilities,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpCollectionUtilities;

type
  /// <summary>
  /// PEM reader implementation.
  /// </summary>
  TPemReader = class(TInterfacedObject, IPemReader)
  strict private
  const
    LineLength = Int32(64);
  var
    FReader: TStream;
    FTextBuffer: TStringBuilder;
    FPushback: TStack<Int32>;

    function BufferedString(): String;
    function SeekDash(): Boolean;
    function SeekColon(AUpTo: Int32): Boolean;
    function ConsumeDash(): Boolean;
    procedure SkipWhiteSpace();
    function Expect(const AValue: String): Boolean;
    function BufferUntilStopChar(AStopChar: Char; ASkipWhiteSpace: Boolean): Boolean;
    procedure PushBack(AValue: Int32);
    function ReadChar(): Int32;

  public
    constructor Create(const AReader: TStream);
    destructor Destroy; override;

    function GetReader: TStream;
    function ReadPemObject(): IPemObject;

    property Reader: TStream read GetReader;
  end;

implementation

{ TPemReader }

constructor TPemReader.Create(const AReader: TStream);
begin
  Inherited Create();
  if AReader = nil then
    raise EArgumentNilCryptoLibException.Create('Reader cannot be nil');
  FReader := AReader;
  FTextBuffer := TStringBuilder.Create();
  FPushback := TStack<Int32>.Create();
end;

destructor TPemReader.Destroy;
begin
  FPushback.Free;
  FTextBuffer.Free;
  Inherited Destroy;
end;

function TPemReader.GetReader: TStream;
begin
  Result := FReader;
end;

function TPemReader.ReadChar(): Int32;
var
  LByte: Byte;
  LBytesRead: Int32;
begin
  if FPushback.Count > 0 then
  begin
    Result := FPushback.Pop();
    Exit;
  end;

  LBytesRead := FReader.Read(LByte, 1);
  if LBytesRead = 0 then
    Result := -1
  else
    Result := Int32(LByte);
end;

procedure TPemReader.PushBack(AValue: Int32);
begin
  FPushback.Push(AValue);
end;

function TPemReader.BufferedString(): String;
begin
  Result := FTextBuffer.ToString();
  FTextBuffer.Length := 0;
end;

function TPemReader.SeekDash(): Boolean;
var
  LC: Int32;
begin
  LC := ReadChar();
  while LC >= 0 do
  begin
    if LC = Ord('-') then
      Break;
    LC := ReadChar();
  end;

  PushBack(LC);
  Result := LC >= 0;
end;

function TPemReader.SeekColon(AUpTo: Int32): Boolean;
var
  LC: Int32;
  LRead: TList<Int32>;
  LReadPos: Int32;
  LColonFound: Boolean;
begin
  LC := 0;
  LColonFound := False;
  LRead := TList<Int32>.Create();
  try
    while (AUpTo >= 0) and (LC >= 0) do
    begin
      LC := ReadChar();
      LRead.Add(LC);
      if LC = Ord(':') then
      begin
        LColonFound := True;
        Break;
      end;
      System.Dec(AUpTo);
    end;

    LReadPos := LRead.Count;
    while LReadPos > 0 do
    begin
      System.Dec(LReadPos);
      PushBack(LRead[LReadPos]);
    end;

    Result := LColonFound;
  finally
    LRead.Free();
  end;
end;

function TPemReader.ConsumeDash(): Boolean;
var
  LC: Int32;
begin
  LC := ReadChar();
  while LC >= 0 do
  begin
    if LC <> Ord('-') then
      Break;
    LC := ReadChar();
  end;

  PushBack(LC);
  Result := LC >= 0;
end;

procedure TPemReader.SkipWhiteSpace();
var
  LC: Int32;
begin
  LC := ReadChar();
  while LC >= 0 do
  begin
    if LC > Ord(' ') then
      Break;
    LC := ReadChar();
  end;

  PushBack(LC);
end;

function TPemReader.Expect(const AValue: String): Boolean;
var
  I, LPos: Int32;
  LC: Int32;
begin
  for I := 1 to System.Length(AValue) do
  begin
    LC := ReadChar();
    if LC <> Ord(AValue[I]) then
    begin
      // Push back the character we just read
      PushBack(LC);
      // Push back all previously read characters
      LPos := I - 1;
      while LPos > 0 do
      begin
        PushBack(Ord(AValue[LPos]));
        System.Dec(LPos);
      end;
      Result := False;
      Exit;
    end;
  end;
  Result := True;
end;

function TPemReader.BufferUntilStopChar(AStopChar: Char; ASkipWhiteSpace: Boolean): Boolean;
var
  LC: Int32;
begin
  LC := ReadChar();
  while LC >= 0 do
  begin
    if ASkipWhiteSpace and (LC <= Ord(' ')) then
    begin
      LC := ReadChar();
      Continue;
    end;

    if LC = Ord(AStopChar) then
    begin
      PushBack(LC);
      Break;
    end;

    // Append character to buffer
    FTextBuffer.Append(Char(LC));
    LC := ReadChar();
  end;

  Result := LC >= 0;
end;

function TPemReader.ReadPemObject(): IPemObject;
var
  LType: String;
  LHeaders: TList<IPemHeader>;
  LKey, LValue: String;
  LC: Int32;
  LPayload: String;
  LDecodedContent: TCryptoLibByteArray;
  LHeadersArray: TCryptoLibGenericArray<IPemHeader>;
begin
  Result := nil;

  // Look for BEGIN
  while True do
  begin
    // Seek a leading dash, ignore anything up to that point.
    if not SeekDash() then
      Exit;

    // consume dash [-----]BEGIN ...
    if not ConsumeDash() then
      raise EIOCryptoLibException.Create('no data after consuming leading dashes');

    SkipWhiteSpace();

    if Expect('BEGIN') then
      Break;
  end;

  SkipWhiteSpace();

  // Consume type, accepting whitespace
  if not BufferUntilStopChar('-', False) then
    raise EIOCryptoLibException.Create('ran out of data before consuming type');

  LType := TStringUtilities.Trim(BufferedString());

  // Consume dashes after type.
  if not ConsumeDash() then
    raise EIOCryptoLibException.Create('ran out of data consuming header');

  SkipWhiteSpace();

  // Read ahead looking for headers.
  // Look for a colon for up to 64 characters, as an indication there might be a header.
  LHeaders := TList<IPemHeader>.Create();
  try
    while SeekColon(LineLength) do
    begin
      if not BufferUntilStopChar(':', False) then
        raise EIOCryptoLibException.Create('ran out of data reading header key value');

      LKey := TStringUtilities.Trim(BufferedString());

      LC := ReadChar();
      if LC <> Ord(':') then
        raise EIOCryptoLibException.Create('expected colon');

      // We are going to look for well formed headers, if they do not end with a "LF" we cannot
      // discern where they end.
      if not BufferUntilStopChar(#10, False) then
        raise EIOCryptoLibException.Create('ran out of data before consuming header value');

      SkipWhiteSpace();

      LValue := TStringUtilities.Trim(BufferedString());
      LHeaders.Add(TPemHeader.Create(LKey, LValue));
    end;

    // Consume payload, ignoring all white space until we encounter a '-'
    SkipWhiteSpace();

    if not BufferUntilStopChar('-', True) then
      raise EIOCryptoLibException.Create('ran out of data before consuming payload');

    LPayload := BufferedString();

    // Seek the start of the end.
    if not SeekDash() then
      raise EIOCryptoLibException.Create('did not find leading ''-''');

    if not ConsumeDash() then
      raise EIOCryptoLibException.Create('no data after consuming trailing dashes');

    if not Expect('END ' + LType) then
      raise EIOCryptoLibException.Create('END ' + LType + ' was not found.');

    if not SeekDash() then
      raise EIOCryptoLibException.Create('did not find ending ''-''');

    // consume trailing dashes.
    ConsumeDash();

    // Decode base64 payload
    LDecodedContent := TBase64Encoder.Decode(LPayload);

    // Convert headers list to array
    LHeadersArray := TCollectionUtilities.ToArray<IPemHeader>(LHeaders);

    Result := TPemObject.Create(LType, LHeadersArray, LDecodedContent);
  finally
    LHeaders.Free();
  end;
end;

end.
