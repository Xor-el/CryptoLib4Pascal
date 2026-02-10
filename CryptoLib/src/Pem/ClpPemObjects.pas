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

unit ClpPemObjects;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Classes,
  Generics.Collections,
  ClpIAsn1Core,
  ClpIPemObjects,
  ClpCryptoLibTypes,
  ClpEncoders,
  ClpStringUtilities,
  ClpStreamUtilities,
  ClpConverters,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpCollectionUtilities;

type
  /// <summary>
  /// PEM header implementation.
  /// </summary>
  TPemHeader = class sealed(TInterfacedObject, IPemHeader)
  strict private
    FName: String;
    FValue: String;

    function GetName: String;
    function GetValue: String;
    function GetHashCodeInternal(const AStr: String): Int32;

  public
    constructor Create(const AName, AValue: String);

    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI} override;
    function Equals(const AObj: IPemHeader): Boolean; reintroduce;
    function ToString(): String; override;

    property Name: String read GetName;
    property Value: String read GetValue;
  end;

  /// <summary>
  /// PEM object implementation.
  /// </summary>
  TPemObject = class sealed(TInterfacedObject, IPemObject, IPemObjectGenerator)
  strict private
    FType: String;
    FHeaders: TCryptoLibGenericArray<IPemHeader>;
    FContent: TCryptoLibByteArray;

    function GetType: String;
    function GetHeaders: TCryptoLibGenericArray<IPemHeader>;
    function GetContent: TCryptoLibByteArray;

  public
    constructor Create(const AType: String; const AContent: TCryptoLibByteArray); overload;
    constructor Create(const AType: String;
      const AHeaders: TCryptoLibGenericArray<IPemHeader>;
      const AContent: TCryptoLibByteArray); overload;

    function Generate(): IPemObject;

    property &Type: String read GetType;
    property Headers: TCryptoLibGenericArray<IPemHeader> read GetHeaders;
    property Content: TCryptoLibByteArray read GetContent;
  end;

  /// <summary>
  /// PEM reader implementation.
  /// </summary>
  TPemReader = class sealed(TInterfacedObject, IPemReader)
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
    destructor Destroy(); override;

    function GetReader: TStream;
    function ReadPemObject(): IPemObject;

    property Reader: TStream read GetReader;
  end;

  /// <summary>
  /// PEM writer implementation.
  /// </summary>
  TPemWriter = class sealed(TInterfacedObject, IPemWriter)
  strict private
  const
    LineLength = Int32(64);
  var
    FWriter: TStream;
    FNlLength: Int32;
    FBuffer: TCryptoLibByteArray;

    procedure WriteEncoded(const ABytes: TCryptoLibByteArray);
    procedure WritePreEncapsulationBoundary(const AType: String);
    procedure WritePostEncapsulationBoundary(const AType: String);
    procedure WriteString(const AStr: String);
    procedure WriteLine();

  public
    constructor Create(const AWriter: TStream);
    destructor Destroy(); override;

    function GetWriter: TStream;
    function GetOutputSize(const AObj: IPemObject): Int32;
    procedure WriteObject(const AObjGen: IPemObjectGenerator);

    property Writer: TStream read GetWriter;
  end;

  /// <summary>
  /// PEM parser implementation.
  /// </summary>
  TPemParser = class sealed(TInterfacedObject, IPemParser)
  strict private
    FHeader1: String;
    FHeader2: String;
    FFooter1: String;
    FFooter2: String;

    function ReadLine(const AInStream: TStream): String;

  public
    constructor Create(const AType: String);

    function ReadPemObject(const AInStream: TStream): IAsn1Sequence;
  end;

implementation

{ TPemHeader }

constructor TPemHeader.Create(const AName, AValue: String);
begin
  Inherited Create();
  FName := AName;
  FValue := AValue;
end;

function TPemHeader.GetName: String;
begin
  Result := FName;
end;

function TPemHeader.GetValue: String;
begin
  Result := FValue;
end;

function TPemHeader.GetHashCodeInternal(const AStr: String): Int32;
begin
  if AStr = '' then
    Result := 1
  else
    Result := TStringUtilities.GetStringHashCode(AStr);
end;

function TPemHeader.GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
begin
  Result := GetHashCodeInternal(FName) + 31 * GetHashCodeInternal(FValue);
end;

function TPemHeader.Equals(const AObj: IPemHeader): Boolean;
begin
  if AObj = Self as IPemHeader then
  begin
    Result := True;
    Exit;
  end;

  if AObj = nil then
  begin
    Result := False;
    Exit;
  end;

  Result := (FName = AObj.Name) and (FValue = AObj.Value);
end;

function TPemHeader.ToString(): String;
begin
  Result := FName + ':' + FValue;
end;

{ TPemObject }

constructor TPemObject.Create(const AType: String; const AContent: TCryptoLibByteArray);
var
  LEmptyHeaders: TCryptoLibGenericArray<IPemHeader>;
begin
  System.SetLength(LEmptyHeaders, 0);
  Create(AType, LEmptyHeaders, AContent);
end;

constructor TPemObject.Create(const AType: String;
  const AHeaders: TCryptoLibGenericArray<IPemHeader>;
  const AContent: TCryptoLibByteArray);
var
  I: Int32;
begin
  Inherited Create();
  FType := AType;
  System.SetLength(FHeaders, System.Length(AHeaders));
  for I := 0 to System.Length(AHeaders) - 1 do
  begin
    FHeaders[I] := AHeaders[I];
  end;
  FContent := AContent;
end;

function TPemObject.GetType: String;
begin
  Result := FType;
end;

function TPemObject.GetHeaders: TCryptoLibGenericArray<IPemHeader>;
begin
  Result := FHeaders;
end;

function TPemObject.GetContent: TCryptoLibByteArray;
begin
  Result := FContent;
end;

function TPemObject.Generate(): IPemObject;
begin
  Result := Self as IPemObject;
end;

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

destructor TPemReader.Destroy();
begin
  FPushback.Free();
  FTextBuffer.Free();
  Inherited Destroy();
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

{ TPemWriter }

constructor TPemWriter.Create(const AWriter: TStream);
begin
  Inherited Create();
  if AWriter = nil then
    raise EArgumentNilCryptoLibException.Create('Writer cannot be nil');
  FWriter := AWriter;
  FNlLength := System.Length(sLineBreak);
  System.SetLength(FBuffer, LineLength);
end;

destructor TPemWriter.Destroy();
begin
  Inherited Destroy();
end;

function TPemWriter.GetWriter: TStream;
begin
  Result := FWriter;
end;

procedure TPemWriter.WriteString(const AStr: String);
var
  LBytes: TCryptoLibByteArray;
begin
  LBytes := TConverters.ConvertStringToBytes(AStr, TEncoding.ASCII);
  if System.Length(LBytes) > 0 then
  begin
    FWriter.Write(LBytes[0], System.Length(LBytes));
  end;
end;

procedure TPemWriter.WriteLine();
begin
  WriteString(sLineBreak);
end;

procedure TPemWriter.WritePreEncapsulationBoundary(const AType: String);
begin
  WriteString('-----BEGIN ' + AType + '-----');
  WriteLine();
end;

procedure TPemWriter.WritePostEncapsulationBoundary(const AType: String);
begin
  WriteString('-----END ' + AType + '-----');
  WriteLine();
end;

procedure TPemWriter.WriteEncoded(const ABytes: TCryptoLibByteArray);
var
  LEncoded: String;
  LEncodedBytes: TCryptoLibByteArray;
  I, LIndex, LRemaining: Int32;
begin
  LEncoded := TBase64Encoder.Encode(ABytes);
  LEncodedBytes := TConverters.ConvertStringToBytes(LEncoded, TEncoding.ASCII);

  I := 0;
  while I < System.Length(LEncodedBytes) do
  begin
    LIndex := 0;
    LRemaining := System.Length(LEncodedBytes) - I;
    if LRemaining > LineLength then
      LRemaining := LineLength;

    while LIndex < LRemaining do
    begin
      FBuffer[LIndex] := LEncodedBytes[I + LIndex];
      System.Inc(LIndex);
    end;

    FWriter.Write(FBuffer[0], LIndex);
    WriteLine();
    System.Inc(I, LineLength);
  end;
end;

function TPemWriter.GetOutputSize(const AObj: IPemObject): Int32;
var
  LDataLen, I: Int32;
  LHeader: IPemHeader;
begin
  // BEGIN and END boundaries.
  Result := (2 * (System.Length(AObj.&Type) + 10 + FNlLength)) + 6 + 4;

  if System.Length(AObj.Headers) > 0 then
  begin
    for I := 0 to System.Length(AObj.Headers) - 1 do
    begin
      LHeader := AObj.Headers[I];
      Result := Result + System.Length(LHeader.Name) + 2 + System.Length(LHeader.Value) + FNlLength;
    end;

    Result := Result + FNlLength;
  end;

  // base64 encoding
  LDataLen := ((System.Length(AObj.Content) + 2) div 3) * 4;

  Result := Result + LDataLen + (((LDataLen + LineLength - 1) div LineLength) * FNlLength);
end;

procedure TPemWriter.WriteObject(const AObjGen: IPemObjectGenerator);
var
  LObj: IPemObject;
  I: Int32;
  LHeader: IPemHeader;
begin
  LObj := AObjGen.Generate();

  WritePreEncapsulationBoundary(LObj.&Type);

  if System.Length(LObj.Headers) > 0 then
  begin
    for I := 0 to System.Length(LObj.Headers) - 1 do
    begin
      LHeader := LObj.Headers[I];
      WriteString(LHeader.Name);
      WriteString(': ');
      WriteString(LHeader.Value);
      WriteLine();
    end;

    WriteLine();
  end;

  WriteEncoded(LObj.Content);
  WritePostEncapsulationBoundary(LObj.&Type);
end;

{ TPemParser }

constructor TPemParser.Create(const AType: String);
begin
  Inherited Create();
  FHeader1 := '-----BEGIN ' + AType + '-----';
  FHeader2 := '-----BEGIN X509 ' + AType + '-----';
  FFooter1 := '-----END ' + AType + '-----';
  FFooter2 := '-----END X509 ' + AType + '-----';
end;

function TPemParser.ReadLine(const AInStream: TStream): String;
var
  LC: Int32;
  LBuilder: TStringBuilder;
begin
  LBuilder := TStringBuilder.Create;
  try
    repeat
      while True do
      begin
        // ReadByte returns 0..255, or -1 on EOF
        LC := AInStream.ReadByte;

        // EOF
        if LC < 0 then
          Break;

        // Stop on CR or LF - terminate on either one
        if (LC = Ord(#13)) or (LC = Ord(#10)) then
          Break;

        LBuilder.Append(Char(LC));
      end;
    until (LC < 0) or (LBuilder.Length > 0);

    if LC < 0 then
      Result := ''
    else
      Result := LBuilder.ToString;
  finally
    LBuilder.Free;
  end;
end;

function TPemParser.ReadPemObject(const AInStream: TStream): IAsn1Sequence;
var
  LLine: String;
  LPemBuf: TStringBuilder;
  LDecoded: TCryptoLibByteArray;
  LAsn1Obj: IAsn1Object;
begin
  Result := nil;
  LPemBuf := TStringBuilder.Create();
  try
    // Skip until we find the header
    while True do
    begin
      LLine := ReadLine(AInStream);
      if LLine = '' then
      begin
        Exit;
      end;

      if TStringUtilities.StartsWith(LLine, FHeader1) or TStringUtilities.StartsWith(LLine, FHeader2) then
        Break;
    end;

    // Read until we find the footer
    while True do
    begin
      LLine := ReadLine(AInStream);
      if LLine = '' then
      begin
        Exit;
      end;

      if TStringUtilities.StartsWith(LLine, FFooter1) or TStringUtilities.StartsWith(LLine, FFooter2) then
        Break;

      LPemBuf.Append(LLine);
    end;

    if LPemBuf.Length > 0 then
    begin
      LDecoded := TBase64Encoder.Decode(LPemBuf.ToString());
      LAsn1Obj := TAsn1Object.FromByteArray(LDecoded);

      if not Supports(LAsn1Obj, IAsn1Sequence, Result) then
        raise EIOCryptoLibException.Create('malformed PEM data encountered');
    end;
  finally
    LPemBuf.Free();
  end;
end;

end.
