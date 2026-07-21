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

unit Asn1StreamReadTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
  Math,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpAsn1Streams,
  ClpAsn1Parsers,
  ClpIAsn1Parsers,
  ClpIAsn1Generators,
  ClpAsn1Generators,
  ClpIAsn1Core,
  ClpAsn1Core,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  ClpArrayUtilities,
  ClpStreams,
  ClpStreamUtilities,
  CryptoLibTestBase;

type

  TRecordingStream = class(TBaseInputStream)
  strict private
    FData: TCryptoLibByteArray;
    FPos: Int32;
    FFirstBulkReadLength: Int32;

    procedure RecordFirstBulkReadLength(ALength: Int32);
  public
    constructor Create(const AData: TCryptoLibByteArray);

    function Read(var ABuffer; ACount: LongInt): LongInt; override;
    function Read(ABuffer: TCryptoLibByteArray; AOffset, ACount: LongInt): LongInt; override;
    function ReadByte: Int32; override;

    property FirstBulkReadLength: Int32 read FFirstBulkReadLength;
  end;

  TProbeConstructedOctetStream = class(TAsn1ConstructedOctetStream)
  strict private
    FReadByteCallCount: Int32;
  public
    constructor Create(const AParser: IAsn1StreamParser);

    function Read(var ABuffer; ACount: LongInt): LongInt; override;
    function Read(ABuffer: TCryptoLibByteArray; AOffset, ACount: LongInt): LongInt; override;
    function ReadByte: Int32; override;

    property ReadByteCallCount: Int32 read FReadByteCallCount;
  end;

  TProbeConstructedBitStream = class(TAsn1ConstructedBitStream)
  strict private
    FReadByteCallCount: Int32;
  public
    constructor Create(const AParser: IAsn1StreamParser; AOctetAligned: Boolean);

    function Read(var ABuffer; ACount: LongInt): LongInt; override;
    function Read(ABuffer: TCryptoLibByteArray; AOffset, ACount: LongInt): LongInt; override;
    function ReadByte: Int32; override;

    property ReadByteCallCount: Int32 read FReadByteCallCount;
  end;

  TAsn1StreamReadTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    const
      LargePayloadSize = 5000;
      MaxReadByteCallsForBulkPath = 16;

    function BuildBerIndefiniteOctetEncoding(const APayload: TCryptoLibByteArray): TCryptoLibByteArray;
    function BuildBerIndefiniteConstructedBitString(const APayload: TCryptoLibByteArray): TCryptoLibByteArray;

  published
    procedure TestConstructedOctetReadAllRoundTrip;
    procedure TestConstructedOctetReadAllUsesBulkVarRead;
    procedure TestConstructedBitReadAllRoundTrip;
    procedure TestConstructedBitReadAllUsesBulkVarRead;
    procedure TestIndefiniteLengthBulkReadDelegatesToWrappedStream;
    procedure TestIndefiniteLengthRespectsEndOfContentsMarker;
    procedure TestIndefiniteLengthMalformedEndOfContentsRaises;
    procedure TestTaggedPrimitiveWithEmptyContentsDecodes;
    procedure TestImplicitNullRoundTrips;
    procedure TestOctetStringContentsNilIsEmptyNotAnError;
    procedure TestOctetStringFromContentsNilIsEmptyNotAnError;
    procedure TestSequenceAndSetFromNilGenericArrayAreEmpty;
    procedure TestBmpStringAndAddAllAcceptEmpty;
    procedure TestEmptyStringTypesAreAccepted;
    procedure TestBitStringEmptyDataWithZeroPadBitsIsAccepted;
  end;

implementation

{ TRecordingStream }

constructor TRecordingStream.Create(const AData: TCryptoLibByteArray);
begin
  inherited Create;
  FData := AData;
  FPos := 0;
  FFirstBulkReadLength := -1;
end;

procedure TRecordingStream.RecordFirstBulkReadLength(ALength: Int32);
begin
  if FFirstBulkReadLength < 0 then
    FFirstBulkReadLength := ALength;
end;

function TRecordingStream.Read(var ABuffer; ACount: LongInt): LongInt;
var
  LToRead: Int32;
begin
  RecordFirstBulkReadLength(ACount);

  if FPos >= System.Length(FData) then
  begin
    Result := 0;
    Exit;
  end;

  LToRead := Min(ACount, System.Length(FData) - FPos);
  Move(FData[FPos], ABuffer, LToRead);
  Inc(FPos, LToRead);
  Result := LToRead;
end;

function TRecordingStream.Read(ABuffer: TCryptoLibByteArray; AOffset, ACount: LongInt): LongInt;
begin
  TStreamUtilities.ValidateBufferArguments(ABuffer, AOffset, ACount);
  Result := Read(ABuffer[AOffset], ACount);
end;

function TRecordingStream.ReadByte: Int32;
begin
  if FPos >= System.Length(FData) then
    Result := -1
  else
  begin
    Result := FData[FPos];
    Inc(FPos);
  end;
end;

{ TProbeConstructedOctetStream }

constructor TProbeConstructedOctetStream.Create(const AParser: IAsn1StreamParser);
begin
  inherited Create(AParser);
  FReadByteCallCount := 0;
end;

function TProbeConstructedOctetStream.Read(var ABuffer; ACount: LongInt): LongInt;
begin
  Result := inherited Read(ABuffer, ACount);
end;

function TProbeConstructedOctetStream.Read(ABuffer: TCryptoLibByteArray; AOffset, ACount: LongInt): LongInt;
begin
  TStreamUtilities.ValidateBufferArguments(ABuffer, AOffset, ACount);
  Result := Read(ABuffer[AOffset], ACount);
end;

function TProbeConstructedOctetStream.ReadByte: Int32;
begin
  Inc(FReadByteCallCount);
  Result := inherited ReadByte;
end;

{ TProbeConstructedBitStream }

constructor TProbeConstructedBitStream.Create(const AParser: IAsn1StreamParser;
  AOctetAligned: Boolean);
begin
  inherited Create(AParser, AOctetAligned);
  FReadByteCallCount := 0;
end;

function TProbeConstructedBitStream.Read(var ABuffer; ACount: LongInt): LongInt;
begin
  Result := inherited Read(ABuffer, ACount);
end;

function TProbeConstructedBitStream.Read(ABuffer: TCryptoLibByteArray; AOffset, ACount: LongInt): LongInt;
begin
  TStreamUtilities.ValidateBufferArguments(ABuffer, AOffset, ACount);
  Result := Read(ABuffer[AOffset], ACount);
end;

function TProbeConstructedBitStream.ReadByte: Int32;
begin
  Inc(FReadByteCallCount);
  Result := inherited ReadByte;
end;

{ TAsn1StreamReadTest }

function TAsn1StreamReadTest.BuildBerIndefiniteOctetEncoding
  (const APayload: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LBOut: TMemoryStream;
  LOctGen: IBerOctetStringGenerator;
  LOutStream: TStream;
begin
  LBOut := TMemoryStream.Create();
  try
    LOctGen := TBerOctetStringGenerator.Create(LBOut);
    LOutStream := LOctGen.GetOctetOutputStream();
    try
      if System.Length(APayload) > 0 then
        LOutStream.Write(APayload[0], System.Length(APayload));
    finally
      LOutStream.Free;
    end;
    LOctGen := nil;

    LBOut.Position := 0;
    System.SetLength(Result, LBOut.Size);
    LBOut.Read(Result[0], System.Length(Result));
  finally
    LBOut.Free;
  end;
end;

function TAsn1StreamReadTest.BuildBerIndefiniteConstructedBitString
  (const APayload: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LFragmentBodyLen, LFragmentLen, LTotalLen, LI: Int32;
begin
  LFragmentBodyLen := 1 + System.Length(APayload);
  LFragmentLen := 1 + 3 + LFragmentBodyLen;
  LTotalLen := 2 + LFragmentLen + 2;

  System.SetLength(Result, LTotalLen);
  LI := 0;
  Result[LI] := $23;
  Inc(LI);
  Result[LI] := $80;
  Inc(LI);

  Result[LI] := $03;
  Inc(LI);
  Result[LI] := $82;
  Inc(LI);
  Result[LI] := Byte((LFragmentBodyLen shr 8) and $FF);
  Inc(LI);
  Result[LI] := Byte(LFragmentBodyLen and $FF);
  Inc(LI);
  Result[LI] := 0;
  Inc(LI);

  if System.Length(APayload) > 0 then
  begin
    Move(APayload[0], Result[LI], System.Length(APayload));
    Inc(LI, System.Length(APayload));
  end;

  Result[LI] := 0;
  Inc(LI);
  Result[LI] := 0;
end;

procedure TAsn1StreamReadTest.TestConstructedOctetReadAllRoundTrip;
var
  LPayload, LEncoding: TCryptoLibByteArray;
  LParser: IAsn1StreamParser;
  LOctets: IBerOctetString;
  LI: Int32;
begin
  System.SetLength(LPayload, LargePayloadSize);
  for LI := 0 to LargePayloadSize - 1 do
    LPayload[LI] := Byte(LI);

  LEncoding := BuildBerIndefiniteOctetEncoding(LPayload);
  LParser := TAsn1StreamParser.Create(LEncoding);
  LOctets := TBerOctetStringParser.Parse(LParser);

  CheckTrue(TArrayUtilities.AreEqual(LPayload, LOctets.GetOctets()),
    'constructed BER octet string did not round-trip through ReadAll');
end;

procedure TAsn1StreamReadTest.TestConstructedOctetReadAllUsesBulkVarRead;
var
  LPayload, LEncoding, LActual: TCryptoLibByteArray;
  LParser: IAsn1StreamParser;
  LProbe: TProbeConstructedOctetStream;
  LI: Int32;
begin
  System.SetLength(LPayload, LargePayloadSize);
  for LI := 0 to LargePayloadSize - 1 do
    LPayload[LI] := Byte(LI);

  LEncoding := BuildBerIndefiniteOctetEncoding(LPayload);
  LParser := TAsn1StreamParser.Create(LEncoding);
  LProbe := TProbeConstructedOctetStream.Create(LParser);
  try
    LActual := TStreamUtilities.ReadAll(LProbe);
    CheckTrue(TArrayUtilities.AreEqual(LPayload, LActual),
      'constructed BER octet stream did not materialize payload');

    if LProbe.ReadByteCallCount > MaxReadByteCallsForBulkPath then
      Fail(Format('constructed octet stream used byte-at-a-time reads (%d ReadByte calls)',
        [LProbe.ReadByteCallCount]));
  finally
    LProbe.Free;
  end;
end;

procedure TAsn1StreamReadTest.TestConstructedBitReadAllRoundTrip;
var
  LPayload, LEncoding, LActual: TCryptoLibByteArray;
  LParser: IAsn1StreamParser;
  LBits: IBerBitString;
  LI: Int32;
begin
  System.SetLength(LPayload, LargePayloadSize);
  for LI := 0 to LargePayloadSize - 1 do
    LPayload[LI] := Byte(LI xor $5A);

  LEncoding := BuildBerIndefiniteConstructedBitString(LPayload);
  LParser := TAsn1StreamParser.Create(LEncoding);
  LBits := TBerBitStringParser.Parse(LParser);

  LActual := LBits.GetBytes();
  CheckTrue(TArrayUtilities.AreEqual(LPayload, LActual),
    'constructed BER bit string did not round-trip through ReadAll');
end;

procedure TAsn1StreamReadTest.TestConstructedBitReadAllUsesBulkVarRead;
var
  LPayload, LEncoding, LActual: TCryptoLibByteArray;
  LParser: IAsn1StreamParser;
  LProbe: TProbeConstructedBitStream;
  LI: Int32;
begin
  System.SetLength(LPayload, LargePayloadSize);
  for LI := 0 to LargePayloadSize - 1 do
    LPayload[LI] := Byte(LI xor $5A);

  LEncoding := BuildBerIndefiniteConstructedBitString(LPayload);
  LParser := TAsn1StreamParser.Create(LEncoding);
  LProbe := TProbeConstructedBitStream.Create(LParser, False);
  try
    LActual := TStreamUtilities.ReadAll(LProbe);
    CheckTrue(TArrayUtilities.AreEqual(LPayload, LActual),
      'constructed BER bit stream did not materialize payload');

    if LProbe.ReadByteCallCount > MaxReadByteCallsForBulkPath then
      Fail(Format('constructed bit stream used byte-at-a-time reads (%d ReadByte calls)',
        [LProbe.ReadByteCallCount]));
  finally
    LProbe.Free;
  end;
end;

procedure TAsn1StreamReadTest.TestIndefiniteLengthBulkReadDelegatesToWrappedStream;
var
  LPayload: TCryptoLibByteArray;
  LRecording: TRecordingStream;
  LIndefinite: TAsn1IndefiniteLengthInputStream;
  LBuffer: TCryptoLibByteArray;
  LRead, LI: Int32;
begin
  System.SetLength(LPayload, LargePayloadSize);
  for LI := 0 to LargePayloadSize - 1 do
    LPayload[LI] := Byte(LI + 1);

  LRecording := TRecordingStream.Create(LPayload);
  try
    LIndefinite := TAsn1IndefiniteLengthInputStream.Create(LRecording, LargePayloadSize);
    try
      LIndefinite.SetEofOn00(False);

      System.SetLength(LBuffer, TStreamUtilities.DefaultBufferSize);
      LRead := LIndefinite.Read(LBuffer[0], System.Length(LBuffer));

      if LRead <= 1 then
        Fail(Format('indefinite stream bulk read returned too few bytes (%d)', [LRead]));

      if (LRecording.FirstBulkReadLength < 0) or (LRecording.FirstBulkReadLength <= 1) then
        Fail(Format('indefinite stream did not delegate bulk read to wrapped stream (%d)',
          [LRecording.FirstBulkReadLength]));
    finally
      LIndefinite.Free;
    end;
  finally
    LRecording.Free;
  end;
end;

procedure TAsn1StreamReadTest.TestIndefiniteLengthRespectsEndOfContentsMarker;
var
  LPayload: TCryptoLibByteArray;
  LWrapped: TMemoryStream;
  LIndefinite: TAsn1IndefiniteLengthInputStream;
  LBuffer: TCryptoLibByteArray;
  LRead, LI: Int32;
begin
  System.SetLength(LPayload, 4);
  for LI := 0 to 3 do
    LPayload[LI] := Byte(LI + 10);

  LWrapped := TMemoryStream.Create();
  try
    LWrapped.WriteBuffer(LPayload[0], System.Length(LPayload));
    LWrapped.WriteBuffer(TCryptoLibByteArray.Create(0, 0)[0], 2);
    LWrapped.Position := 0;

    LIndefinite := TAsn1IndefiniteLengthInputStream.Create(LWrapped, System.Length(LPayload) + 2);
    try
      System.SetLength(LBuffer, System.Length(LPayload));
      LRead := TStreamUtilities.ReadFully(LIndefinite, LBuffer, 0, System.Length(LBuffer));
      CheckEquals(System.Length(LPayload), LRead,
        'indefinite stream did not return payload before EOC');

      CheckTrue(TArrayUtilities.AreEqual(LPayload, LBuffer),
        'indefinite stream payload mismatch before EOC');

      LRead := LIndefinite.Read(LBuffer[0], System.Length(LBuffer));
      CheckEquals(0, LRead, 'indefinite stream should be exhausted after EOC');
    finally
      LIndefinite.Free;
    end;
  finally
    LWrapped.Free;
  end;
end;

procedure TAsn1StreamReadTest.TestIndefiniteLengthMalformedEndOfContentsRaises;
var
  LWrapped: TMemoryStream;
  LIndefinite: TAsn1IndefiniteLengthInputStream;
begin
  LWrapped := TMemoryStream.Create();
  try
    LWrapped.WriteBuffer(TCryptoLibByteArray.Create(0, 1)[0], 2);
    LWrapped.Position := 0;

    try
      LIndefinite := TAsn1IndefiniteLengthInputStream.Create(LWrapped, 2);
      try
        Fail('expected malformed end-of-contents exception');
      finally
        LIndefinite.Free;
      end;
    except
      on E: EIOCryptoLibException do
        CheckEquals('malformed end-of-contents marker', E.Message);
    end;
  finally
    LWrapped.Free;
  end;
end;

// A context-tagged implicit primitive may carry zero-length contents - RFC 6960 encodes the common
// OCSP status "good" as [0] IMPLICIT NULL, on the wire 80 00. An empty dynamic array is nil in
// Object Pascal, so a nil check on decoded contents rejects this legal encoding.
procedure TAsn1StreamReadTest.TestTaggedPrimitiveWithEmptyContentsDecodes;
var
  LObj: IAsn1Object;
begin
  LObj := TAsn1Object.FromByteArray(TCryptoLibByteArray.Create($80, $00));
  CheckNotNull(LObj, 'a tagged primitive with empty contents must decode');
end;

procedure TAsn1StreamReadTest.TestImplicitNullRoundTrips;
var
  LEncoded: TCryptoLibByteArray;
begin
  LEncoded := TAsn1Object.FromByteArray(TCryptoLibByteArray.Create($80, $00)).GetEncoded();
  CheckEquals(2, System.Length(LEncoded), 'the re-encoding must stay two bytes');
  CheckEquals(Int32($80), Int32(LEncoded[0]), 'the tag octet must survive the round trip');
  CheckEquals(Int32($00), Int32(LEncoded[1]), 'the length octet must stay zero');
end;

// WithContents and WithContentsOptional deliberately differ on nil: nil contents are an empty octet
// string, while "no contents at all" is what the Optional form reports. Pascal cannot tell an empty
// array from nil, so only the Optional form can carry absence.
procedure TAsn1StreamReadTest.TestOctetStringContentsNilIsEmptyNotAnError;
var
  LOctets: IDerOctetString;
begin
  LOctets := TDerOctetString.WithContents(nil);
  CheckNotNull(LOctets, 'nil contents must give the empty octet string, not an error');
  CheckEquals(0, System.Length(LOctets.GetOctets()), 'the octet string must be empty');

  CheckNull(TDerOctetString.WithContentsOptional(nil),
    'the optional form must still report absence as nil');
end;

// An empty OCTET STRING (04 00) is legal, and Pascal cannot tell an empty array from nil, so the
// non-optional FromContents/WithContents builders must accept nil as the empty octet string rather
// than rejecting it. Only the Optional forms carry absence.
procedure TAsn1StreamReadTest.TestOctetStringFromContentsNilIsEmptyNotAnError;
var
  LDer: IDerOctetString;
  LBer: IBerOctetString;
begin
  LDer := TDerOctetString.FromContents(nil);
  CheckNotNull(LDer, 'DER FromContents(nil) must give the empty octet string, not an error');
  CheckEquals(0, System.Length(LDer.GetOctets()), 'the DER octet string must be empty');

  LBer := TBerOctetString.WithContents(nil);
  CheckNotNull(LBer, 'BER WithContents(nil) must give the empty octet string, not an error');
  CheckEquals(0, System.Length(LBer.GetOctets()), 'the BER octet string must be empty');

  LBer := TBerOctetString.FromContents(nil);
  CheckNotNull(LBer, 'BER FromContents(nil) must give the empty octet string, not an error');
  CheckEquals(0, System.Length(LBer.GetOctets()), 'the BER octet string must be empty');

  CheckNull(TDerOctetString.FromContentsOptional(nil),
    'the DER optional form must still report absence as nil');
  CheckNull(TBerOctetString.WithContentsOptional(nil),
    'the BER optional form must still report absence as nil');
  CheckNull(TBerOctetString.FromContentsOptional(nil),
    'the BER optional form must still report absence as nil');
end;

// An empty SEQUENCE (30 00) and SET (31 00) are legal. The generic-array constructors must accept a
// nil/empty element array as the empty container rather than rejecting it.
procedure TAsn1StreamReadTest.TestSequenceAndSetFromNilGenericArrayAreEmpty;
var
  LNilElements: TCryptoLibGenericArray<IAsn1Encodable>;
  LSeq: IDerSequence;
  LSet: IDerSet;
  LEncoded: TCryptoLibByteArray;
begin
  LSeq := TDerSequence.Create(LNilElements);
  CheckNotNull(LSeq, 'an empty element array must give the empty SEQUENCE, not an error');
  CheckEquals(0, LSeq.Count, 'the SEQUENCE must have no elements');
  LEncoded := LSeq.GetEncoded();
  CheckEquals(2, System.Length(LEncoded), 'the empty SEQUENCE must encode to two bytes');
  CheckEquals(Int32($30), Int32(LEncoded[0]), 'the SEQUENCE tag octet');
  CheckEquals(Int32($00), Int32(LEncoded[1]), 'the SEQUENCE length octet must be zero');

  LSet := TDerSet.Create(LNilElements);
  CheckNotNull(LSet, 'an empty element array must give the empty SET, not an error');
  CheckEquals(0, LSet.Count, 'the SET must have no elements');
  LEncoded := LSet.GetEncoded();
  CheckEquals(2, System.Length(LEncoded), 'the empty SET must encode to two bytes');
  CheckEquals(Int32($31), Int32(LEncoded[0]), 'the SET tag octet');
  CheckEquals(Int32($00), Int32(LEncoded[1]), 'the SET length octet must be zero');
end;

// An empty BMPString is legal (a zero-length string), and adding an empty array to a vector is a
// legal no-op. Neither may be rejected because Pascal cannot tell an empty array from nil.
procedure TAsn1StreamReadTest.TestBmpStringAndAddAllAcceptEmpty;
var
  LNilBytes: TCryptoLibByteArray;
  LNilElements: TCryptoLibGenericArray<IAsn1Encodable>;
  LBmp: IDerBmpString;
  LVector: IAsn1EncodableVector;
begin
  LBmp := TDerBmpString.Create(LNilBytes);
  CheckNotNull(LBmp, 'empty BMPString contents must give the empty string, not an error');
  CheckEquals('', LBmp.GetString(), 'the BMPString must be empty');

  LVector := TAsn1EncodableVector.Create();
  LVector.AddAll(LNilElements);
  CheckEquals(0, LVector.Count, 'AddAll of an empty array must be a no-op');
end;

// A zero-length string is legal for every ASN.1 string type, and Pascal's empty string is the
// closest thing to nil, so the string constructors must accept '' rather than rejecting it.
procedure TAsn1StreamReadTest.TestEmptyStringTypesAreAccepted;
var
  LBmp: IDerBmpString;
  LGen: IDerGeneralString;
  LIA5: IDerIA5String;
  LNum: IDerNumericString;
  LPrn: IDerPrintableString;
  LT61: IDerT61String;
  LVis: IDerVisibleString;
begin
  LBmp := TDerBmpString.Create('');
  CheckNotNull(LBmp, 'empty BMPString must be accepted');
  CheckEquals('', LBmp.GetString(), 'BMPString must be empty');

  LGen := TDerGeneralString.Create('');
  CheckNotNull(LGen, 'empty GeneralString must be accepted');
  CheckEquals('', LGen.GetString(), 'GeneralString must be empty');

  LIA5 := TDerIA5String.Create('');
  CheckNotNull(LIA5, 'empty IA5String must be accepted');
  CheckEquals('', LIA5.GetString(), 'IA5String must be empty');

  LNum := TDerNumericString.Create('');
  CheckNotNull(LNum, 'empty NumericString must be accepted');
  CheckEquals('', LNum.GetString(), 'NumericString must be empty');

  LPrn := TDerPrintableString.Create('');
  CheckNotNull(LPrn, 'empty PrintableString must be accepted');
  CheckEquals('', LPrn.GetString(), 'PrintableString must be empty');

  LT61 := TDerT61String.Create('');
  CheckNotNull(LT61, 'empty T61String must be accepted');
  CheckEquals('', LT61.GetString(), 'T61String must be empty');

  LVis := TDerVisibleString.Create('');
  CheckNotNull(LVis, 'empty VisibleString must be accepted');
  CheckEquals('', LVis.GetString(), 'VisibleString must be empty');
end;

// The empty BIT STRING (03 01 00) is legal: empty bit data with a zero pad-bit count. The
// data+padBits constructor must accept it, while still rejecting empty data with non-zero pad bits.
procedure TAsn1StreamReadTest.TestBitStringEmptyDataWithZeroPadBitsIsAccepted;
var
  LNilData: TCryptoLibByteArray;
  LBits: IDerBitString;
  LEncoded: TCryptoLibByteArray;
  LRaised: Boolean;
begin
  LBits := TDerBitString.Create(LNilData, 0);
  CheckNotNull(LBits, 'empty bit data with zero pad bits must be accepted');
  LEncoded := LBits.GetEncoded();
  CheckEquals(3, System.Length(LEncoded), 'the empty BIT STRING must encode to three bytes');
  CheckEquals(Int32($03), Int32(LEncoded[0]), 'the BIT STRING tag octet');
  CheckEquals(Int32($01), Int32(LEncoded[1]), 'the length octet must be one');
  CheckEquals(Int32($00), Int32(LEncoded[2]), 'the single content octet is the zero pad-bit count');

  LRaised := False;
  try
    TDerBitString.Create(LNilData, 3);
  except
    on E: EArgumentCryptoLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'empty bit data with non-zero pad bits must still be rejected');
end;

initialization

{$IFDEF FPC}
RegisterTest(TAsn1StreamReadTest);
{$ELSE}
RegisterTest(TAsn1StreamReadTest.Suite);
{$ENDIF FPC}

end.
