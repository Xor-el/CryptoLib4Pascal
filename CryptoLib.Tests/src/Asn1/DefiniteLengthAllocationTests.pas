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

unit DefiniteLengthAllocationTests;

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
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
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

  TDefiniteLengthAllocationTest = class(TCryptoLibAlgorithmTestCase)
  published
    procedure TestDeclaredLengthNotAllocatedUpFront;
    procedure TestTruncatedObjectReportsExpectedMessage;
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

{ TDefiniteLengthAllocationTest }

procedure TDefiniteLengthAllocationTest.TestDeclaredLengthNotAllocatedUpFront;
const
  DeclaredLength = 1 shl 20;
var
  LInput: TCryptoLibByteArray;
  LInStr: TRecordingStream;
  LInputStream: TAsn1InputStream;
  LOctets: IAsn1OctetString;
  LFirstBulkReadLength: Int32;
begin
  System.SetLength(LInput, 5 + DeclaredLength);
  LInput[0] := $04;
  LInput[1] := $83;
  LInput[2] := $10;
  LInput[3] := $00;
  LInput[4] := $00;

  LInStr := TRecordingStream.Create(LInput);
  try
    LInputStream := TAsn1InputStream.Create(LInStr, True);
    try
      LOctets := TAsn1OctetString.GetInstance(LInputStream.ReadObject());
      CheckEquals(DeclaredLength, LOctets.GetOctetsLength(),
        'octet string did not materialize to the declared length');

      LFirstBulkReadLength := LInStr.FirstBulkReadLength;
      if (LFirstBulkReadLength < 0) or (LFirstBulkReadLength >= DeclaredLength) then
        Fail(Format('first bulk read requested the full declared length (%d)',
          [LFirstBulkReadLength]));
    finally
      LInputStream.Free;
    end;
  finally
    LInStr.Free;
  end;
end;

procedure TDefiniteLengthAllocationTest.TestTruncatedObjectReportsExpectedMessage;
const
  DeclaredLength = 1 shl 20;
  BodySupplied = 10;
var
  LInput: TCryptoLibByteArray;
  LInStr: TRecordingStream;
  LInputStream: TAsn1InputStream;
  LExpected: String;
begin
  System.SetLength(LInput, 5 + BodySupplied);
  LInput[0] := $04;
  LInput[1] := $83;
  LInput[2] := $10;
  LInput[3] := $00;
  LInput[4] := $00;

  LExpected := Format('DEF length %d object truncated by %d',
    [DeclaredLength, DeclaredLength - BodySupplied]);

  LInStr := TRecordingStream.Create(LInput);
  try
    LInputStream := TAsn1InputStream.Create(LInStr, True);
    try
      try
        LInputStream.ReadObject();
        Fail('no exception on truncated definite-length object');
      except
        on E: EEndOfStreamCryptoLibException do
          CheckEquals(LExpected, E.Message,
            Format('unexpected truncation message: %s', [E.Message]));
        on E: Exception do
          Fail(Format('unexpected exception: %s', [E.Message]));
      end;
    finally
      LInputStream.Free;
    end;
  finally
    LInStr.Free;
  end;
end;

initialization

{$IFDEF FPC}
RegisterTest(TDefiniteLengthAllocationTest);
{$ELSE}
RegisterTest(TDefiniteLengthAllocationTest.Suite);
{$ENDIF FPC}

end.
