unit CryptoLibTestBase;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpEncoders,
  ClpArrayUtilities,
  ClpConverters,
  ClpCryptoLibTypes,
  CryptoLibTestResourceLoader;

type

  TCryptoLibTestCase = class abstract(TTestCase)

  end;

type

  TCryptoLibAlgorithmTestCase = class abstract(TCryptoLibTestCase)
  protected

    function DecodeHex(const AData: String): TBytes;
    function EncodeHex(const AData: TBytes): String;
    function DecodeBase64(const AData: String): TBytes;
    procedure ZeroFill(const AData: TBytes);
    function Prepend(const AData: TBytes; AValue: Byte): TBytes;
    function AreEqual(const AA, AB: TBytes): Boolean;
    function CopyOfRange(const AData: TBytes; AFrom, ATo: Int32): TBytes;
    function StringToCharArray(const AInput: String): TCryptoLibCharArray;
    function LoadTestResource(const ARelativePath: string): string;
    function LoadTestResourceBytes(const ARelativePath: string): TBytes;
    function TestResourcePath(const ACategory, AFileName: string): string;
    // Fail with a hex diff unless AActual equals AExpected.
    procedure CheckEqual(const AName: string; const AExpected, AActual: TBytes);

  end;

implementation

{ TCryptoLibAlgorithmTestCase }

function TCryptoLibAlgorithmTestCase.DecodeBase64(const AData: String): TBytes;
begin
  Result := TBase64Encoder.Decode(AData);
end;

function TCryptoLibAlgorithmTestCase.DecodeHex(const AData: String): TBytes;
begin
  Result := THexEncoder.Decode(AData);
end;

function TCryptoLibAlgorithmTestCase.EncodeHex(const AData: TBytes): String;
begin
  Result := THexEncoder.Encode(AData);
end;

function TCryptoLibAlgorithmTestCase.Prepend(const AData: TBytes;
  AValue: Byte): TBytes;
begin
  Result := TArrayUtilities.Prepend<Byte>(AData, AValue);
end;

procedure TCryptoLibAlgorithmTestCase.ZeroFill(const AData: TBytes);
begin
  TArrayUtilities.Fill<Byte>(AData, 0, System.Length(AData), Byte(0));
end;

function TCryptoLibAlgorithmTestCase.AreEqual(const AA, AB: TBytes): Boolean;
begin
  Result := TArrayUtilities.AreEqual(AA, AB);
end;

function TCryptoLibAlgorithmTestCase.CopyOfRange(const AData: TBytes; AFrom, ATo: Int32): TBytes;
begin
  Result := TArrayUtilities.CopyOfRange<Byte>(AData, AFrom, ATo);
end;

function TCryptoLibAlgorithmTestCase.StringToCharArray(const AInput: String): TCryptoLibCharArray;
begin
  Result := TConverters.ConvertStringToCharArray(AInput);
end;

function TCryptoLibAlgorithmTestCase.LoadTestResource(const ARelativePath: string): string;
begin
  Result := TCryptoLibTestResourceLoader.Instance.LoadAsString(ARelativePath);
end;

function TCryptoLibAlgorithmTestCase.LoadTestResourceBytes(const ARelativePath: string): TBytes;
begin
  Result := TCryptoLibTestResourceLoader.Instance.LoadAsBytes(ARelativePath);
end;

function TCryptoLibAlgorithmTestCase.TestResourcePath(const ACategory, AFileName: string): string;
begin
  Result := ACategory + '/' + AFileName;
end;

procedure TCryptoLibAlgorithmTestCase.CheckEqual(const AName: string;
  const AExpected, AActual: TBytes);
begin
  if not AreEqual(AExpected, AActual) then
    Fail(Format('%s Failed - expected %s got %s',
      [AName, EncodeHex(AExpected), EncodeHex(AActual)]));
end;

end.
