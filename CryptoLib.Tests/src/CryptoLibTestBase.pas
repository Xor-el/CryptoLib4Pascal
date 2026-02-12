unit CryptoLibTestBase;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$WARNINGS OFF}
{$NOTES OFF}
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
  ClpArrayUtilities;

type

  TCryptoLibTestCase = class abstract(TTestCase)

  end;

type

  TCryptoLibAlgorithmTestCase = class abstract(TCryptoLibTestCase)
  protected

    function DecodeHex(const data: String): TBytes;
    function EncodeHex(const data: TBytes): String;
    function DecodeBase64(const data: String): TBytes;
    procedure ZeroFill(const data: TBytes);
    function Prepend(const data: TBytes; b: Byte): TBytes;
    function AreEqual(const A, b: TBytes): Boolean;
    function CopyOfRange(const AData: TBytes; AFrom, ATo: Int32): TBytes;

  end;

implementation

{ TCryptoLibAlgorithmTestCase }

function TCryptoLibAlgorithmTestCase.DecodeBase64(const data: String): TBytes;
begin
  result := TBase64Encoder.Decode(data);
end;

function TCryptoLibAlgorithmTestCase.DecodeHex(const data: String): TBytes;
begin
  result := THexEncoder.Decode(data);
end;

function TCryptoLibAlgorithmTestCase.EncodeHex(const data: TBytes): String;
begin
  result := THexEncoder.Encode(data);
end;

function TCryptoLibAlgorithmTestCase.Prepend(const data: TBytes;
  b: Byte): TBytes;
begin
  result := TArrayUtilities.Prepend<Byte>(data, b);
end;

procedure TCryptoLibAlgorithmTestCase.ZeroFill(const data: TBytes);
begin
  TArrayUtilities.Fill<Byte>(data, 0, System.Length(data), Byte(0));
end;

function TCryptoLibAlgorithmTestCase.AreEqual(const A, b: TBytes): Boolean;
begin
  result := TArrayUtilities.AreEqual<Byte>(A, b);
end;

function TCryptoLibAlgorithmTestCase.CopyOfRange(const AData: TBytes; AFrom, ATo: Int32): TBytes;
begin
  Result := TArrayUtilities.CopyOfRange<Byte>(AData, AFrom, ATo);
end;

end.
