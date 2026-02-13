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

    function DecodeHex(const AData: String): TBytes;
    function EncodeHex(const AData: TBytes): String;
    function DecodeBase64(const AData: String): TBytes;
    procedure ZeroFill(const AData: TBytes);
    function Prepend(const AData: TBytes; AValue: Byte): TBytes;
    function AreEqual(const AA, AB: TBytes): Boolean;
    function CopyOfRange(const AData: TBytes; AFrom, ATo: Int32): TBytes;

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

end.
