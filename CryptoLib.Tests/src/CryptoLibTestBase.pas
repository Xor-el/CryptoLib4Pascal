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
  ClpArrayUtils;

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

  end;

implementation

{ TCryptoLibAlgorithmTestCase }

function TCryptoLibAlgorithmTestCase.DecodeBase64(const data: String): TBytes;
begin
  result := TBase64.Decode(data);
end;

function TCryptoLibAlgorithmTestCase.DecodeHex(const data: String): TBytes;
begin
  result := THex.Decode(data);
end;

function TCryptoLibAlgorithmTestCase.EncodeHex(const data: TBytes): String;
begin
  result := THex.Encode(data);
end;

function TCryptoLibAlgorithmTestCase.Prepend(const data: TBytes;
  b: Byte): TBytes;
begin
  result := TArrayUtils.Prepend(data, b);
end;

procedure TCryptoLibAlgorithmTestCase.ZeroFill(const data: TBytes);
begin
  TArrayUtils.ZeroFill(data);
end;

function TCryptoLibAlgorithmTestCase.AreEqual(const A, b: TBytes): Boolean;
begin
  result := TArrayUtils.AreEqual(A, b);
end;

end.
