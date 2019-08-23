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

unit Asn1IntegerTests;

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
  ClpBigInteger,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  CryptoLibTestBase,
  ClpCryptoLibTypes;

type
  TTestAsn1Integer = class(TCryptoLibAlgorithmTestCase)
  var
  private
    FSuspectKey: TBytes;

    procedure SetAllowUnsafeProperty(allowUnsafe: Boolean);

    // Ensure existing single byte behavior.
    procedure DoTestValidEncodingSingleByte();

    procedure DoTestValidEncodingMultiByte();

    procedure DoTestInvalidEncoding_00();

    procedure DoTestInvalidEncoding_ff();

    procedure DoTestInvalidEncoding_00_32bits();

    procedure DoTestInvalidEncoding_ff_32bits();

    procedure DoTestLooseValidEncoding_zero_32BAligned();

    procedure DoTestLooseValidEncoding_FF_32BAligned();

    procedure DoTestLooseValidEncoding_FF_32BAligned_1not0();

    procedure DoTestLooseValidEncoding_FF_32BAligned_2not0();

    procedure DoTestOversizedEncoding();

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestAsn1Integer;
  end;

implementation

{ TTestAsn1Integer }

procedure TTestAsn1Integer.SetAllowUnsafeProperty(allowUnsafe: Boolean);
begin
  TDerInteger.AllowUnsafeInteger := allowUnsafe;
end;

procedure TTestAsn1Integer.SetUp;
begin
  inherited;
  FSuspectKey := DecodeBase64
    ('MIGJAoGBAHNc+iExm94LUrJdPSJ4QJ9tDRuvaNmGVHpJ4X7a5zKI02v+2E7RotuiR2MHDJfVJkb9LUs2kb3XBlyENhtMLsbeH+3Muy3'
    + 'hGDlh/mLJSh1s4c5jDKBRYOHom7Uc8wP0P2+zBCA+OEdikNDFBaP5PbR2Xq9okG2kPh35M2quAiMTAgMBAAE=');
end;

procedure TTestAsn1Integer.TearDown;
begin
  inherited;

end;

procedure TTestAsn1Integer.DoTestValidEncodingSingleByte;
var
  rawInt: TBytes;
  i: IDerInteger;
begin
  SetAllowUnsafeProperty(false);

  //
  // Without property, single byte.
  //
  rawInt := DecodeHex('10');
  i := TDerInteger.Create(rawInt);
  CheckEquals(i.Value.Int32Value, 16);

  //
  // With property set.
  //
  SetAllowUnsafeProperty(true);

  rawInt := DecodeHex('10');
  i := TDerInteger.Create(rawInt);
  CheckEquals(i.Value.Int32Value, 16);
end;

procedure TTestAsn1Integer.DoTestValidEncodingMultiByte;
var
  rawInt: TBytes;
  i: IDerInteger;
begin
  SetAllowUnsafeProperty(false);

  //
  // Without property, single byte.
  //
  rawInt := DecodeHex('10FF');
  i := TDerInteger.Create(rawInt);
  CheckEquals(i.Value.Int32Value, 4351);

  //
  // With property set.
  //
  SetAllowUnsafeProperty(true);

  rawInt := DecodeHex('10FF');
  i := TDerInteger.Create(rawInt);
  CheckEquals(i.Value.Int32Value, 4351);
end;

procedure TTestAsn1Integer.DoTestInvalidEncoding_00;
var
  rawInt: TBytes;
  i: IDerInteger;
begin
  SetAllowUnsafeProperty(false);

  try

    rawInt := DecodeHex('0010FF');
    i := TDerInteger.Create(rawInt);
    CheckEquals(i.Value.Int32Value, 4351);

    Fail('Expecting EArgumentCryptoLibException');

  except
    on e: EArgumentCryptoLibException do
    begin
      CheckEquals('Malformed Integer', e.Message);
    end;

  end;

end;

procedure TTestAsn1Integer.DoTestInvalidEncoding_ff;
var
  rawInt: TBytes;
  i: IDerInteger;
begin
  SetAllowUnsafeProperty(false);

  try

    rawInt := DecodeHex('FF81FF');
    i := TDerInteger.Create(rawInt);
    CheckEquals(i.Value.Int32Value, 4351);

    Fail('Expecting EArgumentCryptoLibException');

  except
    on e: EArgumentCryptoLibException do
    begin
      CheckEquals('Malformed Integer', e.Message);
    end;

  end;

end;

procedure TTestAsn1Integer.DoTestInvalidEncoding_00_32bits;
var
  rawInt: TBytes;
  i: IDerInteger;
begin
  SetAllowUnsafeProperty(false);

  // Check what would pass loose validation fails outside of loose validation.

  try

    rawInt := DecodeHex('0000000010FF');
    i := TDerInteger.Create(rawInt);
    CheckEquals(i.Value.Int32Value, 4351);

    Fail('Expecting EArgumentCryptoLibException');

  except
    on e: EArgumentCryptoLibException do
    begin
      CheckEquals('Malformed Integer', e.Message);
    end;

  end;

end;

procedure TTestAsn1Integer.DoTestInvalidEncoding_ff_32bits;
var
  rawInt: TBytes;
  i: IDerInteger;
begin
  SetAllowUnsafeProperty(false);

  // Check what would pass loose validation fails outside of loose validation.

  try

    rawInt := DecodeHex('FFFFFFFF01FF');
    i := TDerInteger.Create(rawInt);
    CheckEquals(i.Value.Int32Value, 4351);

    Fail('Expecting EArgumentCryptoLibException');

  except
    on e: EArgumentCryptoLibException do
    begin
      CheckEquals('Malformed Integer', e.Message);
    end;

  end;

end;

procedure TTestAsn1Integer.DoTestLooseValidEncoding_zero_32BAligned;
var
  rawInt: TBytes;
  i: IDerInteger;
begin
  //
  // Should pass as loose validation permits 3 leading 0x00 bytes.
  //
  SetAllowUnsafeProperty(true);

  rawInt := DecodeHex('00000010FF000000');
  i := TDerInteger.Create(rawInt);
  CheckEquals(i.Value.Int64Value, Int64(72997666816));

end;

procedure TTestAsn1Integer.DoTestLooseValidEncoding_FF_32BAligned;
var
  rawInt: TBytes;
  i: IDerInteger;
begin
  //
  // Should pass as loose validation permits 3 leading 0xFF bytes
  //
  SetAllowUnsafeProperty(true);

  rawInt := DecodeHex('FFFFFF10FF000000');
  i := TDerInteger.Create(rawInt);
  CheckEquals(i.Value.Int64Value, Int64(-1026513960960));

end;

procedure TTestAsn1Integer.DoTestLooseValidEncoding_FF_32BAligned_1not0;
var
  rawInt: TBytes;
  i: IDerInteger;
begin
  //
  // Should pass as loose validation permits 3 leading 0xFF bytes.
  //
  SetAllowUnsafeProperty(true);

  rawInt := DecodeHex('FFFEFF10FF000000');
  i := TDerInteger.Create(rawInt);
  CheckEquals(i.Value.Int64Value, Int64(-282501490671616));

end;

procedure TTestAsn1Integer.DoTestLooseValidEncoding_FF_32BAligned_2not0;
var
  rawInt: TBytes;
  i: IDerInteger;
begin
  //
  // Should pass as loose validation permits 3 leading 0xFF bytes.
  //
  SetAllowUnsafeProperty(true);

  rawInt := DecodeHex('FFFFFE10FF000000');
  i := TDerInteger.Create(rawInt);
  CheckEquals(i.Value.Int64Value, Int64(-2126025588736));

end;

procedure TTestAsn1Integer.DoTestOversizedEncoding;
var
  rawInt: TBytes;
  i: IDerInteger;
begin
  //
  // Should pass as loose validation permits 3 leading 0xFF bytes.
  //
  SetAllowUnsafeProperty(true);

  rawInt := DecodeHex('FFFFFFFE10FF000000000000');
  i := TDerInteger.Create(rawInt);
  CheckTrue(TBigInteger.Create(DecodeHex('FFFFFFFE10FF000000000000'))
    .Equals(i.Value));

  rawInt := DecodeHex('FFFFFFFFFE10FF000000000000');

  try

    i := TDerInteger.Create(rawInt);

  except
    on e: EArgumentCryptoLibException do
    begin
      CheckEquals('Malformed Integer', e.Message);
    end;

  end;

end;

procedure TTestAsn1Integer.TestAsn1Integer;
var
  i: IDerInteger;
  en: IDerEnumerated;
begin
  SetAllowUnsafeProperty(true);

  TAsn1Sequence.GetInstance(FSuspectKey);

  DoTestValidEncodingSingleByte();
  DoTestValidEncodingMultiByte();
  DoTestInvalidEncoding_00();
  DoTestInvalidEncoding_ff();
  DoTestInvalidEncoding_00_32bits();
  DoTestInvalidEncoding_ff_32bits();
  DoTestLooseValidEncoding_zero_32BAligned();
  DoTestLooseValidEncoding_FF_32BAligned();
  DoTestLooseValidEncoding_FF_32BAligned_1not0();
  DoTestLooseValidEncoding_FF_32BAligned_2not0();
  DoTestOversizedEncoding();

  SetAllowUnsafeProperty(true);

  i := TDerInteger.Create
    (DecodeHex
    ('ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e'));

  en := TDerEnumerated.Create
    (DecodeHex
    ('005a47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e'));

  SetAllowUnsafeProperty(false);

  try

    i := TDerInteger.Create
      (DecodeHex
      ('ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b'));

    Fail('No Exception');

  except
    on e: EArgumentCryptoLibException do
    begin
      CheckEquals('Malformed Integer', e.Message);
    end;

  end;

  try

    TAsn1Sequence.GetInstance(FSuspectKey);

    Fail('No Exception');

  except
    on e: EAsn1CryptoLibException do
    begin
      CheckEquals('Corrupted Stream Detected: Malformed Integer', e.Message);
    end;

  end;

  try

    i := TDerInteger.Create
      (DecodeHex
      ('ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e'));

    Fail('No Exception');

  except
    on e: EArgumentCryptoLibException do
    begin
      CheckEquals('Malformed Integer', e.Message);
    end;

  end;

  try

    en := TDerEnumerated.Create
      (DecodeHex
      ('ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e'));

    Fail('No Exception');

  except
    on e: EArgumentCryptoLibException do
    begin
      CheckEquals('Malformed Enumerated', e.Message);
    end;

  end;

  try

    en := TDerEnumerated.Create
      (DecodeHex
      ('005a47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e'));

    Fail('No Exception');

  except
    on e: EArgumentCryptoLibException do
    begin
      CheckEquals('Malformed Enumerated', e.Message);
    end;

  end;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestAsn1Integer);
{$ELSE}
  RegisterTest(TTestAsn1Integer.Suite);
{$ENDIF FPC}

end.
