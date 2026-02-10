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
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpBigInteger,
  ClpEncoders,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TAsn1IntegerTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    FSuspectKey: TCryptoLibByteArray;
  protected
    procedure SetUp; override;
    procedure TearDown; override;

    procedure CheckArgumentException(const AException: Exception;
      const AExpectedMessage: String); overload;
    procedure CheckArgumentException(const AErrorText: String;
      const AException: Exception; const AExpectedMessage: String); overload;
    procedure CheckIntValue(const AInteger: IDerInteger; AValue: Int32);
    procedure CheckLongValue(const AInteger: IDerInteger; AValue: Int64);

  published
    //Ensure existing single byte behavior
    procedure TestValidEncodingSingleByte;
    procedure TestValidEncodingMultiByte;
    procedure TestInvalidEncoding_00;
    procedure TestInvalidEncoding_FF;
    procedure TestInvalidEncoding_00_32Bits;
    procedure TestInvalidEncoding_FF_32Bits;
    //Should pass as loose validation permits 3 leading 0x00 bytes.
    procedure TestLooseValidEncoding_Zero_32BAligned;
    //Should pass as loose validation permits 3 leading 0xFF bytes
    procedure TestLooseValidEncoding_FF_32BAligned;
    //Should pass as loose validation permits 3 leading 0xFF bytes.
    procedure TestLooseValidEncoding_FF_32BAligned_1Not0;
    //Should pass as loose validation permits 3 leading 0xFF bytes.
    procedure TestLooseValidEncoding_FF_32BAligned_2Not0;
    //Should pass as loose validation permits 3 leading 0xFF bytes.
    procedure TestOversizedEncoding;
    procedure TestSuspectKeySequence;
    procedure TestLargeIntegerWithUnsafeAllowed;
    procedure TestLargeEnumeratedWithUnsafeAllowed;
    procedure TestLargeIntegerWithUnsafeDisabled;
    procedure TestSuspectKeySequenceWithUnsafeDisabled;
    procedure TestLargeIntegerWithUnsafeDisabled2;
    procedure TestLargeEnumeratedWithUnsafeDisabled;
    procedure TestLargeEnumeratedWithUnsafeDisabled2;

  end;

implementation

{ TAsn1IntegerTest }

procedure TAsn1IntegerTest.SetUp;
begin
  inherited;
  FSuspectKey := TBase64Encoder.Decode
    ('MIGJAoGBAHNc+iExm94LUrJdPSJ4QJ9tDRuvaNmGVHpJ4X7a5zKI02v+2E7RotuiR2MHDJfVJkb9LUs2kb3XBlyENhtMLsbeH+3Muy3' +
    'hGDlh/mLJSh1s4c5jDKBRYOHom7Uc8wP0P2+zBCA+OEdikNDFBaP5PbR2Xq9okG2kPh35M2quAiMTAgMBAAE=');
end;

procedure TAsn1IntegerTest.TearDown;
begin
  FSuspectKey := nil;
  inherited;
end;

procedure TAsn1IntegerTest.CheckArgumentException(const AException: Exception;
  const AExpectedMessage: String);
begin
  CheckTrue(AException.Message.StartsWith(AExpectedMessage),
    Format('Exception message "%s" does not start with "%s"',
    [AException.Message, AExpectedMessage]));
end;

procedure TAsn1IntegerTest.CheckArgumentException(const AErrorText: String;
  const AException: Exception; const AExpectedMessage: String);
begin
  CheckTrue(AException.Message.StartsWith(AExpectedMessage),
    Format('%s: Exception message "%s" does not start with "%s"',
    [AErrorText, AException.Message, AExpectedMessage]));
end;

procedure TAsn1IntegerTest.CheckIntValue(const AInteger: IDerInteger;
  AValue: Int32);
var
  LVal: TBigInteger;
begin
  LVal := AInteger.Value;
  CheckEquals(AValue, LVal.Int32Value, 'IntValue mismatch');
  CheckEquals(AValue, LVal.Int32ValueExact, 'IntValueExact mismatch');
  CheckEquals(AValue, AInteger.IntValueExact, 'Integer.IntValueExact mismatch');
  CheckTrue(AInteger.HasValue(AValue), Format('HasValue(%d) should return True',
    [AValue]));
end;

procedure TAsn1IntegerTest.CheckLongValue(const AInteger: IDerInteger;
  AValue: Int64);
var
  LVal: TBigInteger;
begin
  LVal := AInteger.Value;
  CheckEquals(AValue, LVal.Int64Value, 'LongValue mismatch');
  CheckEquals(AValue, LVal.Int64ValueExact, 'LongValueExact mismatch');
  CheckEquals(AValue, AInteger.LongValueExact,
    'Integer.LongValueExact mismatch');
  CheckTrue(AInteger.HasValue(AValue), Format('HasValue(%d) should return True',
    [AValue]));
end;

procedure TAsn1IntegerTest.TestInvalidEncoding_00;
var
  LRawInt: TCryptoLibByteArray;
  LInteger: IDerInteger;
begin
  TDerInteger.AllowUnsafeInteger := False;
  try
    LRawInt := DecodeHex('0010FF');
    LInteger := TDerInteger.Create(LRawInt);
    CheckEquals(4351, LInteger.Value.Int32Value, 'Value should be 4351');
    Fail('Expecting illegal argument exception.');
  except
    on E: EArgumentCryptoLibException do
    begin
      CheckArgumentException(E, 'malformed integer');
    end;
  end;
end;

procedure TAsn1IntegerTest.TestInvalidEncoding_00_32Bits;
var
  LRawInt: TCryptoLibByteArray;
begin
  TDerInteger.AllowUnsafeInteger := False;

  try
    LRawInt := DecodeHex('0000000010FF');
    TDerInteger.Create(LRawInt);
    Fail('Expecting illegal argument exception.');
  except
    on E: EArgumentCryptoLibException do
    begin
      CheckArgumentException(E, 'malformed integer');
    end;
  end;
end;

procedure TAsn1IntegerTest.TestInvalidEncoding_FF;
var
  LRawInt: TCryptoLibByteArray;
begin
  TDerInteger.AllowUnsafeInteger := False;

  try
    LRawInt := DecodeHex('FF81FF');
    TDerInteger.Create(LRawInt);
    Fail('Expecting illegal argument exception.');
  except
    on E: EArgumentCryptoLibException do
    begin
      CheckArgumentException(E, 'malformed integer');
    end;
  end;
end;

procedure TAsn1IntegerTest.TestInvalidEncoding_FF_32Bits;
var
  LRawInt: TCryptoLibByteArray;
begin
  TDerInteger.AllowUnsafeInteger := False;

  try
    LRawInt := DecodeHex('FFFFFFFF01FF');
    TDerInteger.Create(LRawInt);
    Fail('Expecting illegal argument exception.');
  except
    on E: EArgumentCryptoLibException do
    begin
      CheckArgumentException(E, 'malformed integer');
    end;
  end;
end;

procedure TAsn1IntegerTest.TestLooseValidEncoding_FF_32BAligned;
var
  LRawInt: TCryptoLibByteArray;
  LInteger: IDerInteger;
begin
  TDerInteger.AllowUnsafeInteger := True;
  LRawInt := DecodeHex('FFFFFF10FF000000');
  LInteger := TDerInteger.Create(LRawInt);
  CheckLongValue(LInteger, -1026513960960);
end;

procedure TAsn1IntegerTest.TestLooseValidEncoding_FF_32BAligned_1Not0;
var
  LRawInt: TCryptoLibByteArray;
  LInteger: IDerInteger;
begin
  TDerInteger.AllowUnsafeInteger := True;
  LRawInt := DecodeHex('FFFEFF10FF000000');
  LInteger := TDerInteger.Create(LRawInt);
  CheckLongValue(LInteger, -282501490671616);
end;

procedure TAsn1IntegerTest.TestLooseValidEncoding_FF_32BAligned_2Not0;
var
  LRawInt: TCryptoLibByteArray;
  LInteger: IDerInteger;
begin
  TDerInteger.AllowUnsafeInteger := True;
  LRawInt := DecodeHex('FFFFFE10FF000000');
  LInteger := TDerInteger.Create(LRawInt);
  CheckLongValue(LInteger, -2126025588736);
end;

procedure TAsn1IntegerTest.TestLooseValidEncoding_Zero_32BAligned;
var
  LRawInt: TCryptoLibByteArray;
  LInteger: IDerInteger;
begin
  TDerInteger.AllowUnsafeInteger := True;
  LRawInt := DecodeHex('00000010FF000000');
  LInteger := TDerInteger.Create(LRawInt);
  CheckLongValue(LInteger, 72997666816);
end;

procedure TAsn1IntegerTest.TestOversizedEncoding;
var
  LRawInt: TCryptoLibByteArray;
  LInteger: IDerInteger;
  LBigInteger: TBigInteger;
begin
  TDerInteger.AllowUnsafeInteger := True;
  LRawInt := DecodeHex('FFFFFFFE10FF000000000000');
  LInteger := TDerInteger.Create(LRawInt);
  LBigInteger := TBigInteger.Create(DecodeHex('FFFFFFFE10FF000000000000'));
  CheckTrue(LInteger.Value.Equals(LBigInteger), 'BigInteger value mismatch');

  LRawInt := DecodeHex('FFFFFFFFFE10FF000000000000');
  try
    LInteger := TDerInteger.Create(LRawInt);
  except
    on E: EArgumentCryptoLibException do
    begin
      CheckArgumentException(E, 'malformed integer');
    end;
  end;
end;

procedure TAsn1IntegerTest.TestValidEncodingMultiByte;
var
  LRawInt: TCryptoLibByteArray;
  LInteger: IDerInteger;
begin
  TDerInteger.AllowUnsafeInteger := False;

  LRawInt := DecodeHex('10FF');
  LInteger := TDerInteger.Create(LRawInt);
  CheckIntValue(LInteger, 4351);

  TDerInteger.AllowUnsafeInteger := True;

  LRawInt := DecodeHex('10FF');
  LInteger := TDerInteger.Create(LRawInt);
  CheckIntValue(LInteger, 4351);
end;

procedure TAsn1IntegerTest.TestValidEncodingSingleByte;
var
  LRawInt: TCryptoLibByteArray;
  LInteger: IDerInteger;
begin
  TDerInteger.AllowUnsafeInteger := False;

  LRawInt := DecodeHex('10');
  LInteger := TDerInteger.Create(LRawInt);
  CheckIntValue(LInteger, 16);

  TDerInteger.AllowUnsafeInteger := True;

  LRawInt := DecodeHex('10');
  LInteger := TDerInteger.Create(LRawInt);
  CheckIntValue(LInteger, 16);
end;

procedure TAsn1IntegerTest.TestSuspectKeySequence;
begin
  TDerInteger.AllowUnsafeInteger := True;
  TAsn1Sequence.GetInstance(FSuspectKey);
end;

procedure TAsn1IntegerTest.TestLargeIntegerWithUnsafeAllowed;
var
  LInteger: IDerInteger;
begin
  TDerInteger.AllowUnsafeInteger := True;
  LInteger := TDerInteger.Create(DecodeHex
    ('ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e'));
end;

procedure TAsn1IntegerTest.TestLargeEnumeratedWithUnsafeAllowed;
var
  LEnumerated: IDerEnumerated;
begin
  TDerInteger.AllowUnsafeInteger := True;
  LEnumerated := TDerEnumerated.Create(DecodeHex
    ('005a47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e'));
end;

procedure TAsn1IntegerTest.TestLargeIntegerWithUnsafeDisabled;
var
  LOriginalValue: Boolean;
begin
  LOriginalValue := TDerInteger.AllowUnsafeInteger;
  try
    TDerInteger.AllowUnsafeInteger := False;

    try
      TDerInteger.Create(DecodeHex
        ('ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b'));

      Fail('no exception');
    except
      on E: EArgumentCryptoLibException do
      begin
        CheckArgumentException(E, 'malformed integer');
      end;
    end;
  finally
    TDerInteger.AllowUnsafeInteger := LOriginalValue;
  end;
end;

procedure TAsn1IntegerTest.TestSuspectKeySequenceWithUnsafeDisabled;
var
  LOriginalValue: Boolean;
begin
  LOriginalValue := TDerInteger.AllowUnsafeInteger;
  try
    TDerInteger.AllowUnsafeInteger := False;

    try
      TAsn1Sequence.GetInstance(FSuspectKey);

      Fail('no exception');
    except
      on E: EArgumentCryptoLibException do
      begin
        CheckArgumentException('test 1', E,
          'failed to construct sequence from byte[]: corrupted stream detected');
      end;
    end;
  finally
    TDerInteger.AllowUnsafeInteger := LOriginalValue;
  end;
end;

procedure TAsn1IntegerTest.TestLargeIntegerWithUnsafeDisabled2;
var
  LOriginalValue: Boolean;
begin
  LOriginalValue := TDerInteger.AllowUnsafeInteger;
  try
    TDerInteger.AllowUnsafeInteger := False;

    try
      TDerInteger.Create(DecodeHex
        ('ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e'));

      Fail('no exception');
    except
      on E: EArgumentCryptoLibException do
      begin
        CheckArgumentException(E, 'malformed integer');
      end;
    end;
  finally
    TDerInteger.AllowUnsafeInteger := LOriginalValue;
  end;
end;

procedure TAsn1IntegerTest.TestLargeEnumeratedWithUnsafeDisabled;
var
  LOriginalValue: Boolean;
begin
  LOriginalValue := TDerInteger.AllowUnsafeInteger;
  try
    TDerInteger.AllowUnsafeInteger := False;

    try
      TDerEnumerated.Create(DecodeHex
        ('ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e'));

      Fail('no exception');
    except
      on E: EArgumentCryptoLibException do
      begin
        CheckArgumentException(E, 'malformed enumerated');
      end;
    end;
  finally
    TDerInteger.AllowUnsafeInteger := LOriginalValue;
  end;
end;

procedure TAsn1IntegerTest.TestLargeEnumeratedWithUnsafeDisabled2;
var
  LOriginalValue: Boolean;
begin
  LOriginalValue := TDerInteger.AllowUnsafeInteger;
  try
    TDerInteger.AllowUnsafeInteger := False;

    try
      TDerEnumerated.Create(DecodeHex
        ('005a47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e'));

      Fail('no exception');
    except
      on E: EArgumentCryptoLibException do
      begin
        CheckArgumentException(E, 'malformed enumerated');
      end;
    end;
  finally
    TDerInteger.AllowUnsafeInteger := LOriginalValue;
  end;
end;

initialization

{$IFDEF FPC}
RegisterTest(TAsn1IntegerTest);
{$ELSE}
RegisterTest(TAsn1IntegerTest.Suite);
{$ENDIF FPC}

end.
