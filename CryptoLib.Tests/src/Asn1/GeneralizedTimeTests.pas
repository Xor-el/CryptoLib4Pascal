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

unit GeneralizedTimeTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  DateUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpAsn1Core,
  ClpDateTimeUtilities,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  /// <summary>
  /// X.690 test example
  /// </summary>
  TGeneralizedTimeTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    FInput: array [0 .. 20] of String;
    FMzOutput: array [0 .. 20] of String;
    FDerMzOutput: array [0 .. 20] of String;
    FTruncOutput: array [0 .. 1] of String;
    FDerTruncOutput: array [0 .. 1] of String;
  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestDateConversion;
    procedure TestDerEncoding;
    procedure TestTruncatedDerEncoding;
    procedure TestBerDerEncodingDifferences;
    procedure TestEmptyStringException;
    procedure TestUtcEquivalence;
    procedure TestInvalidFormatException;

  end;

implementation

{ TGeneralizedTimeTest }

procedure TGeneralizedTimeTest.SetUp;
begin
  inherited;

  FInput[0] := '20020122122220';
  FInput[1] := '20020122122220Z';
  FInput[2] := '20020122122220-1000';
  FInput[3] := '20020122122220+00';
  FInput[4] := '20020122122220.1';
  FInput[5] := '20020122122220.1Z';
  FInput[6] := '20020122122220.1-1000';
  FInput[7] := '20020122122220.1+00';
  FInput[8] := '20020122122220.01';
  FInput[9] := '20020122122220.01Z';
  FInput[10] := '20020122122220.01-1000';
  FInput[11] := '20020122122220.01+00';
  FInput[12] := '20020122122220.001';
  FInput[13] := '20020122122220.001Z';
  FInput[14] := '20020122122220.001-1000';
  FInput[15] := '20020122122220.001+00';
  FInput[16] := '20020122122220.0001';
  FInput[17] := '20020122122220.0001Z';
  FInput[18] := '20020122122220.0001-1000';
  FInput[19] := '20020122122220.0001+00';
  FInput[20] := '20020122122220.0001+1000';

  FMzOutput[0] := '20020122122220.000Z';
  FMzOutput[1] := '20020122122220.000Z';
  FMzOutput[2] := '20020122222220.000Z';
  FMzOutput[3] := '20020122122220.000Z';
  FMzOutput[4] := '20020122122220.100Z';
  FMzOutput[5] := '20020122122220.100Z';
  FMzOutput[6] := '20020122222220.100Z';
  FMzOutput[7] := '20020122122220.100Z';
  FMzOutput[8] := '20020122122220.010Z';
  FMzOutput[9] := '20020122122220.010Z';
  FMzOutput[10] := '20020122222220.010Z';
  FMzOutput[11] := '20020122122220.010Z';
  FMzOutput[12] := '20020122122220.001Z';
  FMzOutput[13] := '20020122122220.001Z';
  FMzOutput[14] := '20020122222220.001Z';
  FMzOutput[15] := '20020122122220.001Z';
  FMzOutput[16] := '20020122122220.000Z';
  FMzOutput[17] := '20020122122220.000Z';
  FMzOutput[18] := '20020122222220.000Z';
  FMzOutput[19] := '20020122122220.000Z';
  FMzOutput[20] := '20020122022220.000Z';

  FDerMzOutput[0] := '20020122122220Z';
  FDerMzOutput[1] := '20020122122220Z';
  FDerMzOutput[2] := '20020122222220Z';
  FDerMzOutput[3] := '20020122122220Z';
  FDerMzOutput[4] := '20020122122220.1Z';
  FDerMzOutput[5] := '20020122122220.1Z';
  FDerMzOutput[6] := '20020122222220.1Z';
  FDerMzOutput[7] := '20020122122220.1Z';
  FDerMzOutput[8] := '20020122122220.01Z';
  FDerMzOutput[9] := '20020122122220.01Z';
  FDerMzOutput[10] := '20020122222220.01Z';
  FDerMzOutput[11] := '20020122122220.01Z';
  FDerMzOutput[12] := '20020122122220.001Z';
  FDerMzOutput[13] := '20020122122220.001Z';
  FDerMzOutput[14] := '20020122222220.001Z';
  FDerMzOutput[15] := '20020122122220.001Z';
  FDerMzOutput[16] := '20020122122220Z';
  FDerMzOutput[17] := '20020122122220Z';
  FDerMzOutput[18] := '20020122222220Z';
  FDerMzOutput[19] := '20020122122220Z';
  FDerMzOutput[20] := '20020122022220Z';

  FTruncOutput[0] := '200201221222Z';
  FTruncOutput[1] := '2002012212Z';

  FDerTruncOutput[0] := '20020122122200Z';
  FDerTruncOutput[1] := '20020122120000Z';
end;

procedure TGeneralizedTimeTest.TearDown;
begin
  inherited;
end;

procedure TGeneralizedTimeTest.TestDateConversion;
var
  I: Int32;
  LT: IAsn1GeneralizedTime;
  LDateTime: TDateTime;
  LFormatted: String;
  LFormatSettings: TFormatSettings;
begin
  LFormatSettings := TFormatSettings.Invariant;

  for I := 0 to System.Length(FInput) - 1 do
  begin
    LT := TAsn1GeneralizedTime.Create(FInput[I]);

    LDateTime := LT.ToDateTime();
    LFormatted := TDateTimeUtilities.FormatCanonical(LDateTime, 'yyyyMMddHHmmss.fff"Z"',
      LFormatSettings, False);

    if LFormatted <> FMzOutput[I] then
    begin
      Fail('failed long date conversion test ' + IntToStr(I) + ': expected ' +
        FMzOutput[I] + ', got ' + LFormatted);
    end;
  end;
end;

procedure TGeneralizedTimeTest.TestDerEncoding;
var
  I: Int32;
  LDerT: IDerGeneralizedTime;
  LAsn1T: IAsn1GeneralizedTime;
begin
  for I := 0 to System.Length(FDerMzOutput) - 1 do
  begin
    LDerT := TDerGeneralizedTime.Create(FDerMzOutput[I]);
    LAsn1T := TAsn1GeneralizedTime.Create(FDerMzOutput[I]);

    if not AreEqual(LDerT.GetEncoded(), LAsn1T.GetEncoded()) then
    begin
      Fail('DER encoding wrong at index ' + IntToStr(I));
    end;
  end;
end;

procedure TGeneralizedTimeTest.TestTruncatedDerEncoding;
var
  I: Int32;
  LDerT: IDerGeneralizedTime;
  LAsn1T: IAsn1GeneralizedTime;
begin
  for I := 0 to System.Length(FTruncOutput) - 1 do
  begin
    LDerT := TDerGeneralizedTime.Create(FTruncOutput[I]);
    LAsn1T := TAsn1GeneralizedTime.Create(FDerTruncOutput[I]);

    if not AreEqual(LDerT.GetEncoded(), LAsn1T.GetEncoded()) then
    begin
      Fail('trunc DER encoding wrong at index ' + IntToStr(I));
    end;
  end;
end;

procedure TGeneralizedTimeTest.TestBerDerEncodingDifferences;
var
  LBer, LDer: IAsn1GeneralizedTime;
  LBerEncoded, LDerEncoded, LExpected: TCryptoLibByteArray;
begin
  // check BER encoding is still "as given"
  LBer := TAsn1GeneralizedTime.Create('202208091215Z');

  LExpected := DecodeHex('180d3230323230383039313231355a');
  LBerEncoded := LBer.GetEncoded(TAsn1Encodable.DL);
  if not AreEqual(LBerEncoded, LExpected) then
  begin
    Fail('DL encoding wrong');
  end;

  LBerEncoded := LBer.GetEncoded(TAsn1Encodable.Ber);
  if not AreEqual(LBerEncoded, LExpected) then
  begin
    Fail('BER encoding wrong');
  end;

  LExpected := DecodeHex('180f32303232303830393132313530305a');
  LDerEncoded := LBer.GetEncoded(TAsn1Encodable.Der);
  if not AreEqual(LDerEncoded, LExpected) then
  begin
    Fail('DER encoding wrong');
  end;

  // check always uses DER encoding
  LDer := TDerGeneralizedTime.Create('202208091215Z');

  LExpected := DecodeHex('180f32303232303830393132313530305a');
  LDerEncoded := LDer.GetEncoded(TAsn1Encodable.DL);
  if not AreEqual(LDerEncoded, LExpected) then
  begin
    Fail('DL encoding wrong for DerGeneralizedTime');
  end;

  LDerEncoded := LDer.GetEncoded(TAsn1Encodable.Ber);
  if not AreEqual(LDerEncoded, LExpected) then
  begin
    Fail('BER encoding wrong for DerGeneralizedTime');
  end;

  LDerEncoded := LDer.GetEncoded(TAsn1Encodable.Der);
  if not AreEqual(LDerEncoded, LExpected) then
  begin
    Fail('DER encoding wrong for DerGeneralizedTime');
  end;
end;

procedure TGeneralizedTimeTest.TestEmptyStringException;
begin
  try
    TDerGeneralizedTime.Create('');
    Fail('Expected exception for empty string');
  except
    on E: EArgumentNilCryptoLibException do
    begin
      if not E.Message.StartsWith('timeString') then
      begin
        Fail('Wrong exception message: ' + E.Message);
      end;
    end
    else
      raise;
  end;
end;

procedure TGeneralizedTimeTest.TestUtcEquivalence;
var
  LT1, LT2, LU1, LU2: TDateTime;
  LDerUtcTime: IDerUtcTime;
  LDerGeneralizedTime: IDerGeneralizedTime;
begin
  LDerUtcTime := TDerUtcTime.Create('110616114855Z');
  LDerGeneralizedTime := TDerGeneralizedTime.Create('20110616114855Z');
  LT1 := LDerUtcTime.ToDateTime();
  LT2 := LDerGeneralizedTime.ToDateTime();

  if LT1 <> LT2 then
  begin
    Fail('failed UTC equivalence test');
  end;

  LU1 := TTimeZone.Local.ToUniversalTime(LT1);
  LU2 := TTimeZone.Local.ToUniversalTime(LT2);

  if LU1 <> LU2 then
  begin
    Fail('failed UTC conversion test');
  end;
end;

procedure TGeneralizedTimeTest.TestInvalidFormatException;
var
  LDerT: IDerGeneralizedTime;
begin
  try
    // Ensure no stack overflow, only parse format.
    LDerT := TDerGeneralizedTime.Create('20160601140601GMT-04:00');
    Fail('Expected exception for invalid format');
  except
    on E: EArgumentCryptoLibException do
    begin
      if not E.Message.Contains('invalid date string') then
      begin
        Fail('Wrong exception message' + E.Message);
      end;
    end
    else
      raise;
  end;
end;

initialization

{$IFDEF FPC}
RegisterTest(TGeneralizedTimeTest);
{$ELSE}
RegisterTest(TGeneralizedTimeTest.Suite);
{$ENDIF FPC}

end.
