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

unit Asn1TimeFormatTests;

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
  CryptoLibTestBase;

type

  /// <summary>
  /// ASN.1 UTCTime and GeneralizedTime accept/reject format tests.
  /// </summary>
  TAsn1TimeFormatTest = class(TCryptoLibAlgorithmTestCase)
  private
    class function IsValidUtcTime(const S: String): Boolean; static;
    class function IsValidGeneralizedTime(const S: String): Boolean; static;
  published
    procedure TestValidUtcTime;
    procedure TestInvalidUtcTimeFieldRanges;
    procedure TestInvalidUtcTimeStructure;
    procedure TestValidGeneralizedTime;
    procedure TestInvalidGeneralizedTimeFieldRanges;
    procedure TestInvalidGeneralizedTimeStructure;
    /// <summary>
    /// Exact content octets (tag/length stripped) of fuzzing-report inputs that were
    /// previously accepted; every one must be rejected.
    /// </summary>
    procedure TestRejectsReportedCorpusContent;
  end;

implementation

{ TAsn1TimeFormatTest }

class function TAsn1TimeFormatTest.IsValidGeneralizedTime(const S: String): Boolean;
begin
  try
    TAsn1GeneralizedTime.Create(S);
    Result := True;
  except
    on E: Exception do
      Result := False;
  end;
end;

class function TAsn1TimeFormatTest.IsValidUtcTime(const S: String): Boolean;
begin
  try
    TAsn1UtcTime.Create(S);
    Result := True;
  except
    on E: Exception do
      Result := False;
  end;
end;

procedure TAsn1TimeFormatTest.TestValidUtcTime;
begin
  // X.680 sec. 47: minutes mandatory, seconds optional, zone (Z or offset) mandatory.
  CheckTrue(IsValidUtcTime('5001010000Z'), 'no seconds, Z');
  CheckTrue(IsValidUtcTime('500101000000Z'), 'seconds, Z');
  CheckTrue(IsValidUtcTime('5001010000+0500'), 'no seconds, offset');
  CheckTrue(IsValidUtcTime('5001010000+0530'), 'no seconds, offset');
  CheckTrue(IsValidUtcTime('500101000000-0830'), 'seconds, offset');
  CheckTrue(IsValidUtcTime('991231235959Z'), 'boundary fields');
  CheckTrue(IsValidUtcTime('000101120000Z'), 'year 00 is fine');
end;

procedure TAsn1TimeFormatTest.TestInvalidUtcTimeFieldRanges;
begin
  CheckFalse(IsValidUtcTime('000000000000Z'), 'month 00, day 00');
  CheckFalse(IsValidUtcTime('000200000000Z'), 'day 00');
  CheckFalse(IsValidUtcTime('241300000000Z'), 'month 13 (and day/... irrelevant)');
  CheckFalse(IsValidUtcTime('240132000000Z'), 'day 32');
  CheckFalse(IsValidUtcTime('240101240000Z'), 'hour 24');
  CheckFalse(IsValidUtcTime('240101006000Z'), 'minute 60');
  CheckFalse(IsValidUtcTime('240101000060Z'), 'second 60');
  CheckFalse(IsValidUtcTime('240101000000+2460'), 'offset minute 60');
  CheckFalse(IsValidUtcTime('5001010000+05'), 'no seconds, offset (no minutes)');
  CheckFalse(IsValidUtcTime('500101000000+05'), 'seconds, offset (no minutes)');
end;

procedure TAsn1TimeFormatTest.TestInvalidUtcTimeStructure;
begin
  CheckFalse(IsValidUtcTime('240101000000'), 'no zone');
  CheckFalse(IsValidUtcTime('24010100000Z'), 'illegal length 12');
  CheckFalse(IsValidUtcTime('2401010000X'), 'bad terminator');
  CheckFalse(IsValidUtcTime('2401010000+99XX'), 'non-digit offset');
  CheckFalse(IsValidUtcTime(''), 'empty');
  // embedded control byte where seconds digits are expected
  CheckFalse(IsValidUtcTime('2401010000' + #7 + '0Z'), 'embedded control byte');
  // high (negative) byte where a digit is expected
  CheckFalse(IsValidUtcTime('24010' + #255 + '000000Z'), 'high byte in digits');
end;

procedure TAsn1TimeFormatTest.TestValidGeneralizedTime;
begin
  CheckTrue(IsValidGeneralizedTime('2024010100Z'), 'hour only, Z');
  CheckTrue(IsValidGeneralizedTime('202401010000Z'), 'minute, Z');
  CheckTrue(IsValidGeneralizedTime('20240101000000Z'), 'second, Z');
  CheckTrue(IsValidGeneralizedTime('20240101000000.5Z'), 'fractional ''.''');
  CheckTrue(IsValidGeneralizedTime('20240101000000,123Z'), 'fractional '',''');
  CheckTrue(IsValidGeneralizedTime('20240101000000+05'), 'numeric offset (no minutes)');
  CheckTrue(IsValidGeneralizedTime('20240101000000+0500'), 'numeric offset');
  CheckTrue(IsValidGeneralizedTime('20240101000000+0530'), 'numeric offset');
  CheckTrue(IsValidGeneralizedTime('20240101000000'), 'local, full');
  CheckTrue(IsValidGeneralizedTime('2024010100'), 'local, hour only');
  CheckTrue(IsValidGeneralizedTime('19500101000000Z'), '19500101000000Z');
end;

procedure TAsn1TimeFormatTest.TestInvalidGeneralizedTimeFieldRanges;
begin
  CheckFalse(IsValidGeneralizedTime('20240001000000Z'), 'month 00');
  CheckFalse(IsValidGeneralizedTime('20241301000000Z'), 'month 13');
  CheckFalse(IsValidGeneralizedTime('20240132000000Z'), 'day 32');
  CheckFalse(IsValidGeneralizedTime('2024010124Z'), 'hour 24');
  CheckFalse(IsValidGeneralizedTime('202401010060Z'), 'minute 60');
  CheckFalse(IsValidGeneralizedTime('20240101000060Z'), 'second 60');
end;

procedure TAsn1TimeFormatTest.TestInvalidGeneralizedTimeStructure;
begin
  CheckFalse(IsValidGeneralizedTime('202401010'), 'length 9 < 10');
  CheckFalse(IsValidGeneralizedTime('20240101000000.'), 'decimal mark, no digits');
  CheckFalse(IsValidGeneralizedTime('2024010100ZZ'), 'trailing junk after Z');
  CheckFalse(IsValidGeneralizedTime('20240101000000X'), 'bad trailing');
  CheckFalse(IsValidGeneralizedTime('20240101000000+1'), 'truncated offset (no minutes)');
  CheckFalse(IsValidGeneralizedTime('20240101000000+123'), 'truncated offset');
  CheckFalse(IsValidGeneralizedTime('202401' + #10 + '01000000Z'), 'embedded control byte');
end;

procedure TAsn1TimeFormatTest.TestRejectsReportedCorpusContent;
begin
  // 170d 3030303030303030303030305a -> "000000000000Z"
  CheckFalse(IsValidUtcTime('000000000000Z'), '000000000000Z');
  // 170d 3030303230303030303030305a -> "000200000000Z"
  CheckFalse(IsValidUtcTime('000200000000Z'), '000200000000Z');
  // 180f 303430303031303030303030303030 -> "040001000000000"
  CheckFalse(IsValidGeneralizedTime('040001000000000'), '040001000000000');
  // 180f 30343030303130303030303030302e -> "04000100000000."
  CheckFalse(IsValidGeneralizedTime('04000100000000.'), '04000100000000.');
  // 180f 3034303030313030303030303030302a-derived "04000100000000*" (control/punct tail)
  CheckFalse(IsValidGeneralizedTime('04000100000000*'), '04000100000000*');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TAsn1TimeFormatTest);
{$ELSE}
  RegisterTest(TAsn1TimeFormatTest.Suite);
{$ENDIF FPC}

end.
