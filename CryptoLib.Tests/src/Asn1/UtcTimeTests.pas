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

{ *********************************************************************************** }

unit UtcTimeTests;

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
  ClpDateTimeUtilities,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  /// <summary>
  /// X.690 test example
  /// </summary>
  TUtcTimeTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    FInput: array [0 .. 8] of String;
    FOutputPre2040: array [0 .. 8] of String;
    FOutputPost2040: array [0 .. 8] of String;
  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestUtcTime;

  end;

implementation

function GetExpectedDefault(const AIndex: Integer; const APre2040: Boolean;
  const APre, APost: array of String): String;
begin
  if APre2040 then
    Result := APre[AIndex]
  else
    Result := APost[AIndex];
end;

{ TUtcTimeTest }

procedure TUtcTimeTest.SetUp;
begin
  inherited;

  FInput[0] := '020122122220Z';
  FInput[1] := '020122122220-1000';
  FInput[2] := '020122122220+1000';
  FInput[3] := '0201221222Z';
  FInput[4] := '0201221222-1000';
  FInput[5] := '0201221222+1000';
  FInput[6] := '550122122220Z';
  FInput[7] := '5501221222Z';
  FInput[8] := '4007270730Z';

  FOutputPre2040[0] := '20020122122220Z';
  FOutputPre2040[1] := '20020122222220Z';
  FOutputPre2040[2] := '20020122022220Z';
  FOutputPre2040[3] := '20020122122200Z';
  FOutputPre2040[4] := '20020122222200Z';
  FOutputPre2040[5] := '20020122022200Z';
  FOutputPre2040[6] := '19550122122220Z';
  FOutputPre2040[7] := '19550122122200Z';
  FOutputPre2040[8] := '19400727073000Z';

  FOutputPost2040[0] := '20020122122220Z';
  FOutputPost2040[1] := '20020122222220Z';
  FOutputPost2040[2] := '20020122022220Z';
  FOutputPost2040[3] := '20020122122200Z';
  FOutputPost2040[4] := '20020122222200Z';
  FOutputPost2040[5] := '20020122022200Z';
  FOutputPost2040[6] := '19550122122220Z';
  FOutputPost2040[7] := '19550122122200Z';
  FOutputPost2040[8] := '20400727073000Z';
end;

procedure TUtcTimeTest.TearDown;
begin
  inherited;
end;

procedure TUtcTimeTest.TestUtcTime;
var
  I: Int32;
  LUtcTime: IDerUtcTime;
  LDateTime: TDateTime;
  LFormatted: String;
  LPre2040: Boolean;
  LFormatSettings: TFormatSettings;
  LExpectedDefault: String;
begin
  LFormatSettings := TFormatSettings.Invariant;

  LPre2040 := TDateTimeUtilities.TwoDigitYearMax < 2040;

  for I := 0 to System.Length(FInput) - 1 do
  begin
    LUtcTime := TDerUtcTime.Create(FInput[I]);

    // default conversion uses TwoDigitYearMax policy
    LDateTime := LUtcTime.ToDateTime();
    LFormatted := TDateTimeUtilities.FormatCanonical(LDateTime, 'yyyyMMddHHmmssK',
      LFormatSettings, False);

    LExpectedDefault := GetExpectedDefault(I, LPre2040, FOutputPre2040, FOutputPost2040);

    if LFormatted <> LExpectedDefault then
    begin
      Fail('failed date shortened conversion test ' + IntToStr(I) + ': expected ' +
        LExpectedDefault + ', got ' + LFormatted);
    end;

    // conversion with explicit year hint (2029)
    LDateTime := LUtcTime.ToDateTime(2029);
    LFormatted := TDateTimeUtilities.FormatCanonical(LDateTime, 'yyyyMMddHHmmssK',
      LFormatSettings, False);

    if LFormatted <> FOutputPre2040[I] then
    begin
      Fail('failed date conversion test (2029) ' + IntToStr(I) + ': expected ' +
        FOutputPre2040[I] + ', got ' + LFormatted);
    end;

    // conversion with explicit year hint (2049)
    LDateTime := LUtcTime.ToDateTime(2049);
    LFormatted := TDateTimeUtilities.FormatCanonical(LDateTime, 'yyyyMMddHHmmssK',
      LFormatSettings, False);

    if LFormatted <> FOutputPost2040[I] then
    begin
      Fail('failed date conversion test (2049) ' + IntToStr(I) + ': expected ' +
        FOutputPost2040[I] + ', got ' + LFormatted);
    end;
  end;
end;

initialization

{$IFDEF FPC}
RegisterTest(TUtcTimeTest);
{$ELSE}
RegisterTest(TUtcTimeTest.Suite);
{$ENDIF FPC}

end.
