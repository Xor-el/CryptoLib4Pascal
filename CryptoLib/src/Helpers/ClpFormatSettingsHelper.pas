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

unit ClpFormatSettingsHelper;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils;

type
  TFormatSettingsHelper = record helper for TFormatSettings
  public
    class function InvariantCulture: TFormatSettings; static;
  end;

implementation

class function TFormatSettingsHelper.InvariantCulture: TFormatSettings;
begin
{$IFDEF FPC}
  // FPC 3.2.x has TFormatSettings but no built-in TFormatSettings.Invariant.
  // Return a fully initialized invariant-style record.
  Result.CurrencyString := #$00A4; // generic currency sign: ¤
  Result.CurrencyFormat := 0;
  Result.NegCurrFormat := 0;
  Result.CurrencyDecimals := 2;

  Result.ThousandSeparator := ',';
  Result.DecimalSeparator := '.';

  Result.DateSeparator := '/';
  Result.TimeSeparator := ':';
  Result.ListSeparator := ',';

  Result.ShortDateFormat := 'MM/dd/yyyy';
  Result.LongDateFormat := 'dddd, dd MMMM yyyy';
  Result.ShortTimeFormat := 'HH:mm';
  Result.LongTimeFormat := 'HH:mm:ss';

  Result.TimeAMString := 'AM';
  Result.TimePMString := 'PM';

  Result.ShortMonthNames[1]  := 'Jan';
  Result.ShortMonthNames[2]  := 'Feb';
  Result.ShortMonthNames[3]  := 'Mar';
  Result.ShortMonthNames[4]  := 'Apr';
  Result.ShortMonthNames[5]  := 'May';
  Result.ShortMonthNames[6]  := 'Jun';
  Result.ShortMonthNames[7]  := 'Jul';
  Result.ShortMonthNames[8]  := 'Aug';
  Result.ShortMonthNames[9]  := 'Sep';
  Result.ShortMonthNames[10] := 'Oct';
  Result.ShortMonthNames[11] := 'Nov';
  Result.ShortMonthNames[12] := 'Dec';

  Result.LongMonthNames[1]  := 'January';
  Result.LongMonthNames[2]  := 'February';
  Result.LongMonthNames[3]  := 'March';
  Result.LongMonthNames[4]  := 'April';
  Result.LongMonthNames[5]  := 'May';
  Result.LongMonthNames[6]  := 'June';
  Result.LongMonthNames[7]  := 'July';
  Result.LongMonthNames[8]  := 'August';
  Result.LongMonthNames[9]  := 'September';
  Result.LongMonthNames[10] := 'October';
  Result.LongMonthNames[11] := 'November';
  Result.LongMonthNames[12] := 'December';

  Result.ShortDayNames[1] := 'Sun';
  Result.ShortDayNames[2] := 'Mon';
  Result.ShortDayNames[3] := 'Tue';
  Result.ShortDayNames[4] := 'Wed';
  Result.ShortDayNames[5] := 'Thu';
  Result.ShortDayNames[6] := 'Fri';
  Result.ShortDayNames[7] := 'Sat';

  Result.LongDayNames[1] := 'Sunday';
  Result.LongDayNames[2] := 'Monday';
  Result.LongDayNames[3] := 'Tuesday';
  Result.LongDayNames[4] := 'Wednesday';
  Result.LongDayNames[5] := 'Thursday';
  Result.LongDayNames[6] := 'Friday';
  Result.LongDayNames[7] := 'Saturday';

  Result.TwoDigitYearCenturyWindow := 50;
{$ELSE}
  Result := TFormatSettings.Invariant;
{$ENDIF}
end;

end.
