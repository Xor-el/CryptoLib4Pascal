{ Optional SecP521 diagnostics: write rate-limited lines to stderr (CI-captured). }
unit ClpSecP521RuntimeTrace;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCryptoLibTypes;

type
  TSecP521RuntimeTrace = class sealed
  private
  class var
    FConfigChecked: Boolean;
    FEnabled: Boolean;
    FLineCount: Int32;
  public
    const MaxLines = 200;
    class function IsEnabled: Boolean; static;
    class procedure Line(const AMsg: String); static;
    class procedure LineFmt(const AFmt: String; const AArgs: array of const); static;
    class procedure LimbsHex(const ALabel: String; const ALimbs: TCryptoLibUInt32Array; ACount: Int32); static;
  end;

implementation

{ ErrOutput: FPC System standard error (Console + most CI). }

class function TSecP521RuntimeTrace.IsEnabled: Boolean;
var
  L: String;
begin
  if FConfigChecked then
    Exit(FEnabled);
  FConfigChecked := True;
  {$IFDEF CRYPTOLIB_SECP521_TRACE_ALWAYS}
  FEnabled := True;
  {$ELSE}
  L := GetEnvironmentVariable('CRYPTOLIB_SECP521_TRACE');
  FEnabled := SameText(L, '1') or SameText(L, 'true') or SameText(L, 'yes');
  {$ENDIF}
  Result := FEnabled;
end;

class procedure TSecP521RuntimeTrace.Line(const AMsg: String);
begin
  if not IsEnabled then
    Exit;
  if FLineCount >= MaxLines then
    Exit;
  Inc(FLineCount);
  try
    {$IFDEF FPC}
    WriteLn(ErrOutput, '[CryptoLib P-521 #', FLineCount, '/', MaxLines, '] ', AMsg);
    {$ENDIF FPC}
  except
  end;
end;

class procedure TSecP521RuntimeTrace.LineFmt(const AFmt: String; const AArgs: array of const);
begin
  Line(Format(AFmt, AArgs));
end;

class procedure TSecP521RuntimeTrace.LimbsHex(const ALabel: String; const ALimbs: TCryptoLibUInt32Array; ACount: Int32);
var
  I, LN: Int32;
  SB: String;
begin
  if not IsEnabled then
    Exit;
  if FLineCount >= MaxLines then
    Exit;
  LN := System.Length(ALimbs);
  if (ACount < 1) or (ACount > LN) then
  begin
    LineFmt('%s (bad limb count n=%d want=%d)', [ALabel, LN, ACount]);
    Exit;
  end;
  SB := ALabel + ' [';
  for I := 0 to ACount - 1 do
  begin
    if I > 0 then
      SB := SB + ' ';
    SB := SB + IntToHex(Int64(ALimbs[I]) and $FFFFFFFF, 8);
  end;
  Line(SB + ']');
end;

end.
