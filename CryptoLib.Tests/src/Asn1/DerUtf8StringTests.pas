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

unit DerUtf8StringTests;

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
  ClpConverters,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type
  TDerUtf8StringTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    /// <summary>
    /// Unicode code point U+10400 coded as surrogate in two native Java UTF-16
    /// code units
    /// </summary>
    FGlyph1Utf16: TCryptoLibGenericArray<WideChar>;
    /// <summary>
    /// U+10400 coded in UTF-8
    /// </summary>
    FGlyph1Utf8: TCryptoLibByteArray;

    /// <summary>
    /// Unicode code point U+6771 in native Java UTF-16
    /// </summary>
    FGlyph2Utf16: TCryptoLibGenericArray<WideChar>;
    /// <summary>
    /// U+6771 coded in UTF-8
    /// </summary>
    FGlyph2Utf8: TCryptoLibByteArray;

    /// <summary>
    /// Unicode code point U+00DF in native Java UTF-16
    /// </summary>
    FGlyph3Utf16: TCryptoLibGenericArray<WideChar>;
    /// <summary>
    /// U+00DF coded in UTF-8
    /// </summary>
    FGlyph3Utf8: TCryptoLibByteArray;

    /// <summary>
    /// Unicode code point U+0041 in native Java UTF-16
    /// </summary>
    FGlyph4Utf16: TCryptoLibGenericArray<WideChar>;
    /// <summary>
    /// U+0041 coded in UTF-8
    /// </summary>
    FGlyph4Utf8: TCryptoLibByteArray;

    class function WideCharArrayToString(const AChars: TCryptoLibGenericArray<WideChar>): String; static;

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestDerUtf8String;
  end;

implementation

{ TDerUtf8StringTest }

class function TDerUtf8StringTest.WideCharArrayToString(const AChars: TCryptoLibGenericArray<WideChar>): String;
var
  LUnicodeStr: UnicodeString;
begin
  if System.Length(AChars) = 0 then
  begin
    Result := '';
    Exit;
  end;

  // Build a UnicodeString from code units WideChar array (including surrogate pairs).
  SetString(LUnicodeStr, PWideChar(@AChars[0]), System.Length(AChars));
  Result := String(LUnicodeStr);
end;

procedure TDerUtf8StringTest.SetUp;
begin
  inherited;

  // glyph1_utf16 = { 0xD801, 0xDC00 }
  System.SetLength(FGlyph1Utf16, 2);
  FGlyph1Utf16[0] := WideChar($D801);
  FGlyph1Utf16[1] := WideChar($DC00);
  FGlyph1Utf8 := TCryptoLibByteArray.Create($F0, $90, $90, $80);

  // glyph2_utf16 = { 0x6771 }
  System.SetLength(FGlyph2Utf16, 1);
  FGlyph2Utf16[0] := WideChar($6771);
  FGlyph2Utf8 := TCryptoLibByteArray.Create($E6, $9D, $B1);

  // glyph3_utf16 = { 0x00DF }
  System.SetLength(FGlyph3Utf16, 1);
  FGlyph3Utf16[0] := WideChar($00DF);
  FGlyph3Utf8 := TCryptoLibByteArray.Create($C3, $9F);

  // glyph4_utf16 = { 0x0041 }
  System.SetLength(FGlyph4Utf16, 1);
  FGlyph4Utf16[0] := WideChar($0041);
  FGlyph4Utf8 := TCryptoLibByteArray.Create($41);
end;

procedure TDerUtf8StringTest.TearDown;
begin
  FGlyph1Utf16 := nil;
  FGlyph2Utf16 := nil;
  FGlyph3Utf16 := nil;
  FGlyph4Utf16 := nil;

  FGlyph1Utf8 := nil;
  FGlyph2Utf8 := nil;
  FGlyph3Utf8 := nil;
  FGlyph4Utf8 := nil;

  inherited;
end;

procedure TDerUtf8StringTest.TestDerUtf8String;
var
  I: Int32;
  S: String;
  B1, B2, Temp: TCryptoLibByteArray;
  LOctetString: IDerOctetString;
  LDerUtf8StringOne, LDerUtf8StringTwo: IDerUtf8String;

  LGlyphsUtf16: TCryptoLibMatrixGenericArray<WideChar>;
  LGlyphsUtf8: TCryptoLibMatrixGenericArray<Byte>;
begin
  // Build glyph tables.

  System.SetLength(LGlyphsUtf16, 4);
  LGlyphsUtf16[0] := FGlyph1Utf16;
  LGlyphsUtf16[1] := FGlyph2Utf16;
  LGlyphsUtf16[2] := FGlyph3Utf16;
  LGlyphsUtf16[3] := FGlyph4Utf16;

  System.SetLength(LGlyphsUtf8, 4);
  LGlyphsUtf8[0] := FGlyph1Utf8;
  LGlyphsUtf8[1] := FGlyph2Utf8;
  LGlyphsUtf8[2] := FGlyph3Utf8;
  LGlyphsUtf8[3] := FGlyph4Utf8;

  try
    for I := 0 to System.Length(LGlyphsUtf16) - 1 do
    begin
      // Convert code units char array to String safely (preserves surrogate pairs)
      S := WideCharArrayToString(LGlyphsUtf16[I]);

      LDerUtf8StringOne := TDerUtf8String.Create(S);
      B1 := LDerUtf8StringOne.GetEncoded();

      System.SetLength(Temp, System.Length(B1) - 2);
      System.Move(B1[2], Temp[0], System.Length(Temp) * System.SizeOf(Byte));

      LOctetString := TDerOctetString.Create(Temp);

      LDerUtf8StringTwo :=
        TDerUtf8String.Create(
          TConverters.ConvertBytesToString(LOctetString.GetOctets(), TEncoding.UTF8)
        );

      B2 := LDerUtf8StringTwo.GetEncoded();

      if not AreEqual(B1, B2) then
      begin
        Fail('failed UTF-8 encoding and decoding');
      end;

      if not AreEqual(Temp, LGlyphsUtf8[I]) then
      begin
        Fail('failed UTF-8 encoding and decoding');
      end;
    end;
  except
    on E: Exception do
    begin
      Fail('failed with Exception ' + E.Message);
    end;
  end;
end;

initialization

{$IFDEF FPC}
RegisterTest(TDerUtf8StringTest);
{$ELSE}
RegisterTest(TDerUtf8StringTest.Suite);
{$ENDIF FPC}

end.

