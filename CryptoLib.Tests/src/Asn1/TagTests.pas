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

unit TagTests;

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
  ClpSecureRandom,
  ClpISecureRandom,
  ClpBits,
  CryptoLibTestBase;

type

  /// <summary>
  /// X.690 test example
  /// </summary>
  TTestTag = class(TCryptoLibAlgorithmTestCase)
  private

  var
    FlongAppSpecificTag, FlongTagged: TBytes;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestTag;

  end;

implementation

{ TTestTag }

procedure TTestTag.SetUp;
begin
  inherited;
  FlongAppSpecificTag := DecodeHex('5F610101');

  FlongTagged := DecodeBase64
    ('ZSRzIp8gEEZFRENCQTk4NzY1NDMyMTCfIQwyMDA2MDQwMTEyMzSUCCAFERVz' +
    'A4kCAHEXGBkalAggBRcYGRqUCCAFZS6QAkRFkQlURUNITklLRVKSBQECAwQF' +
    'kxAREhMUFRYXGBkalAggBREVcwOJAgBxFxgZGpQIIAUXGBkalAggBWUukAJE' +
    'RZEJVEVDSE5JS0VSkgUBAgMEBZMQERITFBUWFxgZGpQIIAURFXMDiQIAcRcY' +
    'GRqUCCAFFxgZGpQIIAVlLpACREWRCVRFQ0hOSUtFUpIFAQIDBAWTEBESExQV' +
    'FhcYGRqUCCAFERVzA4kCAHEXGBkalAggBRcYGRqUCCAFFxgZGpQIIAUXGBka' + 'lAg=');

end;

procedure TTestTag.TearDown;
begin
  inherited;

end;

procedure TTestTag.TestTag;
var
  aIn: TAsn1InputStream;
  app: IDerApplicationSpecific;
  tagged: IAsn1TaggedObject;
  sr: ISecureRandom;
  LTestTag, I: Int32;
begin

  aIn := TAsn1InputStream.Create(FlongTagged);
  try
    app := aIn.ReadObject() as IDerApplicationSpecific;
  finally
    aIn.Free;
  end;

  aIn := TAsn1InputStream.Create(app.GetContents());
  try
    app := aIn.ReadObject() as IDerApplicationSpecific;
  finally
    aIn.Free;
  end;

  aIn := TAsn1InputStream.Create(app.GetContents());
  try
    tagged := aIn.ReadObject() as IAsn1TaggedObject;

    if (tagged.TagNo <> 32) then
    begin
      Fail('unexpected tag value found - not 32');
    end;

    tagged := TAsn1Object.FromByteArray(tagged.GetEncoded())
      as IAsn1TaggedObject;

    if (tagged.TagNo <> 32) then
    begin
      Fail('unexpected tag value found on recode - not 32');
    end;

    tagged := aIn.ReadObject() as IAsn1TaggedObject;

  finally
    aIn.Free;
  end;

  if (tagged.TagNo <> 33) then
  begin
    Fail('unexpected tag value found - not 33');
  end;

  tagged := TAsn1Object.FromByteArray(tagged.GetEncoded()) as IAsn1TaggedObject;

  if (tagged.TagNo <> 33) then
  begin
    Fail('unexpected tag value found on recode - not 33');
  end;

  aIn := TAsn1InputStream.Create(FlongAppSpecificTag);
  try
    app := aIn.ReadObject() as IDerApplicationSpecific;
  finally
    aIn.Free;
  end;

  if (app.ApplicationTag <> 97) then
  begin
    Fail('incorrect tag number read');
  end;

  app := TAsn1Object.FromByteArray(app.GetEncoded()) as IDerApplicationSpecific;

  if (app.ApplicationTag <> 97) then
  begin
    Fail('incorrect tag number read on recode');
  end;

  sr := TSecureRandom.Create();

  I := 0;
  while I < 100 do
  begin
    LTestTag := TBits.Asr32(sr.NextInt32() and System.High(Int32), sr.Next(26));
    app := TDerApplicationSpecific.Create(LTestTag, TBytes.Create(1));
    app := TAsn1Object.FromByteArray(app.GetEncoded())
      as IDerApplicationSpecific;

    if (app.ApplicationTag <> LTestTag) then
    begin
      Fail(Format
        ('incorrect tag number read on recode (random test value: " %d ")',
        [LTestTag]));
    end;

    System.Inc(I);
  end;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestTag);
{$ELSE}
  RegisterTest(TTestTag.Suite);
{$ENDIF FPC}

end.
