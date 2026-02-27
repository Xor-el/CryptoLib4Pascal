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
  ClpAsn1Core,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpAsn1Streams,
  ClpAsn1Tags,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpBitOperations,
  ClpEncoders,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTagTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    FLongTagged: TCryptoLibByteArray;
    FLongAppSpecificTag: TCryptoLibByteArray;
    FTaggedInteger: TCryptoLibByteArray;
  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestTag;
  end;

implementation

{ TTagTest }

procedure TTagTest.SetUp;
begin
  inherited;
  FLongTagged := TBase64Encoder.Decode(
    'ZSRzIp8gEEZFRENCQTk4NzY1NDMyMTCfIQwyMDA2MDQwMTEyMzSUCCAFERVz' +
    'A4kCAHEXGBkalAggBRcYGRqUCCAFZS6QAkRFkQlURUNITklLRVKSBQECAwQF' +
    'kxAREhMUFRYXGBkalAggBREVcwOJAgBxFxgZGpQIIAUXGBkalAggBWUukAJE' +
    'RZEJVEVDSE5JS0VSkgUBAgMEBZMQERITFBUWFxgZGpQIIAURFXMDiQIAcRcY' +
    'GRqUCCAFFxgZGpQIIAVlLpACREWRCVRFQ0hOSUtFUpIFAQIDBAWTEBESExQV' +
    'FhcYGRqUCCAFERVzA4kCAHEXGBkalAggBRcYGRqUCCAFFxgZGpQIIAUXGBka' +
    'lAg=');
  FLongAppSpecificTag := THexEncoder.Decode('5F610101');
  FTaggedInteger := THexEncoder.Decode('BF2203020101');
end;

procedure TTagTest.TearDown;
begin
  FLongTagged := nil;
  FLongAppSpecificTag := nil;
  FTaggedInteger := nil;
  inherited;
end;

procedure TTagTest.TestTag;
var
  LAIn: TAsn1InputStream;
  LApp: IAsn1TaggedObject;
  LTagged: IAsn1TaggedObject;
  LSequence: IAsn1Sequence;
  LSR: ISecureRandom;
  LTestTag, I: Int32;
begin
  LAIn := TAsn1InputStream.Create(FLongTagged);
  try
    LApp := LAIn.ReadObject() as IAsn1TaggedObject;
  finally
    LAIn.Free;
  end;

  if not LApp.HasTag(TAsn1Tags.Application, 5) then
  begin
    Fail('unexpected tag value found - not 5');
  end;

  LApp := LApp.GetExplicitBaseTagged();
  if not LApp.HasTag(TAsn1Tags.Application, 19) then
  begin
    Fail('unexpected tag value found - not 19');
  end;

  LSequence := LApp.GetBaseUniversal(False, TAsn1Tags.Sequence) as IAsn1Sequence;

  LTagged := LSequence[0] as IAsn1TaggedObject;
  if not LTagged.HasContextTag(32) then
  begin
    Fail('unexpected tag value found - not 32');
  end;

  LTagged := TAsn1TaggedObject.GetInstance(TAsn1Object.FromByteArray(LTagged.GetEncoded())) as IAsn1TaggedObject;
  if not LTagged.HasContextTag(32) then
  begin
    Fail('unexpected tag value found on recode - not 32');
  end;

  LTagged := LSequence[1] as IAsn1TaggedObject;
  if not LTagged.HasContextTag(33) then
  begin
    Fail('unexpected tag value found - not 33');
  end;

  LTagged := TAsn1TaggedObject.GetInstance(TAsn1Object.FromByteArray(LTagged.GetEncoded())) as IAsn1TaggedObject;
  if not LTagged.HasContextTag(33) then
  begin
    Fail('unexpected tag value found on recode - not 33');
  end;

  LAIn := TAsn1InputStream.Create(FLongAppSpecificTag);
  try
    LApp := LAIn.ReadObject() as IAsn1TaggedObject;
  finally
    LAIn.Free;
  end;

  if not LApp.HasTag(TAsn1Tags.Application, 97) then
  begin
    Fail('incorrect tag number read');
  end;

  LApp := TAsn1TaggedObject.GetInstance(TAsn1Object.FromByteArray(LApp.GetEncoded())) as IAsn1TaggedObject;
  if not LApp.HasTag(TAsn1Tags.Application, 97) then
  begin
    Fail('incorrect tag number read on recode');
  end;

  LSR := TSecureRandom.Create();
  for I := 0 to 99 do
  begin
    LTestTag := TBitOperations.Asr32(LSR.NextInt32() and System.High(Int32), LSR.Next(26));
    LApp := TDerTaggedObject.Create(False, TAsn1Tags.Application, LTestTag, TDerOctetString.Create(TCryptoLibByteArray.Create(1)) as IDerOctetString);
    LApp := TAsn1TaggedObject.GetInstance(TAsn1Object.FromByteArray(LApp.GetEncoded())) as IAsn1TaggedObject;

    if not LApp.HasTag(TAsn1Tags.Application, LTestTag) then
    begin
      Fail(Format('incorrect tag number read on recode (random test value: %d)', [LTestTag]));
    end;
  end;

  LTagged := TDerTaggedObject.Create(False, 34, TDerTaggedObject.Create(True, 1000, TDerInteger.One) as IDerTaggedObject);
  if not AreEqual(FTaggedInteger, LTagged.GetEncoded()) then
  begin
    Fail('incorrect encoding for implicit explicit tagged integer');
  end;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTagTest);
{$ELSE}
  RegisterTest(TTagTest.Suite);
{$ENDIF FPC}

end.
