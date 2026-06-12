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

unit Asn1GeneratorTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  Classes,
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIAsn1Generators,
  ClpAsn1Generators,
  ClpIAsn1Core,
  ClpAsn1Core,
  ClpStreamUtilities,
  ClpCryptoLibTypes,
  ClpArrayUtilities,
  CryptoLibTestBase;

type

  /// <summary>
  /// ASN.1 streaming generator tests.
  /// </summary>
  TAsn1GeneratorTest = class(TCryptoLibAlgorithmTestCase)
  private
    procedure AddSequenceContents(const AGen: IBerSequenceGenerator); overload;
    procedure AddSequenceContents(const AGen: IDerSequenceGenerator); overload;
    procedure WriteOctets(const AGen: IBerOctetStringGenerator; const AOctets: TCryptoLibByteArray);
    procedure TestTaggedBerSequence(ATagNo: Int32; ADeclaredExplicit: Boolean; const ASeq: IAsn1Sequence);
    procedure TestTaggedDerSequence(ATagNo: Int32; ADeclaredExplicit: Boolean; const ASeq: IAsn1Sequence);
    procedure TestTaggedBerOctetString(ATagNo: Int32; ADeclaredExplicit: Boolean; const AOctets: TCryptoLibByteArray);
    procedure CheckSequenceRoundTrip(const AEncoding: TCryptoLibByteArray; ATagNo: Int32;
      ADeclaredExplicit: Boolean; const AExpected: IAsn1Sequence);
    procedure CheckBerOctetStringEncoding(const AEncoding, AExpectedOctets: TCryptoLibByteArray;
      const AMessage: String);
    procedure CheckTaggedOctetStringEncoding(const AEncoding: TCryptoLibByteArray; AExpectedTagNo: Int32;
      ADeclaredExplicit: Boolean; const AExpectedOctets: TCryptoLibByteArray; const AMessage: String);
  published
    procedure TestAll;
  end;

implementation

const
  TAG_NOS: array[0..6] of Int32 = (0, 1, 30, 31, 127, 128, 5000);

{ TAsn1GeneratorTest }

procedure TAsn1GeneratorTest.AddSequenceContents(const AGen: IBerSequenceGenerator);
begin
  AGen.AddObject(TDerInteger.ValueOf(4095));
  AGen.AddObject(TDerOctetString.FromContents(TCryptoLibByteArray.Create(1, 2, 3, 4)));
end;

procedure TAsn1GeneratorTest.AddSequenceContents(const AGen: IDerSequenceGenerator);
begin
  AGen.AddObject(TDerInteger.ValueOf(4095));
  AGen.AddObject(TDerOctetString.FromContents(TCryptoLibByteArray.Create(1, 2, 3, 4)));
end;

procedure TAsn1GeneratorTest.WriteOctets(const AGen: IBerOctetStringGenerator; const AOctets: TCryptoLibByteArray);
var
  LOctOut: TStream;
begin
  LOctOut := AGen.GetOctetOutputStream();
  try
    if System.Length(AOctets) > 0 then
      LOctOut.Write(AOctets[0], System.Length(AOctets));
  finally
    LOctOut.Free;
  end;
end;

procedure TAsn1GeneratorTest.CheckSequenceRoundTrip(const AEncoding: TCryptoLibByteArray; ATagNo: Int32;
  ADeclaredExplicit: Boolean; const AExpected: IAsn1Sequence);
var
  LTaggedObject: IAsn1TaggedObject;
  LSequence: IAsn1Sequence;
begin
  LTaggedObject := TAsn1TaggedObject.GetInstance(AEncoding);
  CheckTrue(LTaggedObject.HasContextTag(ATagNo),
    'seq tagNo [' + IntToStr(ATagNo) + ']');

  LSequence := TAsn1Sequence.GetInstance(LTaggedObject, ADeclaredExplicit);
  CheckTrue(AreEqual(AExpected.GetEncoded(TAsn1Encodable.Der),
    LSequence.GetEncoded(TAsn1Encodable.Der)),
    'seq content [' + IntToStr(ATagNo) + '] explicit=' + SysUtils.BoolToStr(ADeclaredExplicit, True));
end;

procedure TAsn1GeneratorTest.CheckBerOctetStringEncoding(const AEncoding, AExpectedOctets: TCryptoLibByteArray;
  const AMessage: String);
var
  LOctetString: IAsn1OctetString;
begin
  LOctetString := TAsn1OctetString.GetInstance(AEncoding);
  CheckTrue(TArrayUtilities.AreEqual(AExpectedOctets, LOctetString.GetOctets()), AMessage);
end;

procedure TAsn1GeneratorTest.CheckTaggedOctetStringEncoding(const AEncoding: TCryptoLibByteArray;
  AExpectedTagNo: Int32; ADeclaredExplicit: Boolean; const AExpectedOctets: TCryptoLibByteArray;
  const AMessage: String);
var
  LTaggedObject: IAsn1TaggedObject;
  LOctetString: IAsn1OctetString;
begin
  LTaggedObject := TAsn1TaggedObject.GetInstance(AEncoding);
  CheckTrue(LTaggedObject.HasContextTag(AExpectedTagNo),
    'octets tagNo [' + IntToStr(AExpectedTagNo) + ']');

  LOctetString := TAsn1OctetString.GetInstance(LTaggedObject, ADeclaredExplicit);
  CheckTrue(TArrayUtilities.AreEqual(AExpectedOctets, LOctetString.GetOctets()), AMessage);
end;

procedure TAsn1GeneratorTest.TestTaggedBerSequence(ATagNo: Int32; ADeclaredExplicit: Boolean;
  const ASeq: IAsn1Sequence);
var
  LBOut: TMemoryStream;
  LGen: IBerSequenceGenerator;
  LExpected, LActual: TCryptoLibByteArray;
  LTagged: IAsn1TaggedObject;
begin
  LBOut := TMemoryStream.Create();
  try
    LGen := TBerSequenceGenerator.Create(LBOut, ATagNo, ADeclaredExplicit);
    AddSequenceContents(LGen);
    LGen.Close();

    LTagged := TBerTaggedObject.Create(ADeclaredExplicit, ATagNo, ASeq);
    LExpected := LTagged.GetEncoded();
    LBOut.Position := 0;
    LActual := TStreamUtilities.ReadAll(LBOut);

    CheckTrue(AreEqual(LExpected, LActual),
      'BER seq [' + IntToStr(ATagNo) + '] explicit=' + SysUtils.BoolToStr(ADeclaredExplicit, True));

    CheckSequenceRoundTrip(LActual, ATagNo, ADeclaredExplicit, ASeq);
  finally
    LBOut.Free;
  end;
end;

procedure TAsn1GeneratorTest.TestTaggedDerSequence(ATagNo: Int32; ADeclaredExplicit: Boolean;
  const ASeq: IAsn1Sequence);
var
  LBOut: TMemoryStream;
  LGen: IDerSequenceGenerator;
  LExpected, LActual: TCryptoLibByteArray;
  LTagged: IAsn1TaggedObject;
begin
  LBOut := TMemoryStream.Create();
  try
    LGen := TDerSequenceGenerator.Create(LBOut, ATagNo, ADeclaredExplicit);
    AddSequenceContents(LGen);
    LGen.Close();

    LTagged := TDerTaggedObject.Create(ADeclaredExplicit, ATagNo, ASeq);
    LExpected := LTagged.GetEncoded(TAsn1Encodable.Der);
    LBOut.Position := 0;
    LActual := TStreamUtilities.ReadAll(LBOut);

    CheckTrue(AreEqual(LExpected, LActual),
      'DER seq [' + IntToStr(ATagNo) + '] explicit=' + SysUtils.BoolToStr(ADeclaredExplicit, True));

    CheckSequenceRoundTrip(LActual, ATagNo, ADeclaredExplicit, ASeq);
  finally
    LBOut.Free;
  end;
end;

procedure TAsn1GeneratorTest.TestTaggedBerOctetString(ATagNo: Int32; ADeclaredExplicit: Boolean;
  const AOctets: TCryptoLibByteArray);
var
  LBOut: TMemoryStream;
  LGen: IBerOctetStringGenerator;
  LActual: TCryptoLibByteArray;
begin
  LBOut := TMemoryStream.Create();
  try
    LGen := TBerOctetStringGenerator.Create(LBOut, ATagNo, ADeclaredExplicit);
    WriteOctets(LGen, AOctets);
    LGen.Close();

    LBOut.Position := 0;
    LActual := TStreamUtilities.ReadAll(LBOut);

    CheckTaggedOctetStringEncoding(LActual, ATagNo, ADeclaredExplicit, AOctets,
      'BER octets [' + IntToStr(ATagNo) + '] explicit=' + SysUtils.BoolToStr(ADeclaredExplicit, True));
  finally
    LBOut.Free;
  end;
end;

procedure TAsn1GeneratorTest.TestAll;
var
  LContent, LActual: TCryptoLibByteArray;
  LVector: IAsn1EncodableVector;
  LBerSeq, LDerSeq: IAsn1Sequence;
  LBOut: TMemoryStream;
  LBerSeqGen: IBerSequenceGenerator;
  LDerSeqGen: IDerSequenceGenerator;
  LBerOctGen: IBerOctetStringGenerator;
  LI: Int32;
begin
  System.SetLength(LContent, 2500);
  for LI := 0 to System.Length(LContent) - 1 do
    LContent[LI] := Byte(LI);

  LVector := TAsn1EncodableVector.Create();
  LVector.Add(TDerInteger.ValueOf(4095));
  LVector.Add(TDerOctetString.FromContents(TCryptoLibByteArray.Create(1, 2, 3, 4)));

  LBerSeq := TBerSequence.FromVector(LVector);
  LDerSeq := TDerSequence.FromVector(LVector);

  LBOut := TMemoryStream.Create();
  try
    LBerSeqGen := TBerSequenceGenerator.Create(LBOut);
    AddSequenceContents(LBerSeqGen);
    LBerSeqGen.Close();

    LBOut.Position := 0;
    LActual := TStreamUtilities.ReadAll(LBOut);
    CheckTrue(AreEqual(LBerSeq.GetEncoded(), LActual), 'untagged BER seq');
  finally
    LBOut.Free;
  end;

  LBOut := TMemoryStream.Create();
  try
    LDerSeqGen := TDerSequenceGenerator.Create(LBOut);
    AddSequenceContents(LDerSeqGen);
    LDerSeqGen.Close();

    LBOut.Position := 0;
    LActual := TStreamUtilities.ReadAll(LBOut);
    CheckTrue(AreEqual(LDerSeq.GetEncoded(TAsn1Encodable.Der), LActual), 'untagged DER seq');
  finally
    LBOut.Free;
  end;

  LBOut := TMemoryStream.Create();
  try
    LBerOctGen := TBerOctetStringGenerator.Create(LBOut);
    WriteOctets(LBerOctGen, LContent);
    LBerOctGen.Close();

    LBOut.Position := 0;
    LActual := TStreamUtilities.ReadAll(LBOut);
    CheckBerOctetStringEncoding(LActual, LContent, 'untagged BER octets');
  finally
    LBOut.Free;
  end;

  for LI := 0 to System.Length(TAG_NOS) - 1 do
  begin
    TestTaggedBerSequence(TAG_NOS[LI], True, LBerSeq);
    TestTaggedBerSequence(TAG_NOS[LI], False, LBerSeq);
    TestTaggedDerSequence(TAG_NOS[LI], True, LDerSeq);
    TestTaggedDerSequence(TAG_NOS[LI], False, LDerSeq);
    TestTaggedBerOctetString(TAG_NOS[LI], True, LContent);
    TestTaggedBerOctetString(TAG_NOS[LI], False, LContent);
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TAsn1GeneratorTest);
{$ELSE}
  RegisterTest(TAsn1GeneratorTest.Suite);
{$ENDIF FPC}

end.
