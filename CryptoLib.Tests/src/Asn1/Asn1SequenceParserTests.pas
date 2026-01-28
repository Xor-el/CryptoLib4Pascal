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

unit Asn1SequenceParserTests;

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
  ClpBigInteger,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIAsn1Parsers,
  ClpAsn1Parsers,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestAsn1SequenceParser = class(TCryptoLibAlgorithmTestCase)
  private

  var
    FSeqData, FNestedSeqData, FExpTagSeqData, FImplTagSeqData,
      FNestedSeqExpTagData, FNestedSeqImpTagData, FBerSeqData,
      FBerDerNestedSeqData, FBerNestedSeqData, FBerExpTagSeqData,
      FBerSeqWithDERNullData: TCryptoLibByteArray;

    procedure DoTestNestedReading(const AData: TCryptoLibByteArray);
    procedure DoTestParseWithNull(const AData: TCryptoLibByteArray);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestDerWriting;
    procedure TestNestedDerWriting;
    procedure TestDerExplicitTaggedSequenceWriting;
    procedure TestDerImplicitTaggedSequenceWriting;
    procedure TestNestedExplicitTagDerWriting;
    procedure TestNestedImplicitTagDerWriting;
    procedure TestBerWriting;
    procedure TestNestedBerDerWriting;
    procedure TestNestedBerWriting;
    procedure TestDerReading;
    procedure TestNestedDerReading;
    procedure TestBerReading;
    procedure TestNestedBerDerReading;
    procedure TestNestedBerReading;
    procedure TestBerExplicitTaggedSequenceWriting;
    procedure TestSequenceWithDerNullReading;

  end;

implementation

{ TTestAsn1SequenceParser }

procedure TTestAsn1SequenceParser.DoTestNestedReading(const AData: TCryptoLibByteArray);
var
  AIn: IAsn1StreamParser;
  Seq, S: IAsn1SequenceParser;
  O: IInterface;
  Count: Int32;
begin
  AIn := TAsn1StreamParser.Create(AData);
  Seq := AIn.ReadObject() as IAsn1SequenceParser;

  Count := 0;

  CheckNotNull(Seq, 'null sequence returned');

  O := Seq.ReadObject();
  while (O <> nil) do
  begin
    case Count of

      0:
        begin
          CheckTrue(Supports(O, IDerInteger));
        end;
      1:
        begin
          CheckTrue(Supports(O, IDerObjectIdentifier));
        end;
      2:
        begin
          CheckTrue(Supports(O, IAsn1SequenceParser));

          S := O as IAsn1SequenceParser;

          // NB: Must exhaust the nested parser
          while (S.ReadObject() <> nil) do
          begin
            // Ignore
          end;

        end;
    end;

    System.Inc(Count);
    O := Seq.ReadObject();
  end;

  CheckEquals(3, Count, 'wrong number of objects in sequence');
end;

procedure TTestAsn1SequenceParser.DoTestParseWithNull(const AData: TCryptoLibByteArray);
var
  AIn: IAsn1StreamParser;
  Seq: IAsn1SequenceParser;
  O: IInterface;
  Count: Int32;
begin
  AIn := TAsn1StreamParser.Create(AData);
  Seq := AIn.ReadObject() as IAsn1SequenceParser;

  Count := 0;

  CheckNotNull(Seq, 'null sequence returned');

  O := Seq.ReadObject();
  while (O <> nil) do
  begin
    case Count of

      0:
        begin
          CheckTrue(Supports(O, IAsn1Null));
        end;
      1:
        begin
          CheckTrue(Supports(O, IDerInteger));
        end;
      2:
        begin
          CheckTrue(Supports(O, IDerObjectIdentifier));
        end;
    end;

    System.Inc(Count);
    O := Seq.ReadObject();
  end;

  CheckEquals(3, Count, 'wrong number of objects in sequence');
end;

procedure TTestAsn1SequenceParser.SetUp;
begin
  inherited;
  FSeqData := DecodeHex('3006020100060129');
  FNestedSeqData := DecodeHex('300b0201000601293003020101');
  FExpTagSeqData := DecodeHex('a1083006020100060129');
  FImplTagSeqData := DecodeHex('a106020100060129');
  FNestedSeqExpTagData := DecodeHex('300d020100060129a1053003020101');
  FNestedSeqImpTagData := DecodeHex('300b020100060129a103020101');

  FBerSeqData := DecodeHex('30800201000601290000');
  FBerDerNestedSeqData := DecodeHex('308002010006012930030201010000');
  FBerNestedSeqData := DecodeHex('3080020100060129308002010100000000');
  FBerExpTagSeqData := DecodeHex('a180308002010006012900000000');
  FBerSeqWithDERNullData := DecodeHex('308005000201000601290000');
end;

procedure TTestAsn1SequenceParser.TearDown;
begin
  inherited;

end;

procedure TTestAsn1SequenceParser.TestBerExplicitTaggedSequenceWriting;
var
  BOut: TMemoryStream;
  SeqGen: IBerSequenceGenerator;
  Temp: TCryptoLibByteArray;
begin
  BOut := TMemoryStream.Create();

  try
    SeqGen := TBerSequenceGenerator.Create(BOut, 1, True);

    SeqGen.AddObject(TDerInteger.Create(TBigInteger.Zero) as IDerInteger);

    SeqGen.AddObject(TDerObjectIdentifier.Create('1.1') as IDerObjectIdentifier);

    SeqGen.Close();

    BOut.Position := 0;
    System.SetLength(Temp, BOut.Size);
    BOut.Read(Temp[0], BOut.Size);

    CheckTrue(AreEqual(FBerExpTagSeqData, Temp),
      'explicit BER tag writing test failed.');
  finally
    BOut.Free;
  end;
end;

procedure TTestAsn1SequenceParser.TestBerReading;
var
  AIn: IAsn1StreamParser;
  Seq: IAsn1SequenceParser;
  Count: Int32;
  O: IInterface;
begin
  AIn := TAsn1StreamParser.Create(FBerSeqData);

  Seq := AIn.ReadObject() as IAsn1SequenceParser;
  Count := 0;

  CheckNotNull(Seq, 'null sequence returned');

  O := Seq.ReadObject();
  while (O <> nil) do
  begin
    case Count of

      0:
        begin
          CheckTrue(Supports(O, IDerInteger));

        end;
      1:
        begin
          CheckTrue(Supports(O, IDerObjectIdentifier));

        end;
    end;

    System.Inc(Count);
    O := Seq.ReadObject();
  end;

  CheckEquals(2, Count, 'wrong number of objects in sequence');
end;


procedure TTestAsn1SequenceParser.TestBerWriting;
var
  BOut: TMemoryStream;
  SeqGen: IBerSequenceGenerator;
  Temp: TCryptoLibByteArray;
begin
  BOut := TMemoryStream.Create();
  try
    SeqGen := TBerSequenceGenerator.Create(BOut);

    SeqGen.AddObject(TDerInteger.Create(TBigInteger.Zero) as IDerInteger);

    SeqGen.AddObject(TDerObjectIdentifier.Create('1.1')
      as IDerObjectIdentifier);

    SeqGen.Close();
    BOut.Position := 0;
    System.SetLength(Temp, BOut.Size);
    BOut.Read(Temp[0], BOut.Size);
    CheckTrue(AreEqual(FBerSeqData, Temp), 'basic BER writing test failed.');
  finally
    BOut.Free;
  end;
end;

procedure TTestAsn1SequenceParser.TestDerExplicitTaggedSequenceWriting;
var
  BOut: TMemoryStream;
  Temp: TCryptoLibByteArray;
  SeqGen: IDerSequenceGenerator;
begin
  BOut := TMemoryStream.Create();
  try
    SeqGen := TDerSequenceGenerator.Create(BOut, 1, True);

    SeqGen.AddObject(TDerInteger.Create(TBigInteger.Zero) as IDerInteger);

    SeqGen.AddObject(TDerObjectIdentifier.Create('1.1')
      as IDerObjectIdentifier);

    SeqGen.Close();

    BOut.Position := 0;
    System.SetLength(Temp, BOut.Size);
    BOut.Read(Temp[0], BOut.Size);

    CheckTrue(AreEqual(FExpTagSeqData, Temp),
      'explicit tag writing test failed.');
  finally
    BOut.Free;
  end;
end;

procedure TTestAsn1SequenceParser.TestDerImplicitTaggedSequenceWriting;
var
  BOut: TMemoryStream;
  SeqGen: IDerSequenceGenerator;
  Temp: TCryptoLibByteArray;
begin
  BOut := TMemoryStream.Create();
  try
    SeqGen := TDerSequenceGenerator.Create(BOut, 1, False);

    SeqGen.AddObject(TDerInteger.Create(TBigInteger.Zero) as IDerInteger);

    SeqGen.AddObject(TDerObjectIdentifier.Create('1.1')
      as IDerObjectIdentifier);

    SeqGen.Close();

    BOut.Position := 0;
    System.SetLength(Temp, BOut.Size);
    BOut.Read(Temp[0], BOut.Size);

    CheckTrue(AreEqual(FImplTagSeqData, Temp),
      'implicit tag writing test failed.');
  finally
    BOut.Free;
  end;
end;

procedure TTestAsn1SequenceParser.TestDerReading;
var
  AIn: IAsn1StreamParser;
  Seq: IAsn1SequenceParser;
  Count: Int32;
  O: IInterface;
begin
  AIn := TAsn1StreamParser.Create(FSeqData);

  Seq := AIn.ReadObject() as IAsn1SequenceParser;
  Count := 0;

  CheckNotNull(Seq, 'null sequence returned');

  O := Seq.ReadObject();
  while (O <> nil) do
  begin
    case Count of

      0:
        begin
          CheckTrue(Supports(O, IDerInteger));

        end;
      1:
        begin
          CheckTrue(Supports(O, IDerObjectIdentifier));

        end;
    end;

    System.Inc(Count);
    O := Seq.ReadObject();
  end;

  CheckEquals(2, Count, 'wrong number of objects in sequence');
end;

procedure TTestAsn1SequenceParser.TestDerWriting;
var
  BOut: TMemoryStream;
  SeqGen: IDerSequenceGenerator;
  Temp: TCryptoLibByteArray;
begin
  BOut := TMemoryStream.Create();
  try
    SeqGen := TDerSequenceGenerator.Create(BOut);

    SeqGen.AddObject(TDerInteger.Create(TBigInteger.Zero) as IDerInteger);

    SeqGen.AddObject(TDerObjectIdentifier.Create('1.1')
      as IDerObjectIdentifier);

    SeqGen.Close();
    BOut.Position := 0;
    System.SetLength(Temp, BOut.Size);
    BOut.Read(Temp[0], BOut.Size);
    CheckTrue(AreEqual(FSeqData, Temp), 'basic DER writing test failed.');
  finally
    BOut.Free;
  end;
end;

procedure TTestAsn1SequenceParser.TestNestedBerDerReading;
begin
  DoTestNestedReading(FBerDerNestedSeqData);
end;

procedure TTestAsn1SequenceParser.TestNestedBerDerWriting;
var
  BOut: TMemoryStream;
  SeqGen1: IBerSequenceGenerator;
  SeqGen2: IDerSequenceGenerator;
  Temp: TCryptoLibByteArray;
begin
  BOut := TMemoryStream.Create();
  try
    SeqGen1 := TBerSequenceGenerator.Create(bOut);

    SeqGen1.AddObject(TDerInteger.Create(TBigInteger.Zero) as IDerInteger);

    SeqGen1.AddObject(TDerObjectIdentifier.Create('1.1')
      as IDerObjectIdentifier);

    SeqGen2 := TDerSequenceGenerator.Create(seqGen1.GetRawOutputStream());

    SeqGen2.AddObject(TDerInteger.Create(TBigInteger.ValueOf(1))
      as IDerInteger);

    SeqGen2.Close();

    SeqGen1.Close();

    BOut.Position := 0;
    System.SetLength(temp, bOut.Size);
    BOut.Read(temp[0], bOut.Size);
    CheckTrue(AreEqual(FBerDerNestedSeqData, temp),
      'nested BER/DER writing test failed.');
  finally
    BOut.Free;
  end;
end;

procedure TTestAsn1SequenceParser.TestNestedBerReading;
begin
  DoTestNestedReading(FBerNestedSeqData);
end;

procedure TTestAsn1SequenceParser.TestNestedBerWriting;
var
  BOut: TMemoryStream;
  SeqGen1, seqGen2: IBerSequenceGenerator;
  Temp: TCryptoLibByteArray;
begin
  BOut := TMemoryStream.Create();
  try
    SeqGen1 := TBerSequenceGenerator.Create(bOut);

    SeqGen1.AddObject(TDerInteger.Create(TBigInteger.Zero) as IDerInteger);

    SeqGen1.AddObject(TDerObjectIdentifier.Create('1.1')
      as IDerObjectIdentifier);

    SeqGen2 := TBerSequenceGenerator.Create(seqGen1.GetRawOutputStream());

    SeqGen2.AddObject(TDerInteger.Create(TBigInteger.ValueOf(1)) as IDerInteger);

    SeqGen2.Close();

    SeqGen1.Close();

    BOut.Position := 0;
    System.SetLength(temp, bOut.Size);
    BOut.Read(temp[0], bOut.Size);
    CheckTrue(AreEqual(FBerNestedSeqData, temp),
      'nested BER writing test failed.');
  finally
    BOut.Free;
  end;
end;

procedure TTestAsn1SequenceParser.TestNestedDerReading;
begin
  DoTestNestedReading(FNestedSeqData);
end;

procedure TTestAsn1SequenceParser.TestNestedDerWriting;
var
  BOut: TMemoryStream;
  SeqGen1, seqGen2: IDerSequenceGenerator;
  Temp: TCryptoLibByteArray;
begin
  BOut := TMemoryStream.Create();
  try
    SeqGen1 := TDerSequenceGenerator.Create(bOut);

    SeqGen1.AddObject(TDerInteger.Create(TBigInteger.Zero) as IDerInteger);

    SeqGen1.AddObject(TDerObjectIdentifier.Create('1.1')
      as IDerObjectIdentifier);

    SeqGen2 := TDerSequenceGenerator.Create(seqGen1.GetRawOutputStream());

    SeqGen2.AddObject(TDerInteger.Create(TBigInteger.One) as IDerInteger);

    SeqGen2.Close();

    SeqGen1.Close();

    BOut.Position := 0;
    System.SetLength(temp, bOut.Size);
    BOut.Read(temp[0], bOut.Size);
    CheckTrue(AreEqual(FNestedSeqData, temp),
      'nested DER writing test failed.');
  finally
    BOut.Free;
  end;
end;

procedure TTestAsn1SequenceParser.TestNestedExplicitTagDerWriting;
var
  BOut: TMemoryStream;
  SeqGen1, seqGen2: IDerSequenceGenerator;
  Temp: TCryptoLibByteArray;
begin
  BOut := TMemoryStream.Create();
  try
    SeqGen1 := TDerSequenceGenerator.Create(bOut);

    SeqGen1.AddObject(TDerInteger.Create(TBigInteger.Zero) as IDerInteger);

    SeqGen1.AddObject(TDerObjectIdentifier.Create('1.1')
      as IDerObjectIdentifier);

    SeqGen2 := TDerSequenceGenerator.Create
      (seqGen1.GetRawOutputStream(), 1, True);

    SeqGen2.AddObject(TDerInteger.Create(TBigInteger.ValueOf(1))
      as IDerInteger);

    SeqGen2.Close();

    SeqGen1.Close();

    BOut.Position := 0;
    System.SetLength(temp, bOut.Size);
    BOut.Read(temp[0], bOut.Size);
    CheckTrue(AreEqual(FNestedSeqExpTagData, temp),
      'nested explicit tagged DER writing test failed.');
  finally
    BOut.Free;
  end;
end;

procedure TTestAsn1SequenceParser.TestNestedImplicitTagDerWriting;
var
  BOut: TMemoryStream;
  SeqGen1, seqGen2: IDerSequenceGenerator;
  Temp: TCryptoLibByteArray;
begin
  BOut := TMemoryStream.Create();
  try
    SeqGen1 := TDerSequenceGenerator.Create(bOut);

    SeqGen1.AddObject(TDerInteger.Create(TBigInteger.Zero) as IDerInteger);

    SeqGen1.AddObject(TDerObjectIdentifier.Create('1.1')
      as IDerObjectIdentifier);

    SeqGen2 := TDerSequenceGenerator.Create(seqGen1.GetRawOutputStream(),
      1, False);

    SeqGen2.AddObject(TDerInteger.Create(TBigInteger.ValueOf(1))
      as IDerInteger);

    SeqGen2.Close();

    SeqGen1.Close();

    BOut.Position := 0;
    System.SetLength(temp, bOut.Size);
    BOut.Read(temp[0], bOut.Size);
    CheckTrue(AreEqual(FNestedSeqImpTagData, temp),
      'nested implicit tagged DER writing test failed.');
  finally
    BOut.Free;
  end;
end;

procedure TTestAsn1SequenceParser.TestSequenceWithDerNullReading;
begin
  DoTestParseWithNull(FBerSeqWithDERNullData);
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestAsn1SequenceParser);
{$ELSE}
  RegisterTest(TTestAsn1SequenceParser.Suite);
{$ENDIF FPC}

end.
