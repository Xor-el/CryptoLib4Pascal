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

unit EqualsAndHashCodeTests;

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
  ClpAsn1Streams,
  ClpConverters,
  ClpCryptoLibTypes,
  ClpDateTimeUtilities,
  CryptoLibTestBase;

type

  TEqualsAndHashCodeTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    FData: TCryptoLibByteArray;
  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestEqualsAndHashCode;
  end;

implementation

{ TEqualsAndHashCodeTest }

procedure TEqualsAndHashCodeTest.SetUp;
begin
  inherited;
  FData := TCryptoLibByteArray.Create(0, 1, 0, 1, 0, 0, 1);
end;

procedure TEqualsAndHashCodeTest.TearDown;
begin
  FData := nil;
  inherited;
end;

procedure TEqualsAndHashCodeTest.TestEqualsAndHashCode;
var
  LValues: TCryptoLibGenericArray<IAsn1Object>;
  LBOut: TMemoryStream;
  LAOut: TAsn1OutputStream;
  LAIn: TAsn1InputStream;
  LObj: IAsn1Object;
  LOutput: TCryptoLibByteArray;
  I: Int32;
  LNow: TDateTime;
begin
  LNow := Now;
  LValues := TCryptoLibGenericArray<IAsn1Object>.Create(
    TBerOctetString.Create(FData),
    TBerSequence.Create(TDerPrintableString.Create('hello world') as IDerPrintableString),
    TBerSet.Create(TDerPrintableString.Create('hello world') as IDerPrintableString),
    TBerTaggedObject.Create(0, TDerPrintableString.Create('hello world') as IDerPrintableString),
    TDerBitString.Create(FData),
    TDerBmpString.Create('hello world'),
    TDerBoolean.True,
    TDerBoolean.False,
    TDerEnumerated.Create(100),
    TDerGeneralizedTime.Create('20070315173729Z'),
    TDerGeneralString.Create('hello world'),
    TDerIA5String.Create('hello'),
    TDerInteger.ValueOf(1000),
    TDerNull.Instance,
    TDerNumericString.Create('123456'),
    TDerObjectIdentifier.Create('1.1.1.10000.1'),
    TAsn1RelativeOid.Create('3.2.0.123456'),
    TDerOctetString.Create(FData),
    TDerPrintableString.Create('hello world'),
    TDerSequence.Create(TDerPrintableString.Create('hello world') as IDerPrintableString),
    TDerSet.Create(TDerPrintableString.Create('hello world') as IDerPrintableString),
    TDerT61String.Create('hello world'),
    TDerTaggedObject.Create(0, TDerPrintableString.Create('hello world') as IDerPrintableString),
    TDerUniversalString.Create(FData),
    TDerUtcTime.Create(LNow, 2049),
    TDerUtf8String.Create('hello world'),
    TDerVisibleString.Create('hello world'),
    TDerGraphicString.Create(DecodeHex('deadbeef')),
    TDerVideotexString.Create(TConverters.ConvertStringToBytes('Hello World', TEncoding.ANSI))
  );

  LBOut := TMemoryStream.Create();
   // LeaveOpen is False so TAsn1OutputStream owns LBOut and will free it.
  LAOut := TAsn1OutputStream.CreateStream(LBOut);
  try
    for I := 0 to System.Length(LValues) - 1 do
    begin
      LAOut.WriteObject(LValues[I]);
    end;

    System.SetLength(LOutput, LBOut.Size);
    LBOut.Position := 0;
    LBOut.Read(LOutput[0], LBOut.Size);
    LAIn := TAsn1InputStream.Create(LOutput);

    try
      for I := 0 to System.Length(LValues) - 1 do
      begin
        LObj := LAIn.ReadObject();
        if not LObj.Equals(LValues[I]) then
        begin
          Fail(Format('Failed equality test for %s', [(LObj as TObject).ClassName]));
        end;
        if LObj.GetHashCode() <> LValues[I].GetHashCode() then
        begin
          Fail(Format('Failed hashCode test for %s', [(LObj as TObject).ClassName]));
        end;
      end;
    finally
      LAIn.Free;
    end;
  finally
    LAOut.Free;
  end;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TEqualsAndHashCodeTest);
{$ELSE}
  RegisterTest(TEqualsAndHashCodeTest.Suite);
{$ENDIF FPC}

end.
