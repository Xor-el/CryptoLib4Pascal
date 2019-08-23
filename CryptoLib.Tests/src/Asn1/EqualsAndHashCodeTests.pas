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
  ClpConverters,
  ClpIAsn1Objects,
  ClpAsn1Objects,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestEqualsAndHashCode = class(TCryptoLibAlgorithmTestCase)
  private

  var
    Fdata: TBytes;
    Fvalues: TCryptoLibGenericArray<IAsn1Object>;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEqualsAndHashCode;

  end;

implementation

{ TTestEqualsAndHashCode }

procedure TTestEqualsAndHashCode.SetUp;
begin
  inherited;
  Fdata := TBytes.Create(0, 1, 0, 1, 0, 0, 1);
  Fvalues := TCryptoLibGenericArray<IAsn1Object>.Create(

    TBerOctetString.Create(Fdata),

    TDerApplicationSpecific.Create(0, Fdata), TDerBitString.Create(Fdata),

    TDerBoolean.True, TDerBoolean.False, TDerEnumerated.Create(100),
    TDerBmpString.Create('hello world'),

    TDerGeneralString.Create('hello world'), TDerIA5String.Create('hello'),
    TDerInteger.Create(1000), TDerNull.Instance,
    TDerNumericString.Create('123456'),
    TDerObjectIdentifier.Create('1.1.1.10000.1'), TDerOctetString.Create(Fdata),
    TDerPrintableString.Create('hello world'),

    TDerT61String.Create('hello world'),

    TDerUniversalString.Create(Fdata),

    TDerUtf8String.Create('hello world'),
    TDerVisibleString.Create('hello world'),
    TDerGraphicString.Create(DecodeHex('deadbeef')),
    TDerVideotexString.Create(TConverters.ConvertStringToBytes('Hello World',
    TEncoding.ANSI)),

    TBerTaggedObject.Create(0, TDerPrintableString.Create('hello world')
    as IDerPrintableString),

    TDerTaggedObject.Create(0, TDerPrintableString.Create('hello world')
    as IDerPrintableString),

    TBerSequence.Create(TDerPrintableString.Create('hello world')
    as IDerPrintableString),
    TBerSet.Create(TDerPrintableString.Create('hello world')
    as IDerPrintableString),
    TDerSequence.Create(TDerPrintableString.Create('hello world')
    as IDerPrintableString),
    TDerSet.Create(TDerPrintableString.Create('hello world')
    as IDerPrintableString)

    );

end;

procedure TTestEqualsAndHashCode.TearDown;
begin
  inherited;

end;

procedure TTestEqualsAndHashCode.TestEqualsAndHashCode;
var
  bOut: TMemoryStream;
  aOut: TAsn1OutputStream;
  aIn: TAsn1InputStream;
  o: IAsn1Object;
  temp: TBytes;
  i: Int32;
begin
  bOut := TMemoryStream.Create();
  aOut := TAsn1OutputStream.Create(bOut);
  try

    i := 0;
    while i <> System.Length(Fvalues) do
    begin
      aOut.WriteObject(Fvalues[i]);
      System.Inc(i);
    end;

    System.SetLength(temp, bOut.Size);
    bOut.Position := 0;
    bOut.Read(temp[0], bOut.Size);
    aIn := TAsn1InputStream.Create(temp);

    try
      i := 0;
      while i <> System.Length(Fvalues) do
      begin

        o := aIn.ReadObject();

        if (not o.Equals(Fvalues[i])) then
        begin
          Fail(Format('Failed equality test for %s',
            [(o as TAsn1Object).ClassName]));
        end;

        if (not(o.GetHashCode() = Fvalues[i].GetHashCode())) then
        begin
          Fail(Format('Failed hashCode test for %s',
            [(o as TAsn1Object).ClassName]));
        end;

        System.Inc(i);
      end;
    finally
      aIn.Free;
    end;

  finally
    bOut.Free;
    aOut.Free;
  end;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestEqualsAndHashCode);
{$ELSE}
  RegisterTest(TTestEqualsAndHashCode.Suite);
{$ENDIF FPC}

end.
