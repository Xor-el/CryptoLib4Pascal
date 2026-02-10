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

unit InputStreamTests;

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
  ClpIAsn1Core,
  ClpAsn1Streams,
  ClpEncoders,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TInputStreamTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    FOutOfBoundsLength: TCryptoLibByteArray;
    FNegativeLength: TCryptoLibByteArray;
    FOutsideLimitLength: TCryptoLibByteArray;
    FClassCast2: TCryptoLibByteArray;
    FClassCast3: TCryptoLibByteArray;
  protected
    procedure SetUp; override;
    procedure TearDown; override;

    procedure DoTestWithByteArray(const AData: TCryptoLibByteArray; const AMessage: String);

  published
    procedure TestInputStream;
  end;

implementation

{ TInputStreamTest }

procedure TInputStreamTest.SetUp;
begin
  inherited;
  FOutOfBoundsLength := TCryptoLibByteArray.Create($30, $FF, $FF, $FF, $FF, $FF);
  FNegativeLength := TCryptoLibByteArray.Create($30, $84, $FF, $FF, $FF, $FF);
  FOutsideLimitLength := TCryptoLibByteArray.Create($30, $83, $0F, $FF, $FF);
  FClassCast2 := TBase64Encoder.Decode('JICNbaBUTTq7uxj5mg==');
  FClassCast3 := TBase64Encoder.Decode('JAKzADNCxhrrBSVS');
end;

procedure TInputStreamTest.TearDown;
begin
  FOutOfBoundsLength := nil;
  FNegativeLength := nil;
  FOutsideLimitLength := nil;
  FClassCast2 := nil;
  FClassCast3 := nil;
  inherited;
end;

procedure TInputStreamTest.DoTestWithByteArray(const AData: TCryptoLibByteArray; const AMessage: String);
var
  LInput: TAsn1InputStream;
  LP: IAsn1Object;
  LAsn1: IAsn1Sequence;
  I: Int32;
  LC: IAsn1Convertible;
begin
  try
    LInput := TAsn1InputStream.Create(AData);
    try
      LP := LInput.ReadObject();
      while LP <> nil do
      begin
        LAsn1 := TAsn1Sequence.GetInstance(LP);
        for I := 0 to LAsn1.Count - 1 do
        begin
          LC := LAsn1[I];
        end;
        LP := LInput.ReadObject();
      end;
    finally
      LInput.Free;
    end;
  except
    on E: EIOCryptoLibException do
    begin
      CheckEquals(AMessage, E.Message, Format('Expected message "%s" but got "%s"', [AMessage, E.Message]));
    end;
    on E: EAsn1ParsingCryptoLibException do
    begin
      CheckEquals(AMessage, E.Message, Format('Expected message "%s" but got "%s"', [AMessage, E.Message]));
    end;
  end;
end;

procedure TInputStreamTest.TestInputStream;
var
  LAIn: TAsn1InputStream;
begin
  LAIn := TAsn1InputStream.Create(FOutOfBoundsLength);
  try
    try
      LAIn.ReadObject();
      Fail('out of bounds length not detected.');
    except
      on E: EIOCryptoLibException do
      begin
        if not E.Message.Equals('invalid long form definite-length 0xFF') then
        begin
          Fail(Format('wrong exception: %s', [E.Message]));
        end;
      end;
    end;
  finally
    LAIn.Free;
  end;

  // NOTE: Not really a "negative" length, but 32 bits
  LAIn := TAsn1InputStream.Create(FNegativeLength);
  try
    try
      LAIn.ReadObject();
      Fail('negative length not detected.');
    except
      on E: EIOCryptoLibException do
      begin
        if not E.Message.Equals('long form definite-length more than 31 bits') then
        begin
          Fail(Format('wrong exception: %s', [E.Message]));
        end;
      end;
    end;
  finally
    LAIn.Free;
  end;

  LAIn := TAsn1InputStream.Create(FOutsideLimitLength);
  try
    try
      LAIn.ReadObject();
      Fail('outside limit length not detected.');
    except
      on E: EIOCryptoLibException do
      begin
        if not E.Message.Equals('corrupted stream - out of bounds length found: 1048575 >= 5') then
        begin
          Fail(Format('wrong exception: %s', [E.Message]));
        end;
      end;
    end;
  finally
    LAIn.Free;
  end;

  DoTestWithByteArray(FClassCast2, 'unknown object encountered: TDLTaggedObjectParser');
  DoTestWithByteArray(FClassCast3, 'unknown object encountered in constructed OCTET STRING: TDLTaggedObject');
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TInputStreamTest);
{$ELSE}
  RegisterTest(TInputStreamTest.Suite);
{$ENDIF FPC}

end.
