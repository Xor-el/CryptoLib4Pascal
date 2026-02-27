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

unit OctetStringTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  Classes,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpIAsn1Parsers,
  ClpAsn1Parsers,
  ClpIAsn1Generators,
  ClpAsn1Generators,
  ClpStreamUtilities,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TOctetStringTest = class(TCryptoLibAlgorithmTestCase)
  published
    procedure TestReadingWriting;
    procedure TestReadingWritingZeroInLength;
    procedure TestReadingWritingNested;
  end;

implementation

{ TOctetStringTest }

procedure TOctetStringTest.TestReadingWriting;
var
  LBOut: TMemoryStream;
  LOctGen: IBerOctetStringGenerator;
  LOutStream: TStream;
  LAIn: IAsn1StreamParser;
  LS: IBerOctetStringParser;
  LInStream: TStream;
  LCount: Int32;
  LByte: Int32;
  LBOutBytes: TCryptoLibByteArray;
begin
  LBOut := TMemoryStream.Create();
  try
    LOctGen := TBerOctetStringGenerator.Create(LBOut);
    LOutStream := LOctGen.GetOctetOutputStream();
    try
      LOutStream.Write(TCryptoLibByteArray.Create(1, 2, 3, 4), 0, 4);
      LOutStream.Write(TCryptoLibByteArray.Create(0, 0, 0, 0), 0, 4);
    finally
      LOutStream.Free;
    end;
    LOctGen := nil;
    LBOutBytes := nil;

    LBOut.Position := 0;
    System.SetLength(LBOutBytes, LBOut.Size);

    LBOut.Read(LBOutBytes, 0, System.Length(LBOutBytes));

    LAIn := TAsn1StreamParser.Create(LBOutBytes);
    LS := LAIn.ReadObject() as IBerOctetStringParser;

    // GetOctetStream returns a NEW stream - caller owns it
    LInStream := LS.GetOctetStream();
    try
      LCount := 0;
      LByte := LInStream.ReadByte();
      while LByte >= 0 do
      begin
        System.Inc(LCount);
        LByte := LInStream.ReadByte();
      end;
      CheckEquals(8, LCount, 'Expected 8 bytes');
    finally
      LInStream.Free;
    end;
  finally
    LBOut.Free;
  end;
end;

procedure TOctetStringTest.TestReadingWritingNested;
var
  LBOut: TMemoryStream;
  LSGen: IBerSequenceGenerator;
  LOctGen: IBerOctetStringGenerator;
  LOutStream: TStream;
  LInSGen: IBerSequenceGenerator;
  LInOctGen: IBerOctetStringGenerator;
  LInOut: TStream;
  LAIn: IAsn1StreamParser;
  LSq: IBerSequenceParser;
  LS: IBerOctetStringParser;
  LAIn2: IAsn1StreamParser;
  LSq2: IBerSequenceParser;
  LInS: IBerOctetStringParser;
  LInStream: TStream;
  LCount: Int32;
  LByte: Int32;
  LBOutBytes: TCryptoLibByteArray;
begin
  LBOut := TMemoryStream.Create();
  try
    LSGen := TBerSequenceGenerator.Create(LBOut);
    LOctGen := TBerOctetStringGenerator.Create(LSGen.GetRawOutputStream());
    LOutStream := LOctGen.GetOctetOutputStream();
    try
      LInSGen := TBerSequenceGenerator.Create(LOutStream);
      LInOctGen := TBerOctetStringGenerator.Create(LInSGen.GetRawOutputStream());
      LInOut := LInOctGen.GetOctetOutputStream();
      try
        LInOut.Write(TCryptoLibByteArray.Create(1, 2, 3, 4), 0, 4);
        LInOut.Write(TCryptoLibByteArray.Create(0, 0, 0, 0, 0, 0, 0, 0, 0, 0), 0, 10);
      finally
        LInOut.Free;
      end;
      LInOctGen := nil;
      LInSGen := nil;
    finally
      LOutStream.Free;
    end;
    LOctGen := nil;
    LSGen := nil;

    LBOutBytes := nil;

    LBOut.Position := 0;
    System.SetLength(LBOutBytes, LBOut.Size);

    LBOut.Read(LBOutBytes, 0, System.Length(LBOutBytes));

    LAIn := TAsn1StreamParser.Create(LBOutBytes);
    LSq := LAIn.ReadObject() as IBerSequenceParser;

    LS := LSq.ReadObject() as IBerOctetStringParser;

    LAIn2 := TAsn1StreamParser.Create(LS.GetOctetStream());
    LSq2 := LAIn2.ReadObject() as IBerSequenceParser;

    LInS := LSq2.ReadObject() as IBerOctetStringParser;

    // GetOctetStream returns a NEW stream - caller owns it
    LInStream := LInS.GetOctetStream();
    try
      LCount := 0;
      LByte := LInStream.ReadByte();
      while LByte >= 0 do
      begin
        System.Inc(LCount);
        LByte := LInStream.ReadByte();
      end;
      CheckEquals(14, LCount, 'Expected 14 bytes');
    finally
      LInStream.Free;
    end;
  finally
    LBOut.Free;
  end;
end;

procedure TOctetStringTest.TestReadingWritingZeroInLength;
var
  LBOut: TMemoryStream;
  LOctGen: IBerOctetStringGenerator;
  LOutStream: TStream;
  LZeroBytes: TCryptoLibByteArray;
  LAIn: IAsn1StreamParser;
  LS: IBerOctetStringParser;
  LInStream: TStream;
  LCount: Int32;
  LByte: Int32;
  LBOutBytes: TCryptoLibByteArray;
begin
  System.SetLength(LZeroBytes, 512);
  LBOut := TMemoryStream.Create();
  try
    LOctGen := TBerOctetStringGenerator.Create(LBOut);
    LOutStream := LOctGen.GetOctetOutputStream();
    try
      LOutStream.Write(TCryptoLibByteArray.Create(1, 2, 3, 4), 0, 4);
      LOutStream.Write(LZeroBytes, 0, 512);  // forces a zero to appear in length
    finally
      LOutStream.Free;
    end;
    LOctGen := nil;

    LBOutBytes := nil;

    LBOut.Position := 0;
    System.SetLength(LBOutBytes, LBOut.Size);

    LBOut.Read(LBOutBytes, 0, System.Length(LBOutBytes));

    LAIn := TAsn1StreamParser.Create(LBOutBytes);
    LS := LAIn.ReadObject() as IBerOctetStringParser;

    // GetOctetStream returns a NEW stream - caller owns it
    LInStream := LS.GetOctetStream();
    try
      LCount := 0;
      LByte := LInStream.ReadByte();
      while LByte >= 0 do
      begin
        System.Inc(LCount);
        LByte := LInStream.ReadByte();
      end;
      CheckEquals(516, LCount, 'Expected 516 bytes');
    finally
      LInStream.Free;
    end;
  finally
    LBOut.Free;
  end;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TOctetStringTest);
{$ELSE}
  RegisterTest(TOctetStringTest.Suite);
{$ENDIF FPC}

end.
