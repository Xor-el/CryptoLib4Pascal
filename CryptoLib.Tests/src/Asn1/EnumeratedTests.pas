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

unit EnumeratedTests;

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
  ClpEncoders,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  /// <summary>
  /// Tests used to verify correct decoding of the ENUMERATED type.
  /// </summary>
  TEnumeratedTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    /// <summary>
    /// Test vector used to test decoding of multiple items.
    /// </summary>
    /// <remarks>This sample uses an ENUMERATED and a BOOLEAN.</remarks>
    FMultipleSingleByteItems: TCryptoLibByteArray;
    /// <summary>
    /// Test vector used to test decoding of multiple items.
    /// </summary>
    /// <remarks>This sample uses two ENUMERATEDs.</remarks>
    FMultipleDoubleByteItems: TCryptoLibByteArray;
    /// <summary>
    /// Test vector used to test decoding of multiple items.
    /// </summary>
    /// <remarks>This sample uses an ENUMERATED and an OBJECT IDENTIFIER.</remarks>
    FMultipleTripleByteItems: TCryptoLibByteArray;
  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    /// <summary>
    /// Makes sure multiple identically sized values are parsed correctly.
    /// </summary>
    procedure TestReadingMultipleSingleByteItems;
    /// <summary>
    /// Makes sure multiple identically sized values are parsed correctly.
    /// </summary>
    procedure TestReadingMultipleDoubleByteItems;
    /// <summary>
    /// Makes sure multiple identically sized values are parsed correctly.
    /// </summary>
    procedure TestReadingMultipleTripleByteItems;

  end;

implementation

{ TEnumeratedTest }

procedure TEnumeratedTest.SetUp;
begin
  inherited;
  FMultipleSingleByteItems := DecodeHex('30060a01010101ff');
  FMultipleDoubleByteItems := DecodeHex('30080a0201010a020202');
  FMultipleTripleByteItems := DecodeHex('300a0a0301010106032b0601');
end;

procedure TEnumeratedTest.TearDown;
begin
  FMultipleSingleByteItems := nil;
  FMultipleDoubleByteItems := nil;
  FMultipleTripleByteItems := nil;
  inherited;
end;

procedure TEnumeratedTest.TestReadingMultipleSingleByteItems;
var
  LObj: IAsn1Object;
  LSequence: IDerSequence;
  LEnumerated: IDerEnumerated;
  LBoolean: IDerBoolean;
begin
  LObj := TAsn1Object.FromByteArray(FMultipleSingleByteItems);

  CheckTrue(Supports(LObj, IDerSequence), 'Null ASN.1 SEQUENCE');
  LSequence := LObj as IDerSequence;

  CheckEquals(2, LSequence.Count, '2 items expected');

  LEnumerated := LSequence[0] as IDerEnumerated;

  CheckTrue(LEnumerated <> nil, 'ENUMERATED expected');

  CheckEquals(1, LEnumerated.IntValueExact, 'Unexpected ENUMERATED value');
  CheckTrue(LEnumerated.HasValue(1), 'Unexpected ENUMERATED value');

  LBoolean := LSequence[1] as IDerBoolean;

  CheckTrue(LBoolean <> nil, 'BOOLEAN expected');

  CheckTrue(LBoolean.IsTrue, 'Unexpected BOOLEAN value');
end;

procedure TEnumeratedTest.TestReadingMultipleDoubleByteItems;
var
  LObj: IAsn1Object;
  LSequence: IDerSequence;
  LEnumerated1, LEnumerated2: IDerEnumerated;
begin
  LObj := TAsn1Object.FromByteArray(FMultipleDoubleByteItems);

  CheckTrue(Supports(LObj, IDerSequence), 'Null ASN.1 SEQUENCE');
  LSequence := LObj as IDerSequence;

  CheckEquals(2, LSequence.Count, '2 items expected');

  LEnumerated1 := LSequence[0] as IDerEnumerated;

  CheckTrue(LEnumerated1 <> nil, 'ENUMERATED expected');

  CheckEquals(257, LEnumerated1.IntValueExact, 'Unexpected ENUMERATED value');
  CheckTrue(LEnumerated1.HasValue(257), 'Unexpected ENUMERATED value');

  LEnumerated2 := LSequence[1] as IDerEnumerated;

  CheckTrue(LEnumerated2 <> nil, 'ENUMERATED expected');

  CheckEquals(514, LEnumerated2.IntValueExact, 'Unexpected ENUMERATED value');
  CheckTrue(LEnumerated2.HasValue(514), 'Unexpected ENUMERATED value');
end;

procedure TEnumeratedTest.TestReadingMultipleTripleByteItems;
var
  LObj: IAsn1Object;
  LSequence: IDerSequence;
  LEnumerated: IDerEnumerated;
  LObjectId: IDerObjectIdentifier;
begin
  LObj := TAsn1Object.FromByteArray(FMultipleTripleByteItems);

  CheckTrue(Supports(LObj, IDerSequence), 'Null ASN.1 SEQUENCE');
  LSequence := LObj as IDerSequence;

  CheckEquals(2, LSequence.Count, '2 items expected');

  LEnumerated := LSequence[0] as IDerEnumerated;

  CheckTrue(LEnumerated <> nil, 'ENUMERATED expected');

  CheckEquals(65793, LEnumerated.IntValueExact, 'Unexpected ENUMERATED value');
  CheckTrue(LEnumerated.HasValue(65793), 'Unexpected ENUMERATED value');

  LObjectId := LSequence[1] as IDerObjectIdentifier;

  CheckTrue(LObjectId <> nil, 'OBJECT IDENTIFIER expected');

  CheckEquals('1.3.6.1', LObjectId.Id, 'Unexpected OBJECT IDENTIFIER value');
end;

initialization

{$IFDEF FPC}
RegisterTest(TEnumeratedTest);
{$ELSE}
RegisterTest(TEnumeratedTest.Suite);
{$ENDIF FPC}

end.
