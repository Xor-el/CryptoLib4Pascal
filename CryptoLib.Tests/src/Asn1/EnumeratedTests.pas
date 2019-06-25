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
  CryptoLibTestBase;

type

  /// <summary>
  /// Tests used to verify correct decoding of the ENUMERATED type.
  /// </summary>
  TTestEnumerated = class(TCryptoLibAlgorithmTestCase)
  var
  private
    FMultipleSingleByteItems, FMultipleDoubleByteItems,
      FMultipleTripleByteItems: TBytes;

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

{ TTestEnumerated }

procedure TTestEnumerated.SetUp;
begin
  inherited;
  /// <summary>
  /// Test vector used to test decoding of multiple items.
  /// </summary>
  /// <remarks>This sample uses an ENUMERATED and a BOOLEAN.</remarks>
  FMultipleSingleByteItems := DecodeHex('30060a01010101ff');
  /// <summary>
  /// Test vector used to test decoding of multiple items.
  /// </summary>
  /// <remarks>This sample uses two ENUMERATEDs.</remarks>
  FMultipleDoubleByteItems := DecodeHex('30080a0201010a020202');
  /// <summary>
  /// Test vector used to test decoding of multiple items.
  /// </summary>
  /// <remarks>This sample uses an ENUMERATED and an OBJECT IDENTIFIER.</remarks>
  FMultipleTripleByteItems := DecodeHex('300a0a0301010106032b0601');
end;

procedure TTestEnumerated.TearDown;
begin
  inherited;

end;

procedure TTestEnumerated.TestReadingMultipleSingleByteItems;
var
  obj: IAsn1Object;
  sequence: IDerSequence;
  enumerated: IDerEnumerated;
  boolean: IDerBoolean;
begin
  obj := TAsn1Object.FromByteArray(FMultipleSingleByteItems);

  CheckTrue(Supports(obj, IDerSequence), 'Null ASN.1 SEQUENCE');

  sequence := obj as IDerSequence;

  CheckEquals(2, sequence.Count, '2 items expected');

  enumerated := sequence[0] as IDerEnumerated;

  CheckNotNull(enumerated, 'ENUMERATED expected');

  CheckEquals(1, enumerated.Value.Int32Value, 'Unexpected ENUMERATED value');

  boolean := sequence[1] as IDerBoolean;

  CheckNotNull(boolean, 'BOOLEAN expected');

  CheckTrue(boolean.IsTrue, 'Unexpected BOOLEAN value');
end;

procedure TTestEnumerated.TestReadingMultipleDoubleByteItems;
var
  obj: IAsn1Object;
  sequence: IDerSequence;
  enumerated, enumerated2: IDerEnumerated;
begin
  obj := TAsn1Object.FromByteArray(FMultipleDoubleByteItems);

  CheckTrue(Supports(obj, IDerSequence), 'Null ASN.1 SEQUENCE');

  sequence := obj as IDerSequence;

  CheckEquals(2, sequence.Count, '2 items expected');

  enumerated := sequence[0] as IDerEnumerated;

  CheckNotNull(enumerated, 'ENUMERATED expected');

  CheckEquals(257, enumerated.Value.Int32Value, 'Unexpected ENUMERATED value');

  enumerated2 := sequence[1] as IDerEnumerated;

  CheckNotNull(enumerated2, 'ENUMERATED expected');

  CheckEquals(514, enumerated2.Value.Int32Value, 'Unexpected ENUMERATED value');
end;

procedure TTestEnumerated.TestReadingMultipleTripleByteItems;
var
  obj: IAsn1Object;
  sequence: IDerSequence;
  enumerated: IDerEnumerated;
  objectId: IDerObjectIdentifier;
begin
  obj := TAsn1Object.FromByteArray(FMultipleTripleByteItems);

  CheckTrue(Supports(obj, IDerSequence), 'Null ASN.1 SEQUENCE');

  sequence := obj as IDerSequence;

  CheckEquals(2, sequence.Count, '2 items expected');

  enumerated := sequence[0] as IDerEnumerated;

  CheckNotNull(enumerated, 'ENUMERATED expected');

  CheckEquals(65793, enumerated.Value.Int32Value,
    'Unexpected ENUMERATED value');

  objectId := sequence[1] as IDerObjectIdentifier;

  CheckNotNull(objectId, 'OBJECT IDENTIFIER expected');

  CheckEquals('1.3.6.1', objectId.Id, 'Unexpected OBJECT IDENTIFIER value');
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestEnumerated);
{$ELSE}
  RegisterTest(TTestEnumerated.Suite);
{$ENDIF FPC}

end.
