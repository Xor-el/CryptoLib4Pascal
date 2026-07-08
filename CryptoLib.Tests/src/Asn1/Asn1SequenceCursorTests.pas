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

unit Asn1SequenceCursorTests;

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
  ClpIAsn1Core,
  ClpAsn1Utilities,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  /// <summary>
  /// Direct edge-case tests for the TAsn1Utilities sequence cursor helpers
  /// (Read / ReadOptional / ReadContextTagged / CheckSequenceSize / RequireEndOfSequence).
  /// </summary>
  TTestAsn1SequenceCursor = class(TCryptoLibAlgorithmTestCase)
  private
    function IntSeq(const AValues: array of Int32): IAsn1Sequence;
  published
    procedure TestReadMandatoryAndRequireEnd;
    procedure TestCheckSequenceSizeRejectsWrongSize;
    procedure TestCheckSequenceSizeRejectsNil;
    procedure TestReadRejectsPrematureEnd;
    procedure TestRequireEndRejectsTrailing;
    procedure TestReadEncodableReturnsRawElement;
    procedure TestReadOptionalPresentAdvances;
    procedure TestReadOptionalAbsentDoesNotAdvance;
    procedure TestReadContextTaggedExplicit;
  end;

implementation

function TTestAsn1SequenceCursor.IntSeq(const AValues: array of Int32): IAsn1Sequence;
var
  LElements: TCryptoLibGenericArray<IAsn1Encodable>;
  LI: Int32;
begin
  LElements := nil;
  System.SetLength(LElements, System.Length(AValues));
  for LI := 0 to System.Length(AValues) - 1 do
    LElements[LI] := TDerInteger.ValueOf(AValues[LI]);
  Result := TDerSequence.FromElements(LElements);
end;

procedure TTestAsn1SequenceCursor.TestReadMandatoryAndRequireEnd;
var
  LSeq: IAsn1Sequence;
  LPos: Int32;
  LA, LB: IDerInteger;
begin
  LSeq := IntSeq([7, 11]);
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(LSeq, 2, 2);
  LA := TAsn1Utilities.Read<IDerInteger>(LSeq, LPos, TDerInteger.GetInstance);
  LB := TAsn1Utilities.Read<IDerInteger>(LSeq, LPos, TDerInteger.GetInstance);
  TAsn1Utilities.RequireEndOfSequence(LSeq, LPos);
  CheckTrue(LA.HasValue(7), 'first element');
  CheckTrue(LB.HasValue(11), 'second element');
  CheckEquals(2, LPos, 'position after two reads');
end;

procedure TTestAsn1SequenceCursor.TestCheckSequenceSizeRejectsWrongSize;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TAsn1Utilities.CheckSequenceSize(IntSeq([1, 2, 3]), 2, 2);
  except
    on E: EArgumentCryptoLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'expected bad-sequence-size exception');
end;

procedure TTestAsn1SequenceCursor.TestCheckSequenceSizeRejectsNil;
var
  LSeq: IAsn1Sequence;
  LRaised: Boolean;
begin
  LSeq := nil;
  LRaised := False;
  try
    TAsn1Utilities.CheckSequenceSize(LSeq, 0, 3);
  except
    on E: EArgumentNilCryptoLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'expected nil-sequence exception');
end;

procedure TTestAsn1SequenceCursor.TestReadRejectsPrematureEnd;
var
  LSeq: IAsn1Sequence;
  LPos: Int32;
  LRaised: Boolean;
begin
  LSeq := IntSeq([1]);
  LPos := 0;
  TAsn1Utilities.Read<IDerInteger>(LSeq, LPos, TDerInteger.GetInstance);
  LRaised := False;
  try
    TAsn1Utilities.Read<IDerInteger>(LSeq, LPos, TDerInteger.GetInstance);
  except
    on E: EArgumentCryptoLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'expected premature-end exception');
end;

procedure TTestAsn1SequenceCursor.TestRequireEndRejectsTrailing;
var
  LSeq: IAsn1Sequence;
  LPos: Int32;
  LRaised: Boolean;
begin
  LSeq := IntSeq([1, 2]);
  LPos := 0;
  TAsn1Utilities.Read<IDerInteger>(LSeq, LPos, TDerInteger.GetInstance);
  LRaised := False;
  try
    TAsn1Utilities.RequireEndOfSequence(LSeq, LPos);
  except
    on E: EArgumentCryptoLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'expected unexpected-elements exception');
end;

procedure TTestAsn1SequenceCursor.TestReadEncodableReturnsRawElement;
var
  LSeq: IAsn1Sequence;
  LPos: Int32;
  LElement: IAsn1Encodable;
begin
  LSeq := IntSeq([42]);
  LPos := 0;
  LElement := TAsn1Utilities.ReadEncodable(LSeq, LPos);
  CheckNotNull(LElement, 'raw element');
  CheckEquals(1, LPos, 'position advanced');
  CheckTrue(TDerInteger.GetInstance(LElement).HasValue(42), 'element value');
end;

procedure TTestAsn1SequenceCursor.TestReadOptionalPresentAdvances;
var
  LSeq: IAsn1Sequence;
  LPos: Int32;
  LValue: IDerInteger;
begin
  LSeq := IntSeq([9]);
  LPos := 0;
  LValue := TAsn1Utilities.ReadOptional<IDerInteger>(LSeq, LPos, TDerInteger.GetOptional);
  CheckNotNull(LValue, 'optional present');
  CheckTrue(LValue.HasValue(9), 'optional value');
  CheckEquals(1, LPos, 'position advanced');
end;

procedure TTestAsn1SequenceCursor.TestReadOptionalAbsentDoesNotAdvance;
var
  LSeq: IAsn1Sequence;
  LPos: Int32;
  LBits: IDerBitString;
  LInt: IDerInteger;
begin
  // sequence holds a DerInteger; an optional DerBitString read must not consume it
  LSeq := IntSeq([5]);
  LPos := 0;
  LBits := TAsn1Utilities.ReadOptional<IDerBitString>(LSeq, LPos, TDerBitString.GetOptional);
  CheckNull(LBits, 'optional absent');
  CheckEquals(0, LPos, 'position not advanced');
  LInt := TAsn1Utilities.Read<IDerInteger>(LSeq, LPos, TDerInteger.GetInstance);
  CheckTrue(LInt.HasValue(5), 'element still readable');
  CheckEquals(1, LPos, 'position advanced after mandatory read');
end;

procedure TTestAsn1SequenceCursor.TestReadContextTaggedExplicit;
var
  LSeq: IAsn1Sequence;
  LPos: Int32;
  LValue: IDerInteger;
begin
  LSeq := TDerSequence.FromElement(TDerTaggedObject.Create(True, 0, TDerInteger.ValueOf(5)) as IDerTaggedObject);
  LPos := 0;
  LValue := TAsn1Utilities.ReadContextTagged<Boolean, IDerInteger>(LSeq, LPos, 0, True, TDerInteger.GetTagged);
  TAsn1Utilities.RequireEndOfSequence(LSeq, LPos);
  CheckNotNull(LValue, 'context-tagged value');
  CheckTrue(LValue.HasValue(5), 'context-tagged value content');
  CheckEquals(1, LPos, 'position advanced');
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestAsn1SequenceCursor);
{$ELSE}
  RegisterTest(TTestAsn1SequenceCursor.Suite);
{$ENDIF FPC}

end.
