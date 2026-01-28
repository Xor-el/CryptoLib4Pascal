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

unit SetTests;

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
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TSetTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    procedure CheckSortedSet(const AAttempt: Int32; const ASet: IAsn1Set);

  published
    procedure TestSet;
  end;

implementation

{ TSetTest }

procedure TSetTest.CheckSortedSet(const AAttempt: Int32; const ASet: IAsn1Set);
begin
  if not (Supports(ASet[0], IDerBoolean) and Supports(ASet[1], IDerInteger) and
    Supports(ASet[2], IDerBitString) and Supports(ASet[3], IDerOctetString)) then
  begin
    Fail(Format('sorting failed on attempt: %d', [AAttempt]));
  end;
end;

procedure TSetTest.TestSet;
var
  LVector: IAsn1EncodableVector;
  LData: TCryptoLibByteArray;
  LSet: IAsn1Set;
  LTagged: IAsn1TaggedObject;
  LSequence: IAsn1Sequence;
begin
  System.SetLength(LData, 10);
  LVector := TAsn1EncodableVector.Create();
  LVector.Add(TDerOctetString.Create(LData));
  LVector.Add(TDerBitString.Create(LData));
  LVector.Add(TDerInteger.ValueOf(100));
  LVector.Add(TDerBoolean.True);

  CheckSortedSet(0, TDerSet.FromVector(LVector));

  LVector := TAsn1EncodableVector.Create();
  LVector.Add(TDerInteger.ValueOf(100));
  LVector.Add(TDerBoolean.True);
  LVector.Add(TDerOctetString.Create(LData));
  LVector.Add(TDerBitString.Create(LData));

  CheckSortedSet(1, TDerSet.FromVector(LVector));

  LVector := TAsn1EncodableVector.Create();
  LVector.Add(TDerBoolean.True);
  LVector.Add(TDerOctetString.Create(LData));
  LVector.Add(TDerBitString.Create(LData));
  LVector.Add(TDerInteger.ValueOf(100));

  CheckSortedSet(2, TDerSet.FromVector(LVector));

  LVector := TAsn1EncodableVector.Create();
  LVector.Add(TDerBitString.Create(LData));
  LVector.Add(TDerOctetString.Create(LData));
  LVector.Add(TDerInteger.ValueOf(100));
  LVector.Add(TDerBoolean.True);

  CheckSortedSet(3, TDerSet.FromVector(LVector));

  LVector := TAsn1EncodableVector.Create();
  LVector.Add(TDerOctetString.Create(LData));
  LVector.Add(TDerBitString.Create(LData));
  LVector.Add(TDerInteger.ValueOf(100));
  LVector.Add(TDerBoolean.True);

  LSet := TBerSet.FromVector(LVector);

  if not Supports(LSet[0], IDerOctetString) then
  begin
    Fail('BER set sort order changed.');
  end;

  // create an implicitly tagged "set" without sorting
  LSequence := TDerSequence.Create(LVector);
  LTagged := TDerTaggedObject.Create(False, 1, LSequence);

  // Encode/decode to get 'tag' as a parsed instance
  LTagged := TAsn1TaggedObject.GetInstance(TAsn1Object.FromByteArray(LTagged.GetEncoded(TAsn1Encodable.Der)));

  LSet := TAsn1Set.GetInstance(LTagged, False);

  if Supports(LSet[0], IDerBoolean) then
  begin
    Fail('sorted when shouldn''t be.');
  end;

  // equality test
  LVector := TAsn1EncodableVector.Create();
  LVector.Add(TDerBoolean.True);
  LVector.Add(TDerBoolean.True);
  LVector.Add(TDerBoolean.True);

  LSet := TDerSet.FromVector(LVector);
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TSetTest);
{$ELSE}
  RegisterTest(TSetTest.Suite);
{$ENDIF FPC}

end.
