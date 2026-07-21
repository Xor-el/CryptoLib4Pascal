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

unit CryptoLibHashSetTests;

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
  ClpCryptoLibHashSet,
  ClpCryptoLibComparers,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type
  TCryptoLibHashSetTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    function NewSet(): TCryptoLibHashSet<String>;
    /// <summary>True when AItem is somewhere in AItems.</summary>
    function ArrayHas(const AItems: TCryptoLibStringArray; const AItem: String): Boolean;

  published
    procedure TestAddReportsWhetherItemWasNew;
    procedure TestRemoveReportsWhetherItemWasPresent;
    procedure TestContainsAndClear;
    procedure TestAddRangeSkipsDuplicates;
    procedure TestToArrayHoldsEveryItemOnce;
    procedure TestEnumeratorVisitsEveryItem;
  end;

implementation

{ TCryptoLibHashSetTest }

function TCryptoLibHashSetTest.NewSet(): TCryptoLibHashSet<String>;
begin
  Result := TCryptoLibHashSet<String>.Create
    (TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
end;

function TCryptoLibHashSetTest.ArrayHas(const AItems: TCryptoLibStringArray;
  const AItem: String): Boolean;
var
  LIdx: Int32;
begin
  Result := False;
  for LIdx := 0 to System.High(AItems) do
  begin
    if AItems[LIdx] = AItem then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

procedure TCryptoLibHashSetTest.TestAddReportsWhetherItemWasNew;
var
  LSet: TCryptoLibHashSet<String>;
begin
  LSet := NewSet();
  try
    CheckTrue(LSet.Add('alpha'), 'the first add of an item reports it as new');
    CheckFalse(LSet.Add('alpha'), 'adding an item already present reports it as not new');
    CheckEquals(1, LSet.Count, 'a duplicate add does not grow the set');
  finally
    LSet.Free;
  end;
end;

procedure TCryptoLibHashSetTest.TestRemoveReportsWhetherItemWasPresent;
var
  LSet: TCryptoLibHashSet<String>;
begin
  LSet := NewSet();
  try
    LSet.Add('alpha');

    CheckFalse(LSet.Remove('beta'), 'removing an absent item reports nothing was removed');
    CheckEquals(1, LSet.Count, 'removing an absent item leaves the set alone');

    CheckTrue(LSet.Remove('alpha'), 'removing a present item reports it was removed');
    CheckEquals(0, LSet.Count, 'the set is empty once its only item is removed');
  finally
    LSet.Free;
  end;
end;

procedure TCryptoLibHashSetTest.TestContainsAndClear;
var
  LSet: TCryptoLibHashSet<String>;
begin
  LSet := NewSet();
  try
    LSet.Add('alpha');
    LSet.Add('beta');

    CheckTrue(LSet.Contains('alpha'), 'a stored item is found');
    // the supplied comparer decides membership, not the default one
    CheckTrue(LSet.Contains('ALPHA'), 'lookup honours the supplied comparer');
    CheckFalse(LSet.Contains('gamma'), 'an item never added is not found');

    LSet.Clear();
    CheckEquals(0, LSet.Count, 'Clear empties the set');
    CheckFalse(LSet.Contains('alpha'), 'nothing is found after Clear');
  finally
    LSet.Free;
  end;
end;

procedure TCryptoLibHashSetTest.TestAddRangeSkipsDuplicates;
var
  LSet: TCryptoLibHashSet<String>;
begin
  LSet := NewSet();
  try
    LSet.AddRange(TCryptoLibStringArray.Create('alpha', 'beta', 'alpha', 'ALPHA'));
    CheckEquals(2, LSet.Count, 'AddRange keeps only the distinct items');
  finally
    LSet.Free;
  end;
end;

procedure TCryptoLibHashSetTest.TestToArrayHoldsEveryItemOnce;
var
  LSet: TCryptoLibHashSet<String>;
  LItems: TCryptoLibStringArray;
begin
  LSet := NewSet();
  try
    LSet.Add('alpha');
    LSet.Add('beta');
    LSet.Add('alpha');

    LItems := LSet.ToArray();
    CheckEquals(2, System.Length(LItems), 'ToArray is exactly as long as the set');
    // order is unspecified, so check membership rather than position
    CheckTrue(ArrayHas(LItems, 'alpha'), 'ToArray carries the first item');
    CheckTrue(ArrayHas(LItems, 'beta'), 'ToArray carries the second item');
  finally
    LSet.Free;
  end;
end;

procedure TCryptoLibHashSetTest.TestEnumeratorVisitsEveryItem;
var
  LSet: TCryptoLibHashSet<String>;
  LItem: String;
  LSeenAlpha, LSeenBeta: Boolean;
  LCount: Int32;
begin
  LSet := NewSet();
  try
    LSet.Add('alpha');
    LSet.Add('beta');

    LSeenAlpha := False;
    LSeenBeta := False;
    LCount := 0;
    for LItem in LSet do
    begin
      System.Inc(LCount);
      if LItem = 'alpha' then
        LSeenAlpha := True
      else if LItem = 'beta' then
        LSeenBeta := True;
    end;

    CheckEquals(2, LCount, 'the enumerator yields one item per entry');
    CheckTrue(LSeenAlpha, 'the enumerator yields the first item');
    CheckTrue(LSeenBeta, 'the enumerator yields the second item');
  finally
    LSet.Free;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TCryptoLibHashSetTest);
{$ELSE}
  RegisterTest(TCryptoLibHashSetTest.Suite);
{$ENDIF FPC}

end.
