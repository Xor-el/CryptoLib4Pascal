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

unit SpeckLegacyTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpSpeckLegacyEngine,
  ClpISpeckLegacyEngine,
  ClpCryptoLibTypes,
  SpeckBlockCipherTestBase;

type

  TTestSpeckLegacy = class(TSpeckBlockCipherTestBase)
  strict private
  class var
    FSpeck32LegacyBlockCipherVectorKeys,
    FSpeck32LegacyBlockCipherVectorInputs,
    FSpeck32LegacyBlockCipherVectorOutputs,

    FSpeck48LegacyBlockCipherVectorKeys,
    FSpeck48LegacyBlockCipherVectorInputs,
    FSpeck48LegacyBlockCipherVectorOutputs,

    FSpeck64LegacyBlockCipherVectorKeys,
    FSpeck64LegacyBlockCipherVectorInputs,
    FSpeck64LegacyBlockCipherVectorOutputs,

    FSpeck96LegacyBlockCipherVectorKeys,
    FSpeck96LegacyBlockCipherVectorInputs,
    FSpeck96LegacyBlockCipherVectorOutputs,

    FSpeck128LegacyBlockCipherVectorKeys,
    FSpeck128LegacyBlockCipherVectorInputs,
    FSpeck128LegacyBlockCipherVectorOutputs: TCryptoLibStringArray;

    class constructor CreateTestVectors;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestBlockCipherVectorSpeck32;
    procedure TestBlockCipherVectorSpeck48;
    procedure TestBlockCipherVectorSpeck64;
    procedure TestBlockCipherVectorSpeck96;
    procedure TestBlockCipherVectorSpeck128;
  end;

implementation

function CreateSpeck32LegacyEngine: ISpeckLegacyEngine;
begin
  Result := TSpeck32LegacyEngine.Create();
end;

function CreateSpeck48LegacyEngine: ISpeckLegacyEngine;
begin
  Result := TSpeck48LegacyEngine.Create();
end;

function CreateSpeck64LegacyEngine: ISpeckLegacyEngine;
begin
  Result := TSpeck64LegacyEngine.Create();
end;

function CreateSpeck96LegacyEngine: ISpeckLegacyEngine;
begin
  Result := TSpeck96LegacyEngine.Create();
end;

function CreateSpeck128LegacyEngine: ISpeckLegacyEngine;
begin
  Result := TSpeck128LegacyEngine.Create();
end;

{ TTestSpeckLegacy }

class constructor TTestSpeckLegacy.CreateTestVectors;
begin
  FSpeck32LegacyBlockCipherVectorKeys := TCryptoLibStringArray.Create
    ('1918111009080100');

  FSpeck32LegacyBlockCipherVectorInputs := TCryptoLibStringArray.Create
    ('6574694C');

  FSpeck32LegacyBlockCipherVectorOutputs := TCryptoLibStringArray.Create
    ('A86842F2');

  FSpeck48LegacyBlockCipherVectorKeys := TCryptoLibStringArray.Create
    ('1211100A0908020100', '1A19181211100A0908020100');

  FSpeck48LegacyBlockCipherVectorInputs := TCryptoLibStringArray.Create
    ('20796C6C6172', '6D2073696874');

  FSpeck48LegacyBlockCipherVectorOutputs := TCryptoLibStringArray.Create
    ('C049A5385ADC', '735E10B6445D');

  FSpeck64LegacyBlockCipherVectorKeys := TCryptoLibStringArray.Create
    ('131211100B0A090803020100', '1B1A1918131211100B0A090803020100');

  FSpeck64LegacyBlockCipherVectorInputs := TCryptoLibStringArray.Create
    ('74614620736E6165', '3B7265747475432D');

  FSpeck64LegacyBlockCipherVectorOutputs := TCryptoLibStringArray.Create
    ('9F7952EC4175946C', '8C6FA548454E028B');

  FSpeck96LegacyBlockCipherVectorKeys := TCryptoLibStringArray.Create
    ('0D0C0B0A0908050403020100', '1514131211100D0C0B0A0908050403020100');

  FSpeck96LegacyBlockCipherVectorInputs := TCryptoLibStringArray.Create
    ('65776F68202C656761737520', '656D6974206E69202C726576');

  FSpeck96LegacyBlockCipherVectorOutputs := TCryptoLibStringArray.Create
    ('9E4D09AB717862BDDE8F79AA', '2BF31072228A7AE440252EE6');

  FSpeck128LegacyBlockCipherVectorKeys := TCryptoLibStringArray.Create
    ('0F0E0D0C0B0A09080706050403020100',
    '17161514131211100F0E0D0C0B0A09080706050403020100',
    '1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100');

  FSpeck128LegacyBlockCipherVectorInputs := TCryptoLibStringArray.Create
    ('6C617669757165207469206564616D20', '726148206665696843206F7420746E65',
    '65736F6874206E49202E72656E6F6F70');

  FSpeck128LegacyBlockCipherVectorOutputs := TCryptoLibStringArray.Create
    ('A65D9851797832657860FEDF5C570D18', '1BE4CF3A13135566F9BC185DE03C1886',
    '4109010405C0F53E4EEEB48D9C188F43');
end;

procedure TTestSpeckLegacy.SetUp;
begin
  inherited;
end;

procedure TTestSpeckLegacy.TearDown;
begin
  inherited;
end;

procedure TTestSpeckLegacy.TestBlockCipherVectorSpeck32;
begin
  RunSpeckLegacyBlockCipherVectorTests(@CreateSpeck32LegacyEngine,
    'TSpeck32LegacyEngine', FSpeck32LegacyBlockCipherVectorKeys,
    FSpeck32LegacyBlockCipherVectorInputs,
    FSpeck32LegacyBlockCipherVectorOutputs);
end;

procedure TTestSpeckLegacy.TestBlockCipherVectorSpeck48;
begin
  RunSpeckLegacyBlockCipherVectorTests(@CreateSpeck48LegacyEngine,
    'TSpeck48LegacyEngine', FSpeck48LegacyBlockCipherVectorKeys,
    FSpeck48LegacyBlockCipherVectorInputs,
    FSpeck48LegacyBlockCipherVectorOutputs);
end;

procedure TTestSpeckLegacy.TestBlockCipherVectorSpeck64;
begin
  RunSpeckLegacyBlockCipherVectorTests(@CreateSpeck64LegacyEngine,
    'TSpeck64LegacyEngine', FSpeck64LegacyBlockCipherVectorKeys,
    FSpeck64LegacyBlockCipherVectorInputs,
    FSpeck64LegacyBlockCipherVectorOutputs);
end;

procedure TTestSpeckLegacy.TestBlockCipherVectorSpeck96;
begin
  RunSpeckLegacyBlockCipherVectorTests(@CreateSpeck96LegacyEngine,
    'TSpeck96LegacyEngine', FSpeck96LegacyBlockCipherVectorKeys,
    FSpeck96LegacyBlockCipherVectorInputs,
    FSpeck96LegacyBlockCipherVectorOutputs);
end;

procedure TTestSpeckLegacy.TestBlockCipherVectorSpeck128;
begin
  RunSpeckLegacyBlockCipherVectorTests(@CreateSpeck128LegacyEngine,
    'TSpeck128LegacyEngine', FSpeck128LegacyBlockCipherVectorKeys,
    FSpeck128LegacyBlockCipherVectorInputs,
    FSpeck128LegacyBlockCipherVectorOutputs);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestSpeckLegacy);
{$ELSE}
  RegisterTest(TTestSpeckLegacy.Suite);
{$ENDIF FPC}

end.
