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

unit SpeckTests;

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
  ClpSpeckEngine,
  ClpISpeckEngine,
  ClpCryptoLibTypes,
  SpeckBlockCipherTestBase;

type

  TTestSpeck = class(TSpeckBlockCipherTestBase)
  strict private
  class var
    FSpeck32BlockCipherVectorKeys, FSpeck32BlockCipherVectorInputs,
    FSpeck32BlockCipherVectorOutputs,

    FSpeck48BlockCipherVectorKeys, FSpeck48BlockCipherVectorInputs,
    FSpeck48BlockCipherVectorOutputs,

    FSpeck64BlockCipherVectorKeys, FSpeck64BlockCipherVectorInputs,
    FSpeck64BlockCipherVectorOutputs,

    FSpeck96BlockCipherVectorKeys, FSpeck96BlockCipherVectorInputs,
    FSpeck96BlockCipherVectorOutputs,

    FSpeck128BlockCipherVectorKeys, FSpeck128BlockCipherVectorInputs,
    FSpeck128BlockCipherVectorOutputs: TCryptoLibStringArray;

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
    procedure TestSPECK64_CBC_NOPADDING_WITH_IV;
    procedure TestSPECK128_CBC_NOPADDING_WITH_IV;
    procedure TestSPECK64_CTR_NOPADDING_WITH_IV;
    procedure TestSPECK128_CTR_NOPADDING_WITH_IV;
    procedure TestSPECK64_ECB_NOPADDING_NO_IV;
    procedure TestSPECK128_ECB_NOPADDING_NO_IV;
  end;

implementation

function CreateSpeck32Engine: ISpeckEngine;
begin
  Result := TSpeck32Engine.Create();
end;

function CreateSpeck48Engine: ISpeckEngine;
begin
  Result := TSpeck48Engine.Create();
end;

function CreateSpeck64Engine: ISpeckEngine;
begin
  Result := TSpeck64Engine.Create();
end;

function CreateSpeck96Engine: ISpeckEngine;
begin
  Result := TSpeck96Engine.Create();
end;

function CreateSpeck128Engine: ISpeckEngine;
begin
  Result := TSpeck128Engine.Create();
end;

{ TTestSpeck }

class constructor TTestSpeck.CreateTestVectors;
begin
  FSpeck32BlockCipherVectorKeys := TCryptoLibStringArray.Create
    ('0001080910111819');

  FSpeck32BlockCipherVectorInputs := TCryptoLibStringArray.Create('4C697465');

  FSpeck32BlockCipherVectorOutputs := TCryptoLibStringArray.Create('F24268A8');

  FSpeck48BlockCipherVectorKeys := TCryptoLibStringArray.Create
    ('00010208090A101112', '00010208090A101112', '00010208090A10111218191A');

  FSpeck48BlockCipherVectorInputs := TCryptoLibStringArray.Create
    ('72616C6C7920', '72616C6C7920', '74686973206D');

  FSpeck48BlockCipherVectorOutputs := TCryptoLibStringArray.Create
    ('DC5A38A549C0', 'DC5A38A549C0', '5D44B6105E73');

  FSpeck64BlockCipherVectorKeys := TCryptoLibStringArray.Create
    ('0001020308090A0B10111213', '0001020308090A0B1011121318191A1B');

  FSpeck64BlockCipherVectorInputs := TCryptoLibStringArray.Create
    ('65616E7320466174', '2D4375747465723B');

  FSpeck64BlockCipherVectorOutputs := TCryptoLibStringArray.Create
    ('6C947541EC52799F', '8B024E4548A56F8C');

  FSpeck96BlockCipherVectorKeys := TCryptoLibStringArray.Create
    ('00010203040508090A0B0C0D', '00010203040508090A0B0C0D101112131415');

  FSpeck96BlockCipherVectorInputs := TCryptoLibStringArray.Create
    ('2075736167652C20686F7765', '7665722C20696E2074696D65');

  FSpeck96BlockCipherVectorOutputs := TCryptoLibStringArray.Create
    ('AA798FDEBD627871AB094D9E', 'E62E2540E47A8A227210F32B');

  FSpeck128BlockCipherVectorKeys := TCryptoLibStringArray.Create
    ('000102030405060708090A0B0C0D0E0F',
    '000102030405060708090A0B0C0D0E0F1011121314151617',
    '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F');

  FSpeck128BlockCipherVectorInputs := TCryptoLibStringArray.Create
    ('206D616465206974206571756976616C', '656E7420746F20436869656620486172',
    '706F6F6E65722E20496E2074686F7365');

  FSpeck128BlockCipherVectorOutputs := TCryptoLibStringArray.Create
    ('180D575CDFFE60786532787951985DA6', '86183CE05D18BCF9665513133ACFE41B',
    '438F189C8DB4EE4E3EF5C00504010941');
end;

procedure TTestSpeck.SetUp;
begin
  inherited;
end;

procedure TTestSpeck.TearDown;
begin
  inherited;
end;

procedure TTestSpeck.TestBlockCipherVectorSpeck32;
begin
  RunSpeckBlockCipherVectorTests(@CreateSpeck32Engine, 'TSpeck32Engine',
    FSpeck32BlockCipherVectorKeys, FSpeck32BlockCipherVectorInputs,
    FSpeck32BlockCipherVectorOutputs);
end;

procedure TTestSpeck.TestBlockCipherVectorSpeck48;
begin
  RunSpeckBlockCipherVectorTests(@CreateSpeck48Engine, 'TSpeck48Engine',
    FSpeck48BlockCipherVectorKeys, FSpeck48BlockCipherVectorInputs,
    FSpeck48BlockCipherVectorOutputs);
end;

procedure TTestSpeck.TestBlockCipherVectorSpeck64;
begin
  RunSpeckBlockCipherVectorTests(@CreateSpeck64Engine, 'TSpeck64Engine',
    FSpeck64BlockCipherVectorKeys, FSpeck64BlockCipherVectorInputs,
    FSpeck64BlockCipherVectorOutputs);
end;

procedure TTestSpeck.TestBlockCipherVectorSpeck96;
begin
  RunSpeckBlockCipherVectorTests(@CreateSpeck96Engine, 'TSpeck96Engine',
    FSpeck96BlockCipherVectorKeys, FSpeck96BlockCipherVectorInputs,
    FSpeck96BlockCipherVectorOutputs);
end;

procedure TTestSpeck.TestBlockCipherVectorSpeck128;
begin
  RunSpeckBlockCipherVectorTests(@CreateSpeck128Engine, 'TSpeck128Engine',
    FSpeck128BlockCipherVectorKeys, FSpeck128BlockCipherVectorInputs,
    FSpeck128BlockCipherVectorOutputs);
end;

procedure TTestSpeck.TestSPECK64_CBC_NOPADDING_WITH_IV;
begin
  RunCryptoPPSpeck64CbcTests;
end;

procedure TTestSpeck.TestSPECK128_CBC_NOPADDING_WITH_IV;
begin
  RunCryptoPPSpeck128CbcTests;
end;

procedure TTestSpeck.TestSPECK64_CTR_NOPADDING_WITH_IV;
begin
  RunCryptoPPSpeck64CtrTests;
end;

procedure TTestSpeck.TestSPECK128_CTR_NOPADDING_WITH_IV;
begin
  RunCryptoPPSpeck128CtrTests;
end;

procedure TTestSpeck.TestSPECK64_ECB_NOPADDING_NO_IV;
begin
  RunCryptoPPSpeck64EcbTests;
end;

procedure TTestSpeck.TestSPECK128_ECB_NOPADDING_NO_IV;
begin
  RunCryptoPPSpeck128EcbTests;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestSpeck);
{$ELSE}
  RegisterTest(TTestSpeck.Suite);
{$ENDIF FPC}

end.
