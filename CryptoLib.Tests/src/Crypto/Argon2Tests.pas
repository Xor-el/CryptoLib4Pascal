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

unit Argon2Tests;

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
  ClpIKeyParameter,
  ClpArgon2ParametersGenerator,
  ClpIArgon2ParametersGenerator,
  ClpConverters,
  ClpEncoders,
  ClpCryptoLibTypes,
  CryptoLibTestBase,
  Argon2Vectors;

type

  /// <summary>
  /// A test class for Argon2.
  /// </summary>
  TTestArgon2 = class(TCryptoLibAlgorithmTestCase)

  private

    procedure HashTestFromRow(const ARow: TArgon2VectorRow);

    function ParseArgon2Type(const AValue: string): TCryptoLibArgon2Type;
    function ParseArgon2Version(const AValue: string): TCryptoLibArgon2Version;

  protected

    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestVectorsFromInternetDraft;
    procedure TestOthers;

  end;

implementation

{ TTestArgon2 }

function TTestArgon2.ParseArgon2Type(const AValue: string): TCryptoLibArgon2Type;
var
  LLower: string;
begin
  LLower := LowerCase(Trim(AValue));
  if LLower = 'id' then
    Result := TCryptoLibArgon2Type.Argon2ID
  else if LLower = 'i' then
    Result := TCryptoLibArgon2Type.Argon2I
  else if LLower = 'd' then
    Result := TCryptoLibArgon2Type.Argon2D
  else
    raise Exception.Create('Unknown Argon2 type: ' + AValue);
end;

function TTestArgon2.ParseArgon2Version(const AValue: string)
  : TCryptoLibArgon2Version;
begin
  if AValue = '13' then
    Result := TCryptoLibArgon2Version.Argon2Version13
  else if AValue = '10' then
    Result := TCryptoLibArgon2Version.Argon2Version10
  else
    raise Exception.Create('Unknown Argon2 version: ' + AValue);
end;

procedure TTestArgon2.HashTestFromRow(const ARow: TArgon2VectorRow);
var
  LArgon2Generator: IArgon2ParametersGenerator;
  LActual: String;
  LAdditional, LSecret, LSalt, LPassword: TBytes;
  LArgon2Type: TCryptoLibArgon2Type;
  LArgon2Version: TCryptoLibArgon2Version;
  LMemoryCostType: TCryptoLibArgon2MemoryCostType;
  LOutputLenBits: Int32;
begin
  LArgon2Type := ParseArgon2Type(ARow.Argon2Type);
  LArgon2Version := ParseArgon2Version(ARow.Version);
  LOutputLenBits := ARow.OutputLenBytes * 8;

  if SameText(ARow.Source, 'draft') then
  begin
    LAdditional := THexEncoder.Decode(ARow.Additional);
    LSecret := THexEncoder.Decode(ARow.Secret);
    LSalt := THexEncoder.Decode(ARow.Salt);
    LPassword := THexEncoder.Decode(ARow.Password);
    LMemoryCostType := TCryptoLibArgon2MemoryCostType.MemoryAsKB;
  end
  else
  begin
    LAdditional := nil;
    LSecret := nil;
    LSalt := TConverters.ConvertStringToBytes(ARow.Salt, TEncoding.ASCII);
    LPassword := TConverters.ConvertStringToBytes(ARow.Password, TEncoding.ASCII);
    LMemoryCostType := TCryptoLibArgon2MemoryCostType.MemoryPowOfTwo;
  end;

  LArgon2Generator := TArgon2ParametersGenerator.Create();
  LArgon2Generator.Init(LArgon2Type, LArgon2Version, LPassword, LSalt, LSecret,
    LAdditional, ARow.Iterations, ARow.Memory, ARow.Parallelism,
    LMemoryCostType);

  LActual := THexEncoder.Encode
    ((LArgon2Generator.GenerateDerivedMacParameters(LOutputLenBits)
    as IKeyParameter).GetKey());
  LArgon2Generator.Clear();

  CheckEquals(ARow.ExpectedHex, UpperCase(LActual), Format('Expected %s but got %s.',
    [ARow.ExpectedHex, LActual]));
end;

procedure TTestArgon2.SetUp;
begin
  inherited;

end;

procedure TTestArgon2.TearDown;
begin
  inherited;

end;

procedure TTestArgon2.TestVectorsFromInternetDraft;
var
  LRows: TCryptoLibGenericArray<TArgon2VectorRow>;
  LI: Integer;
begin
  LRows := TArgon2Vectors.GetDraftRows;
  for LI := 0 to High(LRows) do
    HashTestFromRow(LRows[LI]);
end;

procedure TTestArgon2.TestOthers;
var
  LRows: TCryptoLibGenericArray<TArgon2VectorRow>;
  LI: Integer;
begin
  LRows := TArgon2Vectors.GetOthersRows;
  for LI := 0 to High(LRows) do
    HashTestFromRow(LRows[LI]);
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestArgon2);
{$ELSE}
  RegisterTest(TTestArgon2.Suite);
{$ENDIF FPC}

end.
