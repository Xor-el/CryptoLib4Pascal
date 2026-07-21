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

unit ScryptTests;

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
  ClpScryptParametersGenerator,
  ClpIScryptParametersGenerator,
  ClpConverters,
  ClpEncoders,
  HlpHashLibExceptions,
  CsvVectorParser,
  CryptoLibTestBase,
  ClpCryptoLibTypes;

type
  TScryptVector = record
    Password: string;
    Salt: string;
    Cost: Int32;
    BlockSize: Int32;
    Parallelism: Int32;
    OutputLenBits: Int32;
    ExpectedHex: string;
  end;

  /// <summary>
  /// A Test class for Scrypt.
  /// </summary>
  TTestScrypt = class(TCryptoLibAlgorithmTestCase)

  private

    const
    // multiplied by 8 to get it in bits
    ONE_AS_OUTPUTLEN_IN_BITS = Int32(1 * 8);

  var
    FExpectedString, FActualString: String;

    function DoTestVector(const APassword, ASalt: String;
      ACost, ABlockSize, AParallelism, AOutputSize: Int32): String;

    procedure DoCheckOk(const AMsg: String; const APassword, ASalt: TBytes;
      ACost, ABlockSize, AParallelism, AOutputSize: Int32);

    procedure DoCheckIllegal(const AMsg: String; const APassword, ASalt: TBytes;
      ACost, ABlockSize, AParallelism, AOutputSize: Int32);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestVectors;
    procedure TestParameters;

  end;

implementation

{ TTestScrypt }

procedure TTestScrypt.SetUp;
begin
  inherited;

end;

procedure TTestScrypt.TearDown;
begin
  inherited;

end;

function TTestScrypt.DoTestVector(const APassword, ASalt: String;
  ACost, ABlockSize, AParallelism, AOutputSize: Int32): String;
var
  LScryptGenerator: IScryptParametersGenerator;
  APasswordBytes, ASaltBytes, OutputBytes: TBytes;
begin
  APasswordBytes := TConverters.ConvertStringToBytes(APassword,
    TEncoding.ASCII);
  ASaltBytes := TConverters.ConvertStringToBytes(ASalt, TEncoding.ASCII);

  LScryptGenerator := TScryptParametersGenerator.Create();

  //
  // Set the parameters.
  //

  LScryptGenerator.Init(APasswordBytes, ASaltBytes, ACost, ABlockSize,
    AParallelism);

  OutputBytes := (LScryptGenerator.GenerateDerivedMacParameters(AOutputSize)
    as IKeyParameter).GetKey();
  LScryptGenerator.Clear();
  Result := THexEncoder.Encode(OutputBytes);
end;

procedure TTestScrypt.DoCheckIllegal(const AMsg: String;
  const APassword, ASalt: TBytes; ACost, ABlockSize, AParallelism,
  AOutputSize: Int32);
var
  LScryptGenerator: IScryptParametersGenerator;
  OutputBytes: TBytes;
begin
  try

    LScryptGenerator := TScryptParametersGenerator.Create();
    //
    // Set the parameters.
    //
    //
    LScryptGenerator.Init(APassword, ASalt, ACost, ABlockSize, AParallelism);

    OutputBytes := (LScryptGenerator.GenerateDerivedMacParameters(AOutputSize)
      as IKeyParameter).GetKey();

    Fail(AMsg);
  except
    on e: EArgumentHashLibException do
    begin
      // pass so we do nothing
    end;
  end;
end;

procedure TTestScrypt.DoCheckOk(const AMsg: String;
  const APassword, ASalt: TBytes; ACost, ABlockSize, AParallelism,
  AOutputSize: Int32);
var
  LScryptGenerator: IScryptParametersGenerator;
  OutputBytes: TBytes;
begin
  try
    try

      LScryptGenerator := TScryptParametersGenerator.Create();
      //
      // Set the parameters.
      //
      //
      LScryptGenerator.Init(APassword, ASalt, ACost, ABlockSize, AParallelism);

      OutputBytes := (LScryptGenerator.GenerateDerivedMacParameters(AOutputSize)
        as IKeyParameter).GetKey();
    except
      on e: EArgumentHashLibException do
      begin
        Fail(AMsg);
      end;
    end;
  finally
    LScryptGenerator.Clear();
  end;
end;

procedure TTestScrypt.TestParameters;
begin
  DoCheckOk('Minimal values', Nil, Nil, 2, 1, 1, ONE_AS_OUTPUTLEN_IN_BITS);
  DoCheckIllegal('Cost parameter must be > 1', Nil, Nil, 1, 1, 1,
    ONE_AS_OUTPUTLEN_IN_BITS);
  DoCheckOk('Cost parameter 32768 OK for r = 1', Nil, Nil, 32768, 1, 1,
    ONE_AS_OUTPUTLEN_IN_BITS);
  DoCheckIllegal('Cost parameter must < 65536 for r = 1', Nil, Nil, 65536, 1, 1,
    ONE_AS_OUTPUTLEN_IN_BITS);
  DoCheckIllegal('Block size must be >= 1', Nil, Nil, 2, 0, 2,
    ONE_AS_OUTPUTLEN_IN_BITS);
  DoCheckIllegal('Parallelisation parameter must be >= 1', Nil, Nil, 2, 1, 0,
    ONE_AS_OUTPUTLEN_IN_BITS);
  // disabled test because it's very expensive
  // DoCheckOk('Parallelisation parameter 65535 OK for r = 4', Nil, Nil, 2, 32,
  // 65535, ONE_AS_OUTPUTLEN_IN_BITS);
  DoCheckIllegal('Parallelisation parameter must be < 65535 for r = 4', Nil,
    Nil, 2, 32, 65536, ONE_AS_OUTPUTLEN_IN_BITS);

  DoCheckIllegal('Len parameter must be > 1', Nil, Nil, 2, 1, 1, 0);
end;

procedure TTestScrypt.TestVectors;
var
  LContent: string;
  LHeader: TCryptoLibStringArray;
  LRows: TCryptoLibGenericArray<TCsvRow>;
  LVector: TScryptVector;
  LI: Integer;
begin
  LContent := LoadTestResource('Crypto/Scrypt/TestVectors.csv');
  LHeader := TCsvVectorParser.GetHeader(LContent);
  LRows := TCsvVectorParser.Parse(LContent, True);
  for LI := 0 to High(LRows) do
  begin
    if not TCsvVectorParser.ParseBoolField(
      TCsvVectorParser.GetField(LRows[LI], LHeader, 'Enabled')) then
      Continue;

    LVector.Password := TCsvVectorParser.GetField(LRows[LI], LHeader, 'Password');
    LVector.Salt := TCsvVectorParser.GetField(LRows[LI], LHeader, 'Salt');
    LVector.Cost := StrToInt(TCsvVectorParser.GetField(LRows[LI], LHeader, 'Cost'));
    LVector.BlockSize := StrToInt(TCsvVectorParser.GetField(LRows[LI], LHeader, 'BlockSize'));
    LVector.Parallelism := StrToInt(TCsvVectorParser.GetField(LRows[LI], LHeader, 'Parallelism'));
    LVector.OutputLenBits := StrToInt(TCsvVectorParser.GetField(LRows[LI], LHeader, 'OutputLenBytes')) * 8;
    LVector.ExpectedHex := TCsvVectorParser.GetField(LRows[LI], LHeader, 'ExpectedHex');

    FActualString := DoTestVector(LVector.Password, LVector.Salt,
      LVector.Cost, LVector.BlockSize, LVector.Parallelism,
      LVector.OutputLenBits);
    FExpectedString := LVector.ExpectedHex;
    CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
      [FExpectedString, FActualString]));
  end;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestScrypt);
{$ELSE}
  RegisterTest(TTestScrypt.Suite);
{$ENDIF FPC}

end.
