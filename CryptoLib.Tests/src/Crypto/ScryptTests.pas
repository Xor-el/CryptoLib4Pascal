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
  HlpHashLibTypes,
  CryptoLibTestBase;

type

  /// <summary>
  /// A Test class for Scrypt.
  /// </summary>
  TTestScrypt = class(TCryptoLibAlgorithmTestCase)

  private

    const
    // multiplied by 8 to get it in bits
    DEFAULT_OUTPUTLEN_IN_BITS = Int32(64 * 8);
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
  Result := TConverters.ConvertBytesToHexString(OutputBytes, False);
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
begin

  FActualString := DoTestVector('', '', 16, 1, 1, DEFAULT_OUTPUTLEN_IN_BITS);
  FExpectedString :=
    '77D6576238657B203B19CA42C18A0497F16B4844E3074AE8DFDFFA3FEDE21442FCD0069DED0948F8326A753A0FC81F17E8D3E0FB2E0D3628CF35E20C38D18906';

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));

  FActualString := DoTestVector('password', 'NaCl', 1024, 8, 16,
    DEFAULT_OUTPUTLEN_IN_BITS);
  FExpectedString :=
    'FDBABE1C9D3472007856E7190D01E9FE7C6AD7CBC8237830E77376634B3731622EAF30D92E22A3886FF109279D9830DAC727AFB94A83EE6D8360CBDFA2CC0640';

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));

  FActualString := DoTestVector('pleaseletmein', 'SodiumChloride', 16384, 8, 1,
    DEFAULT_OUTPUTLEN_IN_BITS);
  FExpectedString :=
    '7023BDCB3AFD7348461C06CD81FD38EBFDA8FBBA904F8E3EA9B543F6545DA1F2D5432955613F0FCF62D49705242A9AF9E61E85DC0D651E40DFCF017B45575887';

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));

  // disabled test because it's very expensive
  // FActualString := DoTestVector('pleaseletmein', 'SodiumChloride', 1048576, 8,
  // 1, DEFAULT_OUTPUTLEN_IN_BITS);
  // FExpectedString :=
  // '2101CB9B6A511AAEADDBBE09CF70F881EC568D574A2FFD4DABE5EE9820ADAA478E56FD8F4BA5D09FFA1C6D927C40F4C337304049E8A952FBCBF45C6FA77A41A4';
  //
  // CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
  // [FExpectedString, FActualString]));

end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestScrypt);
{$ELSE}
  RegisterTest(TTestScrypt.Suite);
{$ENDIF FPC}

end.
