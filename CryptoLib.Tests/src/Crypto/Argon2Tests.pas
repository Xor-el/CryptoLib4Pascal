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
  CryptoLibTestBase;

type

  /// <summary>
  /// A test class for Argon2.
  /// </summary>
  TTestArgon2 = class(TCryptoLibAlgorithmTestCase)

  private

    const
    // multiplied by 8 to get it in bits
    DEFAULT_OUTPUTLEN_IN_BITS = Int32(32 * 8);

    procedure HashTestFromInternetDraft(AArgon2Type: TCryptoLibArgon2Type;
      AArgon2Version: TCryptoLibArgon2Version;
      AIterations, AMemoryAsKB, AParallelism: Int32;
      const AAdditional, ASecret, ASalt, APassword, APasswordRef: String;
      AOutputLength: Int32);

    procedure HashTestOthers(AArgon2Type: TCryptoLibArgon2Type;
      AArgon2Version: TCryptoLibArgon2Version;
      AIterations, AMemory, AParallelism: Int32;
      const APassword, ASalt, APasswordRef: String; AOutputLength: Int32);

  protected

    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestVectorsFromInternetDraft;
    procedure TestOthers;

  end;

implementation

{ TTestArgon2 }

procedure TTestArgon2.HashTestFromInternetDraft(AArgon2Type
  : TCryptoLibArgon2Type; AArgon2Version: TCryptoLibArgon2Version;
  AIterations, AMemoryAsKB, AParallelism: Int32;
  const AAdditional, ASecret, ASalt, APassword, APasswordRef: String;
  AOutputLength: Int32);
var
  LArgon2Generator: IArgon2ParametersGenerator;
  LActual: String;
  LAdditional, LSecret, LSalt, LPassword: TBytes;
begin

  LAdditional := TConverters.ConvertHexStringToBytes(AAdditional);
  LSecret := TConverters.ConvertHexStringToBytes(ASecret);
  LSalt := TConverters.ConvertHexStringToBytes(ASalt);
  LPassword := TConverters.ConvertHexStringToBytes(APassword);

  LArgon2Generator := TArgon2ParametersGenerator.Create();

  //
  // Set the parameters.
  //

  LArgon2Generator.Init(AArgon2Type, AArgon2Version, LPassword, LSalt, LSecret,
    LAdditional, AIterations, AMemoryAsKB, AParallelism,
    TCryptoLibArgon2MemoryCostType.MemoryAsKB);

  LActual := TConverters.ConvertBytesToHexString
    ((LArgon2Generator.GenerateDerivedMacParameters(AOutputLength)
    as IKeyParameter).GetKey(), False);

  LArgon2Generator.Clear();

  CheckEquals(APasswordRef, LActual, Format('Expected %s but got %s.',
    [APasswordRef, LActual]));

end;

procedure TTestArgon2.HashTestOthers(AArgon2Type: TCryptoLibArgon2Type;
  AArgon2Version: TCryptoLibArgon2Version;
  AIterations, AMemory, AParallelism: Int32;
  const APassword, ASalt, APasswordRef: String; AOutputLength: Int32);
var
  LArgon2Generator: IArgon2ParametersGenerator;
  LSalt, LPassword: TBytes;
  LActual: String;
begin

  LSalt := TConverters.ConvertStringToBytes(ASalt, TEncoding.ASCII);
  LPassword := TConverters.ConvertStringToBytes(APassword, TEncoding.ASCII);

  LArgon2Generator := TArgon2ParametersGenerator.Create();

  //
  // Set the parameters.
  //

  LArgon2Generator.Init(AArgon2Type, AArgon2Version, LPassword, LSalt, Nil, Nil,
    AIterations, AMemory, AParallelism,
    TCryptoLibArgon2MemoryCostType.MemoryPowOfTwo);

  LActual := TConverters.ConvertBytesToHexString
    ((LArgon2Generator.GenerateDerivedMacParameters(AOutputLength)
    as IKeyParameter).GetKey(), False);

  LArgon2Generator.Clear();

  CheckEquals(APasswordRef, LActual, Format('Expected %s but got %s.',
    [APasswordRef, LActual]));

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
  LAdditional, LSecret, LSalt, LPassword: String;
  Argon2Version: TCryptoLibArgon2Version;
  Argon2Type: TCryptoLibArgon2Type;
begin

  LAdditional := '040404040404040404040404';
  LSecret := '0303030303030303';
  LSalt := '02020202020202020202020202020202';
  LPassword :=
    '0101010101010101010101010101010101010101010101010101010101010101';

  Argon2Version := TCryptoLibArgon2Version.Argon2Version13;

  Argon2Type := TCryptoLibArgon2Type.Argon2D;

  HashTestFromInternetDraft(Argon2Type, Argon2Version, 3, 32, 4, LAdditional,
    LSecret, LSalt, LPassword,
    '512B391B6F1162975371D30919734294F868E3BE3984F3C1A13A4DB9FABE4ACB',
    DEFAULT_OUTPUTLEN_IN_BITS);

  Argon2Type := TCryptoLibArgon2Type.Argon2I;

  HashTestFromInternetDraft(Argon2Type, Argon2Version, 3, 32, 4, LAdditional,
    LSecret, LSalt, LPassword,
    'C814D9D1DC7F37AA13F0D77F2494BDA1C8DE6B016DD388D29952A4C4672B6CE8',
    DEFAULT_OUTPUTLEN_IN_BITS);

  Argon2Type := TCryptoLibArgon2Type.Argon2ID;

  HashTestFromInternetDraft(Argon2Type, Argon2Version, 3, 32, 4, LAdditional,
    LSecret, LSalt, LPassword,
    '0D640DF58D78766C08C037A34A8B53C9D01EF0452D75B65EB52520E96B01E659',
    DEFAULT_OUTPUTLEN_IN_BITS);

end;

procedure TTestArgon2.TestOthers;
var
  Argon2Version: TCryptoLibArgon2Version;
  Argon2Type: TCryptoLibArgon2Type;
begin

  Argon2Version := TCryptoLibArgon2Version.Argon2Version10;
  Argon2Type := TCryptoLibArgon2Type.Argon2I;

  // Multiple test cases for various input values
  HashTestOthers(Argon2Type, Argon2Version, 2, 16, 1, 'password', 'somesalt',
    'F6C4DB4A54E2A370627AFF3DB6176B94A2A209A62C8E36152711802F7B30C694',
    DEFAULT_OUTPUTLEN_IN_BITS);

  HashTestOthers(Argon2Type, Argon2Version, 2, 20, 1, 'password', 'somesalt',
    '9690EC55D28D3ED32562F2E73EA62B02B018757643A2AE6E79528459DE8106E9',
    DEFAULT_OUTPUTLEN_IN_BITS);

  HashTestOthers(Argon2Type, Argon2Version, 2, 18, 1, 'password', 'somesalt',
    '3E689AAA3D28A77CF2BC72A51AC53166761751182F1EE292E3F677A7DA4C2467',
    DEFAULT_OUTPUTLEN_IN_BITS);

  HashTestOthers(Argon2Type, Argon2Version, 2, 8, 1, 'password', 'somesalt',
    'FD4DD83D762C49BDEAF57C47BDCD0C2F1BABF863FDEB490DF63EDE9975FCCF06',
    DEFAULT_OUTPUTLEN_IN_BITS);
  HashTestOthers(Argon2Type, Argon2Version, 2, 8, 2, 'password', 'somesalt',
    'B6C11560A6A9D61EAC706B79A2F97D68B4463AA3AD87E00C07E2B01E90C564FB',
    DEFAULT_OUTPUTLEN_IN_BITS);
  HashTestOthers(Argon2Type, Argon2Version, 1, 16, 1, 'password', 'somesalt',
    '81630552B8F3B1F48CDB1992C4C678643D490B2B5EB4FF6C4B3438B5621724B2',
    DEFAULT_OUTPUTLEN_IN_BITS);
  HashTestOthers(Argon2Type, Argon2Version, 4, 16, 1, 'password', 'somesalt',
    'F212F01615E6EB5D74734DC3EF40ADE2D51D052468D8C69440A3A1F2C1C2847B',
    DEFAULT_OUTPUTLEN_IN_BITS);
  HashTestOthers(Argon2Type, Argon2Version, 2, 16, 1, 'differentpassword',
    'somesalt',
    'E9C902074B6754531A3A0BE519E5BAF404B30CE69B3F01AC3BF21229960109A3',
    DEFAULT_OUTPUTLEN_IN_BITS);
  HashTestOthers(Argon2Type, Argon2Version, 2, 16, 1, 'password', 'diffsalt',
    '79A103B90FE8AEF8570CB31FC8B22259778916F8336B7BDAC3892569D4F1C497',
    DEFAULT_OUTPUTLEN_IN_BITS);

  HashTestOthers(Argon2Type, Argon2Version, 2, 16, 1, 'password', 'diffsalt',
    '1A097A5D1C80E579583F6E19C7E4763CCB7C522CA85B7D58143738E12CA39F8E6E42734C950FF2463675B97C37BA'
    + '39FEBA4A9CD9CC5B4C798F2AAF70EB4BD044C8D148DECB569870DBD923430B82A083F284BEAE777812CCE18CDAC68EE8CCEF'
    + 'C6EC9789F30A6B5A034591F51AF830F4', 112 * 8);

  Argon2Version := TCryptoLibArgon2Version.Argon2Version13;
  Argon2Type := TCryptoLibArgon2Type.Argon2I;
  // Multiple test cases for various input values

  HashTestOthers(Argon2Type, Argon2Version, 2, 16, 1, 'password', 'somesalt',
    'C1628832147D9720C5BD1CFD61367078729F6DFB6F8FEA9FF98158E0D7816ED0',
    DEFAULT_OUTPUTLEN_IN_BITS);

  HashTestOthers(Argon2Type, Argon2Version, 2, 20, 1, 'password', 'somesalt',
    'D1587ACA0922C3B5D6A83EDAB31BEE3C4EBAEF342ED6127A55D19B2351AD1F41',
    DEFAULT_OUTPUTLEN_IN_BITS);

  HashTestOthers(Argon2Type, Argon2Version, 2, 18, 1, 'password', 'somesalt',
    '296DBAE80B807CDCEAAD44AE741B506F14DB0959267B183B118F9B24229BC7CB',
    DEFAULT_OUTPUTLEN_IN_BITS);

  HashTestOthers(Argon2Type, Argon2Version, 2, 8, 1, 'password', 'somesalt',
    '89E9029F4637B295BEB027056A7336C414FADD43F6B208645281CB214A56452F',
    DEFAULT_OUTPUTLEN_IN_BITS);

  HashTestOthers(Argon2Type, Argon2Version, 2, 8, 2, 'password', 'somesalt',
    '4FF5CE2769A1D7F4C8A491DF09D41A9FBE90E5EB02155A13E4C01E20CD4EAB61',
    DEFAULT_OUTPUTLEN_IN_BITS);
  HashTestOthers(Argon2Type, Argon2Version, 1, 16, 1, 'password', 'somesalt',
    'D168075C4D985E13EBEAE560CF8B94C3B5D8A16C51916B6F4AC2DA3AC11BBECF',
    DEFAULT_OUTPUTLEN_IN_BITS);
  HashTestOthers(Argon2Type, Argon2Version, 4, 16, 1, 'password', 'somesalt',
    'AAA953D58AF3706CE3DF1AEFD4A64A84E31D7F54175231F1285259F88174CE5B',
    DEFAULT_OUTPUTLEN_IN_BITS);
  HashTestOthers(Argon2Type, Argon2Version, 2, 16, 1, 'differentpassword',
    'somesalt',
    '14AE8DA01AFEA8700C2358DCEF7C5358D9021282BD88663A4562F59FB74D22EE',
    DEFAULT_OUTPUTLEN_IN_BITS);
  HashTestOthers(Argon2Type, Argon2Version, 2, 16, 1, 'password', 'diffsalt',
    'B0357CCCFBEF91F3860B0DBA447B2348CBEFECADAF990ABFE9CC40726C521271',
    DEFAULT_OUTPUTLEN_IN_BITS);

end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestArgon2);
{$ELSE}
  RegisterTest(TTestArgon2.Suite);
{$ENDIF FPC}

end.
