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

unit ClpArgon2ParametersGenerator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses

  HlpIHashInfo,
  HlpHashFactory,
  HlpArgon2TypeAndVersion,
  HlpPBKDF_Argon2NotBuildInAdapter,
  ClpPbeParametersGenerator,
  ClpICipherParameters,
  ClpIArgon2ParametersGenerator,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpParameterUtilities,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SArgon2TypeInvalid = 'Selected Argon2Type is Invalid';
  SArgon2VersionInvalid = 'Selected Argon2Version is Invalid';
  SArgon2MemoryCostTypeInvalid = 'Selected Argon2MemoryCostType is Invalid';

type

  /// <summary>
  /// <see href="https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf">
  /// Argon2 Specification</see>, <see href="https://tools.ietf.org/html/draft-irtf-cfrg-argon2-04">
  /// ietf specs</see>
  /// </summary>
  TArgon2ParametersGenerator = class sealed(TPbeParametersGenerator,
    IArgon2ParametersGenerator)

  strict private
  var
    FPassword: TCryptoLibByteArray;
    FPBKDF_Argon2: IPBKDF_Argon2;
    FArgon2Parameters: IArgon2Parameters;

    function GenerateDerivedKey(ADkLen: Int32): TCryptoLibByteArray; inline;

  public

    procedure Clear(); override;

    /// <summary>
    /// construct an Argon2 Parameters generator.
    /// </summary>
    /// <param name="digest">
    /// digest to use for constructing hmac
    /// </param>
    constructor Create();

    destructor Destroy; override;

    procedure Init(AArgon2Type: TCryptoLibArgon2Type;
      AArgon2Version: TCryptoLibArgon2Version; const APassword, ASalt, ASecret,
      AAdditional: TCryptoLibByteArray; AIterations, AMemory, AParallelism: Int32;
      AMemoryCostType: TCryptoLibArgon2MemoryCostType);

    /// <summary>
    /// Generate a key parameter derived from the password, salt, and
    /// iteration count we are currently initialised with.
    /// </summary>
    /// <param name="algorithm">
    /// a parameters object representing a key.
    /// </param>
    /// <param name="keySize">
    /// the length, in bits, of the key required.
    /// </param>
    /// <returns>
    /// a parameters object representing a key.
    /// </returns>
    function GenerateDerivedParameters(const AAlgorithm: String; AKeySize: Int32)
      : ICipherParameters; overload; override;

    /// <summary>
    /// Generate a key with initialisation vector parameter derived from <br />
    /// the password, salt, and iteration count we are currently initialised
    /// with.
    /// </summary>
    function GenerateDerivedParameters(const AAlgorithm: String;
      AKeySize, AIvSize: Int32): ICipherParameters; overload; override;

    /// <summary>
    /// Generate a key parameter for use with a MAC derived from the
    /// password, salt, and iteration count we are currently initialised
    /// with.
    /// </summary>
    function GenerateDerivedMacParameters(AKeySize: Int32)
      : ICipherParameters; override;

  end;

implementation

{ TArgon2ParametersGenerator }

procedure TArgon2ParametersGenerator.Clear();
begin
  TArrayUtilities.Fill<Byte>(FPassword, 0, System.Length(FPassword), Byte(0));

  if FArgon2Parameters <> nil then
  begin
    FArgon2Parameters.Clear();
  end;

  if FPBKDF_Argon2 <> nil then
  begin
    FPBKDF_Argon2.Clear();
  end;
end;

constructor TArgon2ParametersGenerator.Create();
begin
  inherited Create();
end;

destructor TArgon2ParametersGenerator.Destroy();
begin
  Clear();
  inherited Destroy;
end;

function TArgon2ParametersGenerator.GenerateDerivedKey(ADkLen: Int32): TCryptoLibByteArray;
begin
  Result := FPBKDF_Argon2.GetBytes(ADkLen);
end;

function TArgon2ParametersGenerator.GenerateDerivedMacParameters(AKeySize: Int32): ICipherParameters;
var
  LDKey: TCryptoLibByteArray;
  LKeySize: Int32;
begin
  LKeySize := AKeySize div 8;
  LDKey := GenerateDerivedKey(LKeySize);
  Result := TKeyParameter.Create(LDKey, 0, LKeySize);
end;

function TArgon2ParametersGenerator.GenerateDerivedParameters(const AAlgorithm: String;
  AKeySize: Int32): ICipherParameters;
var
  LDKey: TCryptoLibByteArray;
  LKeySize: Int32;
begin
  LKeySize := AKeySize div 8;
  LDKey := GenerateDerivedKey(LKeySize);
  Result := TParameterUtilities.CreateKeyParameter(AAlgorithm, LDKey, 0, LKeySize);
end;

function TArgon2ParametersGenerator.GenerateDerivedParameters(const AAlgorithm: String;
  AKeySize, AIvSize: Int32): ICipherParameters;
var
  LDKey: TCryptoLibByteArray;
  LKey: IKeyParameter;
  LKeySize, LIvSize: Int32;
begin
  LKeySize := AKeySize div 8;
  LIvSize := AIvSize div 8;
  LDKey := GenerateDerivedKey(LKeySize + LIvSize);
  LKey := TParameterUtilities.CreateKeyParameter(AAlgorithm, LDKey, 0, LKeySize);
  Result := TParametersWithIV.Create(LKey, LDKey, LKeySize, LIvSize);
end;

procedure TArgon2ParametersGenerator.Init(AArgon2Type: TCryptoLibArgon2Type;
  AArgon2Version: TCryptoLibArgon2Version; const APassword, ASalt, ASecret,
  AAdditional: TCryptoLibByteArray; AIterations, AMemory, AParallelism: Int32;
  AMemoryCostType: TCryptoLibArgon2MemoryCostType);
var
  LArgon2ParametersBuilder: IArgon2ParametersBuilder;
  LArgon2Version: TArgon2Version;
begin
  FPassword := System.Copy(APassword);

  case AArgon2Type of
    TCryptoLibArgon2Type.Argon2D:
      begin
        LArgon2ParametersBuilder := TArgon2dParametersBuilder.Builder();
      end;

    TCryptoLibArgon2Type.Argon2I:
      begin
        LArgon2ParametersBuilder := TArgon2iParametersBuilder.Builder();
      end;
    TCryptoLibArgon2Type.Argon2ID:
      begin
        LArgon2ParametersBuilder := TArgon2idParametersBuilder.Builder();
      end
  else
    begin
      raise EArgumentCryptoLibException.CreateRes(@SArgon2TypeInvalid);
    end;
  end;

  case AArgon2Version of
    TCryptoLibArgon2Version.Argon2Version10:
      begin
        LArgon2Version := TArgon2Version.a2vARGON2_VERSION_10;
      end;

    TCryptoLibArgon2Version.Argon2Version13:
      begin
        LArgon2Version := TArgon2Version.a2vARGON2_VERSION_13;
      end
  else
    begin
      raise EArgumentCryptoLibException.CreateRes(@SArgon2VersionInvalid);
    end;
  end;

  case AMemoryCostType of
    TCryptoLibArgon2MemoryCostType.MemoryAsKB:
      begin
        LArgon2ParametersBuilder.WithVersion(LArgon2Version).WithSalt(ASalt)
          .WithSecret(ASecret).WithAdditional(AAdditional)
          .WithIterations(AIterations).WithMemoryAsKB(AMemory)
          .WithParallelism(AParallelism);
      end;

    TCryptoLibArgon2MemoryCostType.MemoryPowOfTwo:
      begin
        LArgon2ParametersBuilder.WithVersion(LArgon2Version).WithSalt(ASalt)
          .WithSecret(ASecret).WithAdditional(AAdditional)
          .WithIterations(AIterations).WithMemoryPowOfTwo(AMemory)
          .WithParallelism(AParallelism);
      end
  else
    begin
      raise EArgumentCryptoLibException.CreateRes
        (@SArgon2MemoryCostTypeInvalid);
    end;
  end;

  FArgon2Parameters := LArgon2ParametersBuilder.Build();
  LArgon2ParametersBuilder.Clear();
  FPBKDF_Argon2 := TKDF.TPBKDF_Argon2.CreatePBKDF_Argon2(FPassword,
    FArgon2Parameters);
end;

end.
