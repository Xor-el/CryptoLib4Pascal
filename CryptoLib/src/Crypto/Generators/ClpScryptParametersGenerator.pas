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

unit ClpScryptParametersGenerator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses

  HlpIHashInfo,
  HlpHashFactory,
  ClpICipherParameters,
  ClpPbeParametersGenerator,
  ClpIScryptParametersGenerator,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpParameterUtilities,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

type

  /// <summary>
  /// <a href="http://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01">draft-josefsson-scrypt-kd</a>
  /// Scrypt Specification</see>
  /// </summary>
  TScryptParametersGenerator = class sealed(TPbeParametersGenerator,
    IScryptParametersGenerator)

  strict private
  var
    FPassword, FSalt: TCryptoLibByteArray;
    FPBKDF_Scrypt: HlpIHashInfo.IPBKDF_Scrypt;

    function GenerateDerivedKey(ADkLen: Int32): TCryptoLibByteArray; inline;

  public

    procedure Clear(); override;
    /// <summary>
    /// construct an Scrypt Parameters generator.
    /// </summary>
    constructor Create();

    destructor Destroy; override;

    procedure Init(const APassword, ASalt: TCryptoLibByteArray;
      ACost, ABlockSize, AParallelism: Int32);

    /// <summary>
    /// Generate a key parameter derived from the password, salt,
    /// cost, blockSize, parallelism we are currently initialised with.
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
    /// the password, salt, cost, blockSize, parallelism we are currently initialised with.
    /// </summary>
    /// </summary>
    /// <param name="algorithm">
    /// a parameters object representing a key.
    /// </param>
    /// <param name="keySize">
    /// the length, in bits, of the key required.
    /// </param>
    /// <param name="ivSize">
    /// the length, in bits, of the iv required.
    /// </param>
    /// <returns>
    /// a parameters object representing a key and an iv.
    /// </returns>
    function GenerateDerivedParameters(const AAlgorithm: String;
      AKeySize, AIvSize: Int32): ICipherParameters; overload; override;

    /// <summary>
    /// Generate a key parameter for use with a MAC derived from the
    /// the password, salt, cost, blockSize, parallelism we are currently initialised with.
    /// with.
    /// </summary>
    /// <param name="keySize">
    /// the length, in bits, of the key required.
    /// </param>
    /// <returns>
    /// a parameters object representing a key.
    /// </returns>
    function GenerateDerivedMacParameters(AKeySize: Int32)
      : ICipherParameters; override;

  end;

implementation

{ TScryptParametersGenerator }

procedure TScryptParametersGenerator.Clear();
begin
  TArrayUtilities.Fill<Byte>(FPassword, 0, System.Length(FPassword), Byte(0));
  TArrayUtilities.Fill<Byte>(FSalt, 0, System.Length(FSalt), Byte(0));

  if FPBKDF_Scrypt <> nil then
  begin
    FPBKDF_Scrypt.Clear();
  end;
end;

constructor TScryptParametersGenerator.Create();
begin
  inherited Create();
end;

destructor TScryptParametersGenerator.Destroy;
begin
  Clear();
  inherited Destroy;
end;

function TScryptParametersGenerator.GenerateDerivedKey(ADkLen: Int32): TCryptoLibByteArray;
begin
  Result := FPBKDF_Scrypt.GetBytes(ADkLen);
end;

function TScryptParametersGenerator.GenerateDerivedMacParameters(AKeySize: Int32): ICipherParameters;
var
  LDKey: TCryptoLibByteArray;
  LKeySize: Int32;
begin
  LKeySize := AKeySize div 8;
  LDKey := GenerateDerivedKey(LKeySize);
  Result := TKeyParameter.Create(LDKey, 0, LKeySize);
end;

function TScryptParametersGenerator.GenerateDerivedParameters(const AAlgorithm: String;
  AKeySize: Int32): ICipherParameters;
var
  LDKey: TCryptoLibByteArray;
  LKeySize: Int32;
begin
  LKeySize := AKeySize div 8;
  LDKey := GenerateDerivedKey(LKeySize);
  Result := TParameterUtilities.CreateKeyParameter(AAlgorithm, LDKey, 0, LKeySize);
end;

function TScryptParametersGenerator.GenerateDerivedParameters(const AAlgorithm: String;
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

procedure TScryptParametersGenerator.Init(const APassword, ASalt: TCryptoLibByteArray;
  ACost, ABlockSize, AParallelism: Int32);
begin
  FPassword := System.Copy(APassword);
  FSalt := System.Copy(ASalt);
  FPBKDF_Scrypt := TKDF.TPBKDF_Scrypt.CreatePBKDF_Scrypt(FPassword, FSalt, ACost,
    ABlockSize, AParallelism);
end;

end.
