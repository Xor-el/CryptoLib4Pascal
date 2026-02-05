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

unit ClpPkcs5S2ParametersGenerator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses

  HlpIHashInfo,
  HlpHashFactory,
  ClpIDigest,
  ClpICipherParameters,
  ClpIPkcs5S2ParametersGenerator,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpParameterUtilities,
  ClpPbeParametersGenerator,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

type

  /// <summary>
  /// <see href="https://tools.ietf.org/html/rfc2898#section-5.2">
  /// Pkcs5S2 Specification</see>
  /// </summary>
  TPkcs5S2ParametersGenerator = class sealed(TPbeParametersGenerator,
    IPkcs5S2ParametersGenerator)

  strict private
  var
    FPassword, FSalt: TCryptoLibByteArray;
    FDigest: IDigest;
    FPBKDF2_HMAC: HlpIHashInfo.IPBKDF2_HMAC;

    /// <returns>
    /// the underlying digest.
    /// </returns>
    function GetDigest: IDigest; inline;

    function GenerateDerivedKey(ADkLen: Int32): TCryptoLibByteArray; inline;

  public

    procedure Clear(); override;
    /// <summary>
    /// construct a Pkcs5 Scheme 2 Parameters generator.
    /// </summary>
    /// <param name="digest">
    /// digest to use for constructing hmac
    /// </param>
    constructor Create(const ADigest: IDigest);

    destructor Destroy; override;

    procedure Init(const APassword, ASalt: TCryptoLibByteArray;
      AIterationCount: Int32);

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
    /// password, salt, and iteration count we are currently initialised
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

    /// <value>
    /// the underlying digest.
    /// </value>
    property Digest: IDigest read GetDigest;
  end;

implementation

{ TPkcs5S2ParametersGenerator }

procedure TPkcs5S2ParametersGenerator.Clear();
begin
  TArrayUtilities.Fill<Byte>(FPassword, 0, System.Length(FPassword), Byte(0));
  TArrayUtilities.Fill<Byte>(FSalt, 0, System.Length(FSalt), Byte(0));

  if FPBKDF2_HMAC <> nil then
  begin
    FPBKDF2_HMAC.Clear();
  end;
end;

constructor TPkcs5S2ParametersGenerator.Create(const ADigest: IDigest);
begin
  inherited Create();
  FDigest := ADigest;
end;

destructor TPkcs5S2ParametersGenerator.Destroy;
begin
  Clear();
  inherited Destroy;
end;

function TPkcs5S2ParametersGenerator.GenerateDerivedKey(ADkLen: Int32): TCryptoLibByteArray;
begin
  Result := FPBKDF2_HMAC.GetBytes(ADkLen);
end;

function TPkcs5S2ParametersGenerator.GenerateDerivedMacParameters(AKeySize: Int32): ICipherParameters;
var
  LDKey: TCryptoLibByteArray;
  LKeySize: Int32;
begin
  LKeySize := AKeySize div 8;
  LDKey := GenerateDerivedKey(LKeySize);
  Result := TKeyParameter.Create(LDKey, 0, LKeySize);
end;

function TPkcs5S2ParametersGenerator.GenerateDerivedParameters(const AAlgorithm: String;
  AKeySize: Int32): ICipherParameters;
var
  LDKey: TCryptoLibByteArray;
  LKeySize: Int32;
begin
  LKeySize := AKeySize div 8;
  LDKey := GenerateDerivedKey(LKeySize);
  Result := TParameterUtilities.CreateKeyParameter(AAlgorithm, LDKey, 0, LKeySize);
end;

function TPkcs5S2ParametersGenerator.GenerateDerivedParameters(const AAlgorithm: String;
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

function TPkcs5S2ParametersGenerator.GetDigest: IDigest;
begin
  Result := FDigest;
end;

procedure TPkcs5S2ParametersGenerator.Init(const APassword, ASalt: TCryptoLibByteArray;
  AIterationCount: Int32);
begin
  FPassword := System.Copy(APassword);
  FSalt := System.Copy(ASalt);
  FPBKDF2_HMAC := TKDF.TPBKDF2_HMAC.CreatePBKDF2_HMAC(
    FDigest.GetUnderlyingIHash, FPassword, FSalt, AIterationCount);
end;

end.
