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
  ClpDigestUtilities,
  ClpCryptoLibTypes;

type

  /// <summary>
  /// Generator for PBE derived keys and IVs as defined by PKCS #5 v2.0 Scheme 2.
  /// This generator uses a SHA-1 HMAC as the calculation function.
  /// </summary>
  /// <remarks>
  /// The document this implementation is based on can be found at
  /// <see href="http://www.rsasecurity.com/rsalabs/pkcs/pkcs-5/index.html">
  /// RSA's PKCS #5 Page
  /// </see>.
  /// </remarks>
  TPkcs5S2ParametersGenerator = class sealed(TPbeParametersGenerator,
    IPkcs5S2ParametersGenerator)

  strict private
  var
    FDigest: IDigest;
    FPBKDF2_HMAC: IPBKDF2_HMAC;

    function GenerateDerivedKey(ADkLen: Int32): TCryptoLibByteArray; inline;

  public

    procedure Clear(); override;
    /// <summary>
    /// construct a Pkcs5 Scheme 2 Parameters generator.
    /// </summary>
    /// <param name="ADigest">
    /// digest to use for constructing hmac
    /// </param>
    constructor Create(); overload;
    /// <summary>
    /// construct a Pkcs5 Scheme 2 Parameters generator.
    /// </summary>
    /// <param name="ADigest">
    /// digest to use for constructing hmac
    /// </param>
    constructor Create(const ADigest: IDigest); overload;

    procedure Init(const APassword, ASalt: TCryptoLibByteArray;
      AIterationCount: Int32); override;

    /// <summary>
    /// Generate a key parameter derived from the password, salt, and
    /// iteration count we are currently initialised with.
    /// </summary>
    /// <param name="AAlgorithm">
    /// a parameters object representing a key.
    /// </param>
    /// <param name="AKeySize">
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
    /// <param name="AAlgorithm">
    /// a parameters object representing a key.
    /// </param>
    /// <param name="AKeySize">
    /// the length, in bits, of the key required.
    /// </param>
    /// <param name="AIvSize">
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
    /// <param name="AKeySize">
    /// the length, in bits, of the key required.
    /// </param>
    /// <returns>
    /// a parameters object representing a key.
    /// </returns>
    function GenerateDerivedMacParameters(AKeySize: Int32)
      : ICipherParameters; override;
  end;

implementation

{ TPkcs5S2ParametersGenerator }

procedure TPkcs5S2ParametersGenerator.Clear();
begin
  inherited Clear();

  if FPBKDF2_HMAC <> nil then
  begin
    FPBKDF2_HMAC.Clear();
  end;
end;

constructor TPkcs5S2ParametersGenerator.Create;
begin
  Create(TDigestUtilities.GetDigest('SHA1'));
end;

constructor TPkcs5S2ParametersGenerator.Create(const ADigest: IDigest);
begin
  inherited Create();
  FDigest := ADigest;
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

procedure TPkcs5S2ParametersGenerator.Init(const APassword, ASalt: TCryptoLibByteArray;
  AIterationCount: Int32);
begin
  inherited Init(APassword, ASalt, AIterationCount);
  FPBKDF2_HMAC := TKDF.TPBKDF2_HMAC.CreatePBKDF2_HMAC(FDigest.UnderlyingHasher, FPassword, FSalt, AIterationCount);
end;

end.
