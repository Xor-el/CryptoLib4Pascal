{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpPkcs5S1ParametersGenerator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIDigest,
  ClpICipherParameters,
  ClpIPkcs5S1ParametersGenerator,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpParameterUtilities,
  ClpPbeParametersGenerator,
  ClpCryptoLibTypes;

type

  /// <summary>
  /// Generator for PBE derived keys and IVs as defined by Pkcs 5 V2.0 Scheme 1.
  /// Note this generator is limited to the size of the hash produced by the
  /// digest used to drive it.
  /// </summary>
  TPkcs5S1ParametersGenerator = class sealed(TPbeParametersGenerator,
    IPkcs5S1ParametersGenerator)

  strict private
  var
    FDigest: IDigest;

    function GenerateDerivedKey(): TCryptoLibByteArray;

  public

    /// <summary>
    /// Construct a Pkcs 5 Scheme 1 Parameters generator.
    /// </summary>
    /// <param name="ADigest">the digest to be used as the source of derived keys.</param>
    constructor Create(const ADigest: IDigest);

    /// <summary>
    /// Generate derived parameters for a key of length keySize.
    /// </summary>
    function GenerateDerivedParameters(const AAlgorithm: String; AKeySize: Int32)
      : ICipherParameters; overload; override;

    /// <summary>
    /// Generate derived parameters for a key and IV.
    /// </summary>
    function GenerateDerivedParameters(const AAlgorithm: String;
      AKeySize, AIvSize: Int32): ICipherParameters; overload; override;

    /// <summary>
    /// Generate a key parameter for use with a MAC.
    /// </summary>
    function GenerateDerivedMacParameters(AKeySize: Int32)
      : ICipherParameters; override;

  end;

implementation

{ TPkcs5S1ParametersGenerator }

constructor TPkcs5S1ParametersGenerator.Create(const ADigest: IDigest);
begin
  inherited Create();
  FDigest := ADigest;
end;

function TPkcs5S1ParametersGenerator.GenerateDerivedKey: TCryptoLibByteArray;
var
  LDigestSize, LI: Int32;
begin
  LDigestSize := FDigest.GetDigestSize();
  System.SetLength(Result, LDigestSize);

  FDigest.BlockUpdate(FPassword, 0, System.Length(FPassword));
  FDigest.BlockUpdate(FSalt, 0, System.Length(FSalt));
  FDigest.DoFinal(Result, 0);

  for LI := 1 to FIterationCount - 1 do
  begin
    FDigest.BlockUpdate(Result, 0, System.Length(Result));
    FDigest.DoFinal(Result, 0);
  end;
end;

function TPkcs5S1ParametersGenerator.GenerateDerivedParameters(
  const AAlgorithm: String; AKeySize: Int32): ICipherParameters;
var
  LDKey: TCryptoLibByteArray;
  LKeySize: Int32;
begin
  LKeySize := AKeySize div 8;

  if (LKeySize > FDigest.GetDigestSize()) then
    raise EArgumentCryptoLibException.Create('Can''t Generate a derived key ' +
      IntToStr(LKeySize) + ' bytes long.');

  LDKey := GenerateDerivedKey();
  Result := TParameterUtilities.CreateKeyParameter(AAlgorithm, LDKey, 0,
    LKeySize);
end;

function TPkcs5S1ParametersGenerator.GenerateDerivedParameters(
  const AAlgorithm: String; AKeySize, AIvSize: Int32): ICipherParameters;
var
  LDKey: TCryptoLibByteArray;
  LKey: IKeyParameter;
  LKeySize, LIvSize: Int32;
begin
  LKeySize := AKeySize div 8;
  LIvSize := AIvSize div 8;

  if ((LKeySize + LIvSize) > FDigest.GetDigestSize()) then
    raise EArgumentCryptoLibException.Create('Can''t Generate a derived key ' +
      IntToStr(LKeySize + LIvSize) + ' bytes long.');

  LDKey := GenerateDerivedKey();
  LKey := TParameterUtilities.CreateKeyParameter(AAlgorithm, LDKey, 0,
    LKeySize);
  Result := TParametersWithIV.Create(LKey, LDKey, LKeySize, LIvSize);
end;

function TPkcs5S1ParametersGenerator.GenerateDerivedMacParameters(AKeySize: Int32)
  : ICipherParameters;
var
  LDKey: TCryptoLibByteArray;
  LKeySize: Int32;
begin
  LKeySize := AKeySize div 8;

  if (LKeySize > FDigest.GetDigestSize()) then
    raise EArgumentCryptoLibException.Create('Can''t Generate a derived key ' +
      IntToStr(LKeySize) + ' bytes long.');

  LDKey := GenerateDerivedKey();
  Result := TKeyParameter.Create(LDKey, 0, LKeySize);
end;

end.
