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

unit ClpOpenSslPbeParametersGenerator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIDigest,
  ClpICipherParameters,
  ClpIPbeParametersGenerator,
  ClpIOpenSslPbeParametersGenerator,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpParameterUtilities,
  ClpPbeParametersGenerator,
  ClpDigestUtilities,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

type
	/// <description>
	/// Generator for PBE derived keys and IVs as usd by OpenSSL. Originally this scheme was a simple extension of
	/// PKCS 5 V2.0 Scheme 1 using MD5 with an iteration count of 1. The default digest was changed to SHA-256 with
	/// OpenSSL 1.1.0. This implementation still defaults to MD5, but the digest can now be set.
	/// </description>
  TOpenSslPbeParametersGenerator = class sealed(TPbeParametersGenerator,
    IPbeParametersGenerator, IOpenSslPbeParametersGenerator)
  strict private
  var
    FDigest: IDigest;

    function GenerateDerivedKey(ABytesNeeded: Int32): TCryptoLibByteArray;
  public
    constructor Create(); overload;
		/// <description>
		/// Construct a OpenSSL Parameters generator - digest as specified.
		/// </description>
		/// <param name="ADigest">the digest to use as the PRF.</param>
    constructor Create(const ADigest: IDigest); overload;

    /// <summary>
    /// Initialise - iteration count is fixed at 1 for this algorithm.
    /// </summary>
    procedure Init(const APassword, ASalt: TCryptoLibByteArray); overload; virtual;
    procedure Init(const APassword, ASalt: TCryptoLibByteArray;
      AIterationCount: Int32); overload; override;

    function GenerateDerivedParameters(const AAlgorithm: String; AKeySize: Int32)
      : ICipherParameters; overload; override;
    function GenerateDerivedParameters(const AAlgorithm: String;
      AKeySize, AIvSize: Int32): ICipherParameters; overload; override;
    function GenerateDerivedMacParameters(AKeySize: Int32): ICipherParameters;
      override;
  end;

implementation

{ TOpenSslPbeParametersGenerator }

constructor TOpenSslPbeParametersGenerator.Create;
begin
  Create(TDigestUtilities.GetDigest('MD5'));
end;

constructor TOpenSslPbeParametersGenerator.Create(const ADigest: IDigest);
begin
  inherited Create();
  FDigest := ADigest;
end;

function TOpenSslPbeParametersGenerator.GenerateDerivedKey(ABytesNeeded: Int32)
  : TCryptoLibByteArray;
var
  LBuf: TCryptoLibByteArray;
  LKey: TCryptoLibByteArray;
  LOffset, LLen: Int32;
begin
  System.SetLength(LBuf, FDigest.GetDigestSize());
  System.SetLength(LKey, ABytesNeeded);
  LOffset := 0;

  while True do
  begin
    FDigest.BlockUpdate(FPassword, 0, System.Length(FPassword));
    FDigest.BlockUpdate(FSalt, 0, System.Length(FSalt));
    FDigest.DoFinal(LBuf, 0);

    if ABytesNeeded > System.Length(LBuf) then
      LLen := System.Length(LBuf)
    else
      LLen := ABytesNeeded;

    System.Move(LBuf[0], LKey[LOffset], LLen * System.SizeOf(Byte));
    LOffset := LOffset + LLen;
    ABytesNeeded := ABytesNeeded - LLen;

    if ABytesNeeded = 0 then
      Break;

    FDigest.Reset();
    FDigest.BlockUpdate(LBuf, 0, System.Length(LBuf));
  end;

  Result := LKey;
end;

function TOpenSslPbeParametersGenerator.GenerateDerivedParameters(
  const AAlgorithm: String; AKeySize: Int32): ICipherParameters;
var
  LDKey: TCryptoLibByteArray;
  LKeySize: Int32;
begin
  LKeySize := AKeySize div 8;
  LDKey := GenerateDerivedKey(LKeySize);
  Result := TParameterUtilities.CreateKeyParameter(AAlgorithm, LDKey, 0, LKeySize);
end;

function TOpenSslPbeParametersGenerator.GenerateDerivedParameters(
  const AAlgorithm: String; AKeySize, AIvSize: Int32): ICipherParameters;
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

function TOpenSslPbeParametersGenerator.GenerateDerivedMacParameters(
  AKeySize: Int32): ICipherParameters;
var
  LDKey: TCryptoLibByteArray;
  LKeySize: Int32;
begin
  LKeySize := AKeySize div 8;
  LDKey := GenerateDerivedKey(LKeySize);
  Result := TKeyParameter.Create(LDKey, 0, LKeySize);
end;

procedure TOpenSslPbeParametersGenerator.Init(const APassword,
  ASalt: TCryptoLibByteArray);
begin
  inherited Init(APassword, ASalt, 1);
end;

procedure TOpenSslPbeParametersGenerator.Init(const APassword,
  ASalt: TCryptoLibByteArray; AIterationCount: Int32);
begin
  // Ignore AIterationCount - fixed at 1 for OpenSSL PEM
  inherited Init(APassword, ASalt, 1);
end;

end.
