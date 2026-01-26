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

unit ClpDsaDigestSigner;

{$I ..\..\Include\CryptoLib.inc}

interface

uses

  SysUtils,
  ClpIDsa,
  ClpIDigest,
  ClpBigInteger,
  ClpBigIntegers,
  ClpCryptoLibTypes,
  ClpParameterUtilities,
  ClpSignersEncodings,
  ClpIAsymmetricKeyParameter,
  ClpICipherParameters,
  ClpISigner,
  ClpISignersEncodings,
  ClpIDsaDigestSigner;

resourcestring
  SPrivateKey = 'Signing Requires Private Key.';
  SPublicKey = 'Verification Requires Public Key.';
  SDsaDigestSignerNotInitializedForSignatureGeneration =
    'DSADigestSigner not Initialized for Signature Generation.';
  SDsaDigestSignerNotInitializedForVerification =
    'DSADigestSigner not Initialized for Verification';
  SEncodingError = 'Unable to Encode Signature';

type
  TDsaDigestSigner = class(TInterfacedObject, ISigner, IDsaDigestSigner)

  strict private
  var
    FDigest: IDigest;
    FDsa: IDsa;
    FEncoding: IDsaEncoding;
    FForSigning: Boolean;

  strict protected

    function GetOrder(): TBigInteger; virtual;

  public
    constructor Create(const ADsa: IDsa; const ADigest: IDigest); overload;
    constructor Create(const ADsa: IDsa; const ADigest: IDigest;
      const AEncoding: IDsaEncoding); overload;

    function GetAlgorithmName: String; virtual;
    property AlgorithmName: String read GetAlgorithmName;

    procedure Init(AForSigning: Boolean;
      const AParameters: ICipherParameters); virtual;

    /// <summary>
    /// update the internal digest with the byte b
    /// </summary>
    procedure Update(AInput: Byte); virtual;

    /// <summary>
    /// update the internal digest with the byte array in
    /// </summary>
    procedure BlockUpdate(const AInput: TCryptoLibByteArray;
      AInOff, ALength: Int32); virtual;

    /// <summary>
    /// Return the maximum size for a signature produced by this signer.
    /// </summary>
    function GetMaxSignatureSize: Int32; virtual;

    /// <summary>
    /// Generate a signature for the message we've been loaded with using the
    /// key we were initialised with.
    /// </summary>
    function GenerateSignature(): TCryptoLibByteArray; virtual;

    /// <returns>
    /// true if the internal state represents the signature described in the
    /// passed in array.
    /// </returns>
    function VerifySignature(const ASignature: TCryptoLibByteArray)
      : Boolean; virtual;

    /// <summary>
    /// Reset the internal state
    /// </summary>
    procedure Reset(); virtual;

  end;

implementation

{ TDsaDigestSigner }

procedure TDsaDigestSigner.BlockUpdate(const AInput: TCryptoLibByteArray;
  AInOff, ALength: Int32);
begin
  FDigest.BlockUpdate(AInput, AInOff, ALength);
end;

constructor TDsaDigestSigner.Create(const ADsa: IDsa; const ADigest: IDigest);
begin
  Inherited Create();
  FDsa := ADsa;
  FDigest := ADigest;
  FEncoding := TStandardDsaEncoding.Instance;
end;

constructor TDsaDigestSigner.Create(const ADsa: IDsa; const ADigest: IDigest;
  const AEncoding: IDsaEncoding);
begin
  Inherited Create();
  FDsa := ADsa;
  FDigest := ADigest;
  FEncoding := AEncoding;
end;

function TDsaDigestSigner.GenerateSignature: TCryptoLibByteArray;
var
  LHash: TCryptoLibByteArray;
  LSig: TCryptoLibGenericArray<TBigInteger>;
begin
  if ((not FForSigning)) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SDsaDigestSignerNotInitializedForSignatureGeneration);
  end;

  SetLength(LHash, FDigest.GetDigestSize());
  FDigest.DoFinal(LHash, 0);

  LSig := FDsa.GenerateSignature(LHash);

  try
    Result := FEncoding.Encode(GetOrder(), LSig[0], LSig[1]);
  except
    raise EInvalidOperationCryptoLibException.CreateRes(@SEncodingError);
  end;
end;

function TDsaDigestSigner.GetAlgorithmName: String;
begin
  Result := FDigest.AlgorithmName + 'with' + FDsa.AlgorithmName;
end;

function TDsaDigestSigner.GetOrder: TBigInteger;
begin
  Result := FDsa.Order;
end;

function TDsaDigestSigner.GetMaxSignatureSize: Int32;
begin
  Result := FEncoding.GetMaxEncodingSize(GetOrder());
end;

procedure TDsaDigestSigner.Init(AForSigning: Boolean;
  const AParameters: ICipherParameters);
var
  LK: IAsymmetricKeyParameter;
begin
  FForSigning := AForSigning;

  LK := TParameterUtilities.IgnoreRandom(AParameters) as IAsymmetricKeyParameter;

  if ((AForSigning) and (not LK.IsPrivate)) then
  begin
    raise EInvalidKeyCryptoLibException.CreateRes(@SPrivateKey);
  end;

  if ((not AForSigning) and (LK.IsPrivate)) then
  begin
    raise EInvalidKeyCryptoLibException.CreateRes(@SPublicKey);
  end;

  Reset();

  FDsa.Init(AForSigning, AParameters);
end;

procedure TDsaDigestSigner.Reset;
begin
  FDigest.Reset;
end;

procedure TDsaDigestSigner.Update(AInput: Byte);
begin
  FDigest.Update(AInput);
end;

function TDsaDigestSigner.VerifySignature(const ASignature
  : TCryptoLibByteArray): Boolean;
var
  LHash: TCryptoLibByteArray;
  LSig: TCryptoLibGenericArray<TBigInteger>;
begin
  if (FForSigning) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SDsaDigestSignerNotInitializedForVerification);
  end;

  SetLength(LHash, FDigest.GetDigestSize());
  FDigest.DoFinal(LHash, 0);

  try
    LSig := FEncoding.Decode(GetOrder(), ASignature);
    Result := FDsa.VerifySignature(LHash, LSig[0], LSig[1]);
  except
    Result := false;
  end;

end;

end.
