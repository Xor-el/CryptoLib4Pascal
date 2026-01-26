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

unit ClpSchnorrDigestSigner;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Classes,
  ClpISchnorr,
  ClpISchnorrExt,
  ClpISignersEncodings,
  ClpISchnorrDigestSigner,
  ClpIDigest,
  ClpBigInteger,
  ClpBigIntegers,
  ClpCryptoLibTypes,
  ClpIAsymmetricKeyParameter,
  ClpICipherParameters,
  ClpISigner,
  ClpParameterUtilities;

resourcestring
  SPrivateKey = 'Signing Requires Private Key.';
  SPublicKey = 'Verification Requires Public Key.';
  SSchnorrDigestSignerNotInitializedForSignatureGeneration =
    'SchnorrDigestSigner not Initialized for Signature Generation.';
  SSchnorrDigestSignerNotInitializedForVerification =
    'SchnorrDigestSigner not Initialized for Verification';
  SEncodingError = 'Unable to Encode Signature';

type
  TSchnorrDigestSigner = class(TInterfacedObject, ISigner, ISchnorrDigestSigner)

  strict private
  var
    FDigest: IDigest;
    FSchnorr: ISchnorr;
    FForSigning: Boolean;
    FEncoding: ISchnorrEncoding;
    FBuffer: TMemoryStream;

    function Aggregate: TCryptoLibByteArray; inline;

  strict protected

    function GetOrder(): TBigInteger; virtual;

  public
    // constructor Create(const Schnorr: ISchnorr; const digest: IDigest);
    // overload;
    constructor Create(const ASchnorr: ISchnorrExt; const ADigest: IDigest;
      const AEncoding: ISchnorrEncoding);
    destructor Destroy(); override;

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

{ TSchnorrDigestSigner }

function TSchnorrDigestSigner.Aggregate: TCryptoLibByteArray;
begin
  Result := nil;
  if FBuffer.Size > 0 then
  begin
    FBuffer.Position := 0;
    System.SetLength(Result, FBuffer.Size);
    FBuffer.Read(Result[0], FBuffer.Size);
  end;
end;

procedure TSchnorrDigestSigner.BlockUpdate(const AInput: TCryptoLibByteArray;
  AInOff, ALength: Int32);
begin
  if AInput <> nil then
  begin
    FBuffer.Write(AInput[AInOff], ALength);
  end;
end;

// constructor TSchnorrDigestSigner.Create(const Schnorr: ISchnorr;
// const digest: IDigest);
// begin
// Inherited Create();
// FSchnorr := Schnorr;
// FDigest := digest;
// FBuffer := TMemoryStream.Create();
// end;

constructor TSchnorrDigestSigner.Create(const ASchnorr: ISchnorrExt;
  const ADigest: IDigest; const AEncoding: ISchnorrEncoding);
begin
  Inherited Create();
  FSchnorr := ASchnorr;
  FDigest := ADigest;
  FEncoding := AEncoding;
  FBuffer := TMemoryStream.Create();
end;

destructor TSchnorrDigestSigner.Destroy;
begin
  FBuffer.Free;
  inherited Destroy;
end;

function TSchnorrDigestSigner.GenerateSignature: TCryptoLibByteArray;
var
  LSig: TCryptoLibGenericArray<TBigInteger>;
begin
  if ((not FForSigning)) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SSchnorrDigestSignerNotInitializedForSignatureGeneration);
  end;

  LSig := FSchnorr.GenerateSignature(Aggregate());

  try
    Result := FEncoding.Encode(GetOrder(), LSig[0], LSig[1]);
  except
    raise EInvalidOperationCryptoLibException.CreateRes(@SEncodingError);
  end;
end;

function TSchnorrDigestSigner.GetAlgorithmName: String;
begin
  Result := FDigest.AlgorithmName + 'with' + FSchnorr.AlgorithmName;
end;

function TSchnorrDigestSigner.GetMaxSignatureSize: Int32;
var
  LOrder: TBigInteger;
begin
  LOrder := GetOrder();
  if LOrder.IsInitialized then
  begin
    // Schnorr signature is two big integers (r, s), each the size of the order
    // For standard encoding, add some overhead for ASN.1 structure
    Result := (TBigIntegers.GetByteLength(LOrder) * 2) + 20; // 20 bytes overhead for ASN.1
  end
  else
  begin
    // Fallback: assume 256-bit order (32 bytes per component)
    Result := 84; // 2 * 32 + 20 overhead
  end;
end;

function TSchnorrDigestSigner.GetOrder: TBigInteger;
begin
  if Supports(FSchnorr, ISchnorrExt) then
  begin
    Result := (FSchnorr as ISchnorrExt).Order;
  end
  else
  begin
    Result := Default(TBigInteger);
  end;
end;

procedure TSchnorrDigestSigner.Init(AForSigning: Boolean;
  const AParameters: ICipherParameters);
var
  LKey: IAsymmetricKeyParameter;
begin
  FForSigning := AForSigning;

  LKey := TParameterUtilities.IgnoreRandom(AParameters) as IAsymmetricKeyParameter;

  if (AForSigning and (not LKey.IsPrivate)) then
  begin
    raise EInvalidKeyCryptoLibException.CreateRes(@SPrivateKey);
  end;

  if ((not AForSigning) and LKey.IsPrivate) then
  begin
    raise EInvalidKeyCryptoLibException.CreateRes(@SPublicKey);
  end;

  Reset();

  FSchnorr.Init(AForSigning, AParameters, FDigest);
end;

procedure TSchnorrDigestSigner.Reset;
begin
  FDigest.Reset;
  FBuffer.Clear;
  FBuffer.SetSize(Int64(0));
end;

procedure TSchnorrDigestSigner.Update(AInput: Byte);
begin
  FBuffer.Write(TCryptoLibByteArray.Create(AInput)[0], 1);
end;

function TSchnorrDigestSigner.VerifySignature(const ASignature
  : TCryptoLibByteArray): Boolean;
var
  LSig: TCryptoLibGenericArray<TBigInteger>;
begin
  if (FForSigning) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SSchnorrDigestSignerNotInitializedForVerification);
  end;

  try
    LSig := FEncoding.Decode(GetOrder(), ASignature);
    Result := FSchnorr.VerifySignature(Aggregate(), LSig[0], LSig[1]);
  except
    Result := false;
  end;

end;

end.
