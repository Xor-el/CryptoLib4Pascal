{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpEd25519PhSigner;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIDigest,
  ClpEd25519,
  ClpICipherParameters,
  ClpISigner,
  ClpIEd25519PhSigner,
  ClpIEd25519Parameters,
  ClpEd25519Parameters,
  ClpCryptoLibTypes;

resourcestring
  SNotInitialized = 'Ed25519PhSigner not initialized for %s';
  SPreHashDigestFailed = 'PreHash digest failed';

type
  /// <summary>
  /// Ed25519ph (RFC 8032 section 5.1) signature primitive: pre-hashes the message with SHA-512 before
  /// running pure Ed25519, parameterised by a fixed context captured at construction.
  /// </summary>
  TEd25519PhSigner = class(TInterfacedObject, ISigner, IEd25519PhSigner)

  strict private
  var
    FPreHash: IDigest;
    FContext: TCryptoLibByteArray;
    FForSigning: Boolean;
    FPrivateKey: IEd25519PrivateKeyParameters;
    FPublicKey: IEd25519PublicKeyParameters;

  strict protected
    function GetAlgorithmName: String; virtual;

  public
    /// <summary>
    /// Construct an Ed25519ph signer bound to the supplied <paramref name="AContext"/>. The context
    /// bytes are cloned so the caller may mutate the array afterwards; nil is treated as empty.
    /// </summary>
    constructor Create(const AContext: TCryptoLibByteArray);
    destructor Destroy(); override;

    /// <summary>Initialise for signing (private key) or verification (public key).</summary>
    /// <exception cref="EInvalidCastCryptoLibException">
    /// If <paramref name="AParameters"/> is not an
    /// <see cref="IEd25519PrivateKeyParameters"/> (signing) or
    /// <see cref="IEd25519PublicKeyParameters"/> (verification).
    /// </exception>
    procedure Init(AForSigning: Boolean;
      const AParameters: ICipherParameters); virtual;
    procedure Update(AInput: Byte); virtual;
    procedure BlockUpdate(const ABuf: TCryptoLibByteArray;
      AOff, ALength: Int32); virtual;
    /// <summary>Length in bytes of an Ed25519ph signature (64).</summary>
    function GetMaxSignatureSize: Int32; virtual;
    /// <summary>Finalise the pre-hash and produce the signature.</summary>
    /// <exception cref="EInvalidOperationCryptoLibException">
    /// If the signer was initialised for verification, not signing, or the pre-hash finalisation
    /// produces an unexpected length.
    /// </exception>
    function GenerateSignature(): TCryptoLibByteArray; virtual;
    /// <summary>Finalise the pre-hash and verify <paramref name="ASignature"/>.</summary>
    /// <returns>true if the signature is valid for the accumulated message, bound public key and
    /// captured context; otherwise false.</returns>
    /// <exception cref="EInvalidOperationCryptoLibException">
    /// If the signer was initialised for signing, not verification, or the pre-hash finalisation
    /// produces an unexpected length.
    /// </exception>
    function VerifySignature(const ASignature: TCryptoLibByteArray)
      : Boolean; virtual;
    /// <summary>Reset the pre-hash digest; the captured context survives.</summary>
    procedure Reset(); virtual;

    property AlgorithmName: String read GetAlgorithmName;

  end;

implementation

{ TEd25519PhSigner }

procedure TEd25519PhSigner.BlockUpdate(const ABuf: TCryptoLibByteArray;
  AOff, ALength: Int32);
begin
  FPreHash.BlockUpdate(ABuf, AOff, ALength);
end;

constructor TEd25519PhSigner.Create(const AContext: TCryptoLibByteArray);
var
  LEd25519: TEd25519;
begin
  Inherited Create();
  FContext := System.Copy(AContext);
  LEd25519 := TEd25519.Create();
  try
    FPreHash := LEd25519.CreatePreHash();
  finally
    LEd25519.Free;
  end;
end;

destructor TEd25519PhSigner.Destroy;
begin
  inherited Destroy;
end;

function TEd25519PhSigner.GetAlgorithmName: String;
begin
  Result := 'Ed25519ph';
end;

procedure TEd25519PhSigner.Init(AForSigning: Boolean;
  const AParameters: ICipherParameters);
begin
  FForSigning := AForSigning;

  if (AForSigning) then
  begin
    FPrivateKey := AParameters as IEd25519PrivateKeyParameters;
    FPublicKey := nil;
  end
  else
  begin
    FPrivateKey := nil;
    FPublicKey := AParameters as IEd25519PublicKeyParameters;
  end;

  Reset();
end;

procedure TEd25519PhSigner.Reset;
begin
  FPreHash.Reset();
end;

procedure TEd25519PhSigner.Update(AInput: Byte);
begin
  FPreHash.Update(AInput);
end;

function TEd25519PhSigner.GetMaxSignatureSize: Int32;
begin
  Result := TEd25519.SignatureSize;
end;

function TEd25519PhSigner.GenerateSignature: TCryptoLibByteArray;
var
  LSignature, LMsg: TCryptoLibByteArray;
begin
  if ((not FForSigning) or (FPrivateKey = nil)) then
  begin
    raise EInvalidOperationCryptoLibException.CreateResFmt
      (@SNotInitialized, ['signature generation']);
  end;
  System.SetLength(LMsg, TEd25519.PreHashSize);

  if ((TEd25519.PreHashSize) <> (FPreHash.DoFinal(LMsg, 0))) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes(@SPreHashDigestFailed);
  end;

  System.SetLength(LSignature, TEd25519PrivateKeyParameters.SignatureSize);

  FPrivateKey.Sign(TEd25519.TAlgorithm.Ed25519ph, FContext, LMsg, 0,
    TEd25519.PreHashSize, LSignature, 0);
  Result := LSignature;
end;

function TEd25519PhSigner.VerifySignature(const ASignature
  : TCryptoLibByteArray): Boolean;
var
  LMsg: TCryptoLibByteArray;
begin
  if ((FForSigning) or (FPublicKey = nil)) then
  begin
    raise EInvalidOperationCryptoLibException.CreateResFmt
      (@SNotInitialized, ['verification']);
  end;
  if (TEd25519.SignatureSize <> System.Length(ASignature)) then
  begin
    FPreHash.Reset();
    Result := False;
    Exit;
  end;
  System.SetLength(LMsg, TEd25519.PreHashSize);
  if (TEd25519.PreHashSize <> FPreHash.DoFinal(LMsg, 0)) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes(@SPreHashDigestFailed);
  end;
  Result := FPublicKey.Verify(TEd25519.TAlgorithm.Ed25519ph, FContext, LMsg, 0,
    TEd25519.PreHashSize, ASignature, 0);
end;

end.
