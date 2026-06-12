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

unit ClpEd448PhSigner;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIXof,
  ClpEd448,
  ClpICipherParameters,
  ClpISigner,
  ClpIEd448PhSigner,
  ClpIEd448Parameters,
  ClpEd448Parameters,
  ClpCryptoLibTypes;

resourcestring
  SNotInitializedForSigning =
    'Ed448PhSigner not Initialised for Signature Generation.';
  SNotInitializedForVerifying =
    'Ed448PhSigner not Initialised for Verification';
  SPreHashDigestFailed = 'PreHash Digest Failed';

type
  /// <summary>
  /// Ed448ph (RFC 8032) signature primitive: pre-hashes the message with SHAKE256 before running
  /// pure Ed448, parameterised by a fixed context captured at construction.
  /// </summary>
  TEd448PhSigner = class(TInterfacedObject, ISigner, IEd448PhSigner)

  strict private
  var
    FPreHash: IXof;
    FContext: TCryptoLibByteArray;
    FForSigning: Boolean;
    FPrivateKey: IEd448PrivateKeyParameters;
    FPublicKey: IEd448PublicKeyParameters;

  strict protected
    function GetAlgorithmName: String; virtual;

  public
    /// <summary>
    /// Construct an Ed448ph signer bound to the supplied <paramref name="AContext"/>. The context
    /// bytes are cloned so the caller may mutate the array afterwards; nil is treated as empty.
    /// </summary>
    constructor Create(const AContext: TCryptoLibByteArray);
    destructor Destroy(); override;

    /// <summary>Initialise for signing (private key) or verification (public key).</summary>
    /// <exception cref="EInvalidCastCryptoLibException">
    /// If <paramref name="AParameters"/> is not an
    /// <see cref="IEd448PrivateKeyParameters"/> (signing) or
    /// <see cref="IEd448PublicKeyParameters"/> (verification).
    /// </exception>
    procedure Init(AForSigning: Boolean;
      const AParameters: ICipherParameters); virtual;
    procedure Update(AInput: Byte); virtual;
    procedure BlockUpdate(const ABuf: TCryptoLibByteArray;
      AOff, ALength: Int32); virtual;
    /// <summary>Length in bytes of an Ed448ph signature (114).</summary>
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

{ TEd448PhSigner }

procedure TEd448PhSigner.BlockUpdate(const ABuf: TCryptoLibByteArray;
  AOff, ALength: Int32);
begin
  FPreHash.BlockUpdate(ABuf, AOff, ALength);
end;

constructor TEd448PhSigner.Create(const AContext: TCryptoLibByteArray);
var
  LEd448: TEd448;
begin
  Inherited Create();
  FContext := System.Copy(AContext);
  LEd448 := TEd448.Create();
  try
    FPreHash := LEd448.CreatePrehash();
  finally
    LEd448.Free;
  end;
end;

destructor TEd448PhSigner.Destroy;
begin
  inherited Destroy;
end;

function TEd448PhSigner.GetAlgorithmName: String;
begin
  Result := 'Ed448ph';
end;

procedure TEd448PhSigner.Init(AForSigning: Boolean;
  const AParameters: ICipherParameters);
begin
  FForSigning := AForSigning;

  if (AForSigning) then
  begin
    FPrivateKey := AParameters as IEd448PrivateKeyParameters;
    FPublicKey := nil;
  end
  else
  begin
    FPrivateKey := nil;
    FPublicKey := AParameters as IEd448PublicKeyParameters;
  end;

  Reset();
end;

procedure TEd448PhSigner.Reset;
begin
  FPreHash.Reset();
end;

procedure TEd448PhSigner.Update(AInput: Byte);
begin
  FPreHash.Update(AInput);
end;

function TEd448PhSigner.GetMaxSignatureSize: Int32;
begin
  Result := TEd448.SignatureSize;
end;

function TEd448PhSigner.GenerateSignature: TCryptoLibByteArray;
var
  LSignature, LMsg: TCryptoLibByteArray;
begin
  if ((not FForSigning) or (FPrivateKey = nil)) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SNotInitializedForSigning);
  end;
  System.SetLength(LMsg, TEd448.PrehashSize);

  if ((TEd448.PrehashSize) <> (FPreHash.OutputFinal(LMsg, 0, TEd448.PrehashSize))) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes(@SPreHashDigestFailed);
  end;

  System.SetLength(LSignature, TEd448PrivateKeyParameters.SignatureSize);

  FPrivateKey.Sign(TEd448.TAlgorithm.Ed448ph, FContext, LMsg, 0,
    TEd448.PrehashSize, LSignature, 0);
  Result := LSignature;
end;

function TEd448PhSigner.VerifySignature(const ASignature
  : TCryptoLibByteArray): Boolean;
var
  LMsg: TCryptoLibByteArray;
begin
  if ((FForSigning) or (FPublicKey = nil)) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SNotInitializedForVerifying);
  end;
  if (TEd448.SignatureSize <> System.Length(ASignature)) then
  begin
    FPreHash.Reset();
    Result := False;
    Exit;
  end;
  System.SetLength(LMsg, TEd448.PrehashSize);
  if (TEd448.PrehashSize <> FPreHash.OutputFinal(LMsg, 0, TEd448.PrehashSize)) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes(@SPreHashDigestFailed);
  end;
  Result := FPublicKey.Verify(TEd448.TAlgorithm.Ed448ph, FContext, LMsg, 0,
    TEd448.PrehashSize, ASignature, 0);
end;

end.
