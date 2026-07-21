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

unit ClpEd25519Signer;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SyncObjs,
  ClpEd25519,
  ClpICipherParameters,
  ClpISigner,
  ClpIEd25519Signer,
  ClpIEd25519Parameters,
  ClpEd25519Parameters,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SNotInitialized = 'Ed25519Signer not initialized for %s';

type
  /// <summary>
  /// Pure Ed25519 (RFC 8032) signature primitive. Buffers the message via the streaming
  /// <see cref="ISigner"/> surface and dispatches it to the curve routines on finalisation; no
  /// context is permitted.
  /// </summary>
  TEd25519Signer = class(TInterfacedObject, ISigner, IEd25519Signer)

  strict private
  type
    TBuffer = class
    strict private
    var
      FStream: TMemoryStream;
      FLock: TCriticalSection;

      function GetBufferContent: TCryptoLibByteArray;
      procedure ResetInternal;

    public
      constructor Create();
      destructor Destroy(); override;

      procedure WriteByte(AInput: Byte);
      procedure Write(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32);
      procedure Reset();

      function GenerateSignature(const APrivateKey
        : IEd25519PrivateKeyParameters): TCryptoLibByteArray;
      function VerifySignature(const APublicKey: IEd25519PublicKeyParameters;
        const ASignature: TCryptoLibByteArray): Boolean;
    end;

  strict private
  var
    FBuffer: TBuffer;
    FForSigning: Boolean;
    FPrivateKey: IEd25519PrivateKeyParameters;
    FPublicKey: IEd25519PublicKeyParameters;

  strict protected
    function GetAlgorithmName: String; virtual;

  public
    /// <summary>Construct an uninitialised pure-Ed25519 signer; call Init before use.</summary>
    constructor Create();
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
    /// <summary>Length in bytes of an Ed25519 signature (64).</summary>
    function GetMaxSignatureSize: Int32; virtual;
    /// <summary>Finalise the buffered message and produce the signature. Buffer is reset on return.
    /// </summary>
    /// <exception cref="EInvalidOperationCryptoLibException">
    /// If the signer was initialised for verification, not signing.
    /// </exception>
    function GenerateSignature(): TCryptoLibByteArray; virtual;
    /// <summary>
    /// Finalise the buffered message and verify <paramref name="ASignature"/>. Buffer is reset on
    /// return.
    /// </summary>
    /// <returns>true if the signature is valid for the accumulated message and bound public key;
    /// otherwise false.</returns>
    /// <exception cref="EInvalidOperationCryptoLibException">
    /// If the signer was initialised for signing, not verification.
    /// </exception>
    function VerifySignature(const ASignature: TCryptoLibByteArray)
      : Boolean; virtual;
    /// <summary>Clear and rewind the buffered message.</summary>
    procedure Reset(); virtual;

    property AlgorithmName: String read GetAlgorithmName;

  end;

implementation

{ TEd25519Signer.TBuffer }

constructor TEd25519Signer.TBuffer.Create();
begin
  Inherited Create();
  FStream := TMemoryStream.Create();
  FLock := TCriticalSection.Create();
end;

destructor TEd25519Signer.TBuffer.Destroy;
begin
  FLock.Free;
  FStream.Free;
  inherited Destroy;
end;

function TEd25519Signer.TBuffer.GetBufferContent: TCryptoLibByteArray;
begin
  Result := nil;
  if FStream.Size > 0 then
  begin
    FStream.Position := 0;
    System.SetLength(Result, FStream.Size);
    FStream.Read(Result[0], FStream.Size);
  end;
end;

procedure TEd25519Signer.TBuffer.ResetInternal;
var
  LCount: Int64;
begin
  LCount := FStream.Size;
  if LCount > 0 then
  begin
    FillChar(PByte(FStream.Memory)^, LCount, 0);
  end;
  FStream.Clear;
  FStream.SetSize(Int64(0));
end;

procedure TEd25519Signer.TBuffer.Reset();
begin
  FLock.Enter;
  try
    ResetInternal;
  finally
    FLock.Leave;
  end;
end;

procedure TEd25519Signer.TBuffer.WriteByte(AInput: Byte);
var
  LB: TCryptoLibByteArray;
begin
  LB := TCryptoLibByteArray.Create(AInput);
  FStream.Write(LB[0], 1);
end;

procedure TEd25519Signer.TBuffer.Write(const ABuf: TCryptoLibByteArray;
  AOff, ALen: Int32);
begin
  if (ABuf <> nil) and (ALen > 0) then
    FStream.Write(ABuf[AOff], ALen);
end;

function TEd25519Signer.TBuffer.GenerateSignature(const APrivateKey
  : IEd25519PrivateKeyParameters): TCryptoLibByteArray;
var
  LBuf: TCryptoLibByteArray;
  LCount: Int32;
begin
  FLock.Enter;
  try
    LBuf := GetBufferContent();
    LCount := System.Length(LBuf);
    System.SetLength(Result, TEd25519PrivateKeyParameters.SignatureSize);
    APrivateKey.Sign(TEd25519.TAlgorithm.Ed25519, nil, LBuf, 0, LCount,
      Result, 0);
    ResetInternal;
  finally
    FLock.Leave;
  end;
end;

function TEd25519Signer.TBuffer.VerifySignature(const APublicKey
  : IEd25519PublicKeyParameters;
  const ASignature: TCryptoLibByteArray): Boolean;
var
  LBuf: TCryptoLibByteArray;
  LCount: Int32;
begin
  if TEd25519.SignatureSize <> System.Length(ASignature) then
  begin
    Reset();
    Result := False;
    Exit;
  end;
  FLock.Enter;
  try
    LBuf := GetBufferContent();
    LCount := System.Length(LBuf);
    Result := APublicKey.Verify(TEd25519.TAlgorithm.Ed25519, nil, LBuf, 0,
      LCount, ASignature, 0);
    ResetInternal;
  finally
    FLock.Leave;
  end;
end;

{ TEd25519Signer }

procedure TEd25519Signer.BlockUpdate(const ABuf: TCryptoLibByteArray;
  AOff, ALength: Int32);
begin
  FBuffer.Write(ABuf, AOff, ALength);
end;

constructor TEd25519Signer.Create();
begin
  Inherited Create();
  FBuffer := TBuffer.Create();
end;

destructor TEd25519Signer.Destroy;
begin
  FBuffer.Free;
  inherited Destroy;
end;

function TEd25519Signer.GetAlgorithmName: String;
begin
  Result := 'Ed25519';
end;

procedure TEd25519Signer.Init(AForSigning: Boolean;
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

procedure TEd25519Signer.Reset;
begin
  FBuffer.Reset();
end;

procedure TEd25519Signer.Update(AInput: Byte);
begin
  FBuffer.WriteByte(AInput);
end;

function TEd25519Signer.GetMaxSignatureSize: Int32;
begin
  Result := TEd25519.SignatureSize;
end;

function TEd25519Signer.GenerateSignature: TCryptoLibByteArray;
begin
  if ((not FForSigning) or (FPrivateKey = nil)) then
  begin
    raise EInvalidOperationCryptoLibException.CreateResFmt
      (@SNotInitialized, ['signature generation']);
  end;
  Result := FBuffer.GenerateSignature(FPrivateKey);
end;

function TEd25519Signer.VerifySignature(const ASignature
  : TCryptoLibByteArray): Boolean;
begin
  if ((FForSigning) or (FPublicKey = nil)) then
  begin
    raise EInvalidOperationCryptoLibException.CreateResFmt
      (@SNotInitialized, ['verification']);
  end;
  Result := FBuffer.VerifySignature(FPublicKey, ASignature);
end;

end.
