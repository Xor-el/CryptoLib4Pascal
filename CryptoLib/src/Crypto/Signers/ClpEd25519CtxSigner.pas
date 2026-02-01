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

unit ClpEd25519CtxSigner;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SyncObjs,
  ClpEd25519,
  ClpICipherParameters,
  ClpISigner,
  ClpIEd25519CtxSigner,
  ClpIEd25519PrivateKeyParameters,
  ClpIEd25519PublicKeyParameters,
  ClpEd25519PrivateKeyParameters,
  ClpCryptoLibTypes;

resourcestring
  SContextNil = 'Ctx must not be Nil for Ed25519ctx/Ed25519ph';
  SNotInitializedForSigning =
    'Ed25519CtxSigner not Initialised for Signature Generation.';
  SNotInitializedForVerifying =
    'Ed25519CtxSigner not Initialised for Verification';

type
  TEd25519CtxSigner = class(TInterfacedObject, ISigner, IEd25519CtxSigner)

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
        : IEd25519PrivateKeyParameters;
        const AContext: TCryptoLibByteArray): TCryptoLibByteArray;
      function VerifySignature(const APublicKey: IEd25519PublicKeyParameters;
        const AContext: TCryptoLibByteArray;
        const ASignature: TCryptoLibByteArray): Boolean;
    end;

  strict private
  var
    FContext: TCryptoLibByteArray;
    FBuffer: TBuffer;
    FForSigning: Boolean;
    FPrivateKey: IEd25519PrivateKeyParameters;
    FPublicKey: IEd25519PublicKeyParameters;

  strict protected
    function GetAlgorithmName: String; virtual;

  public
    constructor Create(const AContext: TCryptoLibByteArray);
    destructor Destroy(); override;

    procedure Init(AForSigning: Boolean;
      const AParameters: ICipherParameters); virtual;
    procedure Update(AInput: Byte); virtual;
    procedure BlockUpdate(const ABuf: TCryptoLibByteArray;
      AOff, ALength: Int32); virtual;
    function GetMaxSignatureSize: Int32; virtual;
    function GenerateSignature(): TCryptoLibByteArray; virtual;
    function VerifySignature(const ASignature: TCryptoLibByteArray)
      : Boolean; virtual;
    procedure Reset(); virtual;

    property AlgorithmName: String read GetAlgorithmName;

  end;

implementation

{ TEd25519CtxSigner.TBuffer }

constructor TEd25519CtxSigner.TBuffer.Create();
begin
  Inherited Create();
  FStream := TMemoryStream.Create();
  FLock := TCriticalSection.Create();
end;

destructor TEd25519CtxSigner.TBuffer.Destroy;
begin
  FLock.Free;
  FStream.Free;
  inherited Destroy;
end;

function TEd25519CtxSigner.TBuffer.GetBufferContent: TCryptoLibByteArray;
begin
  Result := nil;
  if FStream.Size > 0 then
  begin
    FStream.Position := 0;
    System.SetLength(Result, FStream.Size);
    FStream.Read(Result[0], FStream.Size);
  end;
end;

procedure TEd25519CtxSigner.TBuffer.ResetInternal;
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

procedure TEd25519CtxSigner.TBuffer.Reset();
begin
  FLock.Enter;
  try
    ResetInternal;
  finally
    FLock.Leave;
  end;
end;

procedure TEd25519CtxSigner.TBuffer.WriteByte(AInput: Byte);
var
  LB: TCryptoLibByteArray;
begin
  LB := TCryptoLibByteArray.Create(AInput);
  FStream.Write(LB[0], 1);
end;

procedure TEd25519CtxSigner.TBuffer.Write(const ABuf: TCryptoLibByteArray;
  AOff, ALen: Int32);
begin
  if (ABuf <> nil) and (ALen > 0) then
    FStream.Write(ABuf[AOff], ALen);
end;

function TEd25519CtxSigner.TBuffer.GenerateSignature(const APrivateKey
  : IEd25519PrivateKeyParameters;
  const AContext: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LBuf: TCryptoLibByteArray;
  LCount: Int32;
begin
  FLock.Enter;
  try
    LBuf := GetBufferContent();
    LCount := System.Length(LBuf);
    System.SetLength(Result, TEd25519PrivateKeyParameters.SignatureSize);
    APrivateKey.Sign(TEd25519.TAlgorithm.Ed25519ctx, AContext, LBuf, 0,
      LCount, Result, 0);
    ResetInternal;
  finally
    FLock.Leave;
  end;
end;

function TEd25519CtxSigner.TBuffer.VerifySignature(const APublicKey
  : IEd25519PublicKeyParameters; const AContext: TCryptoLibByteArray;
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
    Result := APublicKey.Verify(TEd25519.TAlgorithm.Ed25519ctx, AContext,
      LBuf, 0, LCount, ASignature, 0);
    ResetInternal;
  finally
    FLock.Leave;
  end;
end;

{ TEd25519CtxSigner }

procedure TEd25519CtxSigner.BlockUpdate(const ABuf: TCryptoLibByteArray;
  AOff, ALength: Int32);
begin
  FBuffer.Write(ABuf, AOff, ALength);
end;

constructor TEd25519CtxSigner.Create(const AContext: TCryptoLibByteArray);
begin
  Inherited Create();
  if AContext = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SContextNil);
  FBuffer := TBuffer.Create();
  FContext := System.Copy(AContext);
end;

destructor TEd25519CtxSigner.Destroy;
begin
  FBuffer.Free;
  inherited Destroy;
end;

function TEd25519CtxSigner.GetAlgorithmName: String;
begin
  Result := 'Ed25519ctx';
end;

procedure TEd25519CtxSigner.Init(AForSigning: Boolean;
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

procedure TEd25519CtxSigner.Reset;
begin
  FBuffer.Reset();
end;

procedure TEd25519CtxSigner.Update(AInput: Byte);
begin
  FBuffer.WriteByte(AInput);
end;

function TEd25519CtxSigner.GetMaxSignatureSize: Int32;
begin
  Result := TEd25519.SignatureSize;
end;

function TEd25519CtxSigner.GenerateSignature: TCryptoLibByteArray;
begin
  if ((not FForSigning) or (FPrivateKey = nil)) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SNotInitializedForSigning);
  end;
  Result := FBuffer.GenerateSignature(FPrivateKey, FContext);
end;

function TEd25519CtxSigner.VerifySignature(const ASignature
  : TCryptoLibByteArray): Boolean;
begin
  if ((FForSigning) or (FPublicKey = nil)) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SNotInitializedForVerifying);
  end;
  Result := FBuffer.VerifySignature(FPublicKey, FContext, ASignature);
end;

end.
