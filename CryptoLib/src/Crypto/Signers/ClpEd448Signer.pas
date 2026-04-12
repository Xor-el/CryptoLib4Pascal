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

unit ClpEd448Signer;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SyncObjs,
  ClpEd448,
  ClpICipherParameters,
  ClpISigner,
  ClpIEd448Signer,
  ClpIEd448Parameters,
  ClpEd448Parameters,
  ClpCryptoLibTypes;

resourcestring
  SNotInitializedForSigning =
    'Ed448Signer not Initialised for Signature Generation.';
  SNotInitializedForVerifying =
    'Ed448Signer not Initialised for Verification';

type
  TEd448Signer = class(TInterfacedObject, ISigner, IEd448Signer)

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
        : IEd448PrivateKeyParameters;
        const AContext: TCryptoLibByteArray): TCryptoLibByteArray;
      function VerifySignature(const APublicKey: IEd448PublicKeyParameters;
        const AContext: TCryptoLibByteArray;
        const ASignature: TCryptoLibByteArray): Boolean;
    end;

  strict private
  var
    FContext: TCryptoLibByteArray;
    FBuffer: TBuffer;
    FForSigning: Boolean;
    FPrivateKey: IEd448PrivateKeyParameters;
    FPublicKey: IEd448PublicKeyParameters;

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

{ TEd448Signer.TBuffer }

constructor TEd448Signer.TBuffer.Create();
begin
  Inherited Create();
  FStream := TMemoryStream.Create();
  FLock := TCriticalSection.Create();
end;

destructor TEd448Signer.TBuffer.Destroy;
begin
  FLock.Free;
  FStream.Free;
  inherited Destroy;
end;

function TEd448Signer.TBuffer.GetBufferContent: TCryptoLibByteArray;
begin
  Result := nil;
  if FStream.Size > 0 then
  begin
    FStream.Position := 0;
    System.SetLength(Result, FStream.Size);
    FStream.Read(Result[0], FStream.Size);
  end;
end;

procedure TEd448Signer.TBuffer.ResetInternal;
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

procedure TEd448Signer.TBuffer.Reset();
begin
  FLock.Enter;
  try
    ResetInternal;
  finally
    FLock.Leave;
  end;
end;

procedure TEd448Signer.TBuffer.WriteByte(AInput: Byte);
var
  LB: TCryptoLibByteArray;
begin
  LB := TCryptoLibByteArray.Create(AInput);
  FStream.Write(LB[0], 1);
end;

procedure TEd448Signer.TBuffer.Write(const ABuf: TCryptoLibByteArray;
  AOff, ALen: Int32);
begin
  if (ABuf <> nil) and (ALen > 0) then
    FStream.Write(ABuf[AOff], ALen);
end;

function TEd448Signer.TBuffer.GenerateSignature(const APrivateKey
  : IEd448PrivateKeyParameters;
  const AContext: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LBuf: TCryptoLibByteArray;
  LCount: Int32;
begin
  FLock.Enter;
  try
    LBuf := GetBufferContent();
    LCount := System.Length(LBuf);
    System.SetLength(Result, TEd448PrivateKeyParameters.SignatureSize);
    APrivateKey.Sign(TEd448.TAlgorithm.Ed448, AContext, LBuf, 0,
      LCount, Result, 0);
    ResetInternal;
  finally
    FLock.Leave;
  end;
end;

function TEd448Signer.TBuffer.VerifySignature(const APublicKey
  : IEd448PublicKeyParameters; const AContext: TCryptoLibByteArray;
  const ASignature: TCryptoLibByteArray): Boolean;
var
  LBuf: TCryptoLibByteArray;
  LCount: Int32;
begin
  if TEd448.SignatureSize <> System.Length(ASignature) then
  begin
    Reset();
    Result := False;
    Exit;
  end;
  FLock.Enter;
  try
    LBuf := GetBufferContent();
    LCount := System.Length(LBuf);
    Result := APublicKey.Verify(TEd448.TAlgorithm.Ed448, AContext,
      LBuf, 0, LCount, ASignature, 0);
    ResetInternal;
  finally
    FLock.Leave;
  end;
end;

{ TEd448Signer }

procedure TEd448Signer.BlockUpdate(const ABuf: TCryptoLibByteArray;
  AOff, ALength: Int32);
begin
  FBuffer.Write(ABuf, AOff, ALength);
end;

constructor TEd448Signer.Create(const AContext: TCryptoLibByteArray);
begin
  Inherited Create();
  FBuffer := TBuffer.Create();
  FContext := System.Copy(AContext);
end;

destructor TEd448Signer.Destroy;
begin
  FBuffer.Free;
  inherited Destroy;
end;

function TEd448Signer.GetAlgorithmName: String;
begin
  Result := 'Ed448';
end;

procedure TEd448Signer.Init(AForSigning: Boolean;
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

procedure TEd448Signer.Reset;
begin
  FBuffer.Reset();
end;

procedure TEd448Signer.Update(AInput: Byte);
begin
  FBuffer.WriteByte(AInput);
end;

function TEd448Signer.GetMaxSignatureSize: Int32;
begin
  Result := TEd448.SignatureSize;
end;

function TEd448Signer.GenerateSignature: TCryptoLibByteArray;
begin
  if ((not FForSigning) or (FPrivateKey = nil)) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SNotInitializedForSigning);
  end;
  Result := FBuffer.GenerateSignature(FPrivateKey, FContext);
end;

function TEd448Signer.VerifySignature(const ASignature
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
