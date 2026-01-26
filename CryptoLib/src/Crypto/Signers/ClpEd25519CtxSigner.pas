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
  ClpIEd25519,
  ClpEd25519,
  ClpICipherParameters,
  ClpIEd25519CtxSigner,
  ClpIEd25519PrivateKeyParameters,
  ClpIEd25519PublicKeyParameters,
  ClpEd25519PrivateKeyParameters,
  ClpCryptoLibTypes;

resourcestring
  SNotInitializedForSigning =
    'Ed25519CtxSigner not Initialised for Signature Generation.';
  SNotInitializedForVerifying =
    'Ed25519CtxSigner not Initialised for Verification';

type
  TEd25519CtxSigner = class(TInterfacedObject, IEd25519CtxSigner)

  strict private
  var
    FContext: TCryptoLibByteArray;
    FBuffer: TMemoryStream;
    FForSigning: Boolean;
    FEd25519Instance: IEd25519;
    FPrivateKey: IEd25519PrivateKeyParameters;
    FPublicKey: IEd25519PublicKeyParameters;

    function Aggregate: TCryptoLibByteArray; inline;

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

{ TEd25519CtxSigner }

function TEd25519CtxSigner.Aggregate: TCryptoLibByteArray;
begin
  Result := nil;
  if FBuffer.Size > 0 then
  begin
    FBuffer.Position := 0;
    System.SetLength(Result, FBuffer.Size);
    FBuffer.Read(Result[0], FBuffer.Size);
  end;
end;

procedure TEd25519CtxSigner.BlockUpdate(const ABuf: TCryptoLibByteArray;
  AOff, ALength: Int32);
begin
  if ABuf <> nil then
  begin
    FBuffer.Write(ABuf[AOff], ALength);
  end;
end;

constructor TEd25519CtxSigner.Create(const AContext: TCryptoLibByteArray);
begin
  Inherited Create();
  FBuffer := TMemoryStream.Create();
  FContext := System.Copy(AContext);
  FEd25519Instance := TEd25519.Create();
end;

destructor TEd25519CtxSigner.Destroy;
begin
  FBuffer.Free;
  inherited Destroy;
end;

function TEd25519CtxSigner.GetAlgorithmName: String;
begin
  Result := 'Ed25519Ctx';
end;

procedure TEd25519CtxSigner.Init(AForSigning: Boolean;
  const AParameters: ICipherParameters);
begin
  FForSigning := AForSigning;

  if (AForSigning) then
  begin
    // TODO Allow IAsymmetricCipherKeyPair to be an ICipherParameters?

    FPrivateKey := AParameters as IEd25519PrivateKeyParameters;
    FPublicKey := FPrivateKey.GeneratePublicKey();
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
  FBuffer.Clear;
  FBuffer.SetSize(Int64(0));
end;

procedure TEd25519CtxSigner.Update(AInput: Byte);
begin
  FBuffer.Write(TCryptoLibByteArray.Create(AInput)[0], 1);
end;

function TEd25519CtxSigner.GetMaxSignatureSize: Int32;
begin
  Result := TEd25519.SignatureSize;
end;

function TEd25519CtxSigner.GenerateSignature: TCryptoLibByteArray;
var
  LSignature, LBuf: TCryptoLibByteArray;
  LCount: Int32;
begin
  if ((not FForSigning) or (FPrivateKey = nil)) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SNotInitializedForSigning);
  end;

  System.SetLength(LSignature, TEd25519PrivateKeyParameters.SignatureSize);
  LBuf := Aggregate();
  LCount := System.Length(LBuf);

  FPrivateKey.Sign(TEd25519.TEd25519Algorithm.Ed25519ctx, FPublicKey, FContext,
    LBuf, 0, LCount, LSignature, 0);
  Reset();
  Result := LSignature;
end;

function TEd25519CtxSigner.VerifySignature(const ASignature
  : TCryptoLibByteArray): Boolean;
var
  LBuf, LPk: TCryptoLibByteArray;
  LCount: Int32;
begin
  if ((FForSigning) or (FPublicKey = nil)) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SNotInitializedForVerifying);
  end;
  if (TEd25519.SignatureSize <> System.Length(ASignature)) then
  begin
    Result := false;
    Exit;
  end;
  LPk := FPublicKey.GetEncoded();
  LBuf := Aggregate();
  LCount := System.Length(LBuf);
  Result := FEd25519Instance.Verify(ASignature, 0, LPk, 0, FContext, LBuf,
    0, LCount);
  Reset();
end;

end.
