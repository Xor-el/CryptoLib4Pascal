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

unit ClpEd25519Signer;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpIEd25519,
  ClpEd25519,
  ClpICipherParameters,
  ClpIEd25519Signer,
  ClpIEd25519PrivateKeyParameters,
  ClpIEd25519PublicKeyParameters,
  ClpEd25519PrivateKeyParameters,
  ClpCryptoLibTypes;

resourcestring
  SNotInitializedForSigning =
    'Ed25519Signer not Initialised for Signature Generation.';
  SNotInitializedForVerifying =
    'Ed25519Signer not Initialised for Verification';

type
  TEd25519Signer = class(TInterfacedObject, IEd25519Signer)

  strict private
  var
    FBuffer: TMemoryStream;
    FForSigning: Boolean;
    FEd25519Instance: IEd25519;
    FPrivateKey: IEd25519PrivateKeyParameters;
    FPublicKey: IEd25519PublicKeyParameters;

    function Aggregate: TCryptoLibByteArray; inline;

  strict protected
    function GetAlgorithmName: String; virtual;

  public
    constructor Create();
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

{ TEd25519Signer }

function TEd25519Signer.Aggregate: TCryptoLibByteArray;
begin
  Result := nil;
  if FBuffer.Size > 0 then
  begin
    FBuffer.Position := 0;
    System.SetLength(Result, FBuffer.Size);
    FBuffer.Read(Result[0], FBuffer.Size);
  end;
end;

procedure TEd25519Signer.BlockUpdate(const ABuf: TCryptoLibByteArray;
  AOff, ALength: Int32);
begin
  if ABuf <> nil then
  begin
    FBuffer.Write(ABuf[AOff], ALength);
  end;
end;

constructor TEd25519Signer.Create();
begin
  Inherited Create();
  FBuffer := TMemoryStream.Create();
  FEd25519Instance := TEd25519.Create;
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

procedure TEd25519Signer.Reset;
begin
  FBuffer.Clear;
  FBuffer.SetSize(Int64(0));
end;

procedure TEd25519Signer.Update(AInput: Byte);
begin
  FBuffer.Write(TCryptoLibByteArray.Create(AInput)[0], 1);
end;

function TEd25519Signer.GetMaxSignatureSize: Int32;
begin
  Result := TEd25519.SignatureSize;
end;

function TEd25519Signer.GenerateSignature: TCryptoLibByteArray;
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

  FPrivateKey.Sign(TEd25519.TEd25519Algorithm.Ed25519, FPublicKey, nil, LBuf, 0,
    LCount, LSignature, 0);
  Reset();
  Result := LSignature;
end;

function TEd25519Signer.VerifySignature(const ASignature
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
  Result := FEd25519Instance.Verify(ASignature, 0, LPk, 0, LBuf, 0, LCount);
  Reset();
end;

end.
