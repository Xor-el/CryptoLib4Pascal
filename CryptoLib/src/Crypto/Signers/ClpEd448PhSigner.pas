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

{ TEd448PhSigner }

procedure TEd448PhSigner.BlockUpdate(const ABuf: TCryptoLibByteArray;
  AOff, ALength: Int32);
begin
  FPreHash.BlockUpdate(ABuf, AOff, ALength);
end;

constructor TEd448PhSigner.Create(const AContext: TCryptoLibByteArray);
begin
  Inherited Create();
  FContext := System.Copy(AContext);
  FPreHash := TEd448.CreatePrehash();
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
