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

unit ClpHashMlDsaSigner;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpICipherParameters,
  ClpISigner,
  ClpIHashMlDsaSigner,
  ClpIMlDsaParameters,
  ClpMlDsaParameters,
  ClpIMlDsaEngine,
  ClpParameterUtilities,
  ClpCryptoServicesRegistrar,
  ClpISecureRandom,
  ClpDigestUtilities,
  ClpIXof,
  ClpIDigest,
  ClpAsn1Core,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SCannotUseMlDsa = 'cannot be used for ML-DSA';
  SNotInitializedForSign = 'HashMLDsaSigner not initialised for signature generation.';
  SNotInitializedForVerify = 'HashMLDsaSigner not initialised for verification';
  SMismatchingKeyParameterSet = 'Mismatching key parameter set';
  SParametersNil = 'parameters cannot be nil';
  SMsgRepDigestCloneFailed = 'message representative digest clone failed';

type
  THashMlDsaSigner = class(TInterfacedObject, ISigner, IHashMlDsaSigner)
  strict private
  var
    FMsgRepDigest: IXof;
    FParameters: IMlDsaParameters;
    FPreHashOidEncoding: TCryptoLibByteArray;
    FPreHashDigest: IDigest;
    FDeterministic: Boolean;
    FContext: TCryptoLibByteArray;
    FPrivateKey: IMlDsaPrivateKeyParameters;
    FPublicKey: IMlDsaPublicKeyParameters;
    FEngine: IMlDsaEngine;
    function FinishPreHash: IXof;
    function GetEngine(const AKeyParameters: IMlDsaParameters;
      const ARandom: ISecureRandom): IMlDsaEngine;
  public
    constructor Create(const AParameters: IMlDsaParameters; ADeterministic: Boolean);
    function GetAlgorithmName: String;
    procedure Init(AForSigning: Boolean; const AParameters: ICipherParameters);
    procedure Update(AInput: Byte);
    procedure BlockUpdate(const AInput: TCryptoLibByteArray; AInOff, AInLen: Int32);
    function GetMaxSignatureSize: Int32;
    function GenerateSignature(): TCryptoLibByteArray;
    function VerifySignature(const ASignature: TCryptoLibByteArray): Boolean;
    procedure Reset;
  end;

implementation

{ THashMlDsaSigner }

constructor THashMlDsaSigner.Create(const AParameters: IMlDsaParameters; ADeterministic: Boolean);
begin
  inherited Create;
  if AParameters = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersNil);
  if AParameters.PreHashOid = nil then
    raise EArgumentCryptoLibException.CreateRes(@SCannotUseMlDsa);
  FParameters := AParameters;
  FPreHashOidEncoding := AParameters.PreHashOid.GetEncoded(TAsn1Encodable.Der);
  FPreHashDigest := TDigestUtilities.GetDigest(AParameters.PreHashOid);
  FDeterministic := ADeterministic;
  FMsgRepDigest := TDigestUtilities.GetDigest('SHAKE256-512') as IXof;
end;

function THashMlDsaSigner.GetAlgorithmName: String;
begin
  Result := FParameters.Name;
end;

function THashMlDsaSigner.GetEngine(const AKeyParameters: IMlDsaParameters;
  const ARandom: ISecureRandom): IMlDsaEngine;
begin
  if AKeyParameters.ParameterSet <> FParameters.ParameterSet then
    raise EArgumentCryptoLibException.CreateRes(@SMismatchingKeyParameterSet);
  Result := AKeyParameters.ParameterSet.GetEngine(ARandom);
end;

procedure THashMlDsaSigner.Init(AForSigning: Boolean; const AParameters: ICipherParameters);
var
  LParams: ICipherParameters;
  LProvidedContext: TCryptoLibByteArray;
  LProvidedRandom: ISecureRandom;
  LTr: TCryptoLibByteArray;
begin
  LParams := TParameterUtilities.GetContext(AParameters, 0, 255, LProvidedContext);
  if LProvidedContext = nil then
    SetLength(FContext, 0)
  else
    FContext := LProvidedContext;
  if AForSigning then
  begin
    LParams := TParameterUtilities.GetRandom(LParams, LProvidedRandom);
    FPrivateKey := LParams as IMlDsaPrivateKeyParameters;
    FPublicKey := nil;
    if FDeterministic then
      FEngine := GetEngine(FPrivateKey.Parameters, nil)
    else
      FEngine := GetEngine(FPrivateKey.Parameters,
        TCryptoServicesRegistrar.GetSecureRandom(LProvidedRandom));
  end
  else
  begin
    FPrivateKey := nil;
    FPublicKey := LParams as IMlDsaPublicKeyParameters;
    FEngine := GetEngine(FPublicKey.Parameters, nil);
  end;

  FMsgRepDigest.Reset;
  if FPrivateKey <> nil then
    LTr := FPrivateKey.GetTr
  else
    LTr := FPublicKey.GetPublicKeyHash;
  FEngine.MsgRepBegin(FMsgRepDigest, LTr);
  FMsgRepDigest.Update($01);
  FMsgRepDigest.Update(Byte(System.Length(FContext)));
  if System.Length(FContext) > 0 then
    FMsgRepDigest.BlockUpdate(FContext, 0, System.Length(FContext));
  FMsgRepDigest.BlockUpdate(FPreHashOidEncoding, 0, System.Length(FPreHashOidEncoding));

  Reset;
end;

procedure THashMlDsaSigner.Update(AInput: Byte);
begin
  FPreHashDigest.Update(AInput);
end;

procedure THashMlDsaSigner.BlockUpdate(const AInput: TCryptoLibByteArray; AInOff, AInLen: Int32);
begin
  FPreHashDigest.BlockUpdate(AInput, AInOff, AInLen);
end;

function THashMlDsaSigner.GetMaxSignatureSize: Int32;
begin
  Result := FEngine.CryptoBytes;
end;

function THashMlDsaSigner.FinishPreHash: IXof;
var
  LClone: IDigest;
  LPreHash: TCryptoLibByteArray;
begin
  LClone := FMsgRepDigest.Clone();
  if not Supports(LClone, IXof, Result) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SMsgRepDigestCloneFailed);
  SetLength(LPreHash, FPreHashDigest.GetDigestSize);
  FPreHashDigest.DoFinal(LPreHash, 0);
  Result.BlockUpdate(LPreHash, 0, System.Length(LPreHash));
end;

function THashMlDsaSigner.GenerateSignature: TCryptoLibByteArray;
var
  LMsgRepDigest: IXof;
begin
  if FPrivateKey = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SNotInitializedForSign);
  LMsgRepDigest := FinishPreHash;
  System.SetLength(Result, FEngine.CryptoBytes);
  FEngine.MsgRepEndSign(LMsgRepDigest, Result, System.Length(Result), FPrivateKey.GetRho,
    FPrivateKey.GetK, FPrivateKey.GetT0, FPrivateKey.GetS1, FPrivateKey.GetS2);
end;

function THashMlDsaSigner.VerifySignature(const ASignature: TCryptoLibByteArray): Boolean;
var
  LMsgRepDigest: IXof;
begin
  if FPublicKey = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SNotInitializedForVerify);
  LMsgRepDigest := FinishPreHash;
  Result := FEngine.MsgRepEndVerify(LMsgRepDigest, ASignature, System.Length(ASignature),
    FPublicKey.GetRho, FPublicKey.GetT1);
end;

procedure THashMlDsaSigner.Reset;
begin
  FPreHashDigest.Reset;
end;

end.
