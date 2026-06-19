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

unit ClpMlDsaSigner;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpICipherParameters,
  ClpISigner,
  ClpIMlDsaSigner,
  ClpIMlDsaParameters,
  ClpMlDsaParameters,
  ClpIMlDsaEngine,
  ClpParameterUtilities,
  ClpCryptoServicesRegistrar,
  ClpISecureRandom,
  ClpDigestUtilities,
  ClpIXof,
  ClpCryptoLibTypes;

resourcestring
  SCannotUseHashMlDsa = 'cannot be used for HashML-DSA';
  SNotInitializedForSign = 'ML-DSA signer not initialized for signature generation';
  SNotInitializedForVerify = 'ML-DSA signer not initialized for verification';
  SMismatchingKeyParameterSet = 'mismatching key parameter set';
  SParametersNil = 'parameters cannot be nil';

type
  TMlDsaSigner = class(TInterfacedObject, ISigner, IMlDsaSigner)
  strict private
  var
    FMsgRepDigest: IXof;
    FParameters: IMlDsaParameters;
    FDeterministic: Boolean;
    FContext: TCryptoLibByteArray;
    FPrivateKey: IMlDsaPrivateKeyParameters;
    FPublicKey: IMlDsaPublicKeyParameters;
    FEngine: IMlDsaEngine;
    function GetEngine(const AKeyParameters: IMlDsaParameters): IMlDsaEngine;
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

{ TMlDsaSigner }

constructor TMlDsaSigner.Create(const AParameters: IMlDsaParameters; ADeterministic: Boolean);
begin
  inherited Create;
  if AParameters = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersNil);
  if AParameters.IsPreHash then
    raise EArgumentCryptoLibException.CreateRes(@SCannotUseHashMlDsa);
  FParameters := AParameters;
  FDeterministic := ADeterministic;
  FMsgRepDigest := TDigestUtilities.GetDigest('SHAKE256-512') as IXof;
end;

function TMlDsaSigner.GetAlgorithmName: String;
begin
  Result := FParameters.Name;
end;

function TMlDsaSigner.GetEngine(const AKeyParameters: IMlDsaParameters): IMlDsaEngine;
begin
  if AKeyParameters.ParameterSet <> FParameters.ParameterSet then
    raise EArgumentCryptoLibException.CreateRes(@SMismatchingKeyParameterSet);
  if FDeterministic then
    Result := AKeyParameters.ParameterSet.GetEngine(nil)
  else
    Result := AKeyParameters.ParameterSet.GetEngine(TCryptoServicesRegistrar.GetSecureRandom());
end;

procedure TMlDsaSigner.Init(AForSigning: Boolean; const AParameters: ICipherParameters);
var
  LParams: ICipherParameters;
  LProvidedContext: TCryptoLibByteArray;
  LProvidedRandom: ISecureRandom;
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
      FEngine := GetEngine(FPrivateKey.Parameters)
    else
      FEngine := FPrivateKey.Parameters.ParameterSet.GetEngine(
        TCryptoServicesRegistrar.GetSecureRandom(LProvidedRandom));
  end
  else
  begin
    FPrivateKey := nil;
    FPublicKey := LParams as IMlDsaPublicKeyParameters;
    FEngine := GetEngine(FPublicKey.Parameters);
  end;
  Reset;
end;

procedure TMlDsaSigner.Update(AInput: Byte);
begin
  FMsgRepDigest.Update(AInput);
end;

procedure TMlDsaSigner.BlockUpdate(const AInput: TCryptoLibByteArray; AInOff, AInLen: Int32);
begin
  FMsgRepDigest.BlockUpdate(AInput, AInOff, AInLen);
end;

function TMlDsaSigner.GetMaxSignatureSize: Int32;
begin
  Result := FEngine.CryptoBytes;
end;

function TMlDsaSigner.GenerateSignature: TCryptoLibByteArray;
begin
  if FPrivateKey = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SNotInitializedForSign);
  System.SetLength(Result, FEngine.CryptoBytes);
  FEngine.MsgRepEndSign(FMsgRepDigest, Result, System.Length(Result), FPrivateKey.GetRho,
    FPrivateKey.GetK, FPrivateKey.GetT0, FPrivateKey.GetS1, FPrivateKey.GetS2);
  Reset;
end;

function TMlDsaSigner.VerifySignature(const ASignature: TCryptoLibByteArray): Boolean;
begin
  if FPublicKey = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SNotInitializedForVerify);
  Result := FEngine.MsgRepEndVerify(FMsgRepDigest, ASignature, System.Length(ASignature),
    FPublicKey.GetRho, FPublicKey.GetT1);
  Reset;
end;

procedure TMlDsaSigner.Reset;
var
  LTr: TCryptoLibByteArray;
begin
  FMsgRepDigest.Reset;
  if FPrivateKey <> nil then
    LTr := FPrivateKey.GetTr
  else
    LTr := FPublicKey.GetPublicKeyHash;
  FEngine.MsgRepBegin(FMsgRepDigest, LTr);
  FMsgRepDigest.Update(0);
  FMsgRepDigest.Update(Byte(System.Length(FContext)));
  if System.Length(FContext) > 0 then
    FMsgRepDigest.BlockUpdate(FContext, 0, System.Length(FContext));
end;
end.
