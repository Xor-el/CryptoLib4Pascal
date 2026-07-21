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

unit ClpHashSlhDsaSigner;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpICipherParameters,
  ClpISigner,
  ClpIHashSlhDsaSigner,
  ClpISlhDsaParameters,
  ClpSlhDsaParameters,
  ClpSlhDsaSigner,
  ClpISlhDsaEngine,
  ClpParameterUtilities,
  ClpCryptoServicesRegistrar,
  ClpISecureRandom,
  ClpDigestUtilities,
  ClpIDigest,
  ClpAsn1Core,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SCannotUseSlhDsa = 'cannot be used for SLH-DSA';
  SNotInitializedForSign = 'HashSlhDsaSigner not initialized for signature generation';
  SNotInitializedForVerify = 'HashSlhDsaSigner not initialized for verification';
  SMismatchingKeyParameterSet = 'mismatching key parameter set';
  SParametersNil = 'parameters cannot be nil';

type
  THashSlhDsaSignerBuffer = class(TSlhDsaSignerBuffer)
  public
    procedure Init(const AContext, APreHashOidEncoding: TCryptoLibByteArray); reintroduce; overload;
  end;

  THashSlhDsaSigner = class(TInterfacedObject, ISigner, IHashSlhDsaSigner)
  strict private
  var
    FBuffer: THashSlhDsaSignerBuffer;
    FParameters: ISlhDsaParameters;
    FPreHashOidEncoding: TCryptoLibByteArray;
    FPreHashDigest: IDigest;
    FDeterministic: Boolean;
    FPrivateKey: ISlhDsaPrivateKeyParameters;
    FPublicKey: ISlhDsaPublicKeyParameters;
    FRandom: ISecureRandom;
    FEngine: ISlhDsaEngine;
    function GetEngine(const AKeyParameters: ISlhDsaParameters): ISlhDsaEngine;
    procedure FinishPreHash;
  public
    constructor Create(const AParameters: ISlhDsaParameters; ADeterministic: Boolean);
    destructor Destroy; override;
    function GetAlgorithmName: String;
    procedure Init(AForSigning: Boolean; const AParameters: ICipherParameters);
    procedure Update(AInput: Byte);
    procedure BlockUpdate(const AInput: TCryptoLibByteArray; AInOff, AInLen: Int32);
    function GetMaxSignatureSize: Int32;
    function GenerateSignature: TCryptoLibByteArray;
    function VerifySignature(const ASignature: TCryptoLibByteArray): Boolean;
    procedure Reset;
  end;

implementation

{ THashSlhDsaSignerBuffer }

procedure THashSlhDsaSignerBuffer.Init(const AContext, APreHashOidEncoding: TCryptoLibByteArray);
begin
  TruncateAndClear(0);
  WriteByte($01);
  WriteByte(Byte(System.Length(AContext)));
  if System.Length(AContext) > 0 then
    Write(AContext, 0, System.Length(AContext));
  Write(APreHashOidEncoding, 0, System.Length(APreHashOidEncoding));
  FPrefixLength := FCount;
end;

constructor THashSlhDsaSigner.Create(const AParameters: ISlhDsaParameters; ADeterministic: Boolean);
begin
  inherited Create;
  if AParameters = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersNil);
  if AParameters.PreHashOid = nil then
    raise EArgumentCryptoLibException.CreateRes(@SCannotUseSlhDsa);
  FParameters := AParameters;
  FPreHashOidEncoding := AParameters.PreHashOid.GetEncoded(TAsn1Encodable.Der);
  FPreHashDigest := TDigestUtilities.GetDigest(AParameters.PreHashOid);
  FDeterministic := ADeterministic;
  FBuffer := THashSlhDsaSignerBuffer.Create;
  FEngine := FParameters.ParameterSet.GetEngine;
end;

destructor THashSlhDsaSigner.Destroy;
begin
  FBuffer.Free;
  inherited;
end;

procedure THashSlhDsaSigner.FinishPreHash;
var
  LPreHash: TCryptoLibByteArray;
begin
  System.SetLength(LPreHash, FPreHashDigest.GetDigestSize);
  FPreHashDigest.DoFinal(LPreHash, 0);
  FBuffer.Write(LPreHash);
end;

function THashSlhDsaSigner.GenerateSignature: TCryptoLibByteArray;
begin
  if FPrivateKey = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SNotInitializedForSign);
  FinishPreHash;
  Result := FBuffer.GenerateSignature(FPrivateKey, FRandom);
end;

function THashSlhDsaSigner.GetAlgorithmName: String;
begin
  Result := FParameters.Name;
end;

function THashSlhDsaSigner.GetEngine(const AKeyParameters: ISlhDsaParameters): ISlhDsaEngine;
begin
  if AKeyParameters.ParameterSet <> FParameters.ParameterSet then
    raise EArgumentCryptoLibException.CreateRes(@SMismatchingKeyParameterSet);
  Result := AKeyParameters.ParameterSet.GetEngine;
end;

function THashSlhDsaSigner.GetMaxSignatureSize: Int32;
begin
  Result := FEngine.SignatureLength;
end;

procedure THashSlhDsaSigner.Init(AForSigning: Boolean; const AParameters: ICipherParameters);
var
  LParams: ICipherParameters;
  LProvidedContext: TCryptoLibByteArray;
  LProvidedRandom: ISecureRandom;
begin
  LParams := TParameterUtilities.GetContext(AParameters, 0, 255, LProvidedContext);
  if LProvidedContext = nil then
    SetLength(LProvidedContext, 0);

  if AForSigning then
  begin
    LParams := TParameterUtilities.GetRandom(LParams, LProvidedRandom);
    FPrivateKey := LParams as ISlhDsaPrivateKeyParameters;
    FPublicKey := nil;
    if FDeterministic then
      FRandom := nil
    else
      FRandom := TCryptoServicesRegistrar.GetSecureRandom(LProvidedRandom);
    FEngine := GetEngine(FPrivateKey.Parameters);
  end
  else
  begin
    FPrivateKey := nil;
    FPublicKey := LParams as ISlhDsaPublicKeyParameters;
    FRandom := nil;
    FEngine := GetEngine(FPublicKey.Parameters);
  end;

  FBuffer.Init(LProvidedContext, FPreHashOidEncoding);
  Reset;
end;

procedure THashSlhDsaSigner.Reset;
begin
  FPreHashDigest.Reset;
end;

procedure THashSlhDsaSigner.Update(AInput: Byte);
begin
  FPreHashDigest.Update(AInput);
end;

procedure THashSlhDsaSigner.BlockUpdate(const AInput: TCryptoLibByteArray; AInOff, AInLen: Int32);
begin
  FPreHashDigest.BlockUpdate(AInput, AInOff, AInLen);
end;

function THashSlhDsaSigner.VerifySignature(const ASignature: TCryptoLibByteArray): Boolean;
begin
  if FPublicKey = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SNotInitializedForVerify);
  FinishPreHash;
  if FEngine.SignatureLength <> System.Length(ASignature) then
  begin
    FBuffer.Reset;
    Exit(False);
  end;
  Result := FBuffer.VerifySignature(FPublicKey, ASignature);
end;

end.
