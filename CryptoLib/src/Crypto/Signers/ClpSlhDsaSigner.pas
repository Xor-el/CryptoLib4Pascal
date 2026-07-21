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

unit ClpSlhDsaSigner;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpICipherParameters,
  ClpISigner,
  ClpISlhDsaSigner,
  ClpISlhDsaParameters,
  ClpSlhDsaParameters,
  ClpISlhDsaEngine,
  ClpParameterUtilities,
  ClpCryptoServicesRegistrar,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpArrayUtilities,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SCannotUseHashSlhDsa = 'cannot be used for HashSLH-DSA';
  SNotInitializedForSign = 'SlhDsaSigner not initialized for signature generation';
  SNotInitializedForVerify = 'SlhDsaSigner not initialized for verification';
  SMismatchingKeyParameterSet = 'mismatching key parameter set';
  SParametersNil = 'parameters cannot be nil';

type
  TSlhDsaSignerBuffer = class
  strict protected
  var
    FBuffer: TCryptoLibByteArray;
    FCount: Int32;
    FPrefixLength: Int32;
    procedure TruncateAndClear(ANewLength: Int32);
    procedure EnsureCapacity(ANeeded: Int32);
  public
    procedure WriteByte(AValue: Byte);
    procedure Write(const AData: TCryptoLibByteArray; AOff, ALen: Int32); overload;
    procedure Write(const AData: TCryptoLibByteArray); overload;
    procedure Init(const AContext: TCryptoLibByteArray); virtual;
    function GenerateSignature(const APrivateKey: ISlhDsaPrivateKeyParameters;
      const ARandom: ISecureRandom): TCryptoLibByteArray;
    function VerifySignature(const APublicKey: ISlhDsaPublicKeyParameters;
      const ASignature: TCryptoLibByteArray): Boolean;
    procedure Reset;
  end;

  TSlhDsaSigner = class(TInterfacedObject, ISigner, ISlhDsaSigner)
  strict private
  var
    FBuffer: TSlhDsaSignerBuffer;
    FParameters: ISlhDsaParameters;
    FDeterministic: Boolean;
    FPrivateKey: ISlhDsaPrivateKeyParameters;
    FPublicKey: ISlhDsaPublicKeyParameters;
    FRandom: ISecureRandom;
    FEngine: ISlhDsaEngine;
    function GetEngine(const AKeyParameters: ISlhDsaParameters): ISlhDsaEngine;
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

{ TSlhDsaSignerBuffer }

procedure TSlhDsaSignerBuffer.EnsureCapacity(ANeeded: Int32);
begin
  if ANeeded <= System.Length(FBuffer) then
    Exit;
  System.SetLength(FBuffer, ANeeded + 256);
end;

procedure TSlhDsaSignerBuffer.Init(const AContext: TCryptoLibByteArray);
begin
  TruncateAndClear(0);
  WriteByte($00);
  WriteByte(Byte(System.Length(AContext)));
  if System.Length(AContext) > 0 then
    Write(AContext, 0, System.Length(AContext));
  FPrefixLength := FCount;
end;

procedure TSlhDsaSignerBuffer.Reset;
begin
  TruncateAndClear(FPrefixLength);
end;

procedure TSlhDsaSignerBuffer.TruncateAndClear(ANewLength: Int32);
begin
  TArrayUtilities.Fill(FBuffer, ANewLength, FCount, Byte(0));
  FCount := ANewLength;
end;

procedure TSlhDsaSignerBuffer.Write(const AData: TCryptoLibByteArray);
begin
  Write(AData, 0, System.Length(AData));
end;

procedure TSlhDsaSignerBuffer.Write(const AData: TCryptoLibByteArray; AOff, ALen: Int32);
begin
  EnsureCapacity(FCount + ALen);
  System.Move(AData[AOff], FBuffer[FCount], ALen);
  FCount := FCount + ALen;
end;

procedure TSlhDsaSignerBuffer.WriteByte(AValue: Byte);
begin
  EnsureCapacity(FCount + 1);
  FBuffer[FCount] := AValue;
  System.Inc(FCount);
end;

function TSlhDsaSignerBuffer.GenerateSignature(const APrivateKey: ISlhDsaPrivateKeyParameters;
  const ARandom: ISecureRandom): TCryptoLibByteArray;
var
  LPrivateKey: TSlhDsaPrivateKeyParameters;
  LOptRand: TCryptoLibByteArray;
  LN: Int32;
begin
  LPrivateKey := APrivateKey as TSlhDsaPrivateKeyParameters;
  if ARandom = nil then
    LOptRand := nil
  else
  begin
    LN := APrivateKey.Parameters.ParameterSet.N;
    System.SetLength(LOptRand, LN);
    ARandom.NextBytes(LOptRand);
  end;
  Result := LPrivateKey.SignRaw(LOptRand, FBuffer, 0, FCount);
  Reset;
end;

function TSlhDsaSignerBuffer.VerifySignature(const APublicKey: ISlhDsaPublicKeyParameters;
  const ASignature: TCryptoLibByteArray): Boolean;
var
  LPublicKey: TSlhDsaPublicKeyParameters;
begin
  LPublicKey := APublicKey as TSlhDsaPublicKeyParameters;
  Result := LPublicKey.VerifyRaw(FBuffer, 0, FCount, ASignature);
  Reset;
end;

{ TSlhDsaSigner }

constructor TSlhDsaSigner.Create(const AParameters: ISlhDsaParameters; ADeterministic: Boolean);
begin
  inherited Create;
  if AParameters = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersNil);
  if AParameters.IsPreHash then
    raise EArgumentCryptoLibException.CreateRes(@SCannotUseHashSlhDsa);
  FParameters := AParameters;
  FDeterministic := ADeterministic;
  FBuffer := TSlhDsaSignerBuffer.Create;
  FEngine := FParameters.ParameterSet.GetEngine;
end;

destructor TSlhDsaSigner.Destroy;
begin
  FBuffer.Free;
  inherited;
end;

function TSlhDsaSigner.GenerateSignature: TCryptoLibByteArray;
begin
  if FPrivateKey = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SNotInitializedForSign);
  Result := FBuffer.GenerateSignature(FPrivateKey, FRandom);
end;

function TSlhDsaSigner.GetAlgorithmName: String;
begin
  Result := FParameters.Name;
end;

function TSlhDsaSigner.GetEngine(const AKeyParameters: ISlhDsaParameters): ISlhDsaEngine;
begin
  if AKeyParameters.ParameterSet <> FParameters.ParameterSet then
    raise EArgumentCryptoLibException.CreateRes(@SMismatchingKeyParameterSet);
  Result := AKeyParameters.ParameterSet.GetEngine;
end;

function TSlhDsaSigner.GetMaxSignatureSize: Int32;
begin
  Result := FEngine.SignatureLength;
end;

procedure TSlhDsaSigner.Init(AForSigning: Boolean; const AParameters: ICipherParameters);
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

  FBuffer.Init(LProvidedContext);
end;

procedure TSlhDsaSigner.Reset;
begin
  FBuffer.Reset;
end;

procedure TSlhDsaSigner.Update(AInput: Byte);
begin
  FBuffer.WriteByte(AInput);
end;

procedure TSlhDsaSigner.BlockUpdate(const AInput: TCryptoLibByteArray; AInOff, AInLen: Int32);
begin
  FBuffer.Write(AInput, AInOff, AInLen);
end;

function TSlhDsaSigner.VerifySignature(const ASignature: TCryptoLibByteArray): Boolean;
begin
  if FPublicKey = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SNotInitializedForVerify);
  if FEngine.SignatureLength <> System.Length(ASignature) then
  begin
    Reset;
    Exit(False);
  end;
  Result := FBuffer.VerifySignature(FPublicKey, ASignature);
end;

end.
