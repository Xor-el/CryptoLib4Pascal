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

unit ClpECGenerators;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpBitOperations,
  ClpCryptoLibTypes,
  ClpECParameters,
  ClpIECGenerators,
  ClpIAsn1Objects,
  ClpWNafUtilities,
  ClpIKeyGenerationParameters,
  ClpIECParameters,
  ClpIECCommon,
  ClpMultipliers,
  ClpSecObjectIdentifiers,
  ClpCustomNamedCurves,
  ClpECNamedCurveTable,
  ClpX9ObjectIdentifiers,
  ClpIX9ECAsn1Objects,
  ClpAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPair,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpIAsymmetricCipherKeyPairGenerator;

resourcestring
  SAlgorithmNil = 'Algorithm Cannot be Empty';
  SInvalidKeySize = 'Unknown Key Size "%d"';

type
  TECKeyPairGenerator = class sealed(TInterfacedObject, IECKeyPairGenerator,
    IAsymmetricCipherKeyPairGenerator)
  strict private
    FAlgorithm: String;
    FParameters: IECDomainParameters;
    FRandom: ISecureRandom;
  strict protected
    function CreateBasePointMultiplier(): IECMultiplier; virtual;
  public
    constructor Create(); overload;
    constructor Create(const AAlgorithm: String); overload;
    procedure Init(const AParameters: IKeyGenerationParameters);
    function GenerateKeyPair(): IAsymmetricCipherKeyPair;
    class function FindECCurveByOid(const AOid: IDerObjectIdentifier): IX9ECParameters; static;
    class function GetCorrespondingPublicKey(const APrivKey: IECPrivateKeyParameters): IECPublicKeyParameters; static;
  end;

implementation

constructor TECKeyPairGenerator.Create;
begin
  Create('EC');
end;

constructor TECKeyPairGenerator.Create(const AAlgorithm: String);
begin
  if AAlgorithm = '' then
    raise EArgumentNilCryptoLibException.CreateRes(@SAlgorithmNil);
  FAlgorithm := TECKeyParameters.VerifyAlgorithmName(AAlgorithm);
end;

function TECKeyPairGenerator.CreateBasePointMultiplier: IECMultiplier;
begin
  Result := TFixedPointCombMultiplier.Create();
end;

class function TECKeyPairGenerator.FindECCurveByOid(const AOid: IDerObjectIdentifier): IX9ECParameters;
var
  LEcP: IX9ECParameters;
begin
  LEcP := TCustomNamedCurves.GetByOid(AOid);
  if LEcP = nil then
    LEcP := TECNamedCurveTable.GetByOid(AOid);
  Result := LEcP;
end;

function TECKeyPairGenerator.GenerateKeyPair: IAsymmetricCipherKeyPair;
var
  LN, LD: TBigInteger;
  LMinWeight: Int32;
  LQ: IECPoint;
begin
  LN := FParameters.N;
  LMinWeight := TBitOperations.Asr32(LN.BitLength, 2);
  while True do
  begin
    LD := TBigInteger.Create(LN.BitLength, FRandom);
    if (LD.CompareTo(TBigInteger.One) < 0) or (LD.CompareTo(LN) >= 0) then
      Continue;
    if TWNafUtilities.GetNafWeight(LD) < LMinWeight then
      Continue;
    Break;
  end;
  LQ := CreateBasePointMultiplier().Multiply(FParameters.G, LD);
  Result := TAsymmetricCipherKeyPair.Create(
    TECPublicKeyParameters.Create(FAlgorithm, LQ, FParameters) as IECPublicKeyParameters,
    TECPrivateKeyParameters.Create(FAlgorithm, LD, FParameters) as IECPrivateKeyParameters);
end;

class function TECKeyPairGenerator.GetCorrespondingPublicKey(const APrivKey: IECPrivateKeyParameters): IECPublicKeyParameters;
var
  LEc: IECDomainParameters;
  LQ: IECPoint;
begin
  LEc := APrivKey.Parameters;
  LQ := (TFixedPointCombMultiplier.Create() as IECMultiplier).Multiply(LEc.G, APrivKey.D);
  Result := TECPublicKeyParameters.Create(APrivKey.AlgorithmName, LQ, LEc);
end;

procedure TECKeyPairGenerator.Init(const AParameters: IKeyGenerationParameters);
var
  LEcP: IECKeyGenerationParameters;
  LEcps: IX9ECParameters;
  LOid: IDerObjectIdentifier;
begin
  if Supports(AParameters, IECKeyGenerationParameters, LEcP) then
    FParameters := LEcP.DomainParameters
  else
  begin
    case AParameters.Strength of
      192: LOid := TX9ObjectIdentifiers.Prime192v1;
      224: LOid := TSecObjectIdentifiers.SecP224r1;
      239: LOid := TX9ObjectIdentifiers.Prime239v1;
      256: LOid := TX9ObjectIdentifiers.Prime256v1;
      384: LOid := TSecObjectIdentifiers.SecP384r1;
      521: LOid := TSecObjectIdentifiers.SecP521r1;
    else
      raise EInvalidParameterCryptoLibException.CreateResFmt(@SInvalidKeySize, [AParameters.Strength]);
    end;
    LEcps := FindECCurveByOid(LOid);
    FParameters := TECDomainParameters.Create(LEcps.Curve, LEcps.G, LEcps.N, LEcps.H, LEcps.GetSeed());
  end;
  FRandom := AParameters.Random;
  if FRandom = nil then
    FRandom := TSecureRandom.Create();
end;

end.
