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

unit ClpDHGenerators;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIDHParameters,
  ClpIDHGenerators,
  ClpDHParameters,
  ClpAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPair,
  ClpIKeyGenerationParameters,
  ClpDHKeyGeneratorHelper,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpISecureRandom,
  ClpDHParametersHelper,
  ClpBigInteger,
  ClpCryptoLibTypes;

resourcestring
  SParametersCannotBeNil = '"parameters" Cannot Be Nil';

type
  TDHKeyPairGenerator = class sealed(TInterfacedObject,
    IAsymmetricCipherKeyPairGenerator, IDHKeyPairGenerator)
  strict private
    FParam: IDHKeyGenerationParameters;
  public
    procedure Init(const AParameters: IKeyGenerationParameters);
    function GenerateKeyPair(): IAsymmetricCipherKeyPair;
  end;

  TDHBasicKeyPairGenerator = class sealed(TInterfacedObject,
    IAsymmetricCipherKeyPairGenerator, IDHBasicKeyPairGenerator)
  strict private
    FParam: IDHKeyGenerationParameters;
  public
    procedure Init(const AParameters: IKeyGenerationParameters);
    function GenerateKeyPair(): IAsymmetricCipherKeyPair;
  end;

  TDHParametersGenerator = class(TInterfacedObject, IDHParametersGenerator)
  strict private
    FCertainty, FSize: Int32;
    FRandom: ISecureRandom;
  public
    procedure Init(ASize, ACertainty: Int32; const ARandom: ISecureRandom);
    function GenerateParameters(): IDHParameters; virtual;
  end;

implementation

function TDHKeyPairGenerator.GenerateKeyPair: IAsymmetricCipherKeyPair;
var
  LDhp: IDHParameters;
  LX, LY: TBigInteger;
begin
  LDhp := FParam.Parameters;
  LX := TDHKeyGeneratorHelper.CalculatePrivate(LDhp, FParam.Random);
  LY := TDHKeyGeneratorHelper.CalculatePublic(LDhp, LX);
  Result := TAsymmetricCipherKeyPair.Create(TDHPublicKeyParameters.Create(LY,
    LDhp) as IDHPublicKeyParameters, TDHPrivateKeyParameters.Create(LX, LDhp)
    as IDHPrivateKeyParameters);
end;

procedure TDHKeyPairGenerator.Init(const AParameters: IKeyGenerationParameters);
begin
  if AParameters = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersCannotBeNil);
  if not Supports(AParameters, IDHKeyGenerationParameters, FParam) then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersCannotBeNil);
end;

function TDHBasicKeyPairGenerator.GenerateKeyPair: IAsymmetricCipherKeyPair;
var
  LDhp: IDHParameters;
  LX, LY: TBigInteger;
begin
  LDhp := FParam.Parameters;
  LX := TDHKeyGeneratorHelper.CalculatePrivate(LDhp, FParam.Random);
  LY := TDHKeyGeneratorHelper.CalculatePublic(LDhp, LX);
  Result := TAsymmetricCipherKeyPair.Create(TDHPublicKeyParameters.Create(LY,
    LDhp) as IDHPublicKeyParameters, TDHPrivateKeyParameters.Create(LX, LDhp)
    as IDHPrivateKeyParameters);
end;

procedure TDHBasicKeyPairGenerator.Init(const AParameters: IKeyGenerationParameters);
begin
  if AParameters = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersCannotBeNil);
  if not Supports(AParameters, IDHKeyGenerationParameters, FParam) then
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersCannotBeNil);
end;

function TDHParametersGenerator.GenerateParameters: IDHParameters;
var
  LSafePrimes: TCryptoLibGenericArray<TBigInteger>;
  LP, LQ, LG: TBigInteger;
begin
  LSafePrimes := TDHParametersHelper.GenerateSafePrimes(FSize, FCertainty, FRandom);
  LP := LSafePrimes[0];
  LQ := LSafePrimes[1];
  LG := TDHParametersHelper.SelectGenerator(LP, LQ, FRandom);
  Result := TDHParameters.Create(LP, LG, LQ, TBigInteger.Two, nil);
end;

procedure TDHParametersGenerator.Init(ASize, ACertainty: Int32;
  const ARandom: ISecureRandom);
begin
  FSize := ASize;
  FCertainty := ACertainty;
  FRandom := ARandom;
end;

end.
