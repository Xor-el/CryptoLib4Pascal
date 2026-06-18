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

unit ClpMlDsaGenerators;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsymmetricCipherKeyPair,
  ClpIMlDsaGenerators,
  ClpIMlDsaParameters,
  ClpIMlDsaEngine,
  ClpMlDsaParameters,
  ClpISecureRandom,
  ClpIKeyGenerationParameters,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpCryptoLibTypes;

type
  TMlDsaKeyPairGenerator = class(TInterfacedObject, IMlDsaKeyPairGenerator,
    IAsymmetricCipherKeyPairGenerator)
  strict private
  var
    FRandom: ISecureRandom;
    FParameters: IMlDsaParameters;
  public
    constructor Create;
    procedure Init(const AParameters: IKeyGenerationParameters);
    function GenerateKeyPair(): IAsymmetricCipherKeyPair;
  end;

implementation

{ TMlDsaKeyPairGenerator }

constructor TMlDsaKeyPairGenerator.Create;
begin
  inherited Create;
end;

function TMlDsaKeyPairGenerator.GenerateKeyPair: IAsymmetricCipherKeyPair;
var
  LEngine: IMlDsaEngine;
  LSeed, LRho, LK, LTr, LS1, LS2, LT0, LT1: TCryptoLibByteArray;
  LPrivateKey: IMlDsaPrivateKeyParameters;
  LPublicKey: IMlDsaPublicKeyParameters;
begin
  LEngine := FParameters.ParameterSet.GetEngine(FRandom);
  LEngine.GenerateKeyPair(FRandom, LSeed, LRho, LK, LTr, LS1, LS2, LT0, LT1);
  LPrivateKey := TMlDsaPrivateKeyParameters.Create(FParameters, LRho, LK, LTr, LS1, LS2, LT0, LT1,
    LSeed, TMlDsaPrivateKeyFormat.SeedAndEncoding);
  LPublicKey := TMlDsaPublicKeyParameters.Create(FParameters, LRho, LT1);
  Result := TAsymmetricCipherKeyPair.Create(LPublicKey, LPrivateKey);
end;

procedure TMlDsaKeyPairGenerator.Init(const AParameters: IKeyGenerationParameters);
var
  LGen: IMlDsaKeyGenerationParameters;
begin
  LGen := AParameters as IMlDsaKeyGenerationParameters;
  FRandom := AParameters.Random;
  FParameters := LGen.Parameters;
end;

end.
