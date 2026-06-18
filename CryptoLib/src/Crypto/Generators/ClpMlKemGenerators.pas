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

unit ClpMlKemGenerators;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsymmetricCipherKeyPair,
  ClpIMlKemGenerators,
  ClpIMlKemParameters,
  ClpMlKemParameters,
  ClpISecureRandom,
  ClpIKeyGenerationParameters,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpCryptoLibTypes;

type
  TMlKemKeyPairGenerator = class(TInterfacedObject, IMlKemKeyPairGenerator,
    IAsymmetricCipherKeyPairGenerator)
  strict private
  var
    FRandom: ISecureRandom;
    FParameters: IMlKemParameters;
  public
    constructor Create;
    procedure Init(const AParameters: IKeyGenerationParameters);
    function GenerateKeyPair(): IAsymmetricCipherKeyPair;
  end;

implementation

{ TMlKemKeyPairGenerator }

constructor TMlKemKeyPairGenerator.Create;
begin
  inherited Create;
end;

function TMlKemKeyPairGenerator.GenerateKeyPair: IAsymmetricCipherKeyPair;
var
  LSeed, LEncoding: TCryptoLibByteArray;
  LPrivateKey: IMlKemPrivateKeyParameters;
  LPublicKey: IMlKemPublicKeyParameters;
begin
  FParameters.ParameterSet.Engine.GenerateKemKeyPair(FRandom, LSeed, LEncoding);
  LPrivateKey := TMlKemPrivateKeyParameters.Create(FParameters, LSeed, LEncoding, TMlKemPrivateKeyFormat.SeedAndEncoding);
  LPublicKey := LPrivateKey.GetPublicKey();
  Result := TAsymmetricCipherKeyPair.Create(LPublicKey, LPrivateKey);
end;

procedure TMlKemKeyPairGenerator.Init(const AParameters: IKeyGenerationParameters);
var
  LGen: IMlKemKeyGenerationParameters;
begin
  LGen := AParameters as IMlKemKeyGenerationParameters;
  FRandom := AParameters.Random;
  FParameters := LGen.Parameters;
end;

end.
