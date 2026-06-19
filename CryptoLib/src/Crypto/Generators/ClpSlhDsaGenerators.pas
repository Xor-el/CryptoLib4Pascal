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

unit ClpSlhDsaGenerators;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsymmetricCipherKeyPair,
  ClpISlhDsaGenerators,
  ClpISlhDsaParameters,
  ClpSlhDsaParameters,
  ClpSlhDsaCore,
  ClpISlhDsaEngine,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpIKeyGenerationParameters,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpCryptoLibTypes;

type
  TSlhDsaKeyPairGenerator = class(TInterfacedObject, ISlhDsaKeyPairGenerator,
    IAsymmetricCipherKeyPairGenerator)
  strict private
  var
    FRandom: ISecureRandom;
    FParameters: ISlhDsaParameters;
    function SecRand(AN: Int32): TCryptoLibByteArray;
  public
    constructor Create;
    procedure Init(const AParameters: IKeyGenerationParameters);
    function GenerateKeyPair: IAsymmetricCipherKeyPair;
  end;

implementation

{ TSlhDsaKeyPairGenerator }

constructor TSlhDsaKeyPairGenerator.Create;
begin
  inherited Create;
end;

function TSlhDsaKeyPairGenerator.GenerateKeyPair: IAsymmetricCipherKeyPair;
var
  LEngine: ISlhDsaEngine;
  LSkSeed, LSkPrf, LPkSeed: TCryptoLibByteArray;
  LSk: TSlhDsaSK;
  LPk: TSlhDsaPK;
  LHt: TSlhDsaHT;
  LPrivateKey: ISlhDsaPrivateKeyParameters;
  LPublicKey: ISlhDsaPublicKeyParameters;
begin
  LEngine := FParameters.ParameterSet.GetEngine;
  LSkSeed := SecRand(LEngine.N);
  LSkPrf := SecRand(LEngine.N);
  LPkSeed := SecRand(LEngine.N);

  LSk.Seed := LSkSeed;
  LSk.Prf := LSkPrf;

  LEngine.Init(LPkSeed);
  LHt := TSlhDsaHT.Create(LEngine, LSk.Seed, LPkSeed);
  try
    LPk.Seed := LPkSeed;
    LPk.Root := LHt.GetHTPubKey;
  finally
    LHt.Free;
  end;

  LPrivateKey := TSlhDsaPrivateKeyParameters.Create(FParameters, LSk, LPk);
  LPublicKey := TSlhDsaPublicKeyParameters.Create(FParameters, LPk);
  Result := TAsymmetricCipherKeyPair.Create(LPublicKey, LPrivateKey);
end;

procedure TSlhDsaKeyPairGenerator.Init(const AParameters: IKeyGenerationParameters);
var
  LGen: ISlhDsaKeyGenerationParameters;
begin
  LGen := AParameters as ISlhDsaKeyGenerationParameters;
  FRandom := AParameters.Random;
  FParameters := LGen.Parameters;
end;

function TSlhDsaKeyPairGenerator.SecRand(AN: Int32): TCryptoLibByteArray;
begin
  System.SetLength(Result, AN);
  FRandom.NextBytes(Result);
end;

end.
