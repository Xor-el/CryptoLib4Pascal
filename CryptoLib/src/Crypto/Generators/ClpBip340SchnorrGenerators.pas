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

unit ClpBip340SchnorrGenerators;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsymmetricCipherKeyPair,
  ClpIBip340SchnorrGenerators,
  ClpIBip340SchnorrParameters,
  ClpBip340SchnorrParameters,
  ClpISecureRandom,
  ClpIKeyGenerationParameters,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPairGenerator;

type
  TBip340SchnorrKeyPairGenerator = class(TInterfacedObject,
    IBip340SchnorrKeyPairGenerator, IAsymmetricCipherKeyPairGenerator)
  strict private
    FRandom: ISecureRandom;
  public
    constructor Create();
    procedure Init(const AParameters: IKeyGenerationParameters);
    function GenerateKeyPair(): IAsymmetricCipherKeyPair;
  end;

implementation

constructor TBip340SchnorrKeyPairGenerator.Create;
begin
  inherited Create();
end;

function TBip340SchnorrKeyPairGenerator.GenerateKeyPair: IAsymmetricCipherKeyPair;
var
  LPrivateKey: IBip340SchnorrPrivateKeyParameters;
  LPublicKey: IBip340SchnorrPublicKeyParameters;
begin
  LPrivateKey := TBip340SchnorrPrivateKeyParameters.Create(FRandom);
  LPublicKey := LPrivateKey.GeneratePublicKey();
  Result := TAsymmetricCipherKeyPair.Create(LPublicKey, LPrivateKey);
end;

procedure TBip340SchnorrKeyPairGenerator.Init(const AParameters: IKeyGenerationParameters);
begin
  FRandom := AParameters.Random;
end;

end.
