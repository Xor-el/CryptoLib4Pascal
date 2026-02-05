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

unit ClpX25519Generators;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsymmetricCipherKeyPair,
  ClpIX25519Generators,
  ClpIX25519Parameters,
  ClpX25519Parameters,
  ClpISecureRandom,
  ClpIKeyGenerationParameters,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPairGenerator;

type
  TX25519KeyPairGenerator = class sealed(TInterfacedObject,
    IX25519KeyPairGenerator, IAsymmetricCipherKeyPairGenerator)
  strict private
    FRandom: ISecureRandom;
  public
    procedure Init(const AParameters: IKeyGenerationParameters);
    function GenerateKeyPair(): IAsymmetricCipherKeyPair;
  end;

implementation

function TX25519KeyPairGenerator.GenerateKeyPair: IAsymmetricCipherKeyPair;
var
  LPrivateKey: IX25519PrivateKeyParameters;
  LPublicKey: IX25519PublicKeyParameters;
begin
  LPrivateKey := TX25519PrivateKeyParameters.Create(FRandom);
  LPublicKey := LPrivateKey.GeneratePublicKey();
  Result := TAsymmetricCipherKeyPair.Create(LPublicKey, LPrivateKey);
end;

procedure TX25519KeyPairGenerator.Init(const AParameters: IKeyGenerationParameters);
begin
  FRandom := AParameters.Random;
end;

end.
