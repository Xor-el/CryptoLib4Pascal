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
  /// <summary>
  /// Key-pair generator for X25519 (RFC 7748). Only the <see cref="ISecureRandom"/> from the supplied
  /// key-generation parameters is used; the 32-byte clamped scalar is drawn directly from it.
  /// </summary>
  TX25519KeyPairGenerator = class sealed(TInterfacedObject,
    IX25519KeyPairGenerator, IAsymmetricCipherKeyPairGenerator)
  strict private
    FRandom: ISecureRandom;
  public
    /// <summary>Capture the <see cref="ISecureRandom"/> that will source the scalar.</summary>
    procedure Init(const AParameters: IKeyGenerationParameters);
    /// <summary>Generate a fresh X25519 key pair.</summary>
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
