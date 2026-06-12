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

unit ClpX448Generators;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsymmetricCipherKeyPair,
  ClpIX448Generators,
  ClpIX448Parameters,
  ClpX448Parameters,
  ClpISecureRandom,
  ClpIKeyGenerationParameters,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPairGenerator;

type
  /// <summary>
  /// Key-pair generator for X448 (RFC 7748). Only the <see cref="ISecureRandom"/> from the supplied
  /// key-generation parameters is used; the 56-byte clamped scalar is drawn directly from it.
  /// </summary>
  TX448KeyPairGenerator = class sealed(TInterfacedObject,
    IX448KeyPairGenerator, IAsymmetricCipherKeyPairGenerator)
  strict private
    FRandom: ISecureRandom;
  public
    /// <summary>Capture the <see cref="ISecureRandom"/> that will source the scalar.</summary>
    procedure Init(const AParameters: IKeyGenerationParameters);
    /// <summary>Generate a fresh X448 key pair.</summary>
    function GenerateKeyPair(): IAsymmetricCipherKeyPair;
  end;

implementation

function TX448KeyPairGenerator.GenerateKeyPair: IAsymmetricCipherKeyPair;
var
  LPrivateKey: IX448PrivateKeyParameters;
  LPublicKey: IX448PublicKeyParameters;
begin
  LPrivateKey := TX448PrivateKeyParameters.Create(FRandom);
  LPublicKey := LPrivateKey.GeneratePublicKey();
  Result := TAsymmetricCipherKeyPair.Create(LPublicKey, LPrivateKey);
end;

procedure TX448KeyPairGenerator.Init(const AParameters: IKeyGenerationParameters);
begin
  FRandom := AParameters.Random;
end;

end.
