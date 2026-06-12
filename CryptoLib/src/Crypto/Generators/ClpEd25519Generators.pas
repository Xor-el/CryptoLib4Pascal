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

unit ClpEd25519Generators;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsymmetricCipherKeyPair,
  ClpIEd25519Generators,
  ClpIEd25519Parameters,
  ClpEd25519Parameters,
  ClpISecureRandom,
  ClpIKeyGenerationParameters,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPairGenerator;

type
  /// <summary>
  /// Key-pair generator for Ed25519 (RFC 8032). Only the <see cref="ISecureRandom"/> from the supplied
  /// key-generation parameters is used; the 32-byte seed is drawn directly from it.
  /// </summary>
  TEd25519KeyPairGenerator = class(TInterfacedObject, IEd25519KeyPairGenerator,
    IAsymmetricCipherKeyPairGenerator)
  strict private
    FRandom: ISecureRandom;
  public
    /// <summary>Construct an uninitialised generator; call <see cref="Init"/> before use.</summary>
    constructor Create();
    /// <summary>Capture the <see cref="ISecureRandom"/> that will source the seed.</summary>
    procedure Init(const AParameters: IKeyGenerationParameters);
    /// <summary>Generate a fresh Ed25519 key pair.</summary>
    function GenerateKeyPair(): IAsymmetricCipherKeyPair;
  end;

implementation

constructor TEd25519KeyPairGenerator.Create;
begin
  inherited Create();
end;

function TEd25519KeyPairGenerator.GenerateKeyPair: IAsymmetricCipherKeyPair;
var
  LPrivateKey: IEd25519PrivateKeyParameters;
  LPublicKey: IEd25519PublicKeyParameters;
begin
  LPrivateKey := TEd25519PrivateKeyParameters.Create(FRandom);
  LPublicKey := LPrivateKey.GeneratePublicKey();
  Result := TAsymmetricCipherKeyPair.Create(LPublicKey, LPrivateKey);
end;

procedure TEd25519KeyPairGenerator.Init(const AParameters: IKeyGenerationParameters);
begin
  FRandom := AParameters.Random;
end;

end.
