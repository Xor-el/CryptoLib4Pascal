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

unit ClpEd448Generators;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsymmetricCipherKeyPair,
  ClpIEd448Generators,
  ClpIEd448Parameters,
  ClpEd448Parameters,
  ClpISecureRandom,
  ClpIKeyGenerationParameters,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPairGenerator;

type
  /// <summary>
  /// Key-pair generator for Ed448 (RFC 8032). Only the <see cref="ISecureRandom"/> from the supplied
  /// key-generation parameters is used; the 57-byte seed is drawn directly from it.
  /// </summary>
  TEd448KeyPairGenerator = class sealed(TInterfacedObject,
    IEd448KeyPairGenerator, IAsymmetricCipherKeyPairGenerator)
  strict private
    FRandom: ISecureRandom;
  public
    /// <summary>Capture the <see cref="ISecureRandom"/> that will source the seed.</summary>
    procedure Init(const AParameters: IKeyGenerationParameters);
    /// <summary>Generate a fresh Ed448 key pair.</summary>
    function GenerateKeyPair(): IAsymmetricCipherKeyPair;
  end;

implementation

function TEd448KeyPairGenerator.GenerateKeyPair: IAsymmetricCipherKeyPair;
var
  LPrivateKey: IEd448PrivateKeyParameters;
  LPublicKey: IEd448PublicKeyParameters;
begin
  LPrivateKey := TEd448PrivateKeyParameters.Create(FRandom);
  LPublicKey := LPrivateKey.GeneratePublicKey();
  Result := TAsymmetricCipherKeyPair.Create(LPublicKey, LPrivateKey);
end;

procedure TEd448KeyPairGenerator.Init(const AParameters: IKeyGenerationParameters);
begin
  FRandom := AParameters.Random;
end;

end.
