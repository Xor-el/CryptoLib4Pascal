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

unit ClpCipherKeyGeneratorFactory;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpNistObjectIdentifiers,
  ClpCipherKeyGenerator,
  ClpICipherKeyGenerator,
  ClpKeyGenerationParameters,
  ClpIKeyGenerationParameters,
  ClpISecureRandom,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Factory for creating CipherKeyGenerator instances by OID.
  /// </summary>
  TCipherKeyGeneratorFactory = class sealed(TObject)
  strict private
    class function CreateCipherKeyGenerator(const ARandom: ISecureRandom;
      AKeySize: Int32): ICipherKeyGenerator; static;
  public
    /// <summary>
    /// Create a key generator for the passed in Object Identifier.
    /// </summary>
    class function CreateKeyGenerator(const AAlgorithm: IDerObjectIdentifier;
      const ARandom: ISecureRandom): ICipherKeyGenerator; static;
  end;

implementation

{ TCipherKeyGeneratorFactory }

class function TCipherKeyGeneratorFactory.CreateKeyGenerator(
  const AAlgorithm: IDerObjectIdentifier;
  const ARandom: ISecureRandom): ICipherKeyGenerator;
begin
  if TNistObjectIdentifiers.IdAes128Cbc.Equals(AAlgorithm) then
    Result := CreateCipherKeyGenerator(ARandom, 128)
  else if TNistObjectIdentifiers.IdAes192Cbc.Equals(AAlgorithm) then
    Result := CreateCipherKeyGenerator(ARandom, 192)
  else if TNistObjectIdentifiers.IdAes256Cbc.Equals(AAlgorithm) then
    Result := CreateCipherKeyGenerator(ARandom, 256)
  else
    raise EInvalidOperationCryptoLibException.Create('cannot recognise cipher: ' + AAlgorithm.Id);
end;

class function TCipherKeyGeneratorFactory.CreateCipherKeyGenerator(
  const ARandom: ISecureRandom; AKeySize: Int32): ICipherKeyGenerator;
var
  LKeyGen: ICipherKeyGenerator;
begin
  LKeyGen := TCipherKeyGenerator.Create() as ICipherKeyGenerator;
  LKeyGen.Init(TKeyGenerationParameters.Create(ARandom, AKeySize) as IKeyGenerationParameters);
  Result := LKeyGen;
end;

end.
