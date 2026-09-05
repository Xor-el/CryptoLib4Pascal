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

unit ClpIHpkeKem;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsymmetricKeyParameter,
  ClpIAsymmetricCipherKeyPair,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// HPKE Key Encapsulation Mechanism (RFC 9180 sec. 4). Encap / AuthEncap
  /// return the shared secret and the encapsulation via out parameters.
  /// </summary>
  IHpkeKem = interface(IInterface)
    ['{7E1D0A62-4C39-4F55-8B70-9A2C6D3E1F44}']

    function GeneratePrivateKey(): IAsymmetricCipherKeyPair;

    function DeriveKeyPair(const AIkm: TCryptoLibByteArray)
      : IAsymmetricCipherKeyPair;

    procedure Encap(const APkR: IAsymmetricKeyParameter;
      out ASharedSecret, AEnc: TCryptoLibByteArray); overload;

    procedure Encap(const APkR: IAsymmetricKeyParameter;
      const AKpE: IAsymmetricCipherKeyPair;
      out ASharedSecret, AEnc: TCryptoLibByteArray); overload;

    procedure AuthEncap(const APkR: IAsymmetricKeyParameter;
      const AKpS: IAsymmetricCipherKeyPair;
      out ASharedSecret, AEnc: TCryptoLibByteArray);

    function Decap(const AEnc: TCryptoLibByteArray;
      const AKpR: IAsymmetricCipherKeyPair): TCryptoLibByteArray;

    function AuthDecap(const AEnc: TCryptoLibByteArray;
      const AKpR: IAsymmetricCipherKeyPair; const APkS: IAsymmetricKeyParameter)
      : TCryptoLibByteArray;

    function SerializePublicKey(const AKey: IAsymmetricKeyParameter)
      : TCryptoLibByteArray;

    function SerializePrivateKey(const AKey: IAsymmetricKeyParameter)
      : TCryptoLibByteArray;

    function DeserializePublicKey(const APkEncoded: TCryptoLibByteArray)
      : IAsymmetricKeyParameter;

    function DeserializePrivateKey(const ASkEncoded,
      APkEncoded: TCryptoLibByteArray): IAsymmetricCipherKeyPair;

    function GetEncryptionSize(): Int32;

    property EncryptionSize: Int32 read GetEncryptionSize;
  end;

implementation

end.
