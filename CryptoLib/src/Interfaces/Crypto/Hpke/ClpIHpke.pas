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

unit ClpIHpke;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpHpkeTypes,
  ClpIAsymmetricKeyParameter,
  ClpIAsymmetricCipherKeyPair,
  ClpIHpkeContext,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Hybrid Public Key Encryption (RFC 9180). A single instance pins a
  /// (mode, KEM, KDF, AEAD) suite and exposes the setup, seal/open and export
  /// operations plus KEM-aware key (de)serialization.
  /// </summary>
  IHpke = interface(IInterface)
    ['{1F0C4A82-7B36-4D19-9E58-6C2A0D3B7E55}']

    function GetEncSize(): Int32;
    function GetAeadId(): THpkeAeadId;

    function GeneratePrivateKey(): IAsymmetricCipherKeyPair;
    function DeriveKeyPair(const AIkm: TCryptoLibByteArray)
      : IAsymmetricCipherKeyPair;

    function SerializePublicKey(const APk: IAsymmetricKeyParameter)
      : TCryptoLibByteArray;
    function SerializePrivateKey(const ASk: IAsymmetricKeyParameter)
      : TCryptoLibByteArray;
    function DeserializePublicKey(const APkEncoded: TCryptoLibByteArray)
      : IAsymmetricKeyParameter;
    function DeserializePrivateKey(const ASkEncoded,
      APkEncoded: TCryptoLibByteArray): IAsymmetricCipherKeyPair;

    function SetupBaseS(const APkR: IAsymmetricKeyParameter;
      const AInfo: TCryptoLibByteArray): IHpkeContextWithEncapsulation;
    function SetupBaseR(const AEnc: TCryptoLibByteArray;
      const ASkR: IAsymmetricCipherKeyPair; const AInfo: TCryptoLibByteArray)
      : IHpkeContext;

    function SetupPskS(const APkR: IAsymmetricKeyParameter;
      const AInfo, APsk, APskId: TCryptoLibByteArray)
      : IHpkeContextWithEncapsulation;
    function SetupPskR(const AEnc: TCryptoLibByteArray;
      const ASkR: IAsymmetricCipherKeyPair;
      const AInfo, APsk, APskId: TCryptoLibByteArray): IHpkeContext;

    function SetupAuthS(const APkR: IAsymmetricKeyParameter;
      const AInfo: TCryptoLibByteArray; const ASkS: IAsymmetricCipherKeyPair)
      : IHpkeContextWithEncapsulation;
    function SetupAuthR(const AEnc: TCryptoLibByteArray;
      const ASkR: IAsymmetricCipherKeyPair; const AInfo: TCryptoLibByteArray;
      const APkS: IAsymmetricKeyParameter): IHpkeContext;

    function SetupAuthPskS(const APkR: IAsymmetricKeyParameter;
      const AInfo, APsk, APskId: TCryptoLibByteArray;
      const ASkS: IAsymmetricCipherKeyPair): IHpkeContextWithEncapsulation;
    function SetupAuthPskR(const AEnc: TCryptoLibByteArray;
      const ASkR: IAsymmetricCipherKeyPair;
      const AInfo, APsk, APskId: TCryptoLibByteArray;
      const APkS: IAsymmetricKeyParameter): IHpkeContext;

    procedure Seal(const APkR: IAsymmetricKeyParameter;
      const AInfo, AAad, APt, APsk, APskId: TCryptoLibByteArray;
      const ASkS: IAsymmetricCipherKeyPair;
      out ACt, AEnc: TCryptoLibByteArray);

    function Open(const AEnc: TCryptoLibByteArray;
      const ASkR: IAsymmetricCipherKeyPair;
      const AInfo, AAad, ACt, APsk, APskId: TCryptoLibByteArray;
      const APkS: IAsymmetricKeyParameter): TCryptoLibByteArray;

    procedure SendExport(const APkR: IAsymmetricKeyParameter;
      const AInfo, AExporterContext: TCryptoLibByteArray; AL: Int32;
      const APsk, APskId: TCryptoLibByteArray;
      const ASkS: IAsymmetricCipherKeyPair;
      out AEnc, AExported: TCryptoLibByteArray);

    function ReceiveExport(const AEnc: TCryptoLibByteArray;
      const ASkR: IAsymmetricCipherKeyPair;
      const AInfo, AExporterContext: TCryptoLibByteArray; AL: Int32;
      const APsk, APskId: TCryptoLibByteArray;
      const APkS: IAsymmetricKeyParameter): TCryptoLibByteArray;

    property EncSize: Int32 read GetEncSize;
    property AeadId: THpkeAeadId read GetAeadId;
  end;

implementation

end.
