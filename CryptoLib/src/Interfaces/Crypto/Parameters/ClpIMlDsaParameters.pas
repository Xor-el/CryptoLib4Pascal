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

unit ClpIMlDsaParameters;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIMlDsaEngine,
  ClpIAsymmetricKeyParameter,
  ClpIKeyGenerationParameters,
  ClpISecureRandom,
  ClpCryptoLibTypes;

type
  IMlDsaParameterSet = interface(IInterface)
    ['{A1B2C3D4-E5F6-4789-A012-3456789ABCDE}']
    function GetName: String;
    function GetPrivateKeyLength: Int32;
    function GetPublicKeyLength: Int32;
    function GetSeedLength: Int32;
    function GetEngine(const ARandom: ISecureRandom): IMlDsaEngine;
    property Name: String read GetName;
    property PrivateKeyLength: Int32 read GetPrivateKeyLength;
    property PublicKeyLength: Int32 read GetPublicKeyLength;
    property SeedLength: Int32 read GetSeedLength;
  end;
  IMlDsaParameters = interface(IInterface)
    ['{B2C3D4E5-F6A7-4890-B123-456789ABCDEF}']
    function GetName: String;
    function GetParameterSet: IMlDsaParameterSet;
    function GetOid: IDerObjectIdentifier;
    function GetPreHashOid: IDerObjectIdentifier;
    function GetIsPreHash: Boolean;
    property Name: String read GetName;
    property ParameterSet: IMlDsaParameterSet read GetParameterSet;
    property Oid: IDerObjectIdentifier read GetOid;
    property PreHashOid: IDerObjectIdentifier read GetPreHashOid;
    property IsPreHash: Boolean read GetIsPreHash;
  end;
  IMlDsaKeyParameters = interface(IAsymmetricKeyParameter)
    ['{C3D4E5F6-A7B8-4901-C234-56789ABCDEF0}']
    function GetParameters: IMlDsaParameters;
    property Parameters: IMlDsaParameters read GetParameters;
  end;
  IMlDsaPublicKeyParameters = interface(IMlDsaKeyParameters)
    ['{D4E5F6A7-B8C9-4012-D345-6789ABCDEF01}']
    function GetEncoded(): TCryptoLibByteArray;
    function GetRho: TCryptoLibByteArray;
    function GetT1: TCryptoLibByteArray;
    function GetPublicKeyHash: TCryptoLibByteArray;
  end;
  TMlDsaPrivateKeyFormat = (
    SeedOnly,
    EncodingOnly,
    SeedAndEncoding);
  IMlDsaPrivateKeyParameters = interface(IMlDsaKeyParameters)
    ['{E5F6A7B8-C9D0-4123-E456-789ABCDEF012}']
    function GetEncoded(): TCryptoLibByteArray;
    function GetSeed(): TCryptoLibByteArray;
    function GetPublicKey(): IMlDsaPublicKeyParameters;
    function GetPublicKeyEncoded(): TCryptoLibByteArray;
    function GetPreferredFormat: TMlDsaPrivateKeyFormat;
    function WithPreferredFormat(AFormat: TMlDsaPrivateKeyFormat): IMlDsaPrivateKeyParameters;
    function GetRho: TCryptoLibByteArray;
    function GetK: TCryptoLibByteArray;
    function GetTr: TCryptoLibByteArray;
    function GetS1: TCryptoLibByteArray;
    function GetS2: TCryptoLibByteArray;
    function GetT0: TCryptoLibByteArray;
    property PreferredFormat: TMlDsaPrivateKeyFormat read GetPreferredFormat;
  end;
  IMlDsaKeyGenerationParameters = interface(IKeyGenerationParameters)
    ['{F6A7B8C9-D0E1-4234-F567-89ABCDEF0123}']
    function GetParameters: IMlDsaParameters;
    property Parameters: IMlDsaParameters read GetParameters;
  end;

implementation
end.
