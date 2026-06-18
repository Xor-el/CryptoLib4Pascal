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

unit ClpIMlKemParameters;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIMlKemEngine,
  ClpIAsymmetricKeyParameter,
  ClpIKeyGenerationParameters,
  ClpCryptoLibTypes;

type
  IMlKemParameterSet = interface(IInterface)
    ['{E5F6A7B8-C9D0-4E1F-2A3B-4C5D6E7F8A9B}']
    function GetName: String;
    function GetEncapsulationLength: Int32;
    function GetSecretLength: Int32;
    function GetEngine: IMlKemEngine;
    property Name: String read GetName;
    property EncapsulationLength: Int32 read GetEncapsulationLength;
    property SecretLength: Int32 read GetSecretLength;
    property Engine: IMlKemEngine read GetEngine;
  end;

  IMlKemParameters = interface(IInterface)
    ['{D4E5F6A7-B8C9-4D0E-1F2A-3B4C5D6E7F8A}']
    function GetName: String;
    function GetParameterSet: IMlKemParameterSet;
    function GetOid: IDerObjectIdentifier;
    property Name: String read GetName;
    property ParameterSet: IMlKemParameterSet read GetParameterSet;
    property Oid: IDerObjectIdentifier read GetOid;
  end;

  IMlKemKeyParameters = interface(IAsymmetricKeyParameter)
    ['{F6A7B8C9-D0E1-4F2A-3B4C-5D6E7F8A9B0C}']
    function GetParameters: IMlKemParameters;
    property Parameters: IMlKemParameters read GetParameters;
  end;

  IMlKemPublicKeyParameters = interface(IMlKemKeyParameters)
    ['{A7B8C9D0-E1F2-4A3B-4C5D-6E7F8A9B0C1D}']
    function GetEncoded(): TCryptoLibByteArray;
    function GetEncoding: TCryptoLibByteArray;
    property Encoding: TCryptoLibByteArray read GetEncoding;
  end;

  TMlKemPrivateKeyFormat = (
    SeedOnly,
    EncodingOnly,
    SeedAndEncoding);

  IMlKemPrivateKeyParameters = interface(IMlKemKeyParameters)
    ['{B8C9D0E1-F2A3-4B4C-5D6E-7F8A9B0C1D2E}']
    function GetEncoded(): TCryptoLibByteArray;
    function GetSeed(): TCryptoLibByteArray;
    function GetPublicKey(): IMlKemPublicKeyParameters;
    function GetPublicKeyEncoded(): TCryptoLibByteArray;
    function GetPreferredFormat: TMlKemPrivateKeyFormat;
    function WithPreferredFormat(AFormat: TMlKemPrivateKeyFormat): IMlKemPrivateKeyParameters;
    function GetEncoding: TCryptoLibByteArray;
    property Encoding: TCryptoLibByteArray read GetEncoding;
    property PreferredFormat: TMlKemPrivateKeyFormat read GetPreferredFormat;
  end;

  IMlKemKeyGenerationParameters = interface(IKeyGenerationParameters)
    ['{C9D0E1F2-A3B4-4C5D-6E7F-8A9B0C1D2E3F}']
    function GetParameters: IMlKemParameters;
    property Parameters: IMlKemParameters read GetParameters;
  end;

implementation

end.
