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

unit ClpISlhDsaParameters;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpISlhDsaEngine,
  ClpIAsymmetricKeyParameter,
  ClpIKeyGenerationParameters,
  ClpCryptoLibTypes;

type
  ISlhDsaParameterSet = interface(IInterface)
    ['{D4E5F6A7-B8C9-4012-D345-6789ABCD0104}']
    function GetName: String;
    function GetPrivateKeyLength: Int32;
    function GetPublicKeyLength: Int32;
    function GetN: Int32;
    function GetEngine: ISlhDsaEngine;
    property Name: String read GetName;
    property PrivateKeyLength: Int32 read GetPrivateKeyLength;
    property PublicKeyLength: Int32 read GetPublicKeyLength;
    property N: Int32 read GetN;
  end;

  ISlhDsaParameters = interface(IInterface)
    ['{E5F6A7B8-C9D0-4123-E456-789ABCDE0105}']
    function GetName: String;
    function GetParameterSet: ISlhDsaParameterSet;
    function GetOid: IDerObjectIdentifier;
    function GetPreHashOid: IDerObjectIdentifier;
    function GetIsPreHash: Boolean;
    property Name: String read GetName;
    property ParameterSet: ISlhDsaParameterSet read GetParameterSet;
    property Oid: IDerObjectIdentifier read GetOid;
    property PreHashOid: IDerObjectIdentifier read GetPreHashOid;
    property IsPreHash: Boolean read GetIsPreHash;
  end;

  ISlhDsaKeyParameters = interface(IAsymmetricKeyParameter)
    ['{F6A7B8C9-D0E1-4234-F567-89ABCDEF0106}']
    function GetParameters: ISlhDsaParameters;
    property Parameters: ISlhDsaParameters read GetParameters;
  end;

  ISlhDsaPublicKeyParameters = interface(ISlhDsaKeyParameters)
    ['{A7B8C9D0-E1F2-4345-A678-9ABCDEF00107}']
    function GetEncoded: TCryptoLibByteArray;
  end;

  ISlhDsaPrivateKeyParameters = interface(ISlhDsaKeyParameters)
    ['{B8C9D0E1-F2A3-4456-B789-ABCDEF000108}']
    function GetEncoded: TCryptoLibByteArray;
    function GetPublicKey: ISlhDsaPublicKeyParameters;
    function GetPublicKeyEncoded: TCryptoLibByteArray;
  end;

  ISlhDsaKeyGenerationParameters = interface(IKeyGenerationParameters)
    ['{C9D0E1F2-A3B4-4567-C890-ABCDEF000109}']
    function GetParameters: ISlhDsaParameters;
    property Parameters: ISlhDsaParameters read GetParameters;
  end;

implementation

end.
