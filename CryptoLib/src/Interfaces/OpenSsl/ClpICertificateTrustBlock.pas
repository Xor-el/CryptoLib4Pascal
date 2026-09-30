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

unit ClpICertificateTrustBlock;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// The trust metadata of an OpenSSL trusted certificate: the key purposes it may be used for, the
  /// key purposes it must not be used for, and an optional friendly alias.
  /// </summary>
  ICertificateTrustBlock = interface(IInterface)
    ['{C7A1E2B4-3D5F-4A6C-9E8B-1F2A3B4C5D6E}']

    function GetAlias: String;
    function GetUses: TCryptoLibGenericArray<IDerObjectIdentifier>;
    function GetProhibitions: TCryptoLibGenericArray<IDerObjectIdentifier>;
    function ToAsn1Sequence: IAsn1Sequence;
  end;

implementation

end.
