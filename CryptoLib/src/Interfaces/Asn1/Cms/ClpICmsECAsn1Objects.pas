{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpICmsECAsn1Objects;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects;

type
  /// <summary>
  /// ECC-CMS-SharedInfo (RFC 5753 / CMS ECC).
  /// </summary>
  IEccCmsSharedInfo = interface(IAsn1Encodable)
    ['{F67A1928-A907-4EA8-90C3-0130C8C1F636}']

    function GetKeyInfo: IAlgorithmIdentifier;
    function GetEntityUInfo: IAsn1OctetString;
    function GetSuppPubInfo: IAsn1OctetString;

    property KeyInfo: IAlgorithmIdentifier read GetKeyInfo;
    property EntityUInfo: IAsn1OctetString read GetEntityUInfo;
    property SuppPubInfo: IAsn1OctetString read GetSuppPubInfo;
  end;

implementation

end.
