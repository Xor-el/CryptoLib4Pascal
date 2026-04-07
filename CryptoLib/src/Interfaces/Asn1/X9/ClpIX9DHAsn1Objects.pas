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

unit ClpIX9DHAsn1Objects;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Core,
  ClpIAsn1Objects;

type
  /// <summary>
  /// Interface for DHValidationParms.
  /// </summary>
  IDHValidationParms = interface(IAsn1Encodable)
    ['{A75D3486-080A-43F5-9296-9C74B7DEE7DC}']

    function GetSeed: IDerBitString;
    function GetPGenCounter: IDerInteger;

    property Seed: IDerBitString read GetSeed;
    property PGenCounter: IDerInteger read GetPGenCounter;
  end;

  /// <summary>
  /// Interface for DHPublicKey.
  /// </summary>
  IDHPublicKey = interface(IAsn1Encodable)
    ['{58CCD3A4-111C-449C-AFE3-1B5012164739}']

    function GetY: IDerInteger;

    property Y: IDerInteger read GetY;
  end;

  /// <summary>
  /// Interface for DHDomainParameters.
  /// </summary>
  IDHDomainParameters = interface(IAsn1Encodable)
    ['{18288135-B71F-48B4-8595-57AAB9092FC8}']

    function GetP: IDerInteger;
    function GetG: IDerInteger;
    function GetQ: IDerInteger;
    function GetJ: IDerInteger;
    function GetValidationParms: IDHValidationParms;

    property P: IDerInteger read GetP;
    property G: IDerInteger read GetG;
    property Q: IDerInteger read GetQ;
    property J: IDerInteger read GetJ;
    property ValidationParms: IDHValidationParms read GetValidationParms;
  end;

  /// <summary>
  /// ASN.1 KeySpecificInfo (RFC 2631 / X9.42).
  /// </summary>
  IKeySpecificInfo = interface(IAsn1Encodable)
    ['{E8B7D4C2-91A3-4F8E-B205-1C9A8E7D6F5A}']

    function GetAlgorithm: IDerObjectIdentifier;
    function GetCounter: IAsn1OctetString;

    property Algorithm: IDerObjectIdentifier read GetAlgorithm;
    property Counter: IAsn1OctetString read GetCounter;
  end;

  /// <summary>
  /// ASN.1 OtherInfo (RFC 2631 / X9.42).
  /// </summary>
  IOtherInfo = interface(IAsn1Encodable)
    ['{F9C8E5D3-A2B4-5F9F-C306-2DB0F8E7A94B}']

    function GetKeyInfo: IKeySpecificInfo;
    function GetPartyAInfo: IAsn1OctetString;
    function GetSuppPubInfo: IAsn1OctetString;

    property KeyInfo: IKeySpecificInfo read GetKeyInfo;
    property PartyAInfo: IAsn1OctetString read GetPartyAInfo;
    property SuppPubInfo: IAsn1OctetString read GetSuppPubInfo;
  end;

implementation

end.
