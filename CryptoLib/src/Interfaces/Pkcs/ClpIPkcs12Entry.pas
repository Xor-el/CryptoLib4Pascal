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

unit ClpIPkcs12Entry;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Interface for Pkcs12Entry (PKCS#12 bag entry with attributes).
  /// </summary>
  IPkcs12Entry = interface(IInterface)
    ['{3A4B5C6D-7E8F-9A0B-1C2D-3E4F5A6B7C8D}']

    function GetItem(const AOid: IDerObjectIdentifier): IAsn1Encodable;
    function GetBagAttributeKeys: TCryptoLibGenericArray<IDerObjectIdentifier>;
    function GetHasFriendlyName: Boolean;
    procedure SetFriendlyName(const AName: String);
    function TryGetAttribute(const AOid: IDerObjectIdentifier;
      out AAttribute: IAsn1Encodable): Boolean;

    property BagAttributeKeys: TCryptoLibGenericArray<IDerObjectIdentifier> read GetBagAttributeKeys;
    property Item[const AOid: IDerObjectIdentifier]: IAsn1Encodable read GetItem; default;
    property HasFriendlyName: Boolean read GetHasFriendlyName;
  end;

implementation

end.
