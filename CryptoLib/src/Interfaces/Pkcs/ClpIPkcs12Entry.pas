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

unit ClpIPkcs12Entry;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Base interface for PKCS#12 bag entries (private keys and certificates) carrying optional
  /// PKCS#9 bag attributes such as friendly name and local key identifier.
  /// </summary>
  IPkcs12Entry = interface(IInterface)
    ['{3A4B5C6D-7E8F-9A0B-1C2D-3E4F5A6B7C8D}']

    /// <summary>
    /// Gets the bag attribute value for the given object identifier, or <c>nil</c> if absent.
    /// </summary>
    /// <param name="AOid">The bag attribute OID.</param>
    function GetItem(const AOid: IDerObjectIdentifier): IAsn1Encodable;
    /// <summary>Gets the object identifiers of all bag attributes on this entry.</summary>
    function GetBagAttributeKeys: TCryptoLibGenericArray<IDerObjectIdentifier>;
    /// <summary>
    /// Returns <c>true</c> if this entry has a PKCS#9 friendly name attribute.
    /// </summary>
    function GetHasFriendlyName: Boolean;
    /// <summary>
    /// Sets or replaces the PKCS#9 friendly name bag attribute on this entry.
    /// </summary>
    /// <param name="AName">The friendly name to store.</param>
    procedure SetFriendlyName(const AName: String);
    /// <summary>
    /// Attempts to retrieve a bag attribute by OID.
    /// </summary>
    /// <param name="AOid">The bag attribute OID.</param>
    /// <param name="AAttribute">The attribute value, if present.</param>
    /// <returns><c>true</c> if the attribute was found.</returns>
    function TryGetAttribute(const AOid: IDerObjectIdentifier;
      out AAttribute: IAsn1Encodable): Boolean;

    property BagAttributeKeys: TCryptoLibGenericArray<IDerObjectIdentifier> read GetBagAttributeKeys;
    property Item[const AOid: IDerObjectIdentifier]: IAsn1Encodable read GetItem; default;
    property HasFriendlyName: Boolean read GetHasFriendlyName;
  end;

implementation

end.
