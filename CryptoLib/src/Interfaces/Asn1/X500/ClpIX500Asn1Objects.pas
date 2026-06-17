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

unit ClpIX500Asn1Objects;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpCryptoLibTypes;

type
  IAttributeTypeAndValue = interface;
  IRdn = interface;
  IDirectoryString = interface;

  /// <summary>
  /// AttributeTypeAndValue ::= SEQUENCE { type OBJECT IDENTIFIER, value ANY DEFINED BY type }
  /// </summary>
  IAttributeTypeAndValue = interface(IAsn1Encodable)
    ['{A4B5C6D7-E8F9-4A5B-9C0D-1E2F3A4B5C6D}']

    function GetAttrType: IDerObjectIdentifier;
    function GetValue: IAsn1Encodable;

    property AttrType: IDerObjectIdentifier read GetAttrType;
    property Value: IAsn1Encodable read GetValue;
  end;

  /// <summary>
  /// RelativeDistinguishedName ::= SET SIZE(1..MAX) OF AttributeTypeAndValue
  /// </summary>
  IRdn = interface(IAsn1Encodable)
    ['{B5C6D7E8-F9A0-4B6C-8D1E-2F3A4B5C6D7E}']

    function GetIsMultiValued: Boolean;
    function GetCount: Int32;
    function GetFirst: IAttributeTypeAndValue;
    function GetTypesAndValues: TCryptoLibGenericArray<IAttributeTypeAndValue>;

    property IsMultiValued: Boolean read GetIsMultiValued;
    property Count: Int32 read GetCount;
    property First: IAttributeTypeAndValue read GetFirst;
  end;

  /// <summary>
  /// DirectoryString ::= CHOICE { teletexString, printableString, universalString, utf8String, bmpString }
  /// </summary>
  IDirectoryString = interface(IAsn1Encodable)
    ['{C6D7E8F9-A0B1-4C6D-9E2F-3A4B5C6D7E8F}']

    function GetString: String;
  end;

implementation

end.
