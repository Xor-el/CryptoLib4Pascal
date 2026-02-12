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

unit ClpX509NameEntryConverter;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Core,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpIX509NameEntryConverter,
  ClpEncoders,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Abstract base class for X509NameEntryConverter.
  /// </summary>
  TX509NameEntryConverter = class abstract(TInterfacedObject, IX509NameEntryConverter)

  strict protected
    /// <summary>
    /// Convert an inline encoded hex string rendition of an ASN.1 object back into its corresponding ASN.1 object.
    /// </summary>
    function ConvertHexEncoded(const AHexString: String;
      AOffset: Int32): IAsn1Object;

    /// <summary>
    /// Return true if the passed in string can be represented without loss as a PrintableString, false otherwise.
    /// </summary>
    function CanBePrintable(const AStr: String): Boolean;

  public
    /// <summary>
    /// Convert the passed in string value into the appropriate ASN.1 encoded object.
    /// </summary>
    function GetConvertedValue(const AOid: IDerObjectIdentifier;
      const AValue: String): IAsn1Object; virtual; abstract;

  end;

implementation

{ TX509NameEntryConverter }

function TX509NameEntryConverter.ConvertHexEncoded(const AHexString: String;
  AOffset: Int32): IAsn1Object;
var
  LBytes: TCryptoLibByteArray;
  LHexSubstring: String;
begin
  LHexSubstring := System.Copy(AHexString, AOffset + 1, System.Length(AHexString) - AOffset);
  LBytes := THexEncoder.Decode(LHexSubstring);
  Result := TAsn1Object.FromByteArray(LBytes);
end;

function TX509NameEntryConverter.CanBePrintable(const AStr: String): Boolean;
begin
  Result := TDerPrintableString.IsPrintableString(AStr);
end;

end.
