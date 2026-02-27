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

unit ClpIAsn1Encodings;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Interface for ASN.1 encoding operations.
  /// </summary>
  IAsn1Encoding = interface(IInterface)
    ['{C4D5E6F7-8901-2345-6789-ABCDEF012345}']

    /// <summary>
    /// Encode to the given stream (must be a TAsn1OutputStream).
    /// </summary>
    procedure Encode(const AOut: TStream);

    /// <summary>
    /// Get the length of the encoded data.
    /// </summary>
    function GetLength(): Int32;
  end;

  /// <summary>
  /// Interface for DER encoding.
  /// </summary>
  IDerEncoding = interface(IAsn1Encoding)
    ['{3456789A-BCDE-F012-3456-789ABCDEF012}']

    /// <summary>
    /// Get the tag class.
    /// </summary>
    function GetTagClass(): Int32;
    /// <summary>
    /// Get the tag number.
    /// </summary>
    function GetTagNo(): Int32;
    /// <summary>
    /// Compare this encoding with another.
    /// </summary>
    function CompareTo(const AOther: IDerEncoding): Int32;

    property TagClass: Int32 read GetTagClass;
    property TagNo: Int32 read GetTagNo;
  end;

  /// <summary>
  /// Interface for constructed DER encoding.
  /// </summary>
  IConstructedDerEncoding = interface(IDerEncoding)
    ['{24401A28-DFC0-40ED-99B0-8D4A7B0D8C1C}']

    /// <summary>
    /// Get the contents length.
    /// </summary>
    function GetContentsLength(): Int32;
    /// <summary>
    /// Get the contents elements.
    /// </summary>
    function GetContentsElements(): TCryptoLibGenericArray<IDerEncoding>;
    /// <summary>
    /// Compare length and contents with another encoding.
    /// </summary>
    function CompareLengthAndContents(const AOther: IDerEncoding): Int32;

    property ContentsLength: Int32 read GetContentsLength;
    property ContentsElements: TCryptoLibGenericArray<IDerEncoding> read GetContentsElements;
  end;

  /// <summary>
  /// Interface for tagged DER encoding.
  /// </summary>
  ITaggedDerEncoding = interface(IDerEncoding)
    ['{F2A3B4C5-D6E7-F8A9-0B1C-2D3E4F5A6B7C}']

    /// <summary>
    /// Get the contents length.
    /// </summary>
    function GetContentsLength(): Int32;
    /// <summary>
    /// Get the contents element.
    /// </summary>
    function GetContentsElement(): IDerEncoding;
    /// <summary>
    /// Compare length and contents with another encoding.
    /// </summary>
    function CompareLengthAndContents(const AOther: IDerEncoding): Int32;

    property ContentsLength: Int32 read GetContentsLength;
    property ContentsElement: IDerEncoding read GetContentsElement;
  end;

  /// <summary>
  /// Interface for primitive DER encoding.
  /// </summary>
  IPrimitiveDerEncoding = interface(IDerEncoding)
    ['{A3B4C5D6-E7F8-A9B0-1C2D-3E4F5A6B7C8D}']

    /// <summary>
    /// Get the contents octets.
    /// </summary>
    function GetContentsOctets(): TCryptoLibByteArray;
    /// <summary>
    /// Compare length and contents with another encoding.
    /// </summary>
    function CompareLengthAndContents(const AOther: IDerEncoding): Int32;

    property ContentsOctets: TCryptoLibByteArray read GetContentsOctets;
  end;

  /// <summary>
  /// Interface for primitive DER encoding with suffix.
  /// </summary>
  IPrimitiveDerEncodingSuffixed = interface(IPrimitiveDerEncoding)
    ['{B4C5D6E7-F8A9-B0C1-2D3E-4F5A6B7C8D9E}']

    /// <summary>
    /// Get the contents suffix.
    /// </summary>
    function GetContentsSuffix(): Byte;
    /// <summary>
    /// Compare length and contents with another encoding.
    /// </summary>
    function CompareLengthAndContents(const AOther: IDerEncoding): Int32;

    property ContentsSuffix: Byte read GetContentsSuffix;
  end;

implementation

end.

