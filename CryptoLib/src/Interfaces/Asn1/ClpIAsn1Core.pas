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

unit ClpIAsn1Core;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpCryptoLibTypes,
  ClpIAsn1Encodings;

type
  IAsn1Object = interface; // forward (used by IAsn1Convertible)

  /// <summary>
  /// Interface for ASN.1 convertible objects.
  /// </summary>
  IAsn1Convertible = interface(IInterface)
    ['{13104D9E-9DF1-4CCE-B48C-1ACC2AC362B1}']

    function ToAsn1Object(): IAsn1Object;
  end;

  /// <summary>
  /// Interface for ASN.1 encodable objects.
  /// </summary>
  IAsn1Encodable = interface(IAsn1Convertible)
    ['{E6F78901-2345-6789-ABCD-EF0123456789}']

    procedure EncodeTo(const AOutput: TStream); overload;
    procedure EncodeTo(const AOutput: TStream; const AEncoding: String); overload;
    function GetEncoded(): TCryptoLibByteArray; overload;
    function GetEncoded(const AEncoding: String): TCryptoLibByteArray; overload;
    function GetDerEncoded(): TCryptoLibByteArray;
    function Equals(const AObj: IAsn1Convertible): Boolean; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
  end;

  /// <summary>
  /// Interface for ASN.1 objects.
  /// </summary>
  IAsn1Object = interface(IAsn1Encodable)
    ['{F7890123-4567-89AB-CDEF-0123456789AB}']

    procedure EncodeTo(const AOutput: TStream); overload;
    procedure EncodeTo(const AOutput: TStream; const AEncoding: String); overload;
    function GetEncoded(const AEncoding: String; APreAlloc, APostAlloc: Int32): TCryptoLibByteArray; overload;
    function Equals(const AOther: IAsn1Object): Boolean; overload;
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
    function Asn1GetHashCode(): Int32;
    function CallAsn1Equals(const AObj: IAsn1Object): Boolean;
    function CallAsn1GetHashCode(): Int32;
    /// <summary>
    /// Get string representation of the object.
    /// </summary>
    function ToString(): String;
    /// <summary>
    /// Get encoding for the specified encoding type.
    /// </summary>
    function GetEncoding(AEncoding: Int32): IAsn1Encoding;
    /// <summary>
    /// Get encoding for the specified encoding type with implicit tagging.
    /// </summary>
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
    /// <summary>
    /// Get DER encoding.
    /// </summary>
    function GetEncodingDer(): IDerEncoding;
    /// <summary>
    /// Get DER encoding with implicit tagging.
    /// </summary>
    function GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding;
  end;

  /// <summary>
  /// Interface for ASN.1 encodable vector.
  /// </summary>
  IAsn1EncodableVector = interface(IInterface)
    ['{A78E22EB-DB67-472E-A55F-CD710BCBDBFA}']

    function GetCount(): Int32;
    function GetItem(AIndex: Int32): IAsn1Encodable;

    procedure Add(const AElement: IAsn1Encodable); overload;
    procedure Add(const AElement1, AElement2: IAsn1Encodable); overload;
    procedure Add(const AObjs: array of IAsn1Encodable); overload;
    procedure AddOptional(const AElement: IAsn1Encodable); overload;
    procedure AddOptional(const AElement1, AElement2: IAsn1Encodable); overload;
    procedure AddOptional(const AElements: array of IAsn1Encodable); overload;
    procedure AddOptionalTagged(AIsExplicit: Boolean; ATagNo: Int32;
      const AObj: IAsn1Encodable); overload;
    procedure AddOptionalTagged(AIsExplicit: Boolean; ATagClass, ATagNo: Int32;
      const AObj: IAsn1Encodable); overload;
    procedure AddAll(const AE: TCryptoLibGenericArray<IAsn1Encodable>); overload;
    procedure AddAll(const AOther: IAsn1EncodableVector); overload;

    function CopyElements(): TCryptoLibGenericArray<IAsn1Encodable>;
    function TakeElements(): TCryptoLibGenericArray<IAsn1Encodable>;

    property Items[AIndex: Int32]: IAsn1Encodable read GetItem; default;
    property Count: Int32 read GetCount;
  end;

implementation

end.

