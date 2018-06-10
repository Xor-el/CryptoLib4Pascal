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

unit ClpDerExternal;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  ClpCryptoLibTypes,
  ClpAsn1Object,
  ClpIAsn1TaggedObject,
  ClpDerTaggedObject,
  ClpAsn1Tags,
  ClpIAsn1EncodableVector,
  ClpIDerTaggedObject,
  ClpIProxiedInterface,
  ClpIDerObjectIdentifier,
  ClpIDerInteger,
  ClpIDerExternal;

resourcestring
  SInvalidEncoding = 'Invalid Encoding Value: %d';
  SFewObject = 'Too Few Objects in Input Vector, "v"';
  SVectorTooLarge = 'Input Vector too Large", "vector"';
  SNoTaggedObjectFound =
    'No Tagged Object Found in Vector. Structure Doesn ''t Seem to be of Type External, "Vector"';
  SInvalidEncodingValue = 'Invalid Encoding Value';

type

  /// <summary>
  /// Class representing the DER-type External
  /// </summary>
  TDerExternal = class(TAsn1Object, IDerExternal)

  strict private
  var
    FdirectReference: IDerObjectIdentifier;
    FindirectReference: IDerInteger;
    FdataValueDescriptor, FexternalContent: IAsn1Object;
    Fencoding: Int32;

    function GetDataValueDescriptor: IAsn1Object;
    function GetDirectReference: IDerObjectIdentifier;

    /// <summary>
    /// <para>
    /// The encoding of the content. Valid values are
    /// </para>
    /// <para>
    /// &lt;ul&gt; <br />&lt;li&gt;&lt;code&gt;0&lt;/code&gt;
    /// single-ASN1-type&lt;/li&gt; <br />
    /// &lt;li&gt;&lt;code&gt;1&lt;/code&gt; OCTET STRING&lt;/li&gt; <br />
    /// &lt;li&gt;&lt;code&gt;2&lt;/code&gt; BIT STRING&lt;/li&gt; <br />
    /// &lt;/ul&gt;
    /// </para>
    /// </summary>
    function GetEncoding: Int32;
    function GetExternalContent: IAsn1Object;
    function GetIndirectReference: IDerInteger;
    procedure SetDataValueDescriptor(const Value: IAsn1Object);
    procedure SetDirectReference(const Value: IDerObjectIdentifier);
    procedure SetEncoding(const Value: Int32);
    procedure SetExternalContent(const Value: IAsn1Object);
    procedure SetIndirectReference(const Value: IDerInteger);

    class function GetObjFromVector(const v: IAsn1EncodableVector; index: Int32)
      : IAsn1Object; static; inline;
    class procedure WriteEncodable(ms: TMemoryStream; const e: IAsn1Encodable);
      static; inline;

  strict protected
    function Asn1GetHashCode(): Int32; override;
    function Asn1Equals(const asn1Object: IAsn1Object): Boolean; override;

  public
    constructor Create(const vector: IAsn1EncodableVector); overload;

    /// <summary>
    /// Creates a new instance of DerExternal <br />See X.690 for more
    /// informations about the meaning of these parameters
    /// </summary>
    /// <param name="directReference">
    /// The direct reference or &lt;code&gt;null&lt;/code&gt; if not set.
    /// </param>
    /// <param name="indirectReference">
    /// The indirect reference or &lt;code&gt;null&lt;/code&gt; if not set.
    /// </param>
    /// <param name="dataValueDescriptor">
    /// The data value descriptor or &lt;code&gt;null&lt;/code&gt; if not
    /// set.
    /// </param>
    /// <param name="externalData">
    /// The external data in its encoded form.
    /// </param>
    constructor Create(const directReference: IDerObjectIdentifier;
      const indirectReference: IDerInteger;
      const dataValueDescriptor: IAsn1Object;
      const externalData: IDerTaggedObject); overload;

    constructor Create(const directReference: IDerObjectIdentifier;
      const indirectReference: IDerInteger;
      const dataValueDescriptor: IAsn1Object; encoding: Int32;
      const externalData: IAsn1Object); overload;

    procedure Encode(const derOut: IDerOutputStream); override;

    property dataValueDescriptor: IAsn1Object read GetDataValueDescriptor
      write SetDataValueDescriptor;

    property directReference: IDerObjectIdentifier read GetDirectReference
      write SetDirectReference;

    property encoding: Int32 read GetEncoding write SetEncoding;

    property ExternalContent: IAsn1Object read GetExternalContent
      write SetExternalContent;

    property indirectReference: IDerInteger read GetIndirectReference
      write SetIndirectReference;

  end;

implementation

{ TDerExternal }

class function TDerExternal.GetObjFromVector(const v: IAsn1EncodableVector;
  index: Int32): IAsn1Object;
var
  val: IAsn1Encodable;
begin
  if (v.Count <= index) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SFewObject);
  end;

  val := v[index];
  result := val.ToAsn1Object();
end;

class procedure TDerExternal.WriteEncodable(ms: TMemoryStream;
  const e: IAsn1Encodable);
var
  bs: TCryptoLibByteArray;
begin
  if (e <> Nil) then
  begin
    bs := e.GetDerEncoded();
    ms.Write(bs[0], System.Length(bs));
  end;
end;

function TDerExternal.Asn1Equals(const asn1Object: IAsn1Object): Boolean;
var
  other: IDerExternal;
begin
  if (Self.Equals(asn1Object)) then
  begin
    result := true;
    Exit;
  end;

  if (not Supports(asn1Object, IDerExternal, other)) then
  begin
    result := false;
    Exit;
  end;

  result := directReference.Equals(other.directReference) and
    indirectReference.Equals(other.indirectReference) and
    dataValueDescriptor.Equals(other.dataValueDescriptor) and
    ExternalContent.Equals(other.ExternalContent);
end;

function TDerExternal.Asn1GetHashCode: Int32;
var
  ret: Int32;
begin
  ret := ExternalContent.GetHashCode();
  if (directReference <> Nil) then
  begin
    ret := ret xor directReference.GetHashCode();
  end;
  if (indirectReference <> Nil) then
  begin
    ret := ret xor indirectReference.GetHashCode();
  end;
  if (dataValueDescriptor <> Nil) then
  begin
    ret := ret xor dataValueDescriptor.GetHashCode();
  end;
  result := ret;
end;

constructor TDerExternal.Create(const directReference: IDerObjectIdentifier;
  const indirectReference: IDerInteger; const dataValueDescriptor: IAsn1Object;
  encoding: Int32; const externalData: IAsn1Object);
begin
  Inherited Create();
  FdirectReference := directReference;
  FindirectReference := indirectReference;
  FdataValueDescriptor := dataValueDescriptor;
  Fencoding := encoding;
  FexternalContent := externalData.ToAsn1Object();
end;

constructor TDerExternal.Create(const vector: IAsn1EncodableVector);
var
  offset: Int32;
  enc: IAsn1Object;
  derObjectIdentifier: IDerObjectIdentifier;
  derInteger: IDerInteger;
  obj: IAsn1TaggedObject;
begin
  Inherited Create();
  offset := 0;
  enc := GetObjFromVector(vector, offset);

  if (Supports(enc, IDerObjectIdentifier, derObjectIdentifier)) then
  begin
    directReference := derObjectIdentifier;
    System.Inc(offset);
    enc := GetObjFromVector(vector, offset);
  end;

  if (Supports(enc, IDerInteger, derInteger)) then
  begin
    indirectReference := derInteger;
    System.Inc(offset);
    enc := GetObjFromVector(vector, offset);
  end;
  if (not(Supports(enc, IAsn1TaggedObject))) then
  begin
    dataValueDescriptor := enc;
    System.Inc(offset);
    enc := GetObjFromVector(vector, offset);
  end;

  if (vector.Count <> (offset + 1)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SVectorTooLarge);
  end;

  if (not(Supports(enc, IAsn1TaggedObject, obj))) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SNoTaggedObjectFound);
  end;

  // Use property accessor to include check on value
  encoding := obj.TagNo;

  if ((Fencoding < 0) or (Fencoding > 2)) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes(@SInvalidEncodingValue);
  end;

  FexternalContent := obj.GetObject();
end;

constructor TDerExternal.Create(const directReference: IDerObjectIdentifier;
  const indirectReference: IDerInteger; const dataValueDescriptor: IAsn1Object;
  const externalData: IDerTaggedObject);
begin
  Create(directReference, indirectReference, dataValueDescriptor,
    externalData.TagNo, externalData.ToAsn1Object());
end;

procedure TDerExternal.Encode(const derOut: IDerOutputStream);
var
  ms: TMemoryStream;
  Buffer: TCryptoLibByteArray;
begin
  ms := TMemoryStream.Create();
  try
    WriteEncodable(ms, directReference);
    WriteEncodable(ms, indirectReference);
    WriteEncodable(ms, dataValueDescriptor);
    WriteEncodable(ms, TDerTaggedObject.Create(TAsn1Tags.External,
      ExternalContent));

    System.SetLength(Buffer, ms.Size);
    ms.Position := 0;
    ms.Read(Buffer[0], ms.Size);
    derOut.WriteEncoded(TAsn1Tags.Constructed, TAsn1Tags.External, Buffer);
  finally
    ms.Free;
  end;
end;

function TDerExternal.GetDataValueDescriptor: IAsn1Object;
begin
  result := FdataValueDescriptor;
end;

function TDerExternal.GetDirectReference: IDerObjectIdentifier;
begin
  result := FdirectReference;
end;

function TDerExternal.GetEncoding: Int32;
begin
  result := Fencoding;
end;

function TDerExternal.GetExternalContent: IAsn1Object;
begin
  result := FexternalContent;
end;

function TDerExternal.GetIndirectReference: IDerInteger;
begin
  result := FindirectReference;
end;

procedure TDerExternal.SetDataValueDescriptor(const Value: IAsn1Object);
begin
  FdataValueDescriptor := Value;
end;

procedure TDerExternal.SetDirectReference(const Value: IDerObjectIdentifier);
begin
  FdirectReference := Value;
end;

procedure TDerExternal.SetEncoding(const Value: Int32);
begin
  if ((Fencoding < 0) or (Fencoding > 2)) then
  begin
    raise EInvalidOperationCryptoLibException.CreateResFmt
      (@SInvalidEncoding, [Value]);
  end;

  Fencoding := Value;
end;

procedure TDerExternal.SetExternalContent(const Value: IAsn1Object);
begin
  FexternalContent := Value;
end;

procedure TDerExternal.SetIndirectReference(const Value: IDerInteger);
begin
  FindirectReference := Value;
end;

end.
