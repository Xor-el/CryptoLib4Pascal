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

unit ClpAsn1Core;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  Math,
  ClpStreams,
  ClpCryptoLibTypes,
  ClpIAsn1Core,
  ClpIAsn1Encodings,
  ClpBitOperations,
  ClpAsn1Tags,
  ClpAsn1Streams;

type
  /// <summary>
  /// Abstract base class for ASN.1 encodable objects.
  /// </summary>
  TAsn1Encodable = class abstract(TInterfacedObject, IAsn1Encodable, IAsn1Convertible)
  public
    const
      Ber = 'BER';
      Der = 'DER';
      DL = 'DL';

  public
    /// <summary>
    /// Encode this object to a stream using BER encoding.
    /// </summary>
    procedure EncodeTo(const AOutput: TStream); overload; virtual;
    /// <summary>
    /// Encode this object to a stream using the specified encoding.
    /// </summary>
    procedure EncodeTo(const AOutput: TStream; const AEncoding: String); overload; virtual;
    /// <summary>
    /// Get the encoded representation of this object.
    /// </summary>
    function GetEncoded(): TCryptoLibByteArray; overload;
    function GetEncoded(const AEncoding: String): TCryptoLibByteArray; overload;
    function GetEncoded(const AEncoding: String; APreAlloc, APostAlloc: Int32): TCryptoLibByteArray; overload; virtual;
    /// <summary>
    /// Get the DER encoding of the object, nil if the DER encoding cannot be made.
    /// </summary>
    function GetDerEncoded(): TCryptoLibByteArray;
    /// <summary>
    /// Check if this object equals another.
    /// </summary>
    function Equals(const AObj: IAsn1Convertible): Boolean; reintroduce; overload;
    /// <summary>
    /// Get the hash code for this object.
    /// </summary>
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI} override;
    /// <summary>
    /// Convert this object to an ASN.1 object.
    /// </summary>
    function ToAsn1Object(): IAsn1Object; virtual; abstract;
  end;

  /// <summary>
  /// Vector for ASN.1 encodable objects.
  /// </summary>
  TAsn1EncodableVector = class(TInterfacedObject, IAsn1EncodableVector)
  strict private
    const
      DefaultCapacity = 10;

    class var
      FEmptyElements: TCryptoLibGenericArray<IAsn1Encodable>;
  
  public
    class property EmptyElements: TCryptoLibGenericArray<IAsn1Encodable> read FEmptyElements;

  strict private
    FElements: TCryptoLibGenericArray<IAsn1Encodable>;
    FElementCount: Int32;
    FCopyOnWrite: Boolean;

    function PrepareCapacity(ARequiredCapacity: Int32): Int32;
    procedure Reallocate(AMinCapacity: Int32);
    class function CopyElements(const AElements: TCryptoLibGenericArray<IAsn1Encodable>;
      AElementCount: Int32): TCryptoLibGenericArray<IAsn1Encodable>; overload; static;

  public
    /// <summary>
    /// Create an empty vector with default capacity.
    /// </summary>
    constructor Create(); overload;
    /// <summary>
    /// Create an empty vector with specified initial capacity.
    /// </summary>
    constructor Create(AInitialCapacity: Int32); overload;
    /// <summary>
    /// Create a vector with a single element.
    /// </summary>
    constructor Create(const AElement: IAsn1Encodable); overload;
    /// <summary>
    /// Create a vector with two elements.
    /// </summary>
    constructor Create(const AElement1, AElement2: IAsn1Encodable); overload;
    /// <summary>
    /// Create a vector with multiple elements.
    /// </summary>
    constructor Create(const AElements: array of IAsn1Encodable); overload;

    /// <summary>
    /// Add an element to the vector.
    /// </summary>
    procedure Add(const AElement: IAsn1Encodable); overload;
    /// <summary>
    /// Add two elements to the vector.
    /// </summary>
    procedure Add(const AElement1, AElement2: IAsn1Encodable); overload;
    /// <summary>
    /// Add multiple elements to the vector.
    /// </summary>
    procedure Add(const AObjs: array of IAsn1Encodable); overload;
    /// <summary>
    /// Add an optional element (if not nil).
    /// </summary>
    procedure AddOptional(const AElement: IAsn1Encodable); overload;
    /// <summary>
    /// Add two optional elements.
    /// </summary>
    procedure AddOptional(const AElement1, AElement2: IAsn1Encodable); overload;
    /// <summary>
    /// Add multiple optional elements.
    /// </summary>
    procedure AddOptional(const AElements: array of IAsn1Encodable); overload;
    /// <summary>
    /// Add an optional tagged element.
    /// </summary>
    procedure AddOptionalTagged(AIsExplicit: Boolean; ATagNo: Int32;
      const AObj: IAsn1Encodable); overload;
    /// <summary>
    /// Add an optional tagged element with tag class.
    /// </summary>
    procedure AddOptionalTagged(AIsExplicit: Boolean; ATagClass, ATagNo: Int32;
      const AObj: IAsn1Encodable); overload;
    /// <summary>
    /// Add all elements from an enumerable.
    /// </summary>
    procedure AddAll(const AE: TCryptoLibGenericArray<IAsn1Encodable>); overload;
    /// <summary>
    /// Add all elements from another vector.
    /// </summary>
    procedure AddAll(const AOther: IAsn1EncodableVector); overload;

    /// <summary>
    /// Get an element by index.
    /// </summary>
    function GetItem(AIndex: Int32): IAsn1Encodable;
    /// <summary>
    /// Get the number of elements.
    /// </summary>
    function GetCount(): Int32;
    /// <summary>
    /// Copy all elements to a new array.
    /// </summary>
    function CopyElements(): TCryptoLibGenericArray<IAsn1Encodable>; overload;
    /// <summary>
    /// Take all elements (may return internal array if count matches capacity).
    /// </summary>
    function TakeElements(): TCryptoLibGenericArray<IAsn1Encodable>;

    /// <summary>
    /// Create a vector from a collection.
    /// </summary>
    class function FromCollection(const AC: TCryptoLibGenericArray<IAsn1Encodable>): IAsn1EncodableVector; static;
    /// <summary>
    /// Create a vector from a single element.
    /// </summary>
    class function FromElement(const AElement: IAsn1Encodable): IAsn1EncodableVector; static;
    /// <summary>
    /// Create a vector from an enumerable.
    /// </summary>
    class function FromEnumerable(const AE: TCryptoLibGenericArray<IAsn1Encodable>): IAsn1EncodableVector; static;
    /// <summary>
    /// Clone elements from an array.
    /// </summary>
    class function CloneElements(const AElements: TCryptoLibGenericArray<IAsn1Encodable>): TCryptoLibGenericArray<IAsn1Encodable>; static;

    /// <summary>
    /// Class constructor to initialize static fields.
    /// </summary>
    class constructor Create;

    property Items[AIndex: Int32]: IAsn1Encodable read GetItem; default;
    property Count: Int32 read GetCount;
  end;

  /// <summary>
  /// Abstract base class for ASN.1 objects.
  /// </summary>
  TAsn1Object = class abstract(TAsn1Encodable, IAsn1Object)
  strict protected
    /// <summary>
    /// Compare this object with another ASN.1 object.
    /// </summary>
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; virtual; abstract;
    /// <summary>
    /// Get the hash code for this ASN.1 object.
    /// </summary>
    function Asn1GetHashCode(): Int32; virtual; abstract;

    /// <summary>
    /// Call Asn1Equals (internal method).
    /// </summary>
    function CallAsn1Equals(const AObj: IAsn1Object): Boolean;
    /// <summary>
    /// Call Asn1GetHashCode (internal method).
    /// </summary>
    function CallAsn1GetHashCode(): Int32;

  public
    /// <summary>
    /// Encode this object to a stream using BER encoding.
    /// </summary>
    procedure EncodeTo(const AOutput: TStream); override;
    /// <summary>
    /// Encode this object to a stream using the specified encoding.
    /// </summary>
    procedure EncodeTo(const AOutput: TStream; const AEncoding: String); override;
    /// <summary>
    /// Get the encoded representation of this object.
    /// </summary>
    function GetEncoded(const AEncoding: String; APreAlloc, APostAlloc: Int32): TCryptoLibByteArray; override;
    /// <summary>
    /// Check if this object equals another.
    /// </summary>
    function Equals(const AOther: IAsn1Object): Boolean; reintroduce; overload;
    /// <summary>
    /// Create an ASN.1 object from a byte array.
    /// </summary>
    class function FromByteArray(const AData: TCryptoLibByteArray): IAsn1Object; static;
    /// <summary>
    /// Create an ASN.1 object from a stream.
    /// </summary>
    class function FromStream(const AInStr: TStream): IAsn1Object; static;
    /// <summary>
    /// Get encoding for the specified encoding type.
    /// </summary>
    function GetEncoding(AEncoding: Int32): IAsn1Encoding; virtual; abstract;
    /// <summary>
    /// Get encoding for the specified encoding type with implicit tagging.
    /// </summary>
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; virtual; abstract;
    /// <summary>
    /// Get DER encoding.
    /// </summary>
    function GetEncodingDer(): IDerEncoding; virtual; abstract;
    /// <summary>
    /// Get DER encoding with implicit tagging.
    /// </summary>
    function GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding; virtual; abstract;
    /// <summary>
    /// Convert this object to an ASN.1 object (returns self).
    /// </summary>
    function ToAsn1Object(): IAsn1Object; override;

  private
    /// <summary>
    /// Create an ASN.1 object from a fixed buffer stream.
    /// </summary>
    class function FromBufferStream(const ABufferStream: TFixedBufferStream): IAsn1Object; static;
  end;

implementation

uses
  ClpAsn1Objects; // For TDerTaggedObject in AddOptionalTagged

{ TAsn1Encodable }

procedure TAsn1Encodable.EncodeTo(const AOutput: TStream);
begin
  ToAsn1Object().EncodeTo(AOutput);
end;

procedure TAsn1Encodable.EncodeTo(const AOutput: TStream; const AEncoding: String);
begin
  ToAsn1Object().EncodeTo(AOutput, AEncoding);
end;

function TAsn1Encodable.GetEncoded(): TCryptoLibByteArray;
begin
  Result := GetEncoded(Ber, 0, 0);
end;

function TAsn1Encodable.GetEncoded(const AEncoding: String): TCryptoLibByteArray;
begin
  Result := GetEncoded(AEncoding, 0, 0);
end;

function TAsn1Encodable.GetEncoded(const AEncoding: String; APreAlloc, APostAlloc: Int32): TCryptoLibByteArray;
begin
  Result := ToAsn1Object().GetEncoded(AEncoding, APreAlloc, APostAlloc);
end;

function TAsn1Encodable.GetDerEncoded(): TCryptoLibByteArray;
begin
  try
    Result := GetEncoded(Der);
  except
    on E: EIOCryptoLibException do
      Result := nil;
  end;
end;

function TAsn1Encodable.Equals(const AObj: IAsn1Convertible): Boolean;
var
  LO1, LO2: IAsn1Object;
begin
  if (Self as IAsn1Convertible) = AObj then
  begin
    Result := True;
    Exit;
  end;

  if AObj = nil then
  begin
    Result := False;
    Exit;
  end;

  LO1 := ToAsn1Object();
  LO2 := AObj.ToAsn1Object();
  Result := (LO1 = LO2) or ((LO2 <> nil) and LO1.CallAsn1Equals(LO2));
end;

function TAsn1Encodable.GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
begin
  Result := ToAsn1Object().CallAsn1GetHashCode();
end;

{ TAsn1EncodableVector }

class function TAsn1EncodableVector.CopyElements(const AElements: TCryptoLibGenericArray<IAsn1Encodable>;
  AElementCount: Int32): TCryptoLibGenericArray<IAsn1Encodable>;
var
  I: Int32;
begin
  if AElementCount < 1 then
  begin
    Result := FEmptyElements;
    Exit;
  end;

  System.SetLength(Result, AElementCount);
  for I := 0 to AElementCount - 1 do
    Result[I] := AElements[I];
end;

constructor TAsn1EncodableVector.Create();
begin
  Create(DefaultCapacity);
end;

constructor TAsn1EncodableVector.Create(AInitialCapacity: Int32);
begin
  inherited Create;
  if AInitialCapacity < 0 then
    raise EArgumentCryptoLibException.Create('must not be negative');

  if AInitialCapacity = 0 then
    FElements := FEmptyElements
  else
    System.SetLength(FElements, AInitialCapacity);
  FElementCount := 0;
  FCopyOnWrite := False;
end;

constructor TAsn1EncodableVector.Create(const AElement: IAsn1Encodable);
begin
  Create();
  Add(AElement);
end;

constructor TAsn1EncodableVector.Create(const AElement1, AElement2: IAsn1Encodable);
begin
  Create();
  Add(AElement1);
  Add(AElement2);
end;

constructor TAsn1EncodableVector.Create(const AElements: array of IAsn1Encodable);
var
  I: Int32;
begin
  Create();
  for I := 0 to System.Length(AElements) - 1 do
    Add(AElements[I]);
end;

procedure TAsn1EncodableVector.Add(const AElement: IAsn1Encodable);
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  PrepareCapacity(1);
  FElements[FElementCount] := AElement;
  System.Inc(FElementCount);
end;

procedure TAsn1EncodableVector.Add(const AElement1, AElement2: IAsn1Encodable);
begin
  Add(AElement1);
  Add(AElement2);
end;

procedure TAsn1EncodableVector.Add(const AObjs: array of IAsn1Encodable);
var
  I: Int32;
begin
  for I := 0 to System.Length(AObjs) - 1 do
    Add(AObjs[I]);
end;

procedure TAsn1EncodableVector.AddOptional(const AElement: IAsn1Encodable);
begin
  if AElement <> nil then
    Add(AElement);
end;

procedure TAsn1EncodableVector.AddOptional(const AElement1, AElement2: IAsn1Encodable);
begin
  AddOptional(AElement1);
  AddOptional(AElement2);
end;

procedure TAsn1EncodableVector.AddOptional(const AElements: array of IAsn1Encodable);
var
  I: Int32;
begin
  if System.Length(AElements) > 0 then
  begin
    for I := 0 to System.Length(AElements) - 1 do
      AddOptional(AElements[I]);
  end;
end;

procedure TAsn1EncodableVector.AddOptionalTagged(AIsExplicit: Boolean; ATagNo: Int32;
  const AObj: IAsn1Encodable);
var
  LExplicitness: Int32;
begin
  if AObj <> nil then
  begin
    if AIsExplicit then
      LExplicitness := 1  // DeclaredExplicit
    else
      LExplicitness := 2; // DeclaredImplicit
    Add(TDerTaggedObject.Create(LExplicitness, TAsn1Tags.ContextSpecific, ATagNo, AObj));
  end;
end;

procedure TAsn1EncodableVector.AddOptionalTagged(AIsExplicit: Boolean; ATagClass, ATagNo: Int32;
  const AObj: IAsn1Encodable);
var
  LExplicitness: Int32;
begin
  if AObj <> nil then
  begin
    if AIsExplicit then
      LExplicitness := 1  // DeclaredExplicit
    else
      LExplicitness := 2; // DeclaredImplicit
    Add(TDerTaggedObject.Create(LExplicitness, ATagClass, ATagNo, AObj));
  end;
end;

procedure TAsn1EncodableVector.AddAll(const AE: TCryptoLibGenericArray<IAsn1Encodable>);
var
  I: Int32;
begin
  if AE = nil then
    raise EArgumentNilCryptoLibException.Create('e');

  for I := 0 to System.Length(AE) - 1 do
    Add(AE[I]);
end;

procedure TAsn1EncodableVector.AddAll(const AOther: IAsn1EncodableVector);
var
  I: Int32;
  LOtherElementCount: Int32;
begin
  if AOther = nil then
    raise EArgumentNilCryptoLibException.Create('other');

  LOtherElementCount := AOther.Count;
  if LOtherElementCount < 1 then
    Exit;

  PrepareCapacity(LOtherElementCount);
  for I := 0 to LOtherElementCount - 1 do
  begin
    FElements[FElementCount] := AOther[I];
    System.Inc(FElementCount);
  end;
end;

function TAsn1EncodableVector.GetItem(AIndex: Int32): IAsn1Encodable;
begin
  if AIndex >= FElementCount then
    raise EArgumentOutOfRangeCryptoLibException.CreateFmt('%d >= %d', [AIndex, FElementCount]);

  Result := FElements[AIndex];
end;

function TAsn1EncodableVector.GetCount(): Int32;
begin
  Result := FElementCount;
end;

function TAsn1EncodableVector.CopyElements(): TCryptoLibGenericArray<IAsn1Encodable>;
begin
  Result := CopyElements(FElements, FElementCount);
end;

function TAsn1EncodableVector.TakeElements(): TCryptoLibGenericArray<IAsn1Encodable>;
var
  I: Int32;
begin
  if FElementCount = 0 then
  begin
    Result := FEmptyElements;
    Exit;
  end;

  if System.Length(FElements) = FElementCount then
  begin
    FCopyOnWrite := True;
    Result := FElements;
    Exit;
  end;

  System.SetLength(Result, FElementCount);

  for I := 0 to FElementCount - 1 do
    Result[I] := FElements[I];
end;

function TAsn1EncodableVector.PrepareCapacity(ARequiredCapacity: Int32): Int32;
var
  LCapacity, LMinCapacity: Int32;
begin
  LCapacity := System.Length(FElements);
  LMinCapacity := FElementCount + ARequiredCapacity;
  if (LMinCapacity > LCapacity) or FCopyOnWrite then
    Reallocate(LMinCapacity);
  Result := LMinCapacity;
end;

procedure TAsn1EncodableVector.Reallocate(AMinCapacity: Int32);
var
  I: Int32;
  LOldCapacity, LNewCapacity: Int32;
  LCopy: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  LOldCapacity := System.Length(FElements);
  LNewCapacity := Math.Max(LOldCapacity, AMinCapacity + (TBitOperations.Asr32(AMinCapacity, 1)));

  System.SetLength(LCopy, LNewCapacity);
  for I := 0 to FElementCount - 1 do
    LCopy[I] := FElements[I];

  FElements := LCopy;
  FCopyOnWrite := False;
end;

class function TAsn1EncodableVector.FromCollection(const AC: TCryptoLibGenericArray<IAsn1Encodable>): IAsn1EncodableVector;
var
  LV: TAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(System.Length(AC));
  LV.AddAll(AC);
  Result := LV;
end;

class function TAsn1EncodableVector.FromElement(const AElement: IAsn1Encodable): IAsn1EncodableVector;
var
  LV: TAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(1);
  LV.Add(AElement);
  Result := LV;
end;

class function TAsn1EncodableVector.FromEnumerable(const AE: TCryptoLibGenericArray<IAsn1Encodable>): IAsn1EncodableVector;
var
  LV: TAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create();
  LV.AddAll(AE);
  Result := LV;
end;

class function TAsn1EncodableVector.CloneElements(const AElements: TCryptoLibGenericArray<IAsn1Encodable>): TCryptoLibGenericArray<IAsn1Encodable>;
begin
  Result := CopyElements(AElements, System.Length(AElements));
end;

class constructor TAsn1EncodableVector.Create;
begin
  FEmptyElements := nil;
end;

{ TAsn1Object }

procedure TAsn1Object.EncodeTo(const AOutput: TStream);
var
  LAsn1Out: TAsn1OutputStream;
begin
  LAsn1Out := TAsn1OutputStream.CreateInstance(AOutput, TAsn1Encodable.Ber, True);
  try
    GetEncoding(LAsn1Out.Encoding).Encode(LAsn1Out);
  finally
    LAsn1Out.Free;
  end;
end;

procedure TAsn1Object.EncodeTo(const AOutput: TStream; const AEncoding: String);
var
  LAsn1Out: TAsn1OutputStream;
begin
  LAsn1Out := TAsn1OutputStream.CreateInstance(AOutput, AEncoding, True);
  try
    GetEncoding(LAsn1Out.Encoding).Encode(LAsn1Out);
  finally
    LAsn1Out.Free;
  end;
end;

function TAsn1Object.GetEncoded(const AEncoding: String; APreAlloc, APostAlloc: Int32): TCryptoLibByteArray;
var
  LEncodingType, LLength: Int32;
  LAsn1Encoding: IAsn1Encoding;
  LAsn1Out: TAsn1OutputStream;
begin
  LEncodingType := TAsn1OutputStream.GetEncodingType(AEncoding);
  LAsn1Encoding := GetEncoding(LEncodingType);
  LLength := LAsn1Encoding.GetLength();
  System.SetLength(Result, APreAlloc + LLength + APostAlloc);
  LAsn1Out := TAsn1OutputStream.CreateInstance(Result, APreAlloc, LLength, AEncoding, False);
  try
    LAsn1Encoding.Encode(LAsn1Out);
    // Assert(LAsn1Out.Length = LAsn1Out.Position);
  finally
    LAsn1Out.Free;
  end;
end;

function TAsn1Object.Equals(const AOther: IAsn1Object): Boolean;
begin
  Result := (Self as IAsn1Object) = AOther;
  if not Result and (AOther <> nil) then
    Result := Asn1Equals(AOther);
end;

class function TAsn1Object.FromByteArray(const AData: TCryptoLibByteArray): IAsn1Object;
begin
  Result := FromBufferStream(TFixedBufferStream.Create(AData, 0, System.Length(AData), False));
end;

class function TAsn1Object.FromBufferStream(const ABufferStream: TFixedBufferStream): IAsn1Object;
var
  LAsn1In: TAsn1InputStream;
begin
  LAsn1In := TAsn1InputStream.Create(ABufferStream);
  try
    Result := LAsn1In.ReadObject();
    if LAsn1In.Position <> LAsn1In.Size then
      raise EIOCryptoLibException.Create('extra data found after object');
  finally
    LAsn1In.Free;
  end;
end;

class function TAsn1Object.FromStream(const AInStr: TStream): IAsn1Object;
var
  LLimit: Int32;
  LAsn1In: TAsn1InputStream;
begin
  LLimit := TAsn1InputStream.FindLimit(AInStr);
  LAsn1In := TAsn1InputStream.Create(AInStr, LLimit, True);
  try
    Result := LAsn1In.ReadObject();
  finally
    LAsn1In.Free;
  end;
end;

function TAsn1Object.ToAsn1Object(): IAsn1Object;
begin
  Result := Self as IAsn1Object;
end;

function TAsn1Object.CallAsn1Equals(const AObj: IAsn1Object): Boolean;
begin
  Result := Asn1Equals(AObj);
end;

function TAsn1Object.CallAsn1GetHashCode(): Int32;
begin
  Result := Asn1GetHashCode();
end;

end.
