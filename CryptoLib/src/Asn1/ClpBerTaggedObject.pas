{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                    Copyright (c) 2018 Ugochukwu Mmaduekwe                       * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *        Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring        * }
{ *                        the development of this library                          * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpBerTaggedObject;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpCryptoLibTypes,
  ClpAsn1Tags,
  ClpBerSequence,
  ClpIAsn1OctetString,
  ClpAsn1Encodable,
  ClpBerOctetString,
  ClpIBerOctetString,
  ClpIDerOctetString,
  ClpIAsn1Set,
  ClpIAsn1Sequence,
  ClpIAsn1OutputStream,
  ClpIBerOutputStream,
  ClpIProxiedInterface,
  ClpDerTaggedObject,
  ClpIBerTaggedObject;

resourcestring
  SNotImplemented = 'Not Implemented %s';

type

  /// <summary>
  /// BER TaggedObject - in ASN.1 notation this is any object preceded by <br />
  /// a [n] where n is some number - these are assumed to follow the
  /// construction <br />rules (as with sequences). <br />
  /// </summary>
  TBerTaggedObject = class(TDerTaggedObject, IBerTaggedObject)

  public

    /// <param name="tagNo">
    /// the tag number for this object.
    /// </param>
    /// <param name="obj">
    /// the tagged object.
    /// </param>
    constructor Create(tagNo: Int32; obj: IAsn1Encodable); overload;
    /// <param name="explicitly">
    /// true if an explicitly tagged object.
    /// </param>
    /// <param name="tagNo">
    /// the tag number for this object.
    /// </param>
    /// <param name="obj">
    /// the tagged object.
    /// </param>
    constructor Create(explicitly: Boolean; tagNo: Int32;
      obj: IAsn1Encodable); overload;

    /// <summary>
    /// create an implicitly tagged object that contains a zero length
    /// sequence.
    /// </summary>
    /// <param name="tagNo">
    /// the tag number for this object.
    /// </param>
    constructor Create(tagNo: Int32); overload;

    procedure Encode(derOut: IDerOutputStream); override;

  end;

implementation

{ TBerTaggedObject }

constructor TBerTaggedObject.Create(tagNo: Int32; obj: IAsn1Encodable);
begin
  Inherited Create(tagNo, obj);
end;

constructor TBerTaggedObject.Create(explicitly: Boolean; tagNo: Int32;
  obj: IAsn1Encodable);
begin
  Inherited Create(explicitly, tagNo, obj)
end;

constructor TBerTaggedObject.Create(tagNo: Int32);
begin
  Inherited Create(false, tagNo, TBerSequence.Empty)
end;

procedure TBerTaggedObject.Encode(derOut: IDerOutputStream);
var
  eObj: TList<IAsn1Encodable>;
  enumeratorIBerOctetString: TEnumerator<IDerOctetString>;
  enumeratorIAsn1Sequence, enumeratorIAsn1Set: TEnumerator<IAsn1Encodable>;
  asn1OctetString: IAsn1OctetString;
  berOctetString: IBerOctetString;
  asn1Sequence: IAsn1Sequence;
  asn1Set: IAsn1Set;
  o: IAsn1Encodable;
begin
  eObj := TList<IAsn1Encodable>.Create();
  try
    if ((Supports(derOut, IAsn1OutputStream)) or
      (Supports(derOut, IBerOutputStream))) then
    begin
      derOut.WriteTag(Byte(TAsn1Tags.Constructed or TAsn1Tags.Tagged), tagNo);
      derOut.WriteByte($80);

      if (not IsEmpty()) then
      begin
        if (not explicitly) then
        begin

          // asn1OctetString := obj as IAsn1OctetString;
          if (Supports(obj, IAsn1OctetString, asn1OctetString)) then
          begin
            // berOctetString := asn1OctetString as IBerOctetString;
            if (Supports(asn1OctetString, IBerOctetString, berOctetString)) then
            begin
              enumeratorIBerOctetString := berOctetString.GetEnumerator;
              while enumeratorIBerOctetString.MoveNext do
              begin
                eObj.Add(enumeratorIBerOctetString.Current as IAsn1Encodable);
              end;
            end
            else
            begin
              enumeratorIBerOctetString :=
                TBerOctetString.Create(asn1OctetString.GetOctets())
                .GetEnumerator;
              while enumeratorIBerOctetString.MoveNext do
              begin
                eObj.Add(enumeratorIBerOctetString.Current as IAsn1Encodable);
              end;
            end
          end
          else if Supports(obj, IAsn1Sequence, asn1Sequence) then
          begin
            // eObj := obj as IAsn1Sequence;
            // asn1Sequence := obj as IAsn1Sequence;
            enumeratorIAsn1Sequence := asn1Sequence.GetEnumerator;
            while enumeratorIAsn1Sequence.MoveNext do
            begin
              eObj.Add(enumeratorIAsn1Sequence.Current);
            end;
          end
          else if Supports(obj, IAsn1Set, asn1Set) then
          begin
            // eObj := obj as IAsn1Set;
            // asn1Set := obj as IAsn1Set;
            enumeratorIAsn1Set := asn1Set.GetEnumerator;
            while enumeratorIAsn1Set.MoveNext do
            begin
              eObj.Add(enumeratorIAsn1Set.Current);
            end;
          end
          else
          begin
            raise ENotImplementedCryptoLibException.CreateResFmt
              (@SNotImplemented, [(obj as TAsn1Encodable).ClassName]);
          end;

          for o in eObj do
          begin
            derOut.WriteObject(o);
          end;
        end
        else
        begin
          derOut.WriteObject(obj);
        end;
      end;

      derOut.WriteByte($00);
      derOut.WriteByte($00);
    end
    else
    begin
      (Inherited Encode(derOut));
    end
  finally
    eObj.Free;
  end;

end;

end.
