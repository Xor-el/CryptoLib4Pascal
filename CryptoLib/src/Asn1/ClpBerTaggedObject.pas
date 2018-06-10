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

unit ClpBerTaggedObject;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpCryptoLibTypes,
{$IFDEF DELPHI}
  ClpAsn1TaggedObject,
  ClpIBerSequence,
{$ENDIF DELPHI}
  ClpAsn1Tags,
  ClpBerSequence,
  ClpAsn1OutputStream,
  ClpBerOutputStream,
  ClpIAsn1OctetString,
  ClpAsn1Encodable,
  ClpBerOctetString,
  ClpIBerOctetString,
  ClpIDerOctetString,
  ClpIAsn1Set,
  ClpIAsn1Sequence,
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
    constructor Create(tagNo: Int32; const obj: IAsn1Encodable); overload;
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
      const obj: IAsn1Encodable); overload;

    /// <summary>
    /// create an implicitly tagged object that contains a zero length
    /// sequence.
    /// </summary>
    /// <param name="tagNo">
    /// the tag number for this object.
    /// </param>
    constructor Create(tagNo: Int32); overload;

    procedure Encode(const derOut: IDerOutputStream); override;

  end;

implementation

{ TBerTaggedObject }

constructor TBerTaggedObject.Create(tagNo: Int32; const obj: IAsn1Encodable);
begin
  Inherited Create(tagNo, obj);
end;

constructor TBerTaggedObject.Create(explicitly: Boolean; tagNo: Int32;
  const obj: IAsn1Encodable);
begin
  Inherited Create(explicitly, tagNo, obj)
end;

constructor TBerTaggedObject.Create(tagNo: Int32);
begin
  Inherited Create(false, tagNo, TBerSequence.Empty)
end;

procedure TBerTaggedObject.Encode(const derOut: IDerOutputStream);
var
  eObj: TList<IAsn1Encodable>;
  LListIDerOctetString: TCryptoLibGenericArray<IDerOctetString>;
  LListIAsn1Encodable: TCryptoLibGenericArray<IAsn1Encodable>;
  asn1OctetString: IAsn1OctetString;
  berOctetString: IBerOctetString;
  derOctetString: IDerOctetString;
  asn1Sequence: IAsn1Sequence;
  asn1Set: IAsn1Set;
  o: IAsn1Encodable;
begin
  eObj := TList<IAsn1Encodable>.Create();
  try
    if ((derOut is TAsn1OutputStream) or (derOut is TBerOutputStream)) then
    begin
      derOut.WriteTag(Byte(TAsn1Tags.Constructed or TAsn1Tags.Tagged), tagNo);
      derOut.WriteByte($80);

      if (not IsEmpty()) then
      begin
        if (not explicitly) then
        begin
          if (Supports(obj, IAsn1OctetString, asn1OctetString)) then
          begin
            if (Supports(asn1OctetString, IBerOctetString, berOctetString)) then
            begin
              LListIDerOctetString := berOctetString.GetEnumerable;
              for derOctetString in LListIDerOctetString do
              begin
                eObj.Add(derOctetString as IAsn1Encodable);
              end;
            end
            else
            begin
              berOctetString := TBerOctetString.Create
                (asn1OctetString.GetOctets());
              LListIDerOctetString := berOctetString.GetEnumerable;
              for derOctetString in LListIDerOctetString do
              begin
                eObj.Add(derOctetString as IAsn1Encodable);
              end;
            end
          end
          else if Supports(obj, IAsn1Sequence, asn1Sequence) then
          begin
            LListIAsn1Encodable := asn1Sequence.GetEnumerable;
            for o in LListIAsn1Encodable do
            begin
              eObj.Add(o);
            end;
          end
          else if Supports(obj, IAsn1Set, asn1Set) then
          begin
            LListIAsn1Encodable := asn1Set.GetEnumerable;
            for o in LListIAsn1Encodable do
            begin
              eObj.Add(o);
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
