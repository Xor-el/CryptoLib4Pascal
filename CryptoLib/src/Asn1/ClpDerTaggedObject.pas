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

unit ClpDerTaggedObject;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpAsn1Tags,
  ClpDerSequence,
{$IFDEF DELPHI}
  ClpIDerSequence,
{$ENDIF DELPHI}
  ClpIProxiedInterface,
  ClpAsn1TaggedObject,
  ClpIDerTaggedObject;

type

  /// <summary>
  /// DER TaggedObject - in ASN.1 notation this is any object preceded by <br />
  /// a [n] where n is some number - these are assumed to follow the
  /// construction <br />rules (as with sequences). <br />
  /// </summary>
  TDerTaggedObject = class(TAsn1TaggedObject, IDerTaggedObject)

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

{ TDerTaggedObject }

constructor TDerTaggedObject.Create(tagNo: Int32; const obj: IAsn1Encodable);
begin
  Inherited Create(tagNo, obj);
end;

constructor TDerTaggedObject.Create(explicitly: Boolean; tagNo: Int32;
  const obj: IAsn1Encodable);
begin
  Inherited Create(explicitly, tagNo, obj)
end;

constructor TDerTaggedObject.Create(tagNo: Int32);
begin
  Inherited Create(false, tagNo, TDerSequence.Empty)
end;

procedure TDerTaggedObject.Encode(const derOut: IDerOutputStream);
var
  bytes: TCryptoLibByteArray;
  flags: Int32;
begin
  if (not IsEmpty()) then
  begin
    bytes := obj.GetDerEncoded();

    if (explicitly) then
    begin
      derOut.WriteEncoded(TAsn1Tags.Constructed or TAsn1Tags.Tagged,
        tagNo, bytes);
    end
    else
    begin
      //
      // need to mark constructed types... (preserve Constructed tag)
      //
      flags := (bytes[0] and TAsn1Tags.Constructed) or TAsn1Tags.Tagged;
      derOut.WriteTag(flags, tagNo);
      derOut.Write(bytes[1], System.Length(bytes) - 1);
    end
  end
  else
  begin
    derOut.WriteEncoded(TAsn1Tags.Constructed or TAsn1Tags.Tagged, tagNo, Nil);
  end;
end;

end.
