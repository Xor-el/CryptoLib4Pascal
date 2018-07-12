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

unit ClpX9FieldElement;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpECFieldElement,
  ClpCryptoLibTypes,
  ClpDerOctetString,
  ClpX9IntegerConverter,
  ClpIProxiedInterface,
  ClpIAsn1OctetString,
  ClpIECFieldElement,
  ClpIX9FieldElement,
  ClpAsn1Encodable;

type

  /// <summary>
  /// Class for processing an ECFieldElement as a DER object.
  /// </summary>
  TX9FieldElement = class(TAsn1Encodable, IX9FieldElement)

  strict private
  var
    Ff: IECFieldElement;

    function GetValue: IECFieldElement; inline;

  public
    constructor Create(const f: IECFieldElement); overload;
    constructor Create(const p: TBigInteger; const s: IAsn1OctetString);
      overload; deprecated 'Will be removed';
    constructor Create(m, k1, k2, k3: Int32; const s: IAsn1OctetString);
      overload; deprecated 'Will be removed';

    // /**
    // * Produce an object suitable for an Asn1OutputStream.
    // * <pre>
    // *  FieldElement ::= OCTET STRING
    // * </pre>
    // * <p>
    // * <ol>
    // * <li> if <i>q</i> is an odd prime then the field element is
    // * processed as an Integer and converted to an octet string
    // * according to x 9.62 4.3.1.</li>
    // * <li> if <i>q</i> is 2<sup>m</sup> then the bit string
    // * contained in the field element is converted into an octet
    // * string with the same ordering padded at the front if necessary.
    // * </li>
    // * </ol>
    // * </p>
    // */
    function ToAsn1Object(): IAsn1Object; override;

    property Value: IECFieldElement read GetValue;

  end;

implementation

{ TX9FieldElement }

constructor TX9FieldElement.Create(const p: TBigInteger;
  const s: IAsn1OctetString);
begin
  Create(TFpFieldElement.Create(p, TBigInteger.Create(1, s.GetOctets()))
    as IFpFieldElement)
end;

constructor TX9FieldElement.Create(const f: IECFieldElement);
begin
  Inherited Create();
  Ff := f;
end;

constructor TX9FieldElement.Create(m, k1, k2, k3: Int32;
  const s: IAsn1OctetString);
begin
  Create(TF2mFieldElement.Create(m, k1, k2, k3, TBigInteger.Create(1,
    s.GetOctets())) as IF2mFieldElement)
end;

function TX9FieldElement.GetValue: IECFieldElement;
begin
  result := Ff;
end;

function TX9FieldElement.ToAsn1Object: IAsn1Object;
var
  byteCount: Int32;
  paddedBigInteger: TCryptoLibByteArray;
begin
  byteCount := TX9IntegerConverter.GetByteLength(Ff);
  paddedBigInteger := TX9IntegerConverter.IntegerToBytes(Ff.ToBigInteger(),
    byteCount);

  result := TDerOctetString.Create(paddedBigInteger);
end;

end.
