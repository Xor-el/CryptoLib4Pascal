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

unit ClpX9ECPoint;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpDerOctetString,
  ClpIAsn1OctetString,
  ClpIProxiedInterface,
  ClpIECInterface,
  ClpIX9ECPoint,
  ClpAsn1Encodable;

type
  // /**
  // * class for describing an ECPoint as a Der object.
  // */
  TX9ECPoint = class sealed(TAsn1Encodable, IX9ECPoint)

  strict private
  var
    Fencoding: IAsn1OctetString;
    Fc: IECCurve;
    Fp: IECPoint;

    function GetIsPointCompressed: Boolean; inline;
    function GetPoint: IECPoint; inline;

  public

    constructor Create(const p: IECPoint); overload;
    constructor Create(const p: IECPoint; compressed: Boolean); overload;
    constructor Create(const c: IECCurve;
      const encoding: TCryptoLibByteArray); overload;
    constructor Create(const c: IECCurve; const s: IAsn1OctetString); overload;

    property Point: IECPoint read GetPoint;
    property IsPointCompressed: Boolean read GetIsPointCompressed;

    function GetPointEncoding(): TCryptoLibByteArray; inline;

    // /**
    // * Produce an object suitable for an Asn1OutputStream.
    // * <pre>
    // *  ECPoint ::= OCTET STRING
    // * </pre>
    // * <p>
    // * Octet string produced using ECPoint.GetEncoded().</p>
    // */
    function ToAsn1Object(): IAsn1Object; override;

  end;

implementation

{ TX9ECPoint }

constructor TX9ECPoint.Create(const c: IECCurve;
  const encoding: TCryptoLibByteArray);
begin
  inherited Create();
  Fc := c;
  Fencoding := TDerOctetString.Create(System.Copy(encoding));
end;

constructor TX9ECPoint.Create(const p: IECPoint; compressed: Boolean);
begin
  inherited Create();
  Fp := p.Normalize();
  Fencoding := TDerOctetString.Create(p.GetEncoded(compressed));
end;

constructor TX9ECPoint.Create(const p: IECPoint);
begin
  Create(p, false);
end;

constructor TX9ECPoint.Create(const c: IECCurve; const s: IAsn1OctetString);
begin
  Create(c, s.GetOctets());
end;

function TX9ECPoint.GetPointEncoding(): TCryptoLibByteArray;
begin
  Result := Fencoding.GetOctets();
end;

function TX9ECPoint.GetIsPointCompressed: Boolean;
var
  octets: TCryptoLibByteArray;
begin
  octets := Fencoding.GetOctets();
  Result := (octets <> Nil) and (System.Length(octets) > 0) and
    ((octets[0] = 2) or (octets[0] = 3));
end;

function TX9ECPoint.GetPoint: IECPoint;
begin
  if (Fp = Nil) then
  begin
    Fp := Fc.DecodePoint(Fencoding.GetOctets()).Normalize();
  end;

  Result := Fp;
end;

function TX9ECPoint.ToAsn1Object: IAsn1Object;
begin
  Result := Fencoding;
end;

end.
