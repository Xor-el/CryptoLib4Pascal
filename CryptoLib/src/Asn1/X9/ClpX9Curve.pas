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

unit ClpX9Curve;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpBigInteger,
  ClpIDerSequence,
  ClpIDerInteger,
  ClpIDerObjectIdentifier,
  ClpDerBitString,
  ClpIDerBitString,
  ClpDerSequence,
  ClpX9FieldElement,
  ClpIX9FieldID,
  ClpIX9FieldElement,
  ClpIAsn1OctetString,
  ClpECAlgorithms,
  ClpAsn1OctetString,
  ClpAsn1EncodableVector,
  ClpIAsn1EncodableVector,
  ClpX9ObjectIdentifiers,
  ClpIProxiedInterface,
  ClpIAsn1Sequence,
  ClpIX9Curve,
  ClpECCurve,
  ClpIECInterface,
  ClpAsn1Encodable;

resourcestring
  SCurveNil = 'Curve';
  SNotImplementedECCurve = 'This Type of ECCurve is not Implemented';
  SFieldIDNil = 'FieldID';
  SSeqNil = 'Seq';

type

  /// <summary>
  /// ASN.1 def for Elliptic-Curve Curve structure. See X9.62, for further
  /// details.
  /// </summary>
  TX9Curve = class(TAsn1Encodable, IX9Curve)

  strict private
  var
    FSeed: TCryptoLibByteArray;
    FfieldIdentifier: IDerObjectIdentifier;
    Fcurve: IECCurve;

    function GetCurve: IECCurve; inline;

  public
    constructor Create(const curve: IECCurve); overload;
    constructor Create(const curve: IECCurve;
      const seed: TCryptoLibByteArray); overload;
    constructor Create(const fieldID: IX9FieldID; const seq: IAsn1Sequence);
      overload; deprecated 'Use constructor including order/cofactor';

    constructor Create(const fieldID: IX9FieldID;
      const order, cofactor: TBigInteger; const seq: IAsn1Sequence); overload;

    function GetSeed(): TCryptoLibByteArray; inline;

    property curve: IECCurve read GetCurve;

    /// <summary>
    /// <para>
    /// Produce an object suitable for an Asn1OutputStream. <br />
    /// &lt;pre&gt;
    /// </para>
    /// <para>
    /// Curve ::= Sequence { a FieldElement, b FieldElement, seed BIT
    /// STRING OPTIONAL }
    /// </para>
    /// <para>
    /// <br />&lt;/pre&gt;
    /// </para>
    /// </summary>
    function ToAsn1Object(): IAsn1Object; override;

  end;

implementation

{ TX9Curve }

constructor TX9Curve.Create(const curve: IECCurve;
  const seed: TCryptoLibByteArray);
begin
  Inherited Create();
  if (curve = Nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SCurveNil);
  end;

  Fcurve := curve;
  FSeed := System.Copy(seed);

  if (TECAlgorithms.IsFpCurve(curve)) then
  begin
    FfieldIdentifier := TX9ObjectIdentifiers.PrimeField;
  end
  else if (TECAlgorithms.IsF2mCurve(curve)) then
  begin
    FfieldIdentifier := TX9ObjectIdentifiers.CharacteristicTwoField;
  end
  else
  begin
    raise EArgumentCryptoLibException.CreateRes(@SNotImplementedECCurve);
  end;
end;

constructor TX9Curve.Create(const curve: IECCurve);
begin
  Create(curve, Nil);
end;

constructor TX9Curve.Create(const fieldID: IX9FieldID;
  const seq: IAsn1Sequence);
begin
  Create(fieldID, Default (TBigInteger), Default (TBigInteger), seq);
end;

constructor TX9Curve.Create(const fieldID: IX9FieldID;
  const order, cofactor: TBigInteger; const seq: IAsn1Sequence);
var
  p, A, B: TBigInteger;
  parameters: IDerSequence;
  representation: IDerObjectIdentifier;
  pentanomial: IDerSequence;
  m, k1, k2, k3: Int32;
begin
  Inherited Create();
  if (fieldID = Nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SFieldIDNil);
  end;
  if (seq = Nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SSeqNil);
  end;

  FfieldIdentifier := fieldID.Identifier;

  if (FfieldIdentifier.Equals(TX9ObjectIdentifiers.PrimeField)) then
  begin
    p := (fieldID.parameters as IDerInteger).Value;
    A := TBigInteger.Create(1,
      TAsn1OctetString.GetInstance(seq[0] as TAsn1Encodable).GetOctets());
    B := TBigInteger.Create(1,
      TAsn1OctetString.GetInstance(seq[1] as TAsn1Encodable).GetOctets());
    Fcurve := TFpCurve.Create(p, A, B, order, cofactor);
  end
  else if (FfieldIdentifier.Equals(TX9ObjectIdentifiers.CharacteristicTwoField))
  then
  begin
    // Characteristic two field
    parameters := fieldID.parameters as IDerSequence;
    m := (parameters[0] as IDerInteger).Value.Int32Value;
    representation := parameters[1] as IDerObjectIdentifier;

    k2 := 0;
    k3 := 0;
    if (representation.Equals(TX9ObjectIdentifiers.TPBasis)) then
    begin
      // Trinomial basis representation
      k1 := (parameters[2] as IDerInteger).Value.Int32Value;
    end
    else
    begin
      // Pentanomial basis representation
      pentanomial := parameters[2] as IDerSequence;
      k1 := (pentanomial[0] as IDerInteger).Value.Int32Value;
      k2 := (pentanomial[1] as IDerInteger).Value.Int32Value;
      k3 := (pentanomial[2] as IDerInteger).Value.Int32Value;
    end;
    A := TBigInteger.Create(1,
      TAsn1OctetString.GetInstance(seq[0] as TAsn1Encodable).GetOctets());
    B := TBigInteger.Create(1,
      TAsn1OctetString.GetInstance(seq[1] as TAsn1Encodable).GetOctets());

    Fcurve := TF2mCurve.Create(m, k1, k2, k3, A, B, order, cofactor);
  end
  else
  begin
    raise EArgumentCryptoLibException.CreateRes(@SNotImplementedECCurve);
  end;

  if (seq.Count = 3) then
  begin
    FSeed := (seq[2] as IDerBitString).GetBytes();
  end;

end;

function TX9Curve.GetCurve: IECCurve;
begin
  result := Fcurve;
end;

function TX9Curve.GetSeed: TCryptoLibByteArray;
begin
  result := System.Copy(FSeed);
end;

function TX9Curve.ToAsn1Object: IAsn1Object;
var
  v: IAsn1EncodableVector;
begin
  v := TAsn1EncodableVector.Create();

  if (FfieldIdentifier.Equals(TX9ObjectIdentifiers.PrimeField) or
    FfieldIdentifier.Equals(TX9ObjectIdentifiers.CharacteristicTwoField)) then
  begin
    v.Add([(TX9FieldElement.Create(Fcurve.A) as IX9FieldElement)
      .ToAsn1Object()]);
    v.Add([(TX9FieldElement.Create(Fcurve.B) as IX9FieldElement)
      .ToAsn1Object()]);
  end;

  if (FSeed <> Nil) then
  begin
    v.Add([TDerBitString.Create(FSeed) as IDerBitString]);
  end;

  result := TDerSequence.Create(v);
end;

end.
