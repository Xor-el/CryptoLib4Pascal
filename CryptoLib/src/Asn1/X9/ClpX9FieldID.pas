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

unit ClpX9FieldID;

interface

uses
  ClpCryptoLibTypes,
  ClpIX9FieldID,
  ClpIDerInteger,
  ClpAsn1Sequence,
  ClpIAsn1Sequence,
  ClpAsn1EncodableVector,
  ClpIAsn1EncodableVector,
  ClpX9ObjectIdentifiers,
  ClpDerInteger,
  ClpBigInteger,
  ClpDerSequence,
  ClpDerObjectIdentifier,
  ClpIDerObjectIdentifier,
  ClpIProxiedInterface,
  ClpAsn1Encodable;

resourcestring
  SInconsistentKValues = 'Inconsistent K Values';

type

  /// <summary>
  /// ASN.1 def for Elliptic-Curve Field ID structure. See X9.62, for further
  /// details.
  /// </summary>
  TX9FieldID = class(TAsn1Encodable, IX9FieldID)

  strict private
  var
    Fid: IDerObjectIdentifier;
    Fparameters: IAsn1Object;

    function GetIdentifier: IDerObjectIdentifier; inline;
    function GetParameters: IAsn1Object; inline;

    constructor Create(const seq: IAsn1Sequence); overload;

  public
    // /**
    // * Constructor for elliptic curves over prime fields
    // * <code>F<sub>2</sub></code>.
    // * @param primeP The prime <code>p</code> defining the prime field.
    // */
    constructor Create(const primeP: TBigInteger); overload;
    // /**
    // * Constructor for elliptic curves over binary fields
    // * <code>F<sub>2<sup>m</sup></sub></code>.
    // * @param m  The exponent <code>m</code> of
    // * <code>F<sub>2<sup>m</sup></sub></code>.
    // * @param k1 The integer <code>k1</code> where <code>x<sup>m</sup> +
    // * x<sup>k1</sup> + 1</code>
    // * represents the reduction polynomial <code>f(z)</code>.
    // */
    constructor Create(m, k1: Int32); overload;
    // /**
    // * Constructor for elliptic curves over binary fields
    // * <code>F<sub>2<sup>m</sup></sub></code>.
    // * @param m  The exponent <code>m</code> of
    // * <code>F<sub>2<sup>m</sup></sub></code>.
    // * @param k1 The integer <code>k1</code> where <code>x<sup>m</sup> +
    // * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
    // * represents the reduction polynomial <code>f(z)</code>.
    // * @param k2 The integer <code>k2</code> where <code>x<sup>m</sup> +
    // * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
    // * represents the reduction polynomial <code>f(z)</code>.
    // * @param k3 The integer <code>k3</code> where <code>x<sup>m</sup> +
    // * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
    // * represents the reduction polynomial <code>f(z)</code>..
    // */
    constructor Create(m, k1, k2, k3: Int32); overload;

    property Identifier: IDerObjectIdentifier read GetIdentifier;

    property Parameters: IAsn1Object read GetParameters;

    /// <summary>
    /// <para>
    /// Produce a Der encoding of the following structure. <br />
    /// &lt;pre&gt;
    /// </para>
    /// <para>
    /// FieldID ::= Sequence { fieldType FIELD-ID.&amp;amp;id({IOSet}),
    /// parameters FIELD-ID.&amp;amp;Type({IOSet}{&amp;#64;fieldType})} <br />
    /// </para>
    /// <para>
    /// &lt;/pre&gt; <br />
    /// </para>
    /// </summary>
    function ToAsn1Object(): IAsn1Object; override;

    class function GetInstance(obj: TObject): IX9FieldID; static;

  end;

implementation

{ TX9FieldID }

constructor TX9FieldID.Create(m, k1: Int32);
begin
  Create(m, k1, 0, 0);
end;

constructor TX9FieldID.Create(const primeP: TBigInteger);
begin
  Inherited Create();
  Fid := TX9ObjectIdentifiers.PrimeField;
  Fparameters := TDerInteger.Create(primeP);
end;

constructor TX9FieldID.Create(const seq: IAsn1Sequence);
begin
  Inherited Create();
  Fid := TDerObjectIdentifier.GetInstance(seq[0] as TAsn1Encodable);
  Fparameters := seq[1].ToAsn1Object();
end;

constructor TX9FieldID.Create(m, k1, k2, k3: Int32);
var
  fieldIdParams: IAsn1EncodableVector;
begin
  inherited Create();
  Fid := TX9ObjectIdentifiers.CharacteristicTwoField;

  fieldIdParams := TAsn1EncodableVector.Create
    ([TDerInteger.Create(m) as IDerInteger]);

  if (k2 = 0) then
  begin
    if (k3 <> 0) then
    begin
      raise EArgumentCryptoLibException.CreateRes(@SInconsistentKValues);
    end;

    fieldIdParams.Add([TX9ObjectIdentifiers.TPBasis, TDerInteger.Create(k1)
      as IDerInteger]);
  end
  else
  begin
    if ((k2 <= k1) or (k3 <= k2)) then
    begin
      raise EArgumentCryptoLibException.CreateRes(@SInconsistentKValues);

    end;

    fieldIdParams.Add([TX9ObjectIdentifiers.PPBasis,
      TDerSequence.Create([TDerInteger.Create(k1) as IDerInteger,
      TDerInteger.Create(k2) as IDerInteger, TDerInteger.Create(k3)
      as IDerInteger])]);
  end;

  Fparameters := TDerSequence.Create(fieldIdParams);
end;

function TX9FieldID.GetIdentifier: IDerObjectIdentifier;
begin
  result := Fid;
end;

class function TX9FieldID.GetInstance(obj: TObject): IX9FieldID;
var
  x9FieldId: IX9FieldID;
begin
  x9FieldId := obj as TX9FieldID;
  if (x9FieldId <> Nil) then
  begin
    result := x9FieldId;
    Exit;
  end;
  if (obj = Nil) then
  begin
    result := Nil;
    Exit;
  end;
  result := TX9FieldID.Create(TAsn1Sequence.GetInstance(obj));
end;

function TX9FieldID.GetParameters: IAsn1Object;
begin
  result := Fparameters;
end;

function TX9FieldID.ToAsn1Object: IAsn1Object;
begin
  result := TDerSequence.Create([Fid, Fparameters]);
end;

end.
