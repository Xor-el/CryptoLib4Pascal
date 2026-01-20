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

unit ClpDHDomainParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIDHDomainParameters,
  ClpIDHValidationParams,
  ClpDHValidationParams,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpAsn1Utilities,
  ClpCryptoLibTypes;

resourcestring
  SPNil = 'P Cannot be Nil';
  SGNil = 'G Cannot be Nil';
  SQNil = 'Q Cannot be Nil';
  SJNil = 'J Cannot be Nil';
  SBadSequenceSize = 'Bad Sequence Size "seq": %d';
  SInvalidDHDomainParameters = 'Invalid DHDomainParameters: %s';
  SUnexpectedElementsInSequence = 'Unexpected elements in sequence';

type
  TDHDomainParameters = class(TAsn1Encodable, IDHDomainParameters)

  strict private
  var
    Fp, Fg, Fq, Fj: IDerInteger;
    FvalidationParams: IDHValidationParams;

    function GetP: IDerInteger; inline;
    function GetG: IDerInteger; inline;
    function GetQ: IDerInteger; inline;
    function GetJ: IDerInteger; inline;
    function GetValidationParams: IDHValidationParams; inline;

    constructor Create(const seq: IAsn1Sequence); overload;

  public
    constructor Create(const p, g, q, j: IDerInteger;
      const validationParams: IDHValidationParams); overload;

    function ToAsn1Object(): IAsn1Object; override;

    property p: IDerInteger read GetP;

    property g: IDerInteger read GetG;

    property q: IDerInteger read GetQ;

    property j: IDerInteger read GetJ;

    property validationParams: IDHValidationParams read GetValidationParams;

    class function GetInstance(const obj: IAsn1TaggedObject;
      isExplicit: Boolean): IDHDomainParameters; overload; static; inline;

    class function GetInstance(obj: TObject): IDHDomainParameters; overload;
      static; inline;

  end;

implementation

{ TDHDomainParameters }

function TDHDomainParameters.GetP: IDerInteger;
begin
  result := Fp;
end;

function TDHDomainParameters.GetG: IDerInteger;
begin
  result := Fg;
end;

function TDHDomainParameters.GetJ: IDerInteger;
begin
  result := Fj;
end;

function TDHDomainParameters.GetQ: IDerInteger;
begin
  result := Fq;
end;

function TDHDomainParameters.GetValidationParams: IDHValidationParams;
begin
  result := FvalidationParams;
end;

constructor TDHDomainParameters.Create(const seq: IAsn1Sequence);
var
  LCount: Int32;
  LPos: Int32;
begin
  Inherited Create();
  LCount := seq.Count;
  LPos := 0;
  if (LCount < 3) or (LCount > 5) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize,
      [LCount]);
  end;

  Fp := TDerInteger.GetInstance(seq[LPos] as TAsn1Encodable);
  System.Inc(LPos);

  Fg := TDerInteger.GetInstance(seq[LPos] as TAsn1Encodable);
  System.Inc(LPos);

  Fq := TDerInteger.GetInstance(seq[LPos] as TAsn1Encodable);
  System.Inc(LPos);

  Fj := TAsn1Utilities.ReadOptional<IDerInteger>(seq, LPos, function(AElement: IAsn1Encodable): IDerInteger
    begin
      Result := TDerInteger.GetOptional(AElement);
    end);

  FvalidationParams := TAsn1Utilities.ReadOptional<IDHValidationParams>(seq, LPos, function(AElement: IAsn1Encodable): IDHValidationParams
    begin
      Result := TDHValidationParams.GetOptional(AElement);
    end);

  if LPos <> LCount then
    raise EArgumentCryptoLibException.CreateRes(@SUnexpectedElementsInSequence);
end;

constructor TDHDomainParameters.Create(const p, g, q, j: IDerInteger;
  const validationParams: IDHValidationParams);
begin
  Inherited Create();

  if (p = Nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SPNil);
  end;

  if (g = Nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SGNil);
  end;

  if (q = Nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SQNil);
  end;

  if (j = Nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SJNil);
  end;

  Fp := p;
  Fg := g;
  Fq := q;
  Fj := j;
  FvalidationParams := validationParams;
end;

class function TDHDomainParameters.GetInstance(obj: TObject)
  : IDHDomainParameters;
begin
  if ((obj = Nil) or (obj is TDHDomainParameters)) then
  begin
    result := obj as TDHDomainParameters;
    Exit;
  end;

  if (obj is TAsn1Sequence) then
  begin
    result := TDHDomainParameters.Create(obj as TAsn1Sequence);
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SInvalidDHDomainParameters,
    [obj.ToString]);
end;

class function TDHDomainParameters.GetInstance(const obj: IAsn1TaggedObject;
  isExplicit: Boolean): IDHDomainParameters;
begin
  result := GetInstance(TAsn1Sequence.GetInstance(obj, isExplicit)
    as TAsn1Sequence);
end;

function TDHDomainParameters.ToAsn1Object: IAsn1Object;
var
  v: IAsn1EncodableVector;
begin
  v := TAsn1EncodableVector.Create([p, g, q]);

  if (Fj <> Nil) then
  begin
    v.Add([Fj]);
  end;

  if (FvalidationParams <> Nil) then
  begin
    v.Add([FvalidationParams]);
  end;

  result := TDerSequence.Create(v);
end;

end.
