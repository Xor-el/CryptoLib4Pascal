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

unit ClpGlvTypeBParameters;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIGlvTypeBParameters,
  ClpCryptoLibTypes;

resourcestring
  SInvalidParameters = '"%s" must consist of exactly 2 (initialized) values';

type
  TGlvTypeBParameters = class sealed(TInterfacedObject, IGlvTypeBParameters)

  strict private
    function GetG1: TBigInteger; inline;
    function GetG2: TBigInteger; inline;
    function GetV1A: TBigInteger; inline;
    function GetV1B: TBigInteger; inline;
    function GetV2A: TBigInteger; inline;
    function GetV2B: TBigInteger; inline;
    function GetLambda: TBigInteger; inline;
    function GetBeta: TBigInteger; inline;
    function GetBits: Int32; inline;

    class procedure CheckVector(const v: TCryptoLibGenericArray<TBigInteger>;
      const name: String); static;

  strict protected
    Fbeta, Flambda, Fg1, Fg2, Fv1A, Fv1B, Fv2A, Fv2B: TBigInteger;
    Fbits: Int32;

  public
    constructor Create(const beta, lambda: TBigInteger;
      const v1, v2: TCryptoLibGenericArray<TBigInteger>;
      const g1, g2: TBigInteger; bits: Int32);

    destructor Destroy; override;

    property g1: TBigInteger read GetG1;
    property g2: TBigInteger read GetG2;
    property V1A: TBigInteger read GetV1A;
    property V1B: TBigInteger read GetV1B;
    property V2A: TBigInteger read GetV2A;
    property V2B: TBigInteger read GetV2B;
    property lambda: TBigInteger read GetLambda;
    property beta: TBigInteger read GetBeta;
    property bits: Int32 read GetBits;

  end;

implementation

{ TGlvTypeBParameters }

class procedure TGlvTypeBParameters.CheckVector
  (const v: TCryptoLibGenericArray<TBigInteger>; const name: String);
begin
  if ((v = Nil) or (System.length(v) <> 2) or (not v[0].IsInitialized) or
    (not v[1].IsInitialized)) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidParameters, [name]);
  end;
end;

constructor TGlvTypeBParameters.Create(const beta, lambda: TBigInteger;
  const v1, v2: TCryptoLibGenericArray<TBigInteger>; const g1, g2: TBigInteger;
  bits: Int32);
begin
  CheckVector(v1, 'v1');
  CheckVector(v2, 'v2');

  Fbeta := beta;
  Flambda := lambda;
  Fv1A := v1[0];
  Fv1B := v1[1];
  Fv2A := v2[0];
  Fv2B := v2[1];
  Fg1 := g1;
  Fg2 := g2;
  Fbits := bits;
end;

destructor TGlvTypeBParameters.Destroy;
begin
  inherited Destroy;
end;

function TGlvTypeBParameters.GetG1: TBigInteger;
begin
  Result := Fg1;
end;

function TGlvTypeBParameters.GetG2: TBigInteger;
begin
  Result := Fg2;
end;

function TGlvTypeBParameters.GetV1A: TBigInteger;
begin
  Result := Fv1A;
end;

function TGlvTypeBParameters.GetV1B: TBigInteger;
begin
  Result := Fv1B;
end;

function TGlvTypeBParameters.GetV2A: TBigInteger;
begin
  Result := Fv2A;
end;

function TGlvTypeBParameters.GetV2B: TBigInteger;
begin
  Result := Fv2B;
end;

function TGlvTypeBParameters.GetBeta: TBigInteger;
begin
  Result := Fbeta;
end;

function TGlvTypeBParameters.GetBits: Int32;
begin
  Result := Fbits;
end;

function TGlvTypeBParameters.GetLambda: TBigInteger;
begin
  Result := Flambda;
end;

end.
