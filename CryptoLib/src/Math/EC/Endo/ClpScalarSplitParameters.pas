{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ * ******************************************************************************* * }

unit ClpScalarSplitParameters;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIScalarSplitParameters,
  ClpCryptoLibTypes;

type
  TScalarSplitParameters = class(TInterfacedObject, IScalarSplitParameters)
  strict private
    FV1A, FV1B, FV2A, FV2B, FG1, FG2: TBigInteger;
    FBits: Int32;
    function GetV1A: TBigInteger;
    function GetV1B: TBigInteger;
    function GetV2A: TBigInteger;
    function GetV2B: TBigInteger;
    function GetG1: TBigInteger;
    function GetG2: TBigInteger;
    function GetBits: Int32;
  private
    class procedure CheckVector(const AV: TCryptoLibGenericArray<TBigInteger>;
      const AName: String); static;
  public
    constructor Create(const AV1, AV2: TCryptoLibGenericArray<TBigInteger>;
      const AG1, AG2: TBigInteger; ABits: Int32);
    property V1A: TBigInteger read GetV1A;
    property V1B: TBigInteger read GetV1B;
    property V2A: TBigInteger read GetV2A;
    property V2B: TBigInteger read GetV2B;
    property G1: TBigInteger read GetG1;
    property G2: TBigInteger read GetG2;
    property Bits: Int32 read GetBits;
  end;

implementation

{ TScalarSplitParameters }

class procedure TScalarSplitParameters.CheckVector(
  const AV: TCryptoLibGenericArray<TBigInteger>; const AName: String);
begin
  if (AV = nil) or (System.Length(AV) <> 2) or (not AV[0].IsInitialized) or
    (not AV[1].IsInitialized) then
    raise EArgumentCryptoLibException.Create('Must consist of exactly 2 (non-null) values: ' + AName);
end;

constructor TScalarSplitParameters.Create(const AV1,
  AV2: TCryptoLibGenericArray<TBigInteger>; const AG1, AG2: TBigInteger;
  ABits: Int32);
begin
  Inherited Create;
  CheckVector(AV1, 'v1');
  CheckVector(AV2, 'v2');
  FV1A := AV1[0];
  FV1B := AV1[1];
  FV2A := AV2[0];
  FV2B := AV2[1];
  FG1 := AG1;
  FG2 := AG2;
  FBits := ABits;
end;

function TScalarSplitParameters.GetBits: Int32;
begin
  Result := FBits;
end;

function TScalarSplitParameters.GetG1: TBigInteger;
begin
  Result := FG1;
end;

function TScalarSplitParameters.GetG2: TBigInteger;
begin
  Result := FG2;
end;

function TScalarSplitParameters.GetV1A: TBigInteger;
begin
  Result := FV1A;
end;

function TScalarSplitParameters.GetV1B: TBigInteger;
begin
  Result := FV1B;
end;

function TScalarSplitParameters.GetV2A: TBigInteger;
begin
  Result := FV2A;
end;

function TScalarSplitParameters.GetV2B: TBigInteger;
begin
  Result := FV2B;
end;

end.
