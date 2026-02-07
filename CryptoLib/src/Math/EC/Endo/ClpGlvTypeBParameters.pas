{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ * ******************************************************************************* * }

unit ClpGlvTypeBParameters;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIScalarSplitParameters,
  ClpIGlvTypeBParameters;

type
  TGlvTypeBParameters = class(TInterfacedObject, IGlvTypeBParameters)
  strict private
    FBeta, FLambda: TBigInteger;
    FSplitParams: IScalarSplitParameters;
    function GetBeta: TBigInteger;
    function GetLambda: TBigInteger;
    function GetSplitParams: IScalarSplitParameters;
  public
    constructor Create(const ABeta, ALambda: TBigInteger;
      const ASplitParams: IScalarSplitParameters);
    property Beta: TBigInteger read GetBeta;
    property Lambda: TBigInteger read GetLambda;
    property SplitParams: IScalarSplitParameters read GetSplitParams;
  end;

implementation

{ TGlvTypeBParameters }

constructor TGlvTypeBParameters.Create(const ABeta, ALambda: TBigInteger;
  const ASplitParams: IScalarSplitParameters);
begin
  inherited Create;
  FBeta := ABeta;
  FLambda := ALambda;
  FSplitParams := ASplitParams;
end;

function TGlvTypeBParameters.GetBeta: TBigInteger;
begin
  Result := FBeta;
end;

function TGlvTypeBParameters.GetLambda: TBigInteger;
begin
  Result := FLambda;
end;

function TGlvTypeBParameters.GetSplitParams: IScalarSplitParameters;
begin
  Result := FSplitParams;
end;

end.
