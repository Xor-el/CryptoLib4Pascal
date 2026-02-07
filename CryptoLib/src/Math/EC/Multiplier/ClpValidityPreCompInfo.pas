{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ * ******************************************************************************* * }

unit ClpValidityPreCompInfo;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIValidityPreCompInfo,
  ClpIPreCompInfo;

type
  TValidityPreCompInfo = class sealed(TInterfacedObject, IPreCompInfo,
    IValidityPreCompInfo)
  strict private
    FFailed: Boolean;
    FCurveEquationPassed: Boolean;
    FOrderPassed: Boolean;
  public
    const
      PRECOMP_NAME = 'bc_validity';

    function HasFailed: Boolean;
    procedure ReportFailed;
    function HasCurveEquationPassed: Boolean;
    procedure ReportCurveEquationPassed;
    function HasOrderPassed: Boolean;
    procedure ReportOrderPassed;
  end;

implementation

function TValidityPreCompInfo.HasFailed: Boolean;
begin
  Result := FFailed;
end;

procedure TValidityPreCompInfo.ReportFailed;
begin
  FFailed := True;
end;

function TValidityPreCompInfo.HasCurveEquationPassed: Boolean;
begin
  Result := FCurveEquationPassed;
end;

procedure TValidityPreCompInfo.ReportCurveEquationPassed;
begin
  FCurveEquationPassed := True;
end;

function TValidityPreCompInfo.HasOrderPassed: Boolean;
begin
  Result := FOrderPassed;
end;

procedure TValidityPreCompInfo.ReportOrderPassed;
begin
  FOrderPassed := True;
end;

end.
