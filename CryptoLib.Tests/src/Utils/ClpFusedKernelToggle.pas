{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpFusedKernelToggle;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  ClpFusedKernelRegistry;

type
  TFusedToggleTestProc = procedure of object;

/// <summary>
///   Runs AProc twice: once with fused kernels enabled (production
///   default) and once with them forcibly disabled so the scalar /
///   generic-bulk fallbacks are exercised. Both passes must produce
///   byte-identical outputs. The previous kill-switch state is saved
///   and restored on return (including on exceptions).
/// </summary>
procedure RunWithFusedToggle(AProc: TFusedToggleTestProc);

implementation

procedure RunWithFusedToggle(AProc: TFusedToggleTestProc);
var
  LSaved: Boolean;
begin
  if not Assigned(AProc) then
    Exit;
  LSaved := TFusedKernelGate.ForceDisabled;
  try
    TFusedKernelGate.ForceDisabled := False;
    AProc();
    TFusedKernelGate.ForceDisabled := True;
    AProc();
  finally
    TFusedKernelGate.ForceDisabled := LSaved;
  end;
end;

end.
