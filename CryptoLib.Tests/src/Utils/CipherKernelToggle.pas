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

unit CipherKernelToggle;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  ClpCipherKernelRegistry;

type
  TCipherKernelToggleProc = procedure of object;

/// <summary>
///   Runs AProc twice: once with cipher kernels enabled (production
///   default) and once with them forcibly disabled so the scalar /
///   generic-bulk fallbacks are exercised. Both passes must produce
///   byte-identical outputs. The previous kill-switch state is saved
///   and restored on return (including on exceptions).
/// </summary>
procedure RunWithCipherKernelToggle(AProc: TCipherKernelToggleProc);

implementation

procedure RunWithCipherKernelToggle(AProc: TCipherKernelToggleProc);
var
  LSaved: Boolean;
begin
  if not Assigned(AProc) then
    Exit;
  LSaved := TCipherKernelGate.ForceDisabled;
  try
    TCipherKernelGate.ForceDisabled := False;
    AProc();
    TCipherKernelGate.ForceDisabled := True;
    AProc();
  finally
    TCipherKernelGate.ForceDisabled := LSaved;
  end;
end;

end.
