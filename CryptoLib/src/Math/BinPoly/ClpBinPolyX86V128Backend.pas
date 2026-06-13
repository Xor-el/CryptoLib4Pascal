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

unit ClpBinPolyX86V128Backend;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBinPolyMul,
  ClpCpuFeatures,
  ClpIntrinsicsVector,
  ClpBinPolyX86V128Sizes,
  ClpBinPolyX86V128Medium,
  ClpBinPolyX86V128Large,
  ClpCryptoLibTypes;

resourcestring
  SX86V128BackendRequiresPclmulqdqSupport = 'X86.V128 backend requires PCLMULQDQ support on this target';

type
  /// <summary>
  /// Entry point for the x86/V128 binary-polynomial multiply backend.
  /// </summary>
  TBinPolyX86V128Backend = class sealed
  public
    class function IsEnabled: Boolean; static;
    class function CreateBinPolyMul(AN: Int32; const AReduce: IBinPolyReduce): IBinPolyMul; static;
  end;

implementation

{ TBinPolyX86V128Backend }

class function TBinPolyX86V128Backend.IsEnabled: Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  Result := TCpuFeatures.X86.HasPCLMULQDQ and TIntrinsicsVector.IsPacked;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TBinPolyX86V128Backend.CreateBinPolyMul(AN: Int32; const AReduce: IBinPolyReduce): IBinPolyMul;
var
  LSize: Int32;
begin
  if not IsEnabled then
    raise EInvalidOperationCryptoLibException.CreateRes(@SX86V128BackendRequiresPclmulqdqSupport);

  LSize := (AN + 63) shr 6;
  case LSize of
    1: Result := TBinPolyX86V128Size1.Create(AN, AReduce);
    2: Result := TBinPolyX86V128Size2.Create(AN, AReduce);
    3: Result := TBinPolyX86V128Size3.Create(AN, AReduce);
    4: Result := TBinPolyX86V128Size4.Create(AN, AReduce);
    5: Result := TBinPolyX86V128Size5.Create(AN, AReduce);
    6: Result := TBinPolyX86V128Size6.Create(AN, AReduce);
    7: Result := TBinPolyX86V128Size7.Create(AN, AReduce);
    8: Result := TBinPolyX86V128Size8.Create(AN, AReduce);
    9: Result := TBinPolyX86V128Size9.Create(AN, AReduce);
    10: Result := TBinPolyX86V128Size10.Create(AN, AReduce);
  else
    if LSize >= TBinPolyX86V128Large.KaratsubaCutoff then
      Result := TBinPolyX86V128Large.Create(AN, AReduce)
    else if (LSize and 1) = 0 then
      Result := TBinPolyX86V128MediumEven.Create(AN, AReduce)
    else
      Result := TBinPolyX86V128MediumOdd.Create(AN, AReduce);
  end;
end;

end.
