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

unit ClpPclmulGcmSivKernel;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpFusedKernelTypes,
  ClpIFusedGcmSivKernel,
  ClpFusedKernelRegistry
{$IFDEF CRYPTOLIB_X86_SIMD}
  , ClpCpuFeatures,
  ClpIntrinsicsVector
{$ENDIF CRYPTOLIB_X86_SIMD}
  ;

type
  /// <summary>
  ///   PCLMULQDQ + SSSE3 implementation of IFusedGcmSivKernel. Pure
  ///   POLYVAL: the factory ignores ACipher identity and only requires
  ///   a valid pre-computed H-power table from the caller. Ships on
  ///   both x86_64 and i386.
  /// </summary>
  TPclmulGcmSivKernel = class sealed(TInterfacedObject,
    IFusedGcmSivKernel)
  strict private
  const
    FUSED_POLYVAL_MIN_BLOCKS = 8;
  strict private
    FHPow128: Pointer;
    FMask: Pointer;
  public
    constructor Create(AHPow128, AMask: Pointer);
    function MinimumBlockCount: Int32;
    procedure ProcessPolyvalBatch(AInPtr, AAccumulator: Pointer;
      ABlockCount: Int32);
  end;

  TPclmulGcmSivKernelFactory = class sealed(TInterfacedObject,
    IFusedGcmSivKernelFactory)
  public
    function ProviderName: String;
    function Priority: TFusedKernelPriority;
    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TFusedModeDirection; AHPowers: Pointer;
      out AKernel: IFusedGcmSivKernel): Boolean;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}
procedure GcmSivPolyvalHornerEight(PFS, PC0, PHPow128, PMask: Pointer);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\..\Include\Simd\Common\SimdProc4Begin_x86_64.inc}
{$I ..\..\..\Include\Simd\GcmSiv\PolyvalHornerEight_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\..\Include\Simd\Common\SimdProc4Begin_i386.inc}
{$I ..\..\..\Include\Simd\GcmSiv\PolyvalHornerEight_i386.inc}
{$ENDIF}
end;
{$ENDIF CRYPTOLIB_X86_SIMD}

const
  // PSHUFB full-reverse control used by the POLYVAL Horner batch.
  GcmSivKernelReverseMask: packed array[0..15] of Byte = (
    $0F, $0E, $0D, $0C, $0B, $0A, $09, $08,
    $07, $06, $05, $04, $03, $02, $01, $00);

{ TPclmulGcmSivKernel }

constructor TPclmulGcmSivKernel.Create(AHPow128, AMask: Pointer);
begin
  inherited Create;
  FHPow128 := AHPow128;
  FMask := AMask;
end;

function TPclmulGcmSivKernel.MinimumBlockCount: Int32;
begin
  Result := FUSED_POLYVAL_MIN_BLOCKS;
end;

procedure TPclmulGcmSivKernel.ProcessPolyvalBatch(AInPtr, AAccumulator: Pointer;
  ABlockCount: Int32);
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if ABlockCount <> FUSED_POLYVAL_MIN_BLOCKS then
    Exit;
  GcmSivPolyvalHornerEight(AAccumulator, AInPtr, FHPow128, FMask);
{$ENDIF CRYPTOLIB_X86_SIMD}
end;

{ TPclmulGcmSivKernelFactory }

function TPclmulGcmSivKernelFactory.ProviderName: String;
begin
  Result := 'PCLMULQDQ';
end;

function TPclmulGcmSivKernelFactory.Priority: TFusedKernelPriority;
begin
  Result := TFusedKernelPriority.Baseline;
end;

function TPclmulGcmSivKernelFactory.TryCreate(const ACipher: IBlockCipher;
  ADirection: TFusedModeDirection; AHPowers: Pointer;
  out AKernel: IFusedGcmSivKernel): Boolean;
begin
  AKernel := nil;
  Result := False;
  try
    if AHPowers = nil then
      Exit;
{$IFDEF CRYPTOLIB_X86_SIMD}
    if not (TCpuFeatures.X86.HasPCLMULQDQ and TCpuFeatures.X86.HasSSSE3 and
      TIntrinsicsVector.IsPacked) then
      Exit;
    AKernel := TPclmulGcmSivKernel.Create(AHPowers,
      @GcmSivKernelReverseMask[0]);
    Result := True;
{$ENDIF CRYPTOLIB_X86_SIMD}
  except
    AKernel := nil;
    Result := False;
  end;
end;

initialization
  TFusedKernelRegistry.RegisterGcmSivFactory(
    TPclmulGcmSivKernelFactory.Create() as IFusedGcmSivKernelFactory);

end.
