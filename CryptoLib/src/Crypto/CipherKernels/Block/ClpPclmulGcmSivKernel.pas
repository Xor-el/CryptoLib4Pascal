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
  ClpCipherKernelTypes,
  ClpIGcmSivKernel,
  ClpCipherKernelFactoryBase,
  ClpCipherKernelRegistry,
  ClpGcmSivSimd;

type
  /// <summary>
  ///   PCLMULQDQ implementation of IGcmSivKernel. Pure
  ///   POLYVAL: the factory ignores ACipher identity and only requires
  ///   a valid pre-computed H-power table from the caller. Ships on
  ///   both x86_64 and i386.
  /// </summary>
  TPclmulGcmSivKernel = class sealed(TInterfacedObject,
    IGcmSivKernel)
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

  TPclmulGcmSivKernelFactory = class sealed(TCipherKernelFactoryBase,
    IGcmSivKernelFactory)
  public
    function ProviderName: String; override;
    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TCipherKernelDirection; AHPowers: Pointer;
      out AKernel: IGcmSivKernel): Boolean;
  end;

implementation

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
  if (ABlockCount < FUSED_POLYVAL_MIN_BLOCKS) or
    (ABlockCount mod FUSED_POLYVAL_MIN_BLOCKS <> 0) then
    Exit;
  TGcmSivSimd.ProcessPolyvalBatch(AAccumulator, AInPtr, FHPow128, FMask,
    ABlockCount div FUSED_POLYVAL_MIN_BLOCKS);
end;

{ TPclmulGcmSivKernelFactory }

function TPclmulGcmSivKernelFactory.ProviderName: String;
begin
  Result := 'PCLMULQDQ';
end;

function TPclmulGcmSivKernelFactory.TryCreate(const ACipher: IBlockCipher;
  ADirection: TCipherKernelDirection; AHPowers: Pointer;
  out AKernel: IGcmSivKernel): Boolean;
begin
  AKernel := nil;
  Result := False;
  try
    if AHPowers = nil then
      Exit;
    if not TGcmSivSimd.IsSupported then
      Exit;
    AKernel := TPclmulGcmSivKernel.Create(AHPowers,
      @GcmSivKernelReverseMask[0]);
    Result := True;
  except
    AKernel := nil;
    Result := False;
  end;
end;

initialization
  TCipherKernelRegistry.Register(
    TPclmulGcmSivKernelFactory.Create() as IGcmSivKernelFactory);

end.
