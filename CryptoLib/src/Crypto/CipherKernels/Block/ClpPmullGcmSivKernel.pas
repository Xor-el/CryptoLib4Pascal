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

unit ClpPmullGcmSivKernel;

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
  ///   PMULL (ARMv8) implementation of IGcmSivKernel. Pure
  ///   POLYVAL: the factory ignores ACipher identity and only requires
  ///   a valid pre-computed H-power table from the caller. Available on
  ///   aarch64 (CRYPTOLIB_AARCH64_ASM); no byte-reverse mask is needed.
  /// </summary>
  TPmullGcmSivKernel = class sealed(TInterfacedObject,
    IGcmSivKernel)
  strict private
  const
    FUSED_POLYVAL_MIN_BLOCKS = 8;
  strict private
    FHPow128: Pointer;
  public
    constructor Create(AHPow128: Pointer);
    function MinimumBlockCount: Int32;
    procedure ProcessPolyvalBatch(AInPtr, AAccumulator: Pointer;
      ABlockCount: Int32);
  end;

  TPmullGcmSivKernelFactory = class sealed(TCipherKernelFactoryBase,
    IGcmSivKernelFactory)
  public
    function ProviderName: String; override;
    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TCipherKernelDirection; AHPowers: Pointer;
      out AKernel: IGcmSivKernel): Boolean;
  end;

implementation

{ TPmullGcmSivKernel }

constructor TPmullGcmSivKernel.Create(AHPow128: Pointer);
begin
  inherited Create;
  FHPow128 := AHPow128;
end;

function TPmullGcmSivKernel.MinimumBlockCount: Int32;
begin
  Result := FUSED_POLYVAL_MIN_BLOCKS;
end;

procedure TPmullGcmSivKernel.ProcessPolyvalBatch(AInPtr, AAccumulator: Pointer;
  ABlockCount: Int32);
begin
  if (ABlockCount < FUSED_POLYVAL_MIN_BLOCKS) or
    (ABlockCount mod FUSED_POLYVAL_MIN_BLOCKS <> 0) then
    Exit;
  TGcmSivSimd.ProcessPolyvalBatch(AAccumulator, AInPtr, FHPow128, nil,
    ABlockCount div FUSED_POLYVAL_MIN_BLOCKS);
end;

{ TPmullGcmSivKernelFactory }

function TPmullGcmSivKernelFactory.ProviderName: String;
begin
  Result := 'PMULL';
end;

function TPmullGcmSivKernelFactory.TryCreate(const ACipher: IBlockCipher;
  ADirection: TCipherKernelDirection; AHPowers: Pointer;
  out AKernel: IGcmSivKernel): Boolean;
begin
  AKernel := nil;
  Result := False;
  try
{$IFDEF CRYPTOLIB_AARCH64_ASM}
    if AHPowers = nil then
      Exit;
    if not TGcmSivSimd.IsSupported then
      Exit;
    AKernel := TPmullGcmSivKernel.Create(AHPowers);
    Result := True;
{$ENDIF CRYPTOLIB_AARCH64_ASM}
  except
    AKernel := nil;
    Result := False;
  end;
end;

initialization
  TCipherKernelRegistry.Register(
    TPmullGcmSivKernelFactory.Create() as IGcmSivKernelFactory);

end.
