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

unit EcbBulkParityTests;

{$I ..\..\..\CryptoLib\src\Include\CryptoLib.inc}

interface

uses
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpIBlockCipher,
  ClpIEcbBlockCipher,
  ClpEcbBlockCipher,
{$IFDEF CRYPTOLIB_X86_SIMD}
  ClpAesEngineX86,
{$ENDIF CRYPTOLIB_X86_SIMD}
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  ClpAesEngineArm,
{$ENDIF CRYPTOLIB_AARCH64_ASM}
  BlockCipherTestBase,
  BulkParityTestBase;

type
  /// <summary>
  /// Parity tests for TEcbBlockCipher.ProcessBlocks (IBulkBlockCipherMode):
  /// the bulk path MUST produce byte-identical output to N sequential
  /// ProcessBlock calls in BOTH directions (encrypt and decrypt). Three
  /// engines exercise every branch of the bulk dispatch:
  ///   1. TAesEngineX86   -> 16-byte blocks, AES-NI 8/4/tail fast path.
  ///   2. TAesEngine      -> 16-byte blocks, FAesEngineX86 = nil fallback.
  ///   3. TBlowfishEngine -> 8-byte blocks, FBlockSize &lt;&gt; 16 fallback.
  /// </summary>
  TTestEcbBulkParity = class(TBulkParityTestBase)
  published
{$IFDEF CRYPTOLIB_X86_SIMD}
    procedure TestAesX86EcbBulkParity;
{$ENDIF CRYPTOLIB_X86_SIMD}
{$IFDEF CRYPTOLIB_AARCH64_ASM}
    procedure TestAesArmEcbBulkParity;
{$ENDIF CRYPTOLIB_AARCH64_ASM}
    procedure TestAesScalarEcbBulkParity;
    procedure TestBlowfishEcbBulkParity;
  end;

implementation

function MakeEcb(const AEngineFactory: TBlockCipherFactory): IBlockCipher;
begin
  Result := TEcbBlockCipher.Create(AEngineFactory()) as IEcbBlockCipher;
end;

{ TTestEcbBulkParity }

{$IFDEF CRYPTOLIB_X86_SIMD}
procedure TTestEcbBulkParity.TestAesX86EcbBulkParity;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  RunBulkParity(CreateAesX86Engine, MakeEcb, 16, 0, 16, False, False, True,
    'ECB', 'AES-NI (TAesEngineX86)');
end;
{$ENDIF CRYPTOLIB_X86_SIMD}

{$IFDEF CRYPTOLIB_AARCH64_ASM}
procedure TTestEcbBulkParity.TestAesArmEcbBulkParity;
begin
  if not TAesEngineArm.IsSupported then
    Exit;
  RunBulkParity(CreateAesArmEngine, MakeEcb, 16, 0, 16, False, False, True,
    'ECB', 'AES-CryptoExt (TAesEngineArm)');
end;
{$ENDIF CRYPTOLIB_AARCH64_ASM}

procedure TTestEcbBulkParity.TestAesScalarEcbBulkParity;
begin
  RunBulkParity(CreateAesScalarEngine, MakeEcb, 16, 0, 16, False, False, True,
    'ECB', 'AES scalar (TAesEngine)');
end;

procedure TTestEcbBulkParity.TestBlowfishEcbBulkParity;
begin
  // 8-byte block Blowfish; key well within the 4..56 byte range. Guarantees
  // the FBlockSize <> 16 fallback is covered.
  RunBulkParity(CreateBlowfishEngine, MakeEcb, 16, 0, 8, False, False, True,
    'ECB', 'Blowfish (TBlowfishEngine)');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestEcbBulkParity);
{$ELSE}
  RegisterTest(TTestEcbBulkParity.Suite);
{$ENDIF FPC}

end.
