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

unit CbcBulkParityTests;

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
  ClpICbcBlockCipher,
  ClpCbcBlockCipher,
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
  /// Parity tests for TCbcBlockCipher.ProcessBlocks (IBulkBlockCipherMode):
  /// bulk output and residual chain state MUST match N sequential
  /// ProcessBlock calls, for BOTH encrypt and decrypt. Three engines cover
  /// every dispatch branch:
  ///   1. TAesEngineX86   -> 16-byte blocks; AES-NI bulk encrypt (serial)
  ///                         and bulk decrypt (8/4/tail pipelined).
  ///   2. TAesEngine      -> 16-byte blocks; FAesEngineX86 = nil fallback.
  ///   3. TBlowfishEngine -> 8-byte blocks; FBlockSize &lt;&gt; 16 fallback.
  /// Also asserts that a bulk encrypt followed by a bulk decrypt with the
  /// same IV recovers the original plaintext (in-place AND disjoint buffers).
  /// </summary>
  TTestCbcBulkParity = class(TBulkParityTestBase)
  published
{$IFDEF CRYPTOLIB_X86_SIMD}
    procedure TestAesX86CbcBulkParity;
{$ENDIF CRYPTOLIB_X86_SIMD}
{$IFDEF CRYPTOLIB_AARCH64_ASM}
    procedure TestAesArmCbcBulkParity;
{$ENDIF CRYPTOLIB_AARCH64_ASM}
    procedure TestAesScalarCbcBulkParity;
    procedure TestBlowfishCbcBulkParity;
  end;

implementation

function MakeCbc(const AEngineFactory: TBlockCipherFactory): IBlockCipher;
begin
  Result := TCbcBlockCipher.Create(AEngineFactory()) as ICbcBlockCipher;
end;

{ TTestCbcBulkParity }

{$IFDEF CRYPTOLIB_X86_SIMD}
procedure TTestCbcBulkParity.TestAesX86CbcBulkParity;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  RunBulkParity(CreateAesX86Engine, MakeCbc, 16, 16, 16, True, True, True,
    'CBC', 'AES-NI (TAesEngineX86)');
end;
{$ENDIF CRYPTOLIB_X86_SIMD}

{$IFDEF CRYPTOLIB_AARCH64_ASM}
procedure TTestCbcBulkParity.TestAesArmCbcBulkParity;
begin
  if not TAesEngineArm.IsSupported then
    Exit;
  RunBulkParity(CreateAesArmEngine, MakeCbc, 16, 16, 16, True, True, True,
    'CBC', 'AES-CryptoExt (TAesEngineArm)');
end;
{$ENDIF CRYPTOLIB_AARCH64_ASM}

procedure TTestCbcBulkParity.TestAesScalarCbcBulkParity;
begin
  RunBulkParity(CreateAesScalarEngine, MakeCbc, 16, 16, 16, True, True, True,
    'CBC', 'AES scalar (TAesEngine)');
end;

procedure TTestCbcBulkParity.TestBlowfishCbcBulkParity;
begin
  RunBulkParity(CreateBlowfishEngine, MakeCbc, 16, 8, 8, True, True, True,
    'CBC', 'Blowfish (TBlowfishEngine)');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestCbcBulkParity);
{$ELSE}
  RegisterTest(TTestCbcBulkParity.Suite);
{$ENDIF FPC}

end.
