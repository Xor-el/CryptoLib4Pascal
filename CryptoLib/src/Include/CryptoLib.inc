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

{========================= Compiler Specific Settings =========================}

{$IFDEF FPC}
  {$I CryptoLibFPC.inc}
{$ELSE}
  // Delphi Tokyo and Above
  {$IF CompilerVersion < 32.0}
    {$MESSAGE ERROR 'This Library requires Delphi Tokyo or higher.'}
  {$IFEND}

  {$DEFINE DELPHI}
  {$DEFINITIONINFO ON} // Enable code browsing (Ctrl+Click)
  {$STRINGCHECKS OFF}
  {$WARN DUPLICATE_CTOR_DTOR OFF}

  {========================== Delphi Version Features =========================}

  // XE and Above
  {$IF CompilerVersion >= 22.0}
    {$DEFINE DELPHIXE_UP}
  {$IFEND}

  // XE3 and Above
  {$IF CompilerVersion >= 24.0}
    {$DEFINE TSTREAM_HAS_VIRTUAL_READ_BYTES}
    {$DEFINE TSTREAM_HAS_VIRTUAL_WRITE_BYTES}
  {$IFEND}

  // XE4 and Above
  {$IF CompilerVersion >= 25.0}
    {$DEFINE SHIFT_OVERFLOW_BUG_FIXED}
  {$IFEND}

  // 10.1 Berlin and Above
  {$IF CompilerVersion >= 31.0}
    {$DEFINE HAS_VOLATILE}
  {$IFEND}

  {============================== CPU Architecture ==============================}

  {$DEFINE CRYPTOLIB_LITTLE_ENDIAN}

  {$IFDEF CPUARM}
    {$DEFINE CRYPTOLIB_REQUIRES_PROPER_ALIGNMENT}
  {$ENDIF}

  {$IF DEFINED(CPU386)}
    {$DEFINE CRYPTOLIB_I386}
    {$IFDEF MSWINDOWS}
      {$DEFINE CRYPTOLIB_I386_ASM}
    {$ENDIF}
  {$IFEND}

  {$IF DEFINED(CPUX64)}
    {$DEFINE CRYPTOLIB_X86_64}
    {$IFDEF MSWINDOWS}
      {$DEFINE CRYPTOLIB_X86_64_ASM}
    {$ENDIF}
  {$IFEND}

  {$IFDEF CPUARM32}
    {$DEFINE CRYPTOLIB_ARM32}
  {$ENDIF}

  {$IFDEF CPUARM64}
    {$DEFINE CRYPTOLIB_AARCH64}
  {$ENDIF}

  {================================= Target OS ==================================}

  {$IFDEF MSWINDOWS}
    {$DEFINE CRYPTOLIB_MSWINDOWS}
  {$ENDIF}

  {$IFDEF IOS}
    {$DEFINE CRYPTOLIB_IOS}
  {$ENDIF}

  {$IFDEF MACOS}
    {$IFNDEF IOS}
      {$DEFINE CRYPTOLIB_MACOS}
    {$ENDIF}
  {$ENDIF}

  {$IFDEF ANDROID}
    {$DEFINE CRYPTOLIB_ANDROID}
  {$ENDIF}

  {$IFDEF LINUX}
    {$DEFINE CRYPTOLIB_LINUX}
  {$ENDIF}

  {$IF DEFINED(CRYPTOLIB_ANDROID)
     OR DEFINED(CRYPTOLIB_LINUX)
     OR DEFINED(CRYPTOLIB_IOS)
     OR DEFINED(CRYPTOLIB_MACOS)}
    {$DEFINE CRYPTOLIB_UNIXLIKE}
  {$IFEND}

{$ENDIF}

{========================== Common Feature Detection ===========================}

{$IF DEFINED(CRYPTOLIB_ANDROID) OR DEFINED(CRYPTOLIB_LINUX) OR DEFINED(CRYPTOLIB_SOLARIS)}
  {$DEFINE CRYPTOLIB_HAS_GETRANDOM}
{$IFEND}

{$IF DEFINED(CRYPTOLIB_IOS) OR DEFINED(CRYPTOLIB_MACOS)}
  {$DEFINE CRYPTOLIB_HAS_SECRANDOMCOPYBYTES}
{$IFEND}

{$IF DEFINED(CRYPTOLIB_BSD)}
  {$DEFINE CRYPTOLIB_HAS_ARC4RANDOM_BUF}
{$IFEND}

{$IFDEF CRYPTOLIB_UNIXLIKE}
  {$DEFINE CRYPTOLIB_HAS_DEVRANDOM}
{$ENDIF}

{$IF DEFINED(CRYPTOLIB_LITTLE_ENDIAN) AND NOT DEFINED(CRYPTOLIB_REQUIRES_PROPER_ALIGNMENT)}
  {$DEFINE CRYPTOLIB_HAS_FAST_UNALIGNED_ACCESS_LE}
{$IFEND}

{========================== Common Compiler Settings ==========================}

{$HINTS OFF}
{$WARNINGS OFF}
{$RANGECHECKS OFF}
{$OVERFLOWCHECKS OFF}
{$SCOPEDENUMS ON}
{$POINTERMATH ON}

{========================== Common Defines Settings ===========================}

{$IF DEFINED(CRYPTOLIB_I386) OR DEFINED(CRYPTOLIB_X86_64)}
  {$DEFINE CRYPTOLIB_X86}
{$IFEND}

{$IF DEFINED(CRYPTOLIB_ARM32) OR DEFINED(CRYPTOLIB_AARCH64)}
  {$DEFINE CRYPTOLIB_ARM}
{$IFEND}

{============================ Common SIMD Settings ============================}

// Uncomment to force scalar dispatch (available on all platforms):
// {$DEFINE CRYPTOLIB_FORCE_SCALAR}

{$IF DEFINED(CRYPTOLIB_I386_ASM) OR DEFINED(CRYPTOLIB_X86_64_ASM)}
  {$DEFINE CRYPTOLIB_X86_SIMD}
{$IFEND}

{$IF DEFINED(CRYPTOLIB_ARM32_ASM) OR DEFINED(CRYPTOLIB_AARCH64_ASM)}
  {$DEFINE CRYPTOLIB_ARM_SIMD}
{$IFEND}

{$IFDEF CRYPTOLIB_X86_SIMD}
// Uncomment ONE to force a specific X86 SIMD dispatch level:
// {$DEFINE CRYPTOLIB_FORCE_SSE2}
// {$DEFINE CRYPTOLIB_FORCE_SSSE3}

{$IF (DEFINED(CRYPTOLIB_FORCE_SCALAR) AND DEFINED(CRYPTOLIB_FORCE_SSE2))
   OR (DEFINED(CRYPTOLIB_FORCE_SCALAR) AND DEFINED(CRYPTOLIB_FORCE_SSSE3))
   OR (DEFINED(CRYPTOLIB_FORCE_SSE2) AND DEFINED(CRYPTOLIB_FORCE_SSSE3))}
  {$MESSAGE ERROR 'Only one CRYPTOLIB_FORCE_* define may be enabled at a time.'}
{$IFEND}

{$ENDIF}

{$IFDEF CRYPTOLIB_ARM_SIMD}
// Uncomment ONE to force a specific Arm SIMD dispatch level:
// {$DEFINE CRYPTOLIB_FORCE_NEON}
// {$DEFINE CRYPTOLIB_FORCE_SVE}

{$IF (DEFINED(CRYPTOLIB_FORCE_SCALAR) AND DEFINED(CRYPTOLIB_FORCE_NEON))
  OR (DEFINED(CRYPTOLIB_FORCE_SCALAR) AND DEFINED(CRYPTOLIB_FORCE_SVE))
  OR (DEFINED(CRYPTOLIB_FORCE_NEON) AND DEFINED(CRYPTOLIB_FORCE_SVE))}
  {$MESSAGE ERROR 'Only one CRYPTOLIB_FORCE_* define may be enabled at a time.'}
{$IFEND}

{$ENDIF}

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)
