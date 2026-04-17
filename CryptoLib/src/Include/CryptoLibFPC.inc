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

{$IFDEF ENDIAN_BIG}
  {$MESSAGE FATAL 'This Library does not support "Big Endian" processors yet.'}
{$ENDIF}

{$IF FPC_FULLVERSION < 30204}
  {$MESSAGE ERROR 'This Library requires FreePascal 3.2.4 or higher.'}
{$IFEND}

{========================= FPC Version Features ===============================}

{$IF FPC_FULLVERSION >= 30301}
  {$DEFINE HAS_VOLATILE}
{$IFEND}

{============================== CPU Architecture ==============================}

{$IFDEF FPC_LITTLE_ENDIAN}
  {$DEFINE CRYPTOLIB_LITTLE_ENDIAN}
{$ENDIF}

{$IFDEF FPC_REQUIRES_PROPER_ALIGNMENT}
  {$DEFINE CRYPTOLIB_REQUIRES_PROPER_ALIGNMENT}
{$ENDIF}

{$IF DEFINED(CPU386)}
  {$DEFINE CRYPTOLIB_I386}
  {$DEFINE CRYPTOLIB_I386_ASM}
{$IFEND}

{$IF DEFINED(CPUX64)}
  {$DEFINE CRYPTOLIB_X86_64}
  {$DEFINE CRYPTOLIB_X86_64_ASM}
{$IFEND}

{$IFDEF CPUARM}
  {$DEFINE CRYPTOLIB_ARM32}
  {$DEFINE CRYPTOLIB_ARM32_ASM}
{$ENDIF}

{$IFDEF CPUAARCH64}
  {$DEFINE CRYPTOLIB_AARCH64}
  {$DEFINE CRYPTOLIB_AARCH64_ASM}
{$ENDIF}

{================================= Target OS ==================================}

{$IFDEF MSWINDOWS}
  {$DEFINE CRYPTOLIB_MSWINDOWS}
{$ENDIF}

{$IFDEF UNIX}
  {$DEFINE CRYPTOLIB_UNIX}
{$ENDIF}

{$IFDEF ANDROID}
  {$DEFINE CRYPTOLIB_ANDROID}
  {$UNDEF CRYPTOLIB_UNIX}
{$ENDIF}

{$IFDEF IOS}
  {$DEFINE CRYPTOLIB_IOS}
  {$UNDEF CRYPTOLIB_UNIX}
{$ENDIF}

{$IF DEFINED(DARWIN) AND NOT DEFINED(CRYPTOLIB_IOS)}
  {$DEFINE CRYPTOLIB_MACOS}
  {$UNDEF CRYPTOLIB_UNIX}
{$IFEND}

{$IF DEFINED(FREEBSD) OR DEFINED(NETBSD) OR DEFINED(OPENBSD) OR DEFINED(DRAGONFLY)}
  {$DEFINE CRYPTOLIB_BSD}
  {$UNDEF CRYPTOLIB_UNIX}
{$IFEND}

{$IFDEF LINUX}
  {$DEFINE CRYPTOLIB_LINUX}
  {$UNDEF CRYPTOLIB_UNIX}
{$ENDIF}

{$IFDEF SOLARIS}
  {$DEFINE CRYPTOLIB_SOLARIS}
  {$UNDEF CRYPTOLIB_UNIX}
{$ENDIF}

{$IF DEFINED(CRYPTOLIB_ANDROID)
   OR DEFINED(CRYPTOLIB_LINUX)
   OR DEFINED(CRYPTOLIB_IOS)
   OR DEFINED(CRYPTOLIB_MACOS)
   OR DEFINED(CRYPTOLIB_BSD)
   OR DEFINED(CRYPTOLIB_SOLARIS)
   OR DEFINED(CRYPTOLIB_UNIX)}
  {$DEFINE CRYPTOLIB_UNIXLIKE}
{$IFEND}

{$IF NOT DEFINED(CRYPTOLIB_MSWINDOWS)
   AND NOT DEFINED(CRYPTOLIB_ANDROID)
   AND NOT DEFINED(CRYPTOLIB_IOS)
   AND NOT DEFINED(CRYPTOLIB_MACOS)
   AND NOT DEFINED(CRYPTOLIB_BSD)
   AND NOT DEFINED(CRYPTOLIB_LINUX)
   AND NOT DEFINED(CRYPTOLIB_SOLARIS)
   AND NOT DEFINED(CRYPTOLIB_UNIX)}
  {$MESSAGE ERROR 'UNSUPPORTED TARGET.'}
{$IFEND}

{========================= Compiler Mode & Optimizations ======================}

{$MODE DELPHI}
{$IF DEFINED(CPU386) OR DEFINED(CPUX64)}
  {$ASMMODE INTEL}
{$IFEND}
{$MACRO ON}
{$NOTES OFF}

(*
{$OPTIMIZATION LEVEL3}
{$OPTIMIZATION NOREGVAR}
{$OPTIMIZATION NOUSELOADMODIFYSTORE}
{$OPTIMIZATION ORDERFIELDS}
{$OPTIMIZATION DEADVALUES}
{$IFDEF CPUI386}  {$OPTIMIZATION USEEBP} {$ENDIF}
{$IFDEF CPUX86_64} {$OPTIMIZATION USERBP} {$ENDIF}
*)

