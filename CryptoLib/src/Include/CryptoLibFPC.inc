{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

{$IFDEF ENDIAN_BIG}
   {$MESSAGE FATAL 'This Library does not support "Big Endian" processors yet.'}
{$ENDIF}

{$IF FPC_FULLVERSION < 30301}
   {$MESSAGE ERROR 'This Library requires FreePascal 3.3.1 or higher.'}
{$IFEND}

{========================= FPC Version Features ===============================}

{$IF FPC_FULLVERSION >= 30301}
   {$DEFINE HAS_VOLATILE}
{$IFEND}

{========================= CPU Architecture ===================================}

{$IFDEF CPU386}
   {$DEFINE CRYPTOLIB_X86}
{$ENDIF}

{$IFDEF CPUX64}
   {$DEFINE CRYPTOLIB_X86_64}
{$ENDIF}

{$IFDEF CPUARM}
   {$DEFINE CRYPTOLIB_ARM}
{$ENDIF}

{$IFDEF CPUAARCH64}
   {$DEFINE CRYPTOLIB_AARCH64}
{$ENDIF}

{========================= Target OS ==========================================}

{$IFDEF MSWINDOWS}
   {$DEFINE CRYPTOLIB_MSWINDOWS}
{$ENDIF}

{$IFDEF UNIX}
   {$DEFINE CRYPTOLIB_UNIX}
{$ENDIF}

{$IFDEF ANDROID}
   {$DEFINE CRYPTOLIB_ANDROID}
{$ENDIF}

{$IFDEF IOS}
   {$DEFINE CRYPTOLIB_IOS}
{$ENDIF}

{$IFDEF IPHONESIM}
   {$DEFINE CRYPTOLIB_IOSSIM}
{$ENDIF}

//{$IF DEFINED(IOS) OR DEFINED(IPHONESIM)}
//   {$DEFINE CRYPTOLIB_IOS}
//{$IFEND}

{$IF DEFINED(DARWIN) AND NOT DEFINED(CRYPTOLIB_IOS)}
   {$DEFINE CRYPTOLIB_MACOS}
{$IFEND}

{$IF DEFINED(CRYPTOLIB_IOS) OR DEFINED(CRYPTOLIB_MACOS)}
   {$DEFINE CRYPTOLIB_APPLE}
{$IFEND}

{$IF DEFINED(FREEBSD) OR DEFINED(NETBSD) OR DEFINED(OPENBSD) OR DEFINED(DRAGONFLY)}
   {$DEFINE CRYPTOLIB_GENERIC_BSD}
{$IFEND}

{$IF DEFINED(LINUX) OR DEFINED(CRYPTOLIB_ANDROID)}
   {$DEFINE CRYPTOLIB_LINUX}
{$IFEND}

{$IFDEF SOLARIS}
   {$DEFINE CRYPTOLIB_SOLARIS}
{$ENDIF}

{$IF NOT DEFINED(CRYPTOLIB_MSWINDOWS)
   AND NOT DEFINED(CRYPTOLIB_APPLE)
   AND NOT DEFINED(CRYPTOLIB_GENERIC_BSD)
   AND NOT DEFINED(CRYPTOLIB_LINUX)
   AND NOT DEFINED(CRYPTOLIB_SOLARIS)
   AND NOT DEFINED(CRYPTOLIB_UNIX)}
   {$MESSAGE ERROR 'UNSUPPORTED TARGET.'}
{$IFEND}

{========================= Feature Detection ==================================}

{$IF DEFINED(CRYPTOLIB_LINUX) OR DEFINED(CRYPTOLIB_SOLARIS)}
   {$DEFINE CRYPTOLIB_HAS_GETRANDOM}
{$IFEND}

{========================= Compiler Mode & Optimizations ======================}

{$MODE DELPHI}
{$MACRO ON}
{$NOTES OFF}

{$OPTIMIZATION LEVEL3}
{$OPTIMIZATION NOREGVAR}
{$OPTIMIZATION NOUSELOADMODIFYSTORE}
{$OPTIMIZATION ORDERFIELDS}
{$OPTIMIZATION DEADVALUES}

{$IFDEF CPUI386}
   {$OPTIMIZATION USEEBP}
{$ENDIF}

{$IFDEF CPUX86_64}
   {$OPTIMIZATION USERBP}
{$ENDIF}

