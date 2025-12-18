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

  {$IFDEF CPU386}
     {$DEFINE CRYPTOLIB_X86}
  {$ENDIF}

  {$IFDEF CPUX64}
     {$DEFINE CRYPTOLIB_X86_64}
  {$ENDIF}

  {$IFDEF CPUARM32}
     {$DEFINE CRYPTOLIB_ARM}
  {$ENDIF}

  {$IFDEF CPUARM64}
     {$DEFINE CRYPTOLIB_AARCH64}
  {$ENDIF}

  {$IFDEF IOS}
    {$IFNDEF CPUARM}
       {$DEFINE CRYPTOLIB_IOSSIM}
    {$ENDIF}
  {$ENDIF}

  {$IFDEF IOS}
     {$DEFINE CRYPTOLIB_IOS}
  {$ENDIF}

  {$IFDEF MSWINDOWS}
     {$DEFINE CRYPTOLIB_MSWINDOWS}
  {$ENDIF}

  {$IFDEF MACOS}
     {$IFNDEF IOS}
        {$DEFINE CRYPTOLIB_MACOS}
     {$ENDIF}
  {$ENDIF}

  {$IFDEF ANDROID}
     {$DEFINE CRYPTOLIB_ANDROID}
  {$ENDIF}

  {$IF DEFINED(CRYPTOLIB_IOS) OR DEFINED(CRYPTOLIB_MACOS)}
     {$DEFINE CRYPTOLIB_APPLE}
  {$IFEND}

  {$IF DEFINED(LINUX) OR DEFINED(CRYPTOLIB_ANDROID)}
     {$DEFINE CRYPTOLIB_LINUX}
  {$IFEND}

  {$IFDEF CRYPTOLIB_LINUX}
     {$DEFINE CRYPTOLIB_HAS_GETRANDOM}
  {$ENDIF}

  {$IF DEFINED(CRYPTOLIB_APPLE) OR DEFINED(CRYPTOLIB_LINUX)}
     {$DEFINE CRYPTOLIB_UNIX}
  {$IFEND}

  // XE and Above
  {$IF CompilerVersion >= 22.0}
     {$DEFINE DELPHIXE_UP}
  {$IFEND}

  // XE3 and Above
  {$IF CompilerVersion >= 24.0}
     {$DEFINE SUPPORT_TSTREAM_READ_BYTEARRAY_OVERLOAD}
     {$DEFINE SUPPORT_TSTREAM_WRITE_BYTEARRAY_OVERLOAD}
  {$IFEND}

   // XE4 and Above
  {$IF CompilerVersion >= 25.0}
     {$DEFINE SHIFT_OVERFLOW_BUG_FIXED}
  {$IFEND}

  // 10.1 Berlin and Above
  {$IF CompilerVersion >= 31.0}
     {$DEFINE HAS_VOLATILE}
  {$IFEND}

{$ENDIF}

{========================== Common Compiler Settings ==========================}

{$HINTS OFF}
{$WARNINGS OFF}
{$RANGECHECKS OFF}
{$OVERFLOWCHECKS OFF}
{$SCOPEDENUMS ON}
{$POINTERMATH ON}

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)
