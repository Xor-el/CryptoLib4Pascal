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

{$IFDEF FPC}
{$IFDEF ENDIAN_BIG}
   {$MESSAGE FATAL 'This Library does not support "Big Endian" processors yet.'}
{$ENDIF}

{$IF FPC_FULLVERSION < 30004}
   {$MESSAGE ERROR 'This Library requires FreePascal 3.0.4 or higher.'}
{$IFEND}

{$IF FPC_FULLVERSION >= 30301}
   {$DEFINE HAS_VOLATILE}
{$IFEND}

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

{$IFDEF IPHONESIM}
   {$DEFINE CRYPTOLIB_IOSSIM}
{$ENDIF}

{$IF DEFINED(MSWINDOWS)}
   {$DEFINE CRYPTOLIB_MSWINDOWS}
{$ELSEIF DEFINED(UNIX)}
   {$DEFINE CRYPTOLIB_UNIX}
   {$IF DEFINED(BSD)}
      {$IF DEFINED(DARWIN)}
         {$DEFINE CRYPTOLIB_APPLE}
         {$IF DEFINED(CRYPTOLIB_ARM) OR DEFINED(CRYPTOLIB_AARCH64)}
            {$DEFINE CRYPTOLIB_IOS}
         {$ELSE}
            {$DEFINE CRYPTOLIB_MACOS}
         {$IFEND}
      {$ELSEIF DEFINED(FREEBSD) OR DEFINED(NETBSD) OR DEFINED(OPENBSD) OR DEFINED(DRAGONFLY)}
         {$DEFINE CRYPTOLIB_GENERIC_BSD}
      {$IFEND}
  {$ELSEIF DEFINED(ANDROID)}
     {$DEFINE CRYPTOLIB_ANDROID}
  {$ELSEIF DEFINED(LINUX)}
     {$DEFINE CRYPTOLIB_LINUX}
  {$ELSEIF DEFINED(SOLARIS)}
     {$DEFINE CRYPTOLIB_SOLARIS}
  {$ELSE}
     {$DEFINE CRYPTOLIB_UNDEFINED_UNIX_VARIANTS}
  {$IFEND}
{$ELSE}
   {$MESSAGE ERROR 'UNSUPPORTED TARGET.'}
{$IFEND}

{$IFDEF CRYPTOLIB_ANDROID}
   {$DEFINE CRYPTOLIB_LINUX}
{$ENDIF}

{$IF DEFINED(CRYPTOLIB_LINUX) OR DEFINED(CRYPTOLIB_SOLARIS)}
   {$DEFINE CRYPTOLIB_HAS_GETRANDOM}
{$IFEND}

  {$MODE DELPHI}
  {$MACRO ON}
  {$NOTES OFF}

  {$OPTIMIZATION LEVEL3}

  {$OPTIMIZATION NOREGVAR}
  {$OPTIMIZATION NOUSELOADMODIFYSTORE}
  {$OPTIMIZATION ORDERFIELDS}
  {$OPTIMIZATION DEADVALUES}
  {$IFDEF CPUI386}  {$OPTIMIZATION USEEBP} {$ENDIF}
  {$IFDEF CPUX86_64} {$OPTIMIZATION USERBP} {$ENDIF}
{$ENDIF}

