{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpAesUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipher,
  ClpAesEngine
{$IFDEF CRYPTOLIB_X86_SIMD}
  , ClpAesEngineX86
{$ENDIF}
  ;

type
  /// <summary>
  /// Factory for the default AES block cipher.
  /// When CRYPTOLIB_X86_SIMD is defined, CreateEngine may return TAesEngineX86 when
  /// TAesEngineX86.IsSupported is True.
  /// </summary>
  TAesUtilities = class sealed(TObject)
  public
    class function CreateEngine(): IBlockCipher; static;
    /// <summary>
    /// True when the library is built with CRYPTOLIB_X86_SIMD and AES-NI is available
    /// at runtime (TAesEngineX86.IsSupported). Otherwise False.
    /// </summary>
    class function IsHardwareAccelerated(): Boolean; static;
  end;

implementation

{ TAesUtilities }

class function TAesUtilities.CreateEngine(): IBlockCipher;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if TAesEngineX86.IsSupported then
    Exit(TAesEngineX86.Create());
{$ENDIF}
  Result := TAesEngine.Create();
end;

class function TAesUtilities.IsHardwareAccelerated(): Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  Result := TAesEngineX86.IsSupported;
{$ELSE}
  Result := False;
{$ENDIF}
end;

end.
