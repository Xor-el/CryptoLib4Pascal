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

unit ClpAesUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIAesEngine,
  ClpAesEngine,
  ClpAesSimd;

type
  /// <summary>
  /// Factory for the default AES block cipher. Selects the per-arch hardware
  /// engine at compile time and, when it is available at runtime, returns it
  /// (e.g. AES-NI via <c>TAesEngineX86</c> on x86); otherwise the portable
  /// scalar <c>TAesEngine</c>.
  /// </summary>
  TAesUtilities = class sealed(TObject)
  public
    class function CreateEngine(): IBlockCipher; static;
    /// <summary>
    /// True when the build has a per-arch hardware AES engine and it is available
    /// at runtime (its <c>IsSupported</c> is True). Otherwise False.
    /// </summary>
    class function IsHardwareAccelerated(): Boolean; static;
    /// <summary>
    /// True when ACipher is one of the AES engine variants (every variant tags
    /// itself with <see cref="IAesEngine"/> and produces identical output), i.e.
    /// an engine interchangeable with <see cref="CreateEngine"/>'s result.
    /// </summary>
    class function IsAesEngine(const ACipher: IBlockCipher): Boolean; static;
  end;

implementation

{ TAesUtilities }

class function TAesUtilities.CreateEngine(): IBlockCipher;
var
  LEngine: IBlockCipher;
begin
  if TAesSimd.TryCreateHardwareEngine(LEngine) then
    Exit(LEngine);
  Result := TAesEngine.Create();
end;

class function TAesUtilities.IsHardwareAccelerated(): Boolean;
begin
  Result := TAesSimd.IsSupported;
end;

class function TAesUtilities.IsAesEngine(const ACipher: IBlockCipher): Boolean;
begin
  Result := Supports(ACipher, IAesEngine);
end;

end.
