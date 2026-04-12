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

unit ClpUnixLikeRngCommon;

{$I ..\..\Include\CryptoLib.inc}

interface

{$IFDEF CRYPTOLIB_UNIXLIKE}
uses
{$IFDEF FPC}
  BaseUnix,
{$ELSE}
  Posix.Errno,
{$ENDIF}
  SysUtils;

const
  EINTR = {$IFDEF FPC}ESysEINTR{$ELSE}Posix.Errno.EINTR{$ENDIF};
  EAGAIN = {$IFDEF FPC}ESysEAGAIN{$ELSE}Posix.Errno.EAGAIN{$ENDIF};

type
  /// <summary>
  /// Shared errno / EINTR helpers for Unix-like OS RNG paths (e.g. getrandom, /dev).
  /// </summary>
  TUnixLikeRngCommon = class sealed
  public
    class function GetErrNo: Int32; static; inline;
  end;

{$ENDIF}

implementation

{$IFDEF CRYPTOLIB_UNIXLIKE}

{ TUnixLikeRngCommon }

class function TUnixLikeRngCommon.GetErrNo: Int32;
begin
  Result := Errno;
end;

{$ENDIF}

end.
