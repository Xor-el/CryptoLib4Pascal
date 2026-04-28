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

unit ClpDateTimeHelper;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpDateTimeUtilities;

type
  TDateTimeHelper = record helper for TDateTime
  public
    function ToUniversalTime: TDateTime;
  end;

implementation

function TDateTimeHelper.ToUniversalTime: TDateTime;
begin
  Result := TDateTimeUtilities.ToUniversalTime(Self);
end;

end.
