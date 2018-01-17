{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                    Copyright (c) 2018 Ugochukwu Mmaduekwe                       * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *        Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring        * }
{ *                        the development of this library                          * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpStringHelper;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpBits,
  SysUtils;

type
  TStringHelper = record helper for
    String public
    function GetHashCode: Int32;

  end;

implementation

{ TStringHelper }

function TStringHelper.GetHashCode: Int32;
var
  temp: string;
  I, Top: UInt32;
  LResult: UInt32;
begin
  temp := Self;
  temp := AnsiUpperCase(temp);

  LResult := 0;
{$IFDEF DELPHIXE3_UP}
  I := System.Low(temp);
  Top := System.High(temp);
{$ELSE}
  I := 1;
  Top := System.Length(temp);
{$ENDIF DELPHIXE3_UP}
  while I <= Top do
  begin
    LResult := TBits.RotateLeft32(LResult, 5);
    LResult := LResult xor UInt32(temp[I]);
    System.Inc(I);
  end;
  Result := Int32(LResult);
end;

end.
