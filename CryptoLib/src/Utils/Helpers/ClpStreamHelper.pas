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

unit ClpStreamHelper;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpCryptoLibTypes;

type
  TStreamHelper = class helper for TStream

  public

    function ReadByte(): Int32; inline;
    procedure WriteByte(b: Byte); inline;
  end;

implementation

uses
  ClpStreamSorter; // included here to avoid circular dependency :)

{ TStreamHelper }

function TStreamHelper.ReadByte: Int32;
var
  Buffer: TCryptoLibByteArray;
begin
  System.SetLength(Buffer, 1);
  if (TStreamSorter.Read(Self, Buffer, 0, 1) = 0) then
  begin
    result := -1;
  end
  else
  begin
    result := Int32(Buffer[0]);
  end;
end;

procedure TStreamHelper.WriteByte(b: Byte);
var
  oneByteArray: TCryptoLibByteArray;
begin
  System.SetLength(oneByteArray, 1);
  oneByteArray[0] := b;
  // Self.Write(oneByteArray, 0, 1);
  Self.Write(oneByteArray[0], 1);
end;

end.
