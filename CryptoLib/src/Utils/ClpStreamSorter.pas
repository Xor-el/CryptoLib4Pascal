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

unit ClpStreamSorter;

interface

uses
  Classes,
  ClpStreamHelper,
  ClpIndefiniteLengthInputStream,
  ClpDefiniteLengthInputStream,
  ClpConstructedOctetStream,
  ClpCryptoLibTypes;

type
  TStreamSorter = class sealed(TObject)

  public

    class function Read(input: TStream; var buffer: TCryptoLibByteArray;
      offset, count: Int32): Int32; static;
    class function ReadByte(input: TStream): Int32; static;
  end;

implementation

{ TStreamSorter }

class function TStreamSorter.Read(input: TStream;
  var buffer: TCryptoLibByteArray; offset, count: Int32): Int32;
begin
  if input is TIndefiniteLengthInputStream then
  begin
    Result := (input as TIndefiniteLengthInputStream).
      Read(buffer, offset, count);
  end
  else if input is TDefiniteLengthInputStream then

  begin
    Result := (input as TDefiniteLengthInputStream).Read(buffer, offset, count);
  end
  else if input is TConstructedOctetStream then

  begin
    Result := (input as TConstructedOctetStream).Read(buffer, offset, count);
  end
  else
  begin
    Result := input.Read(buffer[offset], count);
  end;
end;

class function TStreamSorter.ReadByte(input: TStream): Int32;
begin
  if input is TIndefiniteLengthInputStream then
  begin
    Result := (input as TIndefiniteLengthInputStream).ReadByte();
  end
  else if input is TDefiniteLengthInputStream then

  begin
    Result := (input as TDefiniteLengthInputStream).ReadByte();
  end
  else if input is TConstructedOctetStream then

  begin
    Result := (input as TConstructedOctetStream).ReadByte();
  end
  else
  begin
    Result := input.ReadByte();
  end;
end;

end.
