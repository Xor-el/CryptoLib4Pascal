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

unit ClpMacSink;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpIMac,
  ClpStreams,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// A stream that writes data to an IMac for MAC calculation.
  /// </summary>
  TMacSink = class sealed(TBaseOutputStream)

  strict private
  var
    FMac: IMac;

  public
    constructor Create(const AMac: IMac);

    function Write(const ABuffer; ACount: LongInt): LongInt; override;
    procedure WriteByte(AValue: Byte); override;

    property Mac: IMac read FMac;
  end;

implementation

{ TMacSink }

constructor TMacSink.Create(const AMac: IMac);
begin
  inherited Create();
  if AMac = nil then
    raise EArgumentNilCryptoLibException.Create('mac');
  FMac := AMac;
end;

function TMacSink.Write(const ABuffer; ACount: LongInt): LongInt;
var
  LBuffer: TCryptoLibByteArray;
begin
  if ACount > 0 then
  begin
    System.SetLength(LBuffer, ACount);
    System.Move(ABuffer, LBuffer[0], ACount);
    FMac.BlockUpdate(LBuffer, 0, ACount);
  end;
  Result := ACount;
end;

procedure TMacSink.WriteByte(AValue: Byte);
begin
  FMac.Update(AValue);
end;

end.
