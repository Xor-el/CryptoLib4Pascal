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

unit ClpSignerSink;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpISigner,
  ClpStreams,
  ClpCryptoLibTypes;

resourcestring
  SSignerNil = 'signer cannot be nil';

type
  /// <summary>
  /// A stream that writes data to an ISigner for signature calculation.
  /// </summary>
  TSignerSink = class sealed(TBaseOutputStream)

  strict private
  var
    FSigner: ISigner;

  public
    constructor Create(const ASigner: ISigner);

    function Write(const ABuffer; ACount: LongInt): LongInt; override;
    procedure WriteByte(AValue: Byte); override;

    property Signer: ISigner read FSigner;
  end;

implementation

{ TSignerSink }

constructor TSignerSink.Create(const ASigner: ISigner);
begin
  inherited Create();
  if ASigner = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SSignerNil);
  FSigner := ASigner;
end;

function TSignerSink.Write(const ABuffer; ACount: LongInt): LongInt;
var
  LBuffer: TCryptoLibByteArray;
begin
  if ACount > 0 then
  begin
    System.SetLength(LBuffer, ACount);
    System.Move(ABuffer, LBuffer[0], ACount);
    FSigner.BlockUpdate(LBuffer, 0, ACount);
  end;
  Result := ACount;
end;

procedure TSignerSink.WriteByte(AValue: Byte);
begin
  FSigner.Update(AValue);
end;

end.
