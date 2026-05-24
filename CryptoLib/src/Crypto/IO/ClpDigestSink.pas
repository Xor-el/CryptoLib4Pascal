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

unit ClpDigestSink;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpIDigest,
  ClpStreams,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// A stream that writes data to an IDigest for digest calculation.
  /// </summary>
  TDigestSink = class sealed(TBaseOutputStream)

  strict private
  var
    FDigest: IDigest;

  public
    constructor Create(const ADigest: IDigest);

    function Write(const ABuffer; ACount: LongInt): LongInt; override;
    procedure WriteByte(AValue: Byte); override;

    property Digest: IDigest read FDigest;
  end;

implementation

{ TDigestSink }

constructor TDigestSink.Create(const ADigest: IDigest);
begin
  inherited Create();
  if ADigest = nil then
    raise EArgumentNilCryptoLibException.Create('digest');
  FDigest := ADigest;
end;

function TDigestSink.Write(const ABuffer; ACount: LongInt): LongInt;
var
  LBuffer: TCryptoLibByteArray;
begin
  if ACount > 0 then
  begin
    System.SetLength(LBuffer, ACount);
    System.Move(ABuffer, LBuffer[0], ACount);
    FDigest.BlockUpdate(LBuffer, 0, ACount);
  end;
  Result := ACount;
end;

procedure TDigestSink.WriteByte(AValue: Byte);
begin
  FDigest.Update(AValue);
end;

end.
