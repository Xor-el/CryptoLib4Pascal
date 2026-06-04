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

unit PemDerCodec;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
  ClpCryptoLibTypes,
  ClpConverters,
  ClpIPemObject,
  ClpPemReader;

type
  TPemDerCodec = class sealed
  public
    class function BytesToPemString(const APemBytes: TCryptoLibByteArray): string; static;
    class function ExtractDerFromPem(const APemBytes: TCryptoLibByteArray): TCryptoLibByteArray; static;
    class function ExtractDerFromPemString(const APemText: string): TCryptoLibByteArray; static;
  end;

implementation

{ TPemDerCodec }

class function TPemDerCodec.BytesToPemString(const APemBytes: TCryptoLibByteArray): string;
begin
  Result := TConverters.ConvertBytesToString(APemBytes, TEncoding.ASCII);
end;

class function TPemDerCodec.ExtractDerFromPem(const APemBytes: TCryptoLibByteArray): TCryptoLibByteArray;
begin
  Result := ExtractDerFromPemString(BytesToPemString(APemBytes));
end;

class function TPemDerCodec.ExtractDerFromPemString(const APemText: string): TCryptoLibByteArray;
var
  LStream: TBytesStream;
  LReader: TPemReader;
  LPem: IPemObject;
begin
  LStream := TBytesStream.Create(TConverters.ConvertStringToBytes(APemText, TEncoding.ASCII));
  try
    LReader := TPemReader.Create(LStream);
    try
      LPem := LReader.ReadPemObject();
      if LPem = nil then
        raise Exception.Create('PEM object is empty');
      Result := LPem.Content;
    finally
      LReader.Free;
    end;
  finally
    LStream.Free;
  end;
end;

end.
