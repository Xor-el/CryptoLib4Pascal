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

unit ClpPemParser;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Classes,
  ClpIPemParser,
  ClpEncoders,
  ClpStreamUtilities,
  ClpStringUtilities,
  ClpIAsn1Core,
  ClpAsn1Core,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SMalformedPemDataEncountered = 'malformed PEM data encountered';

type
  /// <summary>
  /// PEM parser implementation.
  /// </summary>
  TPemParser = class sealed(TInterfacedObject, IPemParser)
  strict private
    FHeader1: String;
    FHeader2: String;
    FFooter1: String;
    FFooter2: String;

    function ReadLine(const AInStream: TStream): String;

  public
    constructor Create(const AType: String);

    function ReadPemObject(const AInStream: TStream): IAsn1Sequence;
  end;

implementation

{ TPemParser }

constructor TPemParser.Create(const AType: String);
begin
  Inherited Create();
  FHeader1 := '-----BEGIN ' + AType + '-----';
  FHeader2 := '-----BEGIN X509 ' + AType + '-----';
  FFooter1 := '-----END ' + AType + '-----';
  FFooter2 := '-----END X509 ' + AType + '-----';
end;

function TPemParser.ReadLine(const AInStream: TStream): String;
var
  LC: Int32;
  LBuilder: TStringBuilder;
begin
  LBuilder := TStringBuilder.Create;
  try
    repeat
      LC := AInStream.ReadByte;
      while (LC >= 0) and (LC <> Ord(#13)) and (LC <> Ord(#10)) do
      begin
        LBuilder.Append(Char(LC));
        LC := AInStream.ReadByte;
      end;
    until (LC < 0) or (LBuilder.Length > 0);

    // Return whatever we accumulated - only return '' if EOF AND nothing buffered
    if (LC < 0) and (LBuilder.Length = 0) then
      Result := ''
    else
      Result := LBuilder.ToString;
  finally
    LBuilder.Free;
  end;
end;

function TPemParser.ReadPemObject(const AInStream: TStream): IAsn1Sequence;
var
  LLine: String;
  LPemBuf: TStringBuilder;
  LDecoded: TCryptoLibByteArray;
  LAsn1Obj: IAsn1Object;
begin
  Result := nil;
  LPemBuf := TStringBuilder.Create();
  try
    // Skip until we find the header
    while True do
    begin
      LLine := ReadLine(AInStream);
      if LLine = '' then
      begin
        Exit;
      end;

      if TStringUtilities.StartsWith(LLine, FHeader1) or TStringUtilities.StartsWith(LLine, FHeader2) then
        Break;
    end;

    // Read until we find the footer
    while True do
    begin
      LLine := ReadLine(AInStream);
      if LLine = '' then
      begin
        Exit;
      end;

      if TStringUtilities.StartsWith(LLine, FFooter1) or TStringUtilities.StartsWith(LLine, FFooter2) then
        Break;

      LPemBuf.Append(LLine);
    end;

    if LPemBuf.Length > 0 then
    begin
      LDecoded := TBase64Encoder.Decode(LPemBuf.ToString());
      LAsn1Obj := TAsn1Object.FromByteArray(LDecoded);

      if not Supports(LAsn1Obj, IAsn1Sequence, Result) then
        raise EIOCryptoLibException.CreateRes(@SMalformedPemDataEncountered);
    end;
  finally
    LPemBuf.Free;
  end;
end;

end.
