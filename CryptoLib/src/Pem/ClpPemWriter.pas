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

unit ClpPemWriter;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Classes,
  ClpIPemWriter,
  ClpIPemHeader,
  ClpIPemObject,
  ClpCryptoLibTypes,
  ClpEncoders,
  ClpConverters;

type
  /// <summary>
  /// PEM writer implementation.
  /// </summary>
  TPemWriter = class(TInterfacedObject, IPemWriter)
  strict private
  const
    LineLength = Int32(64);
  var
    FWriter: TStream;
    FNlLength: Int32;
    FBuffer: TCryptoLibByteArray;

    procedure WriteEncoded(const ABytes: TCryptoLibByteArray);
    procedure WritePreEncapsulationBoundary(const AType: String);
    procedure WritePostEncapsulationBoundary(const AType: String);
    procedure WriteString(const AStr: String);
    procedure WriteLine();

  public
    constructor Create(const AWriter: TStream);
    destructor Destroy(); override;

    function GetWriter: TStream;
    function GetOutputSize(const AObj: IPemObject): Int32;
    procedure WriteObject(const AObjGen: IPemObjectGenerator); overload;

    property Writer: TStream read GetWriter;
  end;

implementation

{ TPemWriter }

constructor TPemWriter.Create(const AWriter: TStream);
begin
  Inherited Create();
  if AWriter = nil then
    raise EArgumentNilCryptoLibException.Create('Writer cannot be nil');
  FWriter := AWriter;
  FNlLength := System.Length(sLineBreak);
  System.SetLength(FBuffer, LineLength);
end;

destructor TPemWriter.Destroy();
begin
  Inherited Destroy();
end;

function TPemWriter.GetWriter: TStream;
begin
  Result := FWriter;
end;

procedure TPemWriter.WriteString(const AStr: String);
var
  LBytes: TCryptoLibByteArray;
begin
  LBytes := TConverters.ConvertStringToBytes(AStr, TEncoding.ASCII);
  if System.Length(LBytes) > 0 then
  begin
    FWriter.Write(LBytes[0], System.Length(LBytes));
  end;
end;

procedure TPemWriter.WriteLine();
begin
  WriteString(sLineBreak);
end;

procedure TPemWriter.WritePreEncapsulationBoundary(const AType: String);
begin
  WriteString('-----BEGIN ' + AType + '-----');
  WriteLine();
end;

procedure TPemWriter.WritePostEncapsulationBoundary(const AType: String);
begin
  WriteString('-----END ' + AType + '-----');
  WriteLine();
end;

procedure TPemWriter.WriteEncoded(const ABytes: TCryptoLibByteArray);
var
  LEncoded: String;
  LEncodedBytes: TCryptoLibByteArray;
  I, LIndex, LRemaining: Int32;
begin
  LEncoded := TBase64Encoder.Encode(ABytes);
  LEncodedBytes := TConverters.ConvertStringToBytes(LEncoded, TEncoding.ASCII);

  I := 0;
  while I < System.Length(LEncodedBytes) do
  begin
    LIndex := 0;
    LRemaining := System.Length(LEncodedBytes) - I;
    if LRemaining > LineLength then
      LRemaining := LineLength;

    while LIndex < LRemaining do
    begin
      FBuffer[LIndex] := LEncodedBytes[I + LIndex];
      System.Inc(LIndex);
    end;

    FWriter.Write(FBuffer[0], LIndex);
    WriteLine();
    System.Inc(I, LineLength);
  end;
end;

function TPemWriter.GetOutputSize(const AObj: IPemObject): Int32;
var
  LDataLen, I: Int32;
  LHeader: IPemHeader;
begin
  // BEGIN and END boundaries.
  Result := (2 * (System.Length(AObj.&Type) + 10 + FNlLength)) + 6 + 4;

  if System.Length(AObj.Headers) > 0 then
  begin
    for I := 0 to System.Length(AObj.Headers) - 1 do
    begin
      LHeader := AObj.Headers[I];
      Result := Result + System.Length(LHeader.Name) + 2 + System.Length(LHeader.Value) + FNlLength;
    end;

    Result := Result + FNlLength;
  end;

  // base64 encoding
  LDataLen := ((System.Length(AObj.Content) + 2) div 3) * 4;

  Result := Result + LDataLen + (((LDataLen + LineLength - 1) div LineLength) * FNlLength);
end;

procedure TPemWriter.WriteObject(const AObjGen: IPemObjectGenerator);
var
  LObj: IPemObject;
  I: Int32;
  LHeader: IPemHeader;
begin
  LObj := AObjGen.Generate();

  WritePreEncapsulationBoundary(LObj.&Type);

  if System.Length(LObj.Headers) > 0 then
  begin
    for I := 0 to System.Length(LObj.Headers) - 1 do
    begin
      LHeader := LObj.Headers[I];
      WriteString(LHeader.Name);
      WriteString(': ');
      WriteString(LHeader.Value);
      WriteLine();
    end;

    WriteLine();
  end;

  WriteEncoded(LObj.Content);
  WritePostEncapsulationBoundary(LObj.&Type);
end;

end.
