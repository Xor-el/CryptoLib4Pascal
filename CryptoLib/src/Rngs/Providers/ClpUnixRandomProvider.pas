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

unit ClpUnixRandomProvider;

{$I ..\..\Include\CryptoLib.inc}

interface

{$IFDEF CRYPTOLIB_UNIX}
uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpIRandomSourceProvider;

resourcestring
  SRandomDeviceReadError =
    'An Error Occurred while reading random data from random device (file)';

type
  /// <summary>
  /// Unix OS random source provider (fallback for other Unix systems).
  /// Implements /dev/urandom fallback
  /// </summary>
  TUnixRandomProvider = class sealed(TInterfacedObject, IRandomSourceProvider)

  strict private
    function GenRandomBytesUnix(ALen: Int32; AData: PByte): Int32;

  public
    constructor Create();

    procedure GetBytes(const AData: TCryptoLibByteArray);
    procedure GetNonZeroBytes(const AData: TCryptoLibByteArray);
    function GetIsAvailable: Boolean;
    function GetName: String;

  end;

{$ENDIF}

implementation

{$IFDEF CRYPTOLIB_UNIX}
uses
  ClpDevRandomReader;

{ TUnixRandomProvider }

constructor TUnixRandomProvider.Create;
begin
  inherited Create();
end;

function TUnixRandomProvider.GenRandomBytesUnix(ALen: Int32;
  AData: PByte): Int32;
begin
  Result := TDevRandomReader.Read(ALen, AData, ALen);
end;

procedure TUnixRandomProvider.GetBytes(const AData: TCryptoLibByteArray);
var
  LCount: Int32;
begin
  LCount := System.Length(AData);

  if LCount <= 0 then
  begin
    Exit;
  end;

  if GenRandomBytesUnix(LCount, PByte(AData)) <> 0 then
  begin
    raise EOSRandomCryptoLibException.CreateRes(@SRandomDeviceReadError);
  end;
end;

procedure TUnixRandomProvider.GetNonZeroBytes(const AData: TCryptoLibByteArray);
var
  LI: Int32;
  LTmp: TCryptoLibByteArray;
begin
  GetBytes(AData);
  System.SetLength(LTmp, 1);
  for LI := System.Low(AData) to System.High(AData) do
  begin
    while AData[LI] = 0 do
    begin
      GetBytes(LTmp);
      AData[LI] := LTmp[0];
    end;
  end;
end;

function TUnixRandomProvider.GetIsAvailable: Boolean;
begin
  Result := True;
end;

function TUnixRandomProvider.GetName: String;
begin
  Result := 'Unix';
end;

{$ENDIF}

end.
