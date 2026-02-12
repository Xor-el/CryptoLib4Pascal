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

unit ClpGenericBSDRandomProvider;

{$I ..\..\Include\CryptoLib.inc}

interface

{$IFDEF CRYPTOLIB_GENERIC_BSD}
uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpIRandomSourceProvider;

resourcestring
  SArc4RandomBufGenerationError =
    'An Error Occurred while generating random data using arc4random_buf API.';

procedure arc4random_buf(ABytes: PByte; ACount: NativeUInt); cdecl;
  external 'c' name 'arc4random_buf';

type
  /// <summary>
  /// Generic BSD OS random source provider.
  /// Implements BSD variants using arc4random_buf
  /// </summary>
  TGenericBSDRandomProvider = class sealed(TInterfacedObject, IRandomSourceProvider)

  strict private
    function GenRandomBytesGenericBSD(ALen: Int32; AData: PByte): Int32;

  public
    constructor Create();

    procedure GetBytes(const AData: TCryptoLibByteArray);
    procedure GetNonZeroBytes(const AData: TCryptoLibByteArray);
    function GetIsAvailable: Boolean;
    function GetName: String;

  end;

{$ENDIF}

implementation

{$IFDEF CRYPTOLIB_GENERIC_BSD}

{ TGenericBSDRandomProvider }

constructor TGenericBSDRandomProvider.Create;
begin
  inherited Create();
end;

function TGenericBSDRandomProvider.GenRandomBytesGenericBSD(ALen: Int32;
  AData: PByte): Int32;
begin
  arc4random_buf(AData, NativeUInt(ALen));
  Result := 0;
end;

procedure TGenericBSDRandomProvider.GetBytes(const AData: TCryptoLibByteArray);
var
  LCount: Int32;
begin
  LCount := System.Length(AData);

  if LCount <= 0 then
  begin
    Exit;
  end;

  if GenRandomBytesGenericBSD(LCount, PByte(AData)) <> 0 then
  begin
    raise EOSRandomCryptoLibException.CreateRes(@SArc4RandomBufGenerationError);
  end;
end;

procedure TGenericBSDRandomProvider.GetNonZeroBytes(const AData: TCryptoLibByteArray);
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

function TGenericBSDRandomProvider.GetIsAvailable: Boolean;
begin
  Result := True;
end;

function TGenericBSDRandomProvider.GetName: String;
begin
  Result := 'GenericBSD';
end;

{$ENDIF}

end.
