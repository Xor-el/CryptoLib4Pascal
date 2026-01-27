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

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpIRandomSourceProvider;

resourcestring
  SArc4RandomBufGenerationError =
    'An Error Occured while generating random data using arc4random_buf API.';

type
{$IFDEF CRYPTOLIB_GENERIC_BSD}
procedure arc4random_buf(bytes: PByte; count: LongWord); cdecl;
  external 'c' name 'arc4random_buf';
{$ENDIF}

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

implementation

uses
  ClpArrayUtilities;

{ TGenericBSDRandomProvider }

constructor TGenericBSDRandomProvider.Create;
begin
  inherited Create();
end;

function TGenericBSDRandomProvider.GenRandomBytesGenericBSD(ALen: Int32;
  AData: PByte): Int32;
begin
{$IFDEF CRYPTOLIB_GENERIC_BSD}
  arc4random_buf(AData, LongWord(ALen));
  result := 0;
{$ELSE}
  result := -1;
{$ENDIF}
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

{$IFDEF CRYPTOLIB_GENERIC_BSD}
  if GenRandomBytesGenericBSD(LCount, PByte(AData)) <> 0 then
  begin
    raise EOSRandomCryptoLibException.CreateRes(@SArc4RandomBufGenerationError);
  end;
{$ELSE}
  raise EOSRandomCryptoLibException.Create('GenericBSDRandomProvider is only available on BSD platforms');
{$ENDIF}
end;

procedure TGenericBSDRandomProvider.GetNonZeroBytes(const AData: TCryptoLibByteArray);
begin
  repeat
    GetBytes(AData);
  until (TArrayUtilities.NoZeroes(AData));
end;

function TGenericBSDRandomProvider.GetIsAvailable: Boolean;
begin
{$IFDEF CRYPTOLIB_GENERIC_BSD}
  result := True;
{$ELSE}
  result := False;
{$ENDIF}
end;

function TGenericBSDRandomProvider.GetName: String;
begin
  result := 'GenericBSD';
end;

end.
