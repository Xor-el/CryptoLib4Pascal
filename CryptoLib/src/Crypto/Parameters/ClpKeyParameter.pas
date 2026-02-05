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

unit ClpKeyParameter;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIKeyParameter,
  ClpICipherParameters,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SKeyNil = 'Key Cannot be Nil';
  SInvalidKeyOffSet = 'Invalid Key OffSet';
  SInvalidKeyLength = 'Invalid Key Length';

type
  TKeyParameter = class sealed(TInterfacedObject, IKeyParameter,
    ICipherParameters)

  strict private
  var
    FKey: TCryptoLibByteArray;

  public
    constructor Create(const AKey: TCryptoLibByteArray); overload;
    constructor Create(const AKey: TCryptoLibByteArray;
      AKeyOff, AKeyLen: Int32); overload;
    destructor Destroy; override;
    function GetKey(): TCryptoLibByteArray; inline;
    procedure Clear(); inline;

  end;

implementation

{ TKeyParameter }

constructor TKeyParameter.Create(const AKey: TCryptoLibByteArray);
begin
  inherited Create();

  if (AKey = nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SKeyNil);
  end;
  FKey := System.Copy(AKey);
end;

procedure TKeyParameter.Clear;
begin
  TArrayUtilities.Fill<Byte>(FKey, 0, System.Length(FKey), Byte(0));
end;

constructor TKeyParameter.Create(const AKey: TCryptoLibByteArray;
  AKeyOff, AKeyLen: Int32);
begin
  inherited Create();

  if (AKey = nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SKeyNil);
  end;

  if ((AKeyOff < 0) or (AKeyOff > System.Length(AKey))) then
  begin
    raise EArgumentOutOfRangeCryptoLibException.CreateRes(@SInvalidKeyOffSet);
  end;

  if ((AKeyLen < 0) or (AKeyLen > (System.Length(AKey) - AKeyOff))) then
  begin
    raise EArgumentOutOfRangeCryptoLibException.CreateRes(@SInvalidKeyLength);
  end;

  System.SetLength(FKey, AKeyLen);
  System.Move(AKey[AKeyOff], FKey[0], AKeyLen);

end;

destructor TKeyParameter.Destroy;
begin
  Clear();
  inherited Destroy;
end;

function TKeyParameter.GetKey: TCryptoLibByteArray;
begin
  Result := System.Copy(FKey);
end;

end.
