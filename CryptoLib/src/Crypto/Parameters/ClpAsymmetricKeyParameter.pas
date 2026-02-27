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

unit ClpAsymmetricKeyParameter;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpICipherParameters,
  ClpIAsymmetricKeyParameter;

type
  TAsymmetricKeyParameter = class abstract(TInterfacedObject,
    IAsymmetricKeyParameter, ICipherParameters)

  strict private
  var
    FPrivateKey: Boolean;

  strict protected
    function GetPrivateKey: Boolean; inline;
    function GetIsPrivate: Boolean; inline;

    constructor Create(APrivateKey: Boolean);

  public
    property IsPrivate: Boolean read GetIsPrivate;
    property PrivateKey: Boolean read GetPrivateKey;
    function Equals(const AOther: IAsymmetricKeyParameter): Boolean; reintroduce;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

  end;

implementation

{ TAsymmetricKeyParameter }

constructor TAsymmetricKeyParameter.Create(APrivateKey: Boolean);
begin
  inherited Create();
  FPrivateKey := APrivateKey;
end;

function TAsymmetricKeyParameter.Equals(const AOther
  : IAsymmetricKeyParameter): Boolean;
begin
  if (AOther = nil) then
  begin
    Result := False;
    Exit;
  end;
  Result := FPrivateKey = AOther.PrivateKey;
end;

function TAsymmetricKeyParameter.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := Ord(FPrivateKey);
end;

function TAsymmetricKeyParameter.GetIsPrivate: Boolean;
begin
  Result := FPrivateKey;
end;

function TAsymmetricKeyParameter.GetPrivateKey: Boolean;
begin
  Result := FPrivateKey;
end;

end.
