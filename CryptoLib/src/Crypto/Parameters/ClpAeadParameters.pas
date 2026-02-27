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

unit ClpAeadParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAeadParameters,
  ClpICipherParameters,
  ClpIKeyParameter,
  ClpCryptoLibTypes;

resourcestring
  SNonceNil = 'Nonce Cannot be Nil';

type
  TAeadParameters = class sealed(TInterfacedObject, IAeadParameters,
    ICipherParameters)

  strict private
  var
    FKey: IKeyParameter;
    FMacSize: Int32;
    FNonce: TCryptoLibByteArray;
    FAssociatedText: TCryptoLibByteArray;

    function GetKey(): IKeyParameter; inline;
    function GetMacSize(): Int32; inline;

  public
    constructor Create(const AKey: IKeyParameter; AMacSize: Int32;
      const ANonce: TCryptoLibByteArray); overload;
    constructor Create(const AKey: IKeyParameter; AMacSize: Int32;
      const ANonce, AAssociatedText: TCryptoLibByteArray); overload;
    function GetNonce(): TCryptoLibByteArray;
    function GetAssociatedText(): TCryptoLibByteArray;
    property Key: IKeyParameter read GetKey;
    property MacSize: Int32 read GetMacSize;

  end;

implementation

{ TAeadParameters }

constructor TAeadParameters.Create(const AKey: IKeyParameter; AMacSize: Int32;
  const ANonce: TCryptoLibByteArray);
begin
  Create(AKey, AMacSize, ANonce, nil);
end;

constructor TAeadParameters.Create(const AKey: IKeyParameter; AMacSize: Int32;
  const ANonce, AAssociatedText: TCryptoLibByteArray);
begin
  inherited Create();
  if (ANonce = nil) then
    raise EArgumentNilCryptoLibException.CreateRes(@SNonceNil);

  FKey := AKey;
  FNonce := ANonce;
  FMacSize := AMacSize;
  FAssociatedText := AAssociatedText;
end;

function TAeadParameters.GetKey: IKeyParameter;
begin
  Result := FKey;
end;

function TAeadParameters.GetMacSize: Int32;
begin
  Result := FMacSize;
end;

function TAeadParameters.GetNonce: TCryptoLibByteArray;
begin
  Result := System.Copy(FNonce);
end;

function TAeadParameters.GetAssociatedText: TCryptoLibByteArray;
begin
  Result := FAssociatedText;
end;

end.
