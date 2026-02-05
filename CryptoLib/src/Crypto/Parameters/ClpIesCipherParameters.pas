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

unit ClpIesCipherParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpICipherParameters,
  ClpIIESParameters,
  ClpIIesCipherParameters;

type
  TIesCipherParameters = class sealed(TInterfacedObject, IIesCipherParameters,
    ICipherParameters)

  strict private
  var
    FPrivateKey: ICipherParameters;
    FPublicKey: ICipherParameters;
    FIesParameters: IIesParameters;

    function GetPrivateKey: ICipherParameters; inline;
    function GetPublicKey: ICipherParameters; inline;
    function GetIesParameters: IIesParameters; inline;

  public
    constructor Create(const APrivateKey, APublicKey: ICipherParameters;
      const AIesParameters: IIesParameters);

    property PrivateKey: ICipherParameters read GetPrivateKey;
    property PublicKey: ICipherParameters read GetPublicKey;
    property IesParameters: IIesParameters read GetIesParameters;
  end;

implementation

{ TIesCipherParameters }

constructor TIesCipherParameters.Create(const APrivateKey,
  APublicKey: ICipherParameters; const AIesParameters: IIesParameters);
begin
  Inherited Create();
  FPrivateKey := APrivateKey;
  FPublicKey := APublicKey;
  FIesParameters := AIesParameters;
end;

function TIesCipherParameters.GetPrivateKey: ICipherParameters;
begin
  Result := FPrivateKey;
end;

function TIesCipherParameters.GetPublicKey: ICipherParameters;
begin
  Result := FPublicKey;
end;

function TIesCipherParameters.GetIesParameters: IIesParameters;
begin
  Result := FIesParameters;
end;

end.
