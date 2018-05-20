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

unit ClpEphemeralKeyPair;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIEphemeralKeyPair,
  ClpIAsymmetricCipherKeyPair,
  ClpKeyEncoder,
  ClpCryptoLibTypes;

resourcestring
  SParameterFunctionCannotBeNil = 'Parameter Function Cannot be Nil.';

type
  TEphemeralKeyPair = class sealed(TInterfacedObject, IEphemeralKeyPair)

  strict private

    FkeyPair: IAsymmetricCipherKeyPair;
    FUsePointCompression: Boolean;
    FpublicKeyEncoder: TKeyEncoder;

  public

    function getKeyPair(): IAsymmetricCipherKeyPair; inline;

    function getEncodedPublicKey(): TCryptoLibByteArray; inline;

    constructor Create(const keyPair: IAsymmetricCipherKeyPair;
      usePointCompression: Boolean; const publicKeyEncoder: TKeyEncoder);

  end;

implementation

{ TEphemeralKeyPair }

constructor TEphemeralKeyPair.Create(const keyPair: IAsymmetricCipherKeyPair;
  usePointCompression: Boolean; const publicKeyEncoder: TKeyEncoder);
begin
  Inherited Create();
  FkeyPair := keyPair;
  FUsePointCompression := usePointCompression;
  FpublicKeyEncoder := publicKeyEncoder;
end;

function TEphemeralKeyPair.getEncodedPublicKey: TCryptoLibByteArray;
begin
  if Assigned(FpublicKeyEncoder) then
  begin
    result := FpublicKeyEncoder(FkeyPair.Public, FUsePointCompression);
  end
  else
  begin
    raise EArgumentNilCryptoLibException.CreateRes
      (@SParameterFunctionCannotBeNil);
  end;
end;

function TEphemeralKeyPair.getKeyPair: IAsymmetricCipherKeyPair;
begin
  result := FkeyPair;
end;

end.
