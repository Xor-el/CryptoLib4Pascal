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

unit ClpEphemeralKeyPairGenerator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpEphemeralKeyPair,
  ClpIEphemeralKeyPair,
  ClpIEphemeralKeyPairGenerator,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIKeyEncoder;

type
  TEphemeralKeyPairGenerator = class sealed(TInterfacedObject,
    IEphemeralKeyPairGenerator)

  strict private
  var
    FGen: IAsymmetricCipherKeyPairGenerator;
    FKeyEncoder: IKeyEncoder;

  public
    function Generate(): IEphemeralKeyPair; inline;
    constructor Create(const AGen: IAsymmetricCipherKeyPairGenerator;
      const AKeyEncoder: IKeyEncoder);
  end;

implementation

{ TEphemeralKeyPairGenerator }

constructor TEphemeralKeyPairGenerator.Create(
  const AGen: IAsymmetricCipherKeyPairGenerator; const AKeyEncoder: IKeyEncoder);
begin
  inherited Create();
  FGen := AGen;
  FKeyEncoder := AKeyEncoder;
end;

function TEphemeralKeyPairGenerator.Generate: IEphemeralKeyPair;
var
  LEph: IAsymmetricCipherKeyPair;
begin
  LEph := FGen.GenerateKeyPair();
  Result := TEphemeralKeyPair.Create(LEph, FKeyEncoder);
end;

end.
