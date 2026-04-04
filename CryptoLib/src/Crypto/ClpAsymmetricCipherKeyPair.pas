{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpAsymmetricCipherKeyPair;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpIAsymmetricKeyParameter,
  ClpIAsymmetricCipherKeyPair;

resourcestring
  SExpectedPublicKey = 'Expected a Public Key "publicParameter"';
  SExpectedPrivateKey = 'Expected a Private Key "privateParameter"';

type
  /// <summary>
  /// a holding class for public/private parameter pairs <br />
  /// </summary>
  TAsymmetricCipherKeyPair = class sealed(TInterfacedObject,
    IAsymmetricCipherKeyPair)

  strict private
  var
    FPublicParameter, FPrivateParameter: IAsymmetricKeyParameter;

    function GetPrivate: IAsymmetricKeyParameter; inline;
    function GetPublic: IAsymmetricKeyParameter; inline;

  public

    /// <summary>
    /// basic constructor.
    /// </summary>
    /// <param name="APublicParameter">
    /// publicParam a public key parameters object.
    /// </param>
    /// <param name="APrivateParameter">
    /// privateParam the corresponding private key parameters.
    /// </param>
    constructor Create(const APublicParameter, APrivateParameter
      : IAsymmetricKeyParameter);

    /// <summary>
    /// return the public key parameters.
    /// </summary>
    property &Public: IAsymmetricKeyParameter read GetPublic;

    /// <summary>
    /// return the private key parameters.
    /// </summary>
    property &Private: IAsymmetricKeyParameter read GetPrivate;

  end;

implementation

{ TAsymmetricCipherKeyPair }

constructor TAsymmetricCipherKeyPair.Create(const APublicParameter,
  APrivateParameter: IAsymmetricKeyParameter);
begin
  if (APublicParameter.IsPrivate) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SExpectedPublicKey);
  end;
  if (not APrivateParameter.IsPrivate) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SExpectedPrivateKey);
  end;

  FPublicParameter := APublicParameter;
  FPrivateParameter := APrivateParameter;
end;

function TAsymmetricCipherKeyPair.GetPrivate: IAsymmetricKeyParameter;
begin
  Result := FPrivateParameter;
end;

function TAsymmetricCipherKeyPair.GetPublic: IAsymmetricKeyParameter;
begin
  Result := FPublicParameter;
end;

end.
