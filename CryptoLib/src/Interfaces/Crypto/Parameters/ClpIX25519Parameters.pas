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

unit ClpIX25519Parameters;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsymmetricKeyParameter,
  ClpIKeyGenerationParameters,
  ClpCryptoLibTypes;

type
  IX25519PublicKeyParameters = interface(IAsymmetricKeyParameter)
    ['{52D136C4-4DD1-4AF1-9AB8-0783136EF04A}']

    procedure Encode(const ABuf: TCryptoLibByteArray; AOff: Int32);
    function GetEncoded(): TCryptoLibByteArray;

    function Equals(const AOther: IX25519PublicKeyParameters): Boolean; overload;
  end;

  IX25519PrivateKeyParameters = interface(IAsymmetricKeyParameter)
    ['{6C7D2CD5-33A1-4153-A84C-70455CA69729}']

    procedure Encode(const ABuf: TCryptoLibByteArray; AOff: Int32);
    function GetEncoded(): TCryptoLibByteArray;
    function GeneratePublicKey(): IX25519PublicKeyParameters;
    procedure GenerateSecret(const APublicKey: IX25519PublicKeyParameters;
      const ABuf: TCryptoLibByteArray; AOff: Int32);

    function Equals(const AOther: IX25519PrivateKeyParameters): Boolean;
      overload;
  end;

  IX25519KeyGenerationParameters = interface(IKeyGenerationParameters)
    ['{BDDAF238-C842-4449-A7B8-3A537E405A62}']

  end;

implementation

end.
