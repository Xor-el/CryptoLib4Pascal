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

unit ClpIX448Parameters;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsymmetricKeyParameter,
  ClpIKeyGenerationParameters,
  ClpCryptoLibTypes;

type
  IX448PublicKeyParameters = interface(IAsymmetricKeyParameter)
    ['{6FBD9F66-1D70-4995-B632-39886A975EF7}']

    procedure Encode(const ABuf: TCryptoLibByteArray; AOff: Int32);
    function GetEncoded(): TCryptoLibByteArray;

    function Equals(const AOther: IX448PublicKeyParameters): Boolean; overload;
  end;

  IX448PrivateKeyParameters = interface(IAsymmetricKeyParameter)
    ['{A3FF50D8-C4AD-476F-861E-F62AA389FF6E}']

    procedure Encode(const ABuf: TCryptoLibByteArray; AOff: Int32);
    function GetEncoded(): TCryptoLibByteArray;
    function GeneratePublicKey(): IX448PublicKeyParameters;
    procedure GenerateSecret(const APublicKey: IX448PublicKeyParameters;
      const ABuf: TCryptoLibByteArray; AOff: Int32);

    function Equals(const AOther: IX448PrivateKeyParameters): Boolean;
      overload;
  end;

  IX448KeyGenerationParameters = interface(IKeyGenerationParameters)
    ['{852C95DF-6FF8-4C93-AE62-FF3CC2E894DA}']

  end;

implementation

end.
