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

unit ClpIBip340SchnorrParameters;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsymmetricKeyParameter,
  ClpIKeyGenerationParameters,
  ClpCryptoLibTypes;

type
  IBip340SchnorrPublicKeyParameters = interface(IAsymmetricKeyParameter)
    ['{A7E2F1C0-4B3D-4E89-9A12-5C6D7E8F9012}']

    procedure Encode(const ABuf: TCryptoLibByteArray; AOff: Int32);
    function GetEncoded(): TCryptoLibByteArray;

    function Equals(const AOther: IBip340SchnorrPublicKeyParameters): Boolean;
      overload;
  end;

  IBip340SchnorrPrivateKeyParameters = interface(IAsymmetricKeyParameter)
    ['{B8F3E2D1-5C4E-4F90-AB23-6D7E8F901234}']

    procedure Encode(const ABuf: TCryptoLibByteArray; AOff: Int32);
    function GetEncoded(): TCryptoLibByteArray;
    function GeneratePublicKey(): IBip340SchnorrPublicKeyParameters;

    function Equals(const AOther: IBip340SchnorrPrivateKeyParameters): Boolean;
      overload;
  end;

  IBip340SchnorrKeyGenerationParameters = interface(IKeyGenerationParameters)
    ['{C9E4F3D2-6D5F-5091-BC34-7E8F90123456}']

  end;

implementation

end.
