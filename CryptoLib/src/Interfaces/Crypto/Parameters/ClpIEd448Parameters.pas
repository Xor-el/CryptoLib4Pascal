{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIEd448Parameters;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpEd448,
  ClpIAsymmetricKeyParameter,
  ClpIKeyGenerationParameters,
  ClpCryptoLibTypes;

type
  IEd448PublicKeyParameters = interface(IAsymmetricKeyParameter)
    ['{7DFE9158-4A52-4ECA-A087-25D60898A8C8}']

    procedure Encode(const ABuf: TCryptoLibByteArray; AOff: Int32);
    function GetEncoded(): TCryptoLibByteArray;

    function Verify(AAlgorithm: TEd448.TAlgorithm;
      const ACtx, AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32;
      const ASig: TCryptoLibByteArray; ASigOff: Int32): Boolean;

    function Equals(const AOther: IEd448PublicKeyParameters): Boolean;
      overload;
  end;

  IEd448PrivateKeyParameters = interface(IAsymmetricKeyParameter)
    ['{DA8D0731-23B8-4E91-B1DC-44DF9FDFD2CC}']

    procedure Encode(const ABuf: TCryptoLibByteArray; AOff: Int32);
    function GetEncoded(): TCryptoLibByteArray;
    function GeneratePublicKey(): IEd448PublicKeyParameters;

    procedure Sign(AAlgorithm: TEd448.TAlgorithm;
      const ACtx, AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32;
      const ASig: TCryptoLibByteArray; ASigOff: Int32);

    function Equals(const AOther: IEd448PrivateKeyParameters): Boolean;
      overload;
  end;

  IEd448KeyGenerationParameters = interface(IKeyGenerationParameters)
    ['{C59AAC63-DF9B-46C5-99F4-F38F495CEF65}']

  end;

implementation

end.
