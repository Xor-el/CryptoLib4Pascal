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

unit ClpIEd25519PublicKeyParameters;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpEd25519,
  ClpIAsymmetricKeyParameter,
  ClpCryptoLibTypes;

type
  IEd25519PublicKeyParameters = interface(IAsymmetricKeyParameter)
    ['{84C0E096-F4BA-438D-9E20-3ECFAE341E63}']

    procedure Encode(const ABuf: TCryptoLibByteArray; AOff: Int32);
    function GetEncoded(): TCryptoLibByteArray;

    function Verify(AAlgorithm: TEd25519.TAlgorithm;
      const ACtx, AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32;
      const ASig: TCryptoLibByteArray; ASigOff: Int32): Boolean;

    function Equals(const AOther: IEd25519PublicKeyParameters): Boolean;
      overload;
  end;

implementation

end.
