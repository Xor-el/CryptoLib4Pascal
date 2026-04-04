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

unit ClpIChaCha7539Engine;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpISalsa20Engine,
  ClpCryptoLibTypes;

type

  IChaCha7539Engine = interface(ISalsa20Engine)
    ['{3E8B7A2D-C4F1-4D9E-A6B0-7F2E5D8C1A94}']

    procedure DoFinal(const AInBuf: TCryptoLibByteArray; AInOff, AInLen: Int32;
      const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);

    procedure ProcessBlock(const AInBytes: TCryptoLibByteArray; AInOff: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32);

    procedure ProcessBlocks2(const AInBytes: TCryptoLibByteArray; AInOff: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32);

  end;

implementation

end.
