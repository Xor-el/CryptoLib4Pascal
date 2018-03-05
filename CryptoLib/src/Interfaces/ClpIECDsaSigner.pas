{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                    Copyright (c) 2018 Ugochukwu Mmaduekwe                       * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *        Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring        * }
{ *                        the development of this library                          * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIECDsaSigner;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIDsa,
  ClpISecureRandom,
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpIECInterface,
  ClpIECFieldElement;

type
  IECDsaSigner = interface(IDsa)

    ['{72930065-5893-46CA-B49F-51254C2E73FF}']

    function CalculateE(const n: TBigInteger; &message: TCryptoLibByteArray)
      : TBigInteger;

    function CreateBasePointMultiplier(): IECMultiplier;

    function GetDenominator(coordinateSystem: Int32; const p: IECPoint)
      : IECFieldElement;

    function InitSecureRandom(needed: Boolean; const provided: ISecureRandom)
      : ISecureRandom;

  end;

implementation

end.
