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
  ClpIECFieldElement,
  ClpICipherParameters;

type
  IECDsaSigner = interface(IDsa)

    ['{72930065-5893-46CA-B49F-51254C2E73FF}']

    function CalculateE(n: TBigInteger; &message: TCryptoLibByteArray)
      : TBigInteger;

    function CreateBasePointMultiplier(): IECMultiplier;

    function GetDenominator(coordinateSystem: Int32; p: IECPoint)
      : IECFieldElement;

    function InitSecureRandom(needed: Boolean; provided: ISecureRandom)
      : ISecureRandom;

    function GetAlgorithmName: String;
    property AlgorithmName: String read GetAlgorithmName;

    procedure Init(forSigning: Boolean; parameters: ICipherParameters);

    // // 5.3 pg 28
    // /**
    // * Generate a signature for the given message using the key we were
    // * initialised with. For conventional DSA the message should be a SHA-1
    // * hash of the message of interest.
    // *
    // * @param message the message that will be verified later.
    function GenerateSignature(&message: TCryptoLibByteArray)
      : TCryptoLibGenericArray<TBigInteger>;

    // // 5.4 pg 29
    // /**
    // * return true if the value r and s represent a DSA signature for
    // * the passed in message (for standard DSA the message should be
    // * a SHA-1 hash of the real message to be verified).
    // */
    function VerifySignature(&message: TCryptoLibByteArray;
      r, s: TBigInteger): Boolean;

  end;

implementation

end.
