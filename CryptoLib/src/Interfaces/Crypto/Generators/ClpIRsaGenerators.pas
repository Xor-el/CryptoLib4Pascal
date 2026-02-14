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

unit ClpIRsaGenerators;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpBigInteger,
  ClpICipherParameters;

type
  IRsaKeyPairGenerator = interface(IAsymmetricCipherKeyPairGenerator)
    ['{2259ACEB-6CF5-4AC9-9255-9A7DD432B0D2}']
  end;

  IRsaBlindingFactorGenerator = interface(IInterface)
    ['{A3B4C5D6-E7F8-9012-3456-789ABCDEF012}']

    procedure Init(const AParam: ICipherParameters);
    function GenerateBlindingFactor: TBigInteger;

  end;

implementation

end.
