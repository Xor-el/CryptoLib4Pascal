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

unit ClpIDHGenerators;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpISecureRandom,
  ClpIDHParameters;

type
  IDHKeyPairGenerator = interface(IAsymmetricCipherKeyPairGenerator)
    ['{016112AA-A9AD-43E3-A3AA-25428682396F}']
  end;

  IDHBasicKeyPairGenerator = interface(IAsymmetricCipherKeyPairGenerator)
    ['{F8C67480-A3D5-45AC-BEB1-DA3C484844EC}']
  end;

  IDHParametersGenerator = interface(IInterface)
    ['{ECE2C3CF-4DA4-450B-BB37-2C100BC72FF6}']

    procedure Init(ASize, ACertainty: Int32; const ARandom: ISecureRandom);
    function GenerateParameters(): IDHParameters;

  end;

implementation

end.
