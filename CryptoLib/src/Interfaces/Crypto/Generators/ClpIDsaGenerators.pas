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

unit ClpIDsaGenerators;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpISecureRandom,
  ClpIDsaParameters;

type
  IDsaKeyPairGenerator = interface(IAsymmetricCipherKeyPairGenerator)
    ['{37A4647D-2D9A-4EB1-A2AF-B3FBE72B66F3}']
  end;

  IDsaParametersGenerator = interface(IInterface)
    ['{EB5A601B-2267-4485-A519-A80751FC39EA}']

    procedure Init(ASize, ACertainty: Int32;
      const ARandom: ISecureRandom); overload;

    procedure Init(ASize, ACertainty, AIterations: Int32;
      const ARandom: ISecureRandom); overload;

    procedure Init(const AParams: IDsaParameterGenerationParameters); overload;

    function GenerateParameters(): IDsaParameters;

  end;

implementation

end.
