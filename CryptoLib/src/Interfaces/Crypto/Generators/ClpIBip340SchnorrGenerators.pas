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

unit ClpIBip340SchnorrGenerators;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsymmetricCipherKeyPairGenerator;

type
  IBip340SchnorrKeyPairGenerator = interface(IAsymmetricCipherKeyPairGenerator)
    ['{E2F5D4C3-7A6B-4F90-AC34-8D9E0F123456}']
  end;

implementation

end.
