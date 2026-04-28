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

unit ClpIOpenSslPkcs8Generator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIPemObject,
  ClpISecureRandom,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Interface for PKCS#8 PEM generator (unencrypted or encrypted private keys).
  /// </summary>
  IOpenSslPkcs8Generator = interface(IPemObjectGenerator)
    ['{E8D7C6B5-A493-8271-6F5E-4D3C2B1A0908}']

    procedure SetSecureRandom(const AValue: ISecureRandom);
    procedure SetPassword(const AValue: TCryptoLibCharArray);
    procedure SetIterationCount(AValue: Int32);
  end;

implementation

end.
