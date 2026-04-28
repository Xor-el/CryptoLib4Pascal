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

unit ClpIDecryptorBuilderProvider;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpICipherBuilder,
  ClpIX509Asn1Objects;

type
  /// <summary>
  /// Interface describing a provider of cipher builders for creating decrypting ciphers.
  /// </summary>
  IDecryptorBuilderProvider = interface(IInterface)
    ['{2F09D9CA-FCAB-4F06-B4F0-7AE1234033CD}']

    /// <summary>
    /// Return a cipher builder for creating decrypting ciphers.
    /// </summary>
    function CreateDecryptorBuilder(const AAlgorithmDetails: IAlgorithmIdentifier): ICipherBuilder;
  end;

implementation

end.
