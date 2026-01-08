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

unit ClpISubjectPublicKeyInfo;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIAlgorithmIdentifier,
  ClpCryptoLibTypes;

type
  ISubjectPublicKeyInfo = interface(IAsn1Encodable)
    ['{59FD4D04-D393-4A72-B6DB-58781CD4D722}']
    function GetAlgorithm: IAlgorithmIdentifier;
    function GetPublicKeyData: IDerBitString;

    property Algorithm: IAlgorithmIdentifier read GetAlgorithm;
    property PublicKeyData: IDerBitString read GetPublicKeyData;
  end;

implementation

end.
