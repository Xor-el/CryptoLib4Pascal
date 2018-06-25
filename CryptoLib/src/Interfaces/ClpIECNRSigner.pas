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

unit ClpIECNRSigner;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIDsa,
  ClpICipherParameters,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  IECNRSigner = interface(IDsa)
    ['{C136F005-404E-4022-886E-DE5EFCECFF9C}']

    function GetAlgorithmName: String;

    property AlgorithmName: String read GetAlgorithmName;

    procedure Init(forSigning: Boolean; const parameters: ICipherParameters);

    function GenerateSignature(&message: TCryptoLibByteArray)
      : TCryptoLibGenericArray<TBigInteger>;

    function VerifySignature(&message: TCryptoLibByteArray;
      const r, s: TBigInteger): Boolean;

  end;

implementation

end.
