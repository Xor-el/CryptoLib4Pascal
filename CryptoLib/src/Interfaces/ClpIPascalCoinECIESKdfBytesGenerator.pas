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

unit ClpIPascalCoinECIESKdfBytesGenerator;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIDigest,
  ClpIDerivationParameters,
  ClpIBaseKdfBytesGenerator,
  ClpCryptoLibTypes;

type

  IPascalCoinECIESKdfBytesGenerator = interface(IBaseKdfBytesGenerator)
    ['{F6C7D34B-BA6A-45DB-B2A2-088F36557396}']

    function GetDigest(): IDigest;

    procedure Init(const parameters: IDerivationParameters);

    /// <summary>
    /// return the underlying digest.
    /// </summary>
    property digest: IDigest read GetDigest;

    /// <summary>
    /// fill len bytes of the output buffer with bytes generated from the
    /// derivation function.
    /// </summary>
    /// <exception cref="EArgumentCryptoLibException">
    /// if the size of the request will cause an overflow.
    /// </exception>
    /// <exception cref="EDataLengthCryptoLibException">
    /// if the out buffer is too small.
    /// </exception>
    function GenerateBytes(output: TCryptoLibByteArray;
      outOff, length: Int32): Int32;

  end;

implementation

end.
