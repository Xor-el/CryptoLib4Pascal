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

unit ClpIDsaDigestSigner;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpBigInteger,
  ClpICipherParameters,
  ClpISigner;

type

  IDsaDigestSigner = interface(ISigner)
    ['{6BED77E2-6D92-4DB7-8F3F-588EC528A2D7}']

    function DerEncode(const r, s: TBigInteger): TCryptoLibByteArray;

    function DerDecode(encoding: TCryptoLibByteArray)
      : TCryptoLibGenericArray<TBigInteger>;

    function GetAlgorithmName: String;
    property AlgorithmName: String read GetAlgorithmName;

    procedure Init(forSigning: Boolean; const parameters: ICipherParameters);

    /// <summary>
    /// update the internal digest with the byte b
    /// </summary>
    procedure Update(input: Byte);

    /// <summary>
    /// update the internal digest with the byte array in
    /// </summary>
    procedure BlockUpdate(input: TCryptoLibByteArray; inOff, length: Int32);

    /// <summary>
    /// Generate a signature for the message we've been loaded with using the
    /// key we were initialised with.
    /// </summary>
    function GenerateSignature(): TCryptoLibByteArray;

    /// <returns>
    /// true if the internal state represents the signature described in the
    /// passed in array.
    /// </returns>
    function VerifySignature(signature: TCryptoLibByteArray): Boolean;

    /// <summary>
    /// Reset the internal state
    /// </summary>
    procedure Reset();
  end;

implementation

end.
