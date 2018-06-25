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

unit ClpIDsaSigner;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIDsa,
  ClpISecureRandom,
  ClpICipherParameters,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  IDsaSigner = interface(IDsa)
    ['{687C14CD-F126-4886-87FC-535DEB083C2F}']

    function GetAlgorithmName: String;

    function CalculateE(const n: TBigInteger; &message: TCryptoLibByteArray)
      : TBigInteger;

    function InitSecureRandom(needed: Boolean; const provided: ISecureRandom)
      : ISecureRandom;

    procedure Init(forSigning: Boolean; const parameters: ICipherParameters);

    /// <summary>
    /// Generate a signature for the given message using the key we were <br />
    /// initialised with. For conventional DSA the message should be a SHA-1 <br />
    /// hash of the message of interest.
    /// </summary>
    /// <param name="&amp;message">
    /// the message that will be verified later.
    /// </param>
    function GenerateSignature(&message: TCryptoLibByteArray)
      : TCryptoLibGenericArray<TBigInteger>;

    /// <summary>
    /// return true if the value r and s represent a DSA signature for <br />
    /// the passed in message for standard DSA the message should be a <br />
    /// SHA-1 hash of the real message to be verified.
    /// </summary>
    function VerifySignature(&message: TCryptoLibByteArray;
      const r, s: TBigInteger): Boolean;

    property AlgorithmName: String read GetAlgorithmName;

  end;

implementation

end.
