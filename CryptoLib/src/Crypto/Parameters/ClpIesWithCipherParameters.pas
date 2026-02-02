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

unit ClpIesWithCipherParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIESParameters,
  ClpIIESParameters,
  ClpIIESWithCipherParameters,
  ClpCryptoLibTypes;

type

  TIesWithCipherParameters = class(TIesParameters, IIesParameters,
    IIesWithCipherParameters)

  strict private
  var
    FcipherKeySize: Int32;

    function GetCipherKeySize: Int32; inline;
  public

    /// <summary>
    /// Set the IES engine parameters.
    /// </summary>
    /// <param name="ADerivation">
    /// the optional derivation vector for the KDF.
    /// </param>
    /// <param name="AEncoding">
    /// the optional encoding vector for the KDF.
    /// </param>
    /// <param name="AMacKeySize">
    /// the key size (in bits) for the MAC.
    /// </param>
    /// <param name="ACipherKeySize">
    /// the key size (in bits) for the block cipher.
    /// </param>
    constructor Create(const ADerivation, AEncoding: TCryptoLibByteArray;
      AMacKeySize, ACipherKeySize: Int32);

    /// <summary>
    /// Return the key size in bits for the block cipher used with the message
    /// </summary>
    /// <value>
    /// the key size in bits for the block cipher used with the message
    /// </value>
    property CipherKeySize: Int32 read GetCipherKeySize;

  end;

implementation

{ TIESWithCipherParameters }

function TIesWithCipherParameters.GetCipherKeySize: Int32;
begin
  Result := FcipherKeySize;
end;

constructor TIesWithCipherParameters.Create(const ADerivation,
  AEncoding: TCryptoLibByteArray; AMacKeySize, ACipherKeySize: Int32);
begin
  Inherited Create(ADerivation, AEncoding, AMacKeySize);
  FcipherKeySize := ACipherKeySize;
end;

end.
