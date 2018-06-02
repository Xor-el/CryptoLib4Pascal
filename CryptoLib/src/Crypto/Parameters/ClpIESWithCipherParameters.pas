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

unit ClpIESWithCipherParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIESParameters,
  ClpIIESParameters,
  ClpIIESWithCipherParameters,
  ClpCryptoLibTypes;

type

  TIESWithCipherParameters = class(TIESParameters, IIESParameters,
    IIESWithCipherParameters)

  strict private
  var
    FCipherKeySize: Int32;
    FPointCompression: Boolean;
    FNonce: TCryptoLibByteArray;
    function GetCipherKeySize(): Int32; inline;
    function GetPointCompression(): Boolean; inline;
    function GetNonce(): TCryptoLibByteArray; inline;
  public
    property CipherKeySize: Int32 read GetCipherKeySize;
    property PointCompression: Boolean read GetPointCompression;
    property Nonce: TCryptoLibByteArray read GetNonce;

    /// <param name="derivation"> 
    /// the derivation parameter for the KDF function.
    /// </param>
    /// <param name="encoding">
    /// the encoding parameter for the KDF function.
    /// </param>
    /// <param name="nonce">
    /// the iv used in the cipher engine.
    /// </param>
    /// <param name="MacKeySize">
    /// the size of the MAC key (in bits).
    /// </param>
    /// <param name="CipherKeySize">
    /// the size of the associated Cipher key (in bits).
    /// </param>
    /// <param name="PointCompression">
    /// whether to use point compression or not in EphemeralKeyPairGenerator.
    /// </param>
    constructor Create(derivation, encoding, Nonce: TCryptoLibByteArray;
      MacKeySize, CipherKeySize: Int32; PointCompression: Boolean);
  end;

implementation

{ TIESWithCipherParameters }

constructor TIESWithCipherParameters.Create(derivation, encoding,
  Nonce: TCryptoLibByteArray; MacKeySize, CipherKeySize: Int32;
  PointCompression: Boolean);
begin
  Inherited Create(derivation, encoding, MacKeySize);
  FNonce := Nonce;
  FCipherKeySize := CipherKeySize;
  FPointCompression := PointCompression;
end;

function TIESWithCipherParameters.GetCipherKeySize: Int32;
begin
  result := FCipherKeySize;
end;

function TIESWithCipherParameters.GetNonce: TCryptoLibByteArray;
begin
  result := FNonce;
end;

function TIESWithCipherParameters.GetPointCompression: Boolean;
begin
  result := FPointCompression;
end;

end.
