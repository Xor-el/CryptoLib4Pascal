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

unit ClpXChaCha20Engine;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIStreamCipher,
  ClpChaCha7539Engine,
  ClpIXChaCha20Engine,
  ClpChaChaEngine,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SNilKeyReInit = '%s Doesn''t Support Re-Init with Nil Key';
  SInvalidKeySize = '%s Requires a 256 bit Key';
  SInvalidIvSize = '%s Requires a 192 bit IV';

type
  /// <summary>
  ///   Implementation of the XChaCha20 stream cipher (extended-nonce ChaCha20)
  ///   as described in draft-irtf-cfrg-xchacha-03.
  /// </summary>
  /// <remarks>
  ///   XChaCha20 takes a 256-bit key and a 192-bit nonce.
  ///   The first 128 bits of the nonce are used together with the key
  ///   in HChaCha20 to derive a 256-bit subkey.
  ///
  ///   That subkey, together with the remaining 64 bits of the nonce
  ///   (prefixed by four zero bytes to form a 96-bit IETF nonce),
  ///   then drives a standard ChaCha20-IETF stream as defined by RFC 7539.
  /// </remarks>
  TXChaCha20Engine = class(TChaCha7539Engine, IXChaCha20Engine, IStreamCipher)

  strict protected
    function GetAlgorithmName: String; override;
    function GetNonceSize: Int32; override;
    procedure SetKey(const AKeyBytes, AIvBytes: TCryptoLibByteArray); override;

  end;

implementation

{ TXChaCha20Engine }

function TXChaCha20Engine.GetAlgorithmName: String;
begin
  Result := 'XChaCha20';
end;

function TXChaCha20Engine.GetNonceSize: Int32;
begin
  Result := 24;
end;

procedure TXChaCha20Engine.SetKey(const AKeyBytes, AIvBytes: TCryptoLibByteArray);
var
  LSubKey: TCryptoLibByteArray;
  LInnerIv: TCryptoLibByteArray;
  LNoncePrefix: TCryptoLibByteArray;
begin
  if (AKeyBytes = nil) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SNilKeyReInit,
      [AlgorithmName]);
  end;

  if (System.Length(AKeyBytes) <> 32) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidKeySize,
      [AlgorithmName]);
  end;

  if (AIvBytes = nil) or (System.Length(AIvBytes) <> 24) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidIvSize,
      [AlgorithmName]);
  end;

  LNoncePrefix := Copy(AIvBytes, 0, 16);
  System.SetLength(LSubKey, 32);
  try
    TChaChaEngine.HChaCha20(AKeyBytes, LNoncePrefix, LSubKey, 0);
  finally
    TArrayUtilities.Fill<Byte>(LNoncePrefix, 0, System.Length(LNoncePrefix), Byte(0));
  end;

  System.SetLength(LInnerIv, 12);
  TArrayUtilities.Fill<Byte>(LInnerIv, 0, 4, Byte(0));
  System.Move(AIvBytes[16], LInnerIv[4], 8);

  try
    inherited SetKey(LSubKey, LInnerIv);
  finally
    TArrayUtilities.Fill<Byte>(LSubKey, 0, 32, Byte(0));
    TArrayUtilities.Fill<Byte>(LInnerIv, 0, 12, Byte(0));
  end;
end;

end.
