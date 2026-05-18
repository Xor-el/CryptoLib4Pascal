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

unit ClpXChaCha20Poly1305;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIXChaCha20Poly1305,
  ClpIAeadCipher,
  ClpIXChaCha20Engine,
  ClpChaCha20Poly1305,
  ClpIMac,
  ClpPoly1305,
  ClpXChaCha20Engine;

type
  /// <summary>
  ///   XChaCha20-Poly1305 AEAD construction as described in
  ///   draft-irtf-cfrg-xchacha-03 section 2.4.
  /// </summary>
  /// <remarks>
  ///   Identical to ChaCha20-Poly1305 except that the underlying stream
  ///   cipher is XChaCha20 using a 192-bit nonce instead of a 96-bit nonce.
  ///
  ///   The extended nonce makes random-nonce strategies safe at scale.
  ///   With a 192-bit nonce, collisions remain negligibly likely up to
  ///   2^80 messages per key, removing the per-key counter or
  ///   deterministic-nonce constraint imposed by standard
  ///   ChaCha20-Poly1305.
  /// </remarks>
  TXChaCha20Poly1305 = class(TChaCha20Poly1305, IXChaCha20Poly1305, IAeadCipher)

  strict protected
    function GetAlgorithmName: String; override;

  public
    constructor Create(); overload;
    constructor Create(const APoly1305: IMac); overload;
  end;

implementation

{ TXChaCha20Poly1305 }

constructor TXChaCha20Poly1305.Create;
begin
  Create(TPoly1305.Create() as IMac);
end;

constructor TXChaCha20Poly1305.Create(const APoly1305: IMac);
begin
  inherited Create(APoly1305, TXChaCha20Engine.Create() as IXChaCha20Engine, 24);
end;

function TXChaCha20Poly1305.GetAlgorithmName: String;
begin
  Result := 'XChaCha20Poly1305';
end;

end.
