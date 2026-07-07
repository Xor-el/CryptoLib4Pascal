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

unit ClpLib25519;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpArrayUtilities,
  ClpCryptoLibTypes,
  ClpEd25519,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpX25519;

resourcestring
  SInvalidDhSecretKeyLength = 'invalid DH secret key length';
  SInvalidDhPublicKeyLength = 'invalid DH public key length';
  SInvalidDhOutputLength = 'invalid DH output length';
  SInvalidSignSecretKeyLength = 'invalid sign secret key length';
  SInvalidSignPublicKeyLength = 'invalid sign public key length';
  SInvalidSignOutputLength = 'invalid signed message output length';
  SInvalidSignedMessageLength = 'invalid signed message length';
  SInvalidMessageOutputLength = 'invalid message output length';
  SMessageTooLong = 'message too long';

type
  /// <summary>
  /// Implements the lib25519 API (https://lib25519.cr.yp.to).
  /// </summary>
  /// <remarks>
  /// Full interoperability with lib25519 keys, shared secrets, and (signed) messages.
  /// Signing is not guaranteed to be deterministic; signing the same message under the
  /// same key may produce different signed messages each time.
  /// </remarks>
  TLib25519 = class sealed(TObject)
  strict private
  class var
    FRandom: ISecureRandom;
    FEd25519: TEd25519;

    class constructor Create;
    class destructor Destroy;
  public
    const
      /// <summary>Equivalent of lib25519_dh_BYTES.</summary>
      DHBytes = TX25519.PointSize;
      /// <summary>Equivalent of lib25519_dh_PUBLICKEYBYTES.</summary>
      DHPublicKeyBytes = TX25519.PointSize;
      /// <summary>Equivalent of lib25519_dh_SECRETKEYBYTES.</summary>
      DHSecretKeyBytes = TX25519.ScalarSize;
      /// <summary>Equivalent of lib25519_sign_BYTES.</summary>
      SignBytes = TEd25519.SignatureSize;
      /// <summary>Equivalent of lib25519_sign_PUBLICKEYBYTES.</summary>
      SignPublicKeyBytes = TEd25519.PublicKeySize;
      /// <summary>Equivalent of lib25519_sign_SECRETKEYBYTES.</summary>
      SignSecretKeyBytes = TEd25519.SecretKeySize + TEd25519.PublicKeySize;

    /// <summary>
    /// Equivalent of lib25519_dh.
    /// </summary>
    /// <remarks>
    /// Computes the X25519 shared secret between Alice and Bob, given Bob's public key
    /// and Alice's secret key. A lack of contributory behaviour may be detected by testing
    /// whether the output is all zeros (e.g. using TArrayUtilities.AreAllZeroes), but
    /// this check is the caller's responsibility.
    /// </remarks>
    class procedure DH(const AK: TCryptoLibByteArray; AKOff: Int32;
      const APk: TCryptoLibByteArray; APkOff: Int32;
      const ASk: TCryptoLibByteArray; ASkOff: Int32); static;

    /// <summary>Equivalent of lib25519_dh_keypair.</summary>
    class procedure DHKeyPair(const APk: TCryptoLibByteArray; APkOff: Int32;
      const ASk: TCryptoLibByteArray; ASkOff: Int32); static;

    /// <summary>Equivalent of lib25519_sign.</summary>
    class procedure Sign(const ASignedMsg: TCryptoLibByteArray; ASignedMsgOff: Int32;
      out ASignedMsgLen: Int32; const AM: TCryptoLibByteArray; AMOff, AMLen: Int32;
      const ASk: TCryptoLibByteArray; ASkOff: Int32); static;

    /// <summary>Equivalent of lib25519_sign_keypair.</summary>
    class procedure SignKeyPair(const APk: TCryptoLibByteArray; APkOff: Int32;
      const ASk: TCryptoLibByteArray; ASkOff: Int32); static;

    /// <summary>Equivalent of lib25519_sign_open.</summary>
    /// <remarks>
    /// If verification fails, returns False, sets AMlen to -1, and clears the output buffer
    /// over the signed-message length. Callers should always check the return value; other
    /// signature software does not necessarily clear the output buffer on failure.
    /// </remarks>
    class function SignOpen(const AM: TCryptoLibByteArray; AMOff: Int32; out AMlen: Int32;
      const ASignedMsg: TCryptoLibByteArray; ASignedMsgOff, ASignedMsgLen: Int32;
      const APk: TCryptoLibByteArray; APkOff: Int32): Boolean; static;
  end;

implementation

{ TLib25519 }

class constructor TLib25519.Create;
begin
  FRandom := TSecureRandom.Create();
  FEd25519 := TEd25519.Create();
end;

class destructor TLib25519.Destroy;
begin
  FEd25519.Free;
  FEd25519 := nil;
  FRandom := nil;
end;

class procedure TLib25519.DH(const AK: TCryptoLibByteArray; AKOff: Int32;
  const APk: TCryptoLibByteArray; APkOff: Int32;
  const ASk: TCryptoLibByteArray; ASkOff: Int32);
begin
  TArrayUtilities.ValidateSegment(ASk, ASkOff, DHSecretKeyBytes);
  if System.Length(ASk) - ASkOff <> DHSecretKeyBytes then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidDhSecretKeyLength);

  TArrayUtilities.ValidateSegment(APk, APkOff, DHPublicKeyBytes);
  if System.Length(APk) - APkOff <> DHPublicKeyBytes then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidDhPublicKeyLength);

  TArrayUtilities.ValidateSegment(AK, AKOff, DHBytes);
  if System.Length(AK) - AKOff <> DHBytes then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidDhOutputLength);

  TX25519.ScalarMult(ASk, ASkOff, APk, APkOff, AK, AKOff);
end;

class procedure TLib25519.DHKeyPair(const APk: TCryptoLibByteArray; APkOff: Int32;
  const ASk: TCryptoLibByteArray; ASkOff: Int32);
begin
  TArrayUtilities.ValidateSegment(ASk, ASkOff, DHSecretKeyBytes);
  if System.Length(ASk) - ASkOff <> DHSecretKeyBytes then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidDhSecretKeyLength);

  TArrayUtilities.ValidateSegment(APk, APkOff, DHPublicKeyBytes);
  if System.Length(APk) - APkOff <> DHPublicKeyBytes then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidDhPublicKeyLength);

  FRandom.NextBytes(ASk, ASkOff, DHSecretKeyBytes);
  TX25519.ScalarMultBase(ASk, ASkOff, APk, APkOff);
end;

class procedure TLib25519.Sign(const ASignedMsg: TCryptoLibByteArray; ASignedMsgOff: Int32;
  out ASignedMsgLen: Int32; const AM: TCryptoLibByteArray; AMOff, AMLen: Int32;
  const ASk: TCryptoLibByteArray; ASkOff: Int32);
var
  LSmLen: Int32;
begin
  TArrayUtilities.ValidateSegment(ASk, ASkOff, SignSecretKeyBytes);
  if System.Length(ASk) - ASkOff <> SignSecretKeyBytes then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidSignSecretKeyLength);

  if AMLen > MaxInt - SignBytes then
    raise EArgumentCryptoLibException.CreateRes(@SMessageTooLong);

  TArrayUtilities.ValidateSegment(AM, AMOff, AMLen);

  LSmLen := AMLen + SignBytes;
  TArrayUtilities.ValidateSegment(ASignedMsg, ASignedMsgOff, LSmLen);
  if System.Length(ASignedMsg) - ASignedMsgOff < LSmLen then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidSignOutputLength);

  if AMLen > 0 then
    System.Move(AM[AMOff], ASignedMsg[ASignedMsgOff + SignBytes], AMLen);

  FEd25519.Sign(ASk, ASkOff,
    ASk, ASkOff + TEd25519.SecretKeySize,
    ASignedMsg, ASignedMsgOff + SignBytes, AMLen,
    ASignedMsg, ASignedMsgOff);
  ASignedMsgLen := LSmLen;
end;

class procedure TLib25519.SignKeyPair(const APk: TCryptoLibByteArray; APkOff: Int32;
  const ASk: TCryptoLibByteArray; ASkOff: Int32);
begin
  TArrayUtilities.ValidateSegment(ASk, ASkOff, SignSecretKeyBytes);
  if System.Length(ASk) - ASkOff <> SignSecretKeyBytes then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidSignSecretKeyLength);

  TArrayUtilities.ValidateSegment(APk, APkOff, SignPublicKeyBytes);
  if System.Length(APk) - APkOff <> SignPublicKeyBytes then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidSignPublicKeyLength);

  FRandom.NextBytes(ASk, ASkOff, TEd25519.SecretKeySize);
  FEd25519.GeneratePublicKey(ASk, ASkOff, APk, APkOff);
  System.Move(APk[APkOff], ASk[ASkOff + TEd25519.SecretKeySize], TEd25519.PublicKeySize);
end;

class function TLib25519.SignOpen(const AM: TCryptoLibByteArray; AMOff: Int32; out AMlen: Int32;
  const ASignedMsg: TCryptoLibByteArray; ASignedMsgOff, ASignedMsgLen: Int32;
  const APk: TCryptoLibByteArray; APkOff: Int32): Boolean;
var
  LMlen: Int32;
begin
  TArrayUtilities.ValidateSegment(APk, APkOff, SignPublicKeyBytes);
  if System.Length(APk) - APkOff <> SignPublicKeyBytes then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidSignPublicKeyLength);

  if ASignedMsgLen < SignBytes then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidSignedMessageLength);

  TArrayUtilities.ValidateSegment(ASignedMsg, ASignedMsgOff, ASignedMsgLen);

  LMlen := ASignedMsgLen - SignBytes;
  TArrayUtilities.ValidateSegment(AM, AMOff, ASignedMsgLen);
  if System.Length(AM) - AMOff < ASignedMsgLen then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidMessageOutputLength);

  if not FEd25519.Verify(ASignedMsg, ASignedMsgOff, APk, APkOff,
    ASignedMsg, ASignedMsgOff + SignBytes, LMlen) then
  begin
    TArrayUtilities.Fill(AM, AMOff, AMOff + ASignedMsgLen, 0);
    AMlen := -1;
    Exit(False);
  end;

  if LMlen > 0 then
    System.Move(ASignedMsg[ASignedMsgOff + SignBytes], AM[AMOff], LMlen);
  AMlen := LMlen;
  Result := True;
end;

end.
