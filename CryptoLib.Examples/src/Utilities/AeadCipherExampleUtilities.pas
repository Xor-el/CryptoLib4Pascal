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

unit AeadCipherExampleUtilities;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

uses
  SysUtils,
  Math,
  ClpIAeadCipher,
  ClpIBlockCipher,
  ClpAesUtilities,
  ClpGcmBlockCipher,
  ClpCcmBlockCipher,
  ClpEaxBlockCipher,
  ClpOcbBlockCipher,
  ClpGcmSivBlockCipher,
  ClpChaCha20Poly1305,
  ClpXChaCha20Poly1305,
  ClpAeadParameters,
  ClpIAeadParameters,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpArrayUtilities,
  ClpICipherParameters;

type
  /// <summary>Constructs a fresh, uninitialised AEAD cipher instance. The
  /// per-cipher construction (which engine, how many, which mode) is the
  /// only thing that varies, so each table row carries one of these.</summary>
  TAeadCipherFactory = function: IAeadCipher;

  /// <summary>One AEAD cipher demo row.</summary>
  TAeadSpec = record
    DisplayName: string;
    KeyByteCount: Int32;
    NonceByteCount: Int32;
    TagBitLength: Int32;
    NewCipher: TAeadCipherFactory;
  end;

  /// <summary>
  /// Shared driver for the AEAD ciphers, over the native
  /// <c>IAeadCipher</c> interface: random key + nonce, a caller-supplied
  /// AAD, an authenticated encrypt/decrypt roundtrip, and a tamper check
  /// (a modified ciphertext must be rejected on decrypt). Every cipher is
  /// driven incrementally (chunked <c>ProcessBytes</c> + <c>DoFinal</c>);
  /// CCM and GCM-SIV buffer internally and emit all output at
  /// <c>DoFinal</c>, which this driver handles by sizing via
  /// <c>GetOutputSize</c>.
  /// </summary>
  TAeadCipherExampleUtilities = class sealed
  strict private
    class function ProcessIncrementally(const ACipher: IAeadCipher;
      const AInput: TBytes): TBytes; static;
  public
    class function AeadRoundtrip(const ASpec: TAeadSpec; const APlain, AAad: TBytes;
      out ACipherTextLen: Int32; out ATamperRejected: Boolean): Boolean; static;
  end;

function NewAesGcm: IAeadCipher;
function NewAesCcm: IAeadCipher;
function NewAesEax: IAeadCipher;
function NewAesOcb: IAeadCipher;
function NewAesGcmSiv: IAeadCipher;
function NewChaChaPoly: IAeadCipher;
function NewXChaChaPoly: IAeadCipher;

implementation

function NewAesGcm: IAeadCipher;
begin
  Result := TGcmBlockCipher.Create(TAesUtilities.CreateEngine());
end;

function NewAesCcm: IAeadCipher;
begin
  Result := TCcmBlockCipher.Create(TAesUtilities.CreateEngine());
end;

function NewAesEax: IAeadCipher;
begin
  Result := TEaxBlockCipher.Create(TAesUtilities.CreateEngine());
end;

function NewAesOcb: IAeadCipher;
begin
  // OCB needs two block-cipher instances (one for hashing, one for the main path).
  Result := TOcbBlockCipher.Create(TAesUtilities.CreateEngine(), TAesUtilities.CreateEngine());
end;

function NewAesGcmSiv: IAeadCipher;
begin
  // Not reachable via TCipherUtilities.GetCipher - constructed directly. The
  // default constructor builds its own AES engine via TAesUtilities.CreateEngine.
  Result := TGcmSivBlockCipher.Create();
end;

function NewChaChaPoly: IAeadCipher;
begin
  Result := TChaCha20Poly1305.Create();
end;

function NewXChaChaPoly: IAeadCipher;
begin
  Result := TXChaCha20Poly1305.Create();
end;

{ TAeadCipherExampleUtilities }

class function TAeadCipherExampleUtilities.ProcessIncrementally(
  const ACipher: IAeadCipher; const AInput: TBytes): TBytes;
const
  BufferSize = 1024;
var
  LInOff, LOutOff, LChunk, LCount, LInputLen: Int32;
begin
  LInputLen := System.Length(AInput);
  System.SetLength(Result, ACipher.GetOutputSize(LInputLen));
  LInOff := 0;
  LOutOff := 0;
  while LInOff < LInputLen do
  begin
    LChunk := Min(BufferSize, LInputLen - LInOff);
    LCount := ACipher.ProcessBytes(AInput, LInOff, LChunk, Result, LOutOff);
    System.Inc(LOutOff, LCount);
    System.Inc(LInOff, LChunk);
  end;
  LCount := ACipher.DoFinal(Result, LOutOff);
  System.Inc(LOutOff, LCount);
  System.SetLength(Result, LOutOff);
end;

class function TAeadCipherExampleUtilities.AeadRoundtrip(const ASpec: TAeadSpec;
  const APlain, AAad: TBytes; out ACipherTextLen: Int32;
  out ATamperRejected: Boolean): Boolean;
var
  LKey, LNonce, LCipherText, LDecrypted, LTampered: TBytes;
  LSecureRandom: ISecureRandom;
  LParams: IAeadParameters;
  LCipher: IAeadCipher;
begin
  ACipherTextLen := 0;
  ATamperRejected := False;

  LSecureRandom := TSecureRandom.Create();
  System.SetLength(LKey, ASpec.KeyByteCount);
  System.SetLength(LNonce, ASpec.NonceByteCount);
  LSecureRandom.NextBytes(LKey);
  LSecureRandom.NextBytes(LNonce);
  // AMacSize is in BITS; AAad binds associated data into the tag.
  LParams := TAeadParameters.Create(TKeyParameter.Create(LKey) as IKeyParameter,
    ASpec.TagBitLength, LNonce, AAad);

  // Encrypt: ciphertext carries the appended authentication tag.
  LCipher := ASpec.NewCipher();
  LCipher.Init(True, LParams as ICipherParameters);
  LCipherText := ProcessIncrementally(LCipher, APlain);
  ACipherTextLen := System.Length(LCipherText);

  // Decrypt: DoFinal verifies the tag and recovers the plaintext.
  LCipher := ASpec.NewCipher();
  LCipher.Init(False, LParams as ICipherParameters);
  LDecrypted := ProcessIncrementally(LCipher, LCipherText);
  Result := TArrayUtilities.AreEqual(APlain, LDecrypted);

  // Tamper: flip one ciphertext byte; authentication must reject it.
  LTampered := System.Copy(LCipherText, 0, System.Length(LCipherText));
  if System.Length(LTampered) > 0 then
  begin
    LTampered[0] := LTampered[0] xor $01;
    try
      LCipher := ASpec.NewCipher();
      LCipher.Init(False, LParams as ICipherParameters);
      ProcessIncrementally(LCipher, LTampered);
      ATamperRejected := False; // decrypt succeeded - tamper NOT caught
    except
      on E: Exception do
        ATamperRejected := True; // modified ciphertext rejected, as required
    end;
  end;
end;

end.
