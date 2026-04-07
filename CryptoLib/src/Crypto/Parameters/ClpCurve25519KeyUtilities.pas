{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpCurve25519KeyUtilities;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpDigestUtilities,
  ClpX25519,
  ClpX25519Field,
  ClpX25519Parameters,
  ClpIEd25519Parameters,
  ClpIX25519Parameters,
  ClpCryptoLibTypes;

resourcestring
  SCurve25519Ed25519PublicKeyNil = 'Ed25519 public key cannot be nil';
  SCurve25519Ed25519PrivateKeyNil = 'Ed25519 private key cannot be nil';
  SCurve25519Ed25519PublicKeyInvalid = 'Ed25519 public key is invalid or point is not on the curve';

type
  /// <summary>
  /// Curve25519 key utilities (Ed25519 / X25519 conversion and related helpers).
  /// </summary>
  TCurve25519KeyUtilities = class sealed(TObject)
  private
    const
      /// <summary>Size in bytes of Ed25519/X25519 public and private key material.</summary>
      KeySizeBytes = 32;
  public
    /// <summary>
    /// Convert an Ed25519 public key to its X25519 equivalent.
    /// </summary>
    /// <remarks>
    /// Curve25519 exists in two forms: Montgomery (X25519) and twisted Edwards (Ed25519), with a birational map between them.
    /// The Montgomery u-coordinate is u = (1+y)/(1-y) where y is the Edwards y. This implementation decodes the Ed25519
    /// public key bytes (full 32-byte decode, same as TEd25519.DecodePointVar) to get the internal y-value V, computes
    /// u = (1+V)/(1-V) in the field, then normalizes u before encoding so the result matches X25519.ScalarMultBase output.
    /// Normalization is required for a canonical 32-byte encoding; without it the same point can encode differently and break
    /// consistency with the public key derived from the converted private key.
    /// </remarks>
    /// <param name="AEd25519PublicKey">The Ed25519 public key to convert.</param>
    /// <returns>The X25519 public key (32-byte u-coordinate) for the same curve point.</returns>
    class function ToX25519PublicKey(const AEd25519PublicKey: IEd25519PublicKeyParameters): IX25519PublicKeyParameters; static;
    /// <summary>
    /// Convert an Ed25519 private key to its X25519 equivalent.
    /// </summary>
    /// <remarks>
    /// Ed25519 and X25519 use the same scalar on Curve25519: Ed25519 derives it as the first 32 bytes of SHA-512(seed)
    /// then applies the same clamping as X25519 (PruneScalar in Ed25519 matches ClampPrivateKey in X25519). This method
    /// therefore hashes the Ed25519 seed with SHA-512, takes the first 32 bytes, clamps them with TX25519.ClampPrivateKey,
    /// and returns an X25519 private key. The resulting scalar is the same as used for the Ed25519 public key, so the
    /// converted X25519 public (from this private via ScalarMultBase) matches the converted Ed25519 public (via ToX25519PublicKey).
    /// Clamping is done in this utility; TX25519PrivateKeyParameters does not clamp internally.
    /// </remarks>
    /// <param name="AEd25519PrivateKey">The Ed25519 private key (32-byte seed).</param>
    /// <returns>The X25519 private key (32-byte clamped scalar) for the same scalar.</returns>
    class function ToX25519PrivateKey(const AEd25519PrivateKey: IEd25519PrivateKeyParameters): IX25519PrivateKeyParameters; static;
  end;

implementation

{ TCurve25519KeyUtilities }

class function TCurve25519KeyUtilities.ToX25519PrivateKey(const AEd25519PrivateKey: IEd25519PrivateKeyParameters): IX25519PrivateKeyParameters;
var
  LSeed, LHash, LScalar: TCryptoLibByteArray;
begin
  if AEd25519PrivateKey = nil then
    raise EArgumentNilCryptoLibException.Create(SCurve25519Ed25519PrivateKeyNil);
  LSeed := AEd25519PrivateKey.GetEncoded();
  LHash := TDigestUtilities.CalculateDigest('SHA-512', LSeed);
  System.SetLength(LScalar, KeySizeBytes);
  System.Move(LHash[0], LScalar[0], KeySizeBytes);
  TX25519.ClampPrivateKey(LScalar);
  Result := TX25519PrivateKeyParameters.Create(LScalar);
end;

class function TCurve25519KeyUtilities.ToX25519PublicKey(const AEd25519PublicKey: IEd25519PublicKeyParameters): IX25519PublicKeyParameters;
var
  LPk, LEncoded: TCryptoLibByteArray;
  LY, LOne, LOneMinusY, LOnePlusY, LInv, LU: TCryptoLibInt32Array;
begin
  if AEd25519PublicKey = nil then
    raise EArgumentNilCryptoLibException.Create(SCurve25519Ed25519PublicKeyNil);
  LPk := AEd25519PublicKey.GetEncoded();
  LY := TX25519Field.Create();
  TX25519Field.Decode255(LPk, LY);
  LOne := TX25519Field.Create();
  TX25519Field.One(LOne);
  LOneMinusY := TX25519Field.Create();
  TX25519Field.Sub(LOne, LY, LOneMinusY);
  if TX25519Field.IsZeroVar(LOneMinusY) then
    raise EArgumentCryptoLibException.Create(SCurve25519Ed25519PublicKeyInvalid);
  LOnePlusY := TX25519Field.Create();
  TX25519Field.Add(LOne, LY, LOnePlusY);
  LInv := TX25519Field.Create();
  TX25519Field.Inv(LOneMinusY, LInv);
  LU := TX25519Field.Create();
  TX25519Field.Mul(LOnePlusY, LInv, LU);
  TX25519Field.Normalize(LU);
  System.SetLength(LEncoded, KeySizeBytes);
  TX25519Field.Encode(LU, LEncoded);
  Result := TX25519PublicKeyParameters.Create(LEncoded);
end;

end.
