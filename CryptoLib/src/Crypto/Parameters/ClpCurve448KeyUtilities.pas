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

unit ClpCurve448KeyUtilities;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpDigestUtilities,
  ClpIXof,
  ClpX448,
  ClpX448Field,
  ClpX448Parameters,
  ClpIEd448Parameters,
  ClpIX448Parameters,
  ClpCryptoLibTypes;

resourcestring
  SCurve448Ed448PublicKeyNil = 'Ed448 public key cannot be nil';
  SCurve448Ed448PrivateKeyNil = 'Ed448 private key cannot be nil';
  SCurve448Ed448PublicKeyInvalid = 'Ed448 public key is invalid or point is not on the curve';

type
  /// <summary>
  /// Curve448 key utilities (Ed448 / X448 conversion and related helpers).
  /// </summary>
  TCurve448KeyUtilities = class sealed(TObject)
  private
    const
      /// <summary>Size in bytes of Ed448 public key and seed (57). Ed448 encodes the curve point as y (56 bytes) plus sign bit of x.</summary>
      Ed448KeySizeBytes = 57;
      /// <summary>Size in bytes of X448 public and private key material (56).</summary>
      X448KeySizeBytes = 56;
      /// <summary>
      /// Edwards curve parameter for edwards448 (Goldilocks). The curve is x² + y² = 1 + d·x²·y²; RFC 7748 Section 4.2
      /// (https://www.rfc-editor.org/rfc/rfc7748) defines edwards448 with d = -39081. This constant is the absolute
      /// value used in the denominator (1 + Ed448CurveParamD·y²) when recovering x² = (1−y²)/(1+d·y²) for the 4-isogeny u = y²/x².
      /// </summary>
      Ed448CurveParamD = UInt32(39081);
  public
    /// <summary>
    /// Convert an Ed448 public key to its X448 equivalent.
    /// </summary>
    /// <remarks>
    /// Curve448 exists in two forms: Montgomery (X448) and Edwards (Ed448 / Goldilocks), related by a 4-isogeny (RFC 7748,
    /// https://www.rfc-editor.org/rfc/rfc7748). The Montgomery u-coordinate is u = y²/x²; from the edwards448 curve equation
    /// x² + y² = 1 + d·x²·y² (with d = -39081 per RFC 7748), we have x² = (1−y²)/(1+d·y²), so u = y²·(1+d·y²)/(1−y²).
    /// Like Curve25519 (which uses u = (1+y)/(1−y) from y only), this implementation decodes the Ed448 public key bytes
    /// (first 56 bytes = y; the 57th byte holds only the sign bit of x) to the field element Y, validates that the point
    /// is on the curve using SqrtRatioVar (so that (1−y²)/(1+d·y²) is a square), then computes u = Y²·(1+d·Y²)/(1−Y²)
    /// in TX448Field, normalizes and encodes to 56 bytes so the result matches X448.ScalarMultBase output for the same scalar.
    /// Invalid keys or the degenerate case 1−y² = 0 raise an exception.
    /// </remarks>
    /// <param name="AEd448PublicKey">The Ed448 public key to convert.</param>
    /// <returns>The X448 public key (56-byte u-coordinate) for the same curve point.</returns>
    class function ToX448PublicKey(const AEd448PublicKey: IEd448PublicKeyParameters): IX448PublicKeyParameters; static;
    /// <summary>
    /// Convert an Ed448 private key to its X448 equivalent.
    /// </summary>
    /// <remarks>
    /// Ed448 and X448 use the same scalar on Curve448. Ed448 derives it by hashing the 57-byte seed with SHAKE256 to 114 bytes
    /// (RFC 8032, https://www.rfc-editor.org/rfc/rfc8032). X448 uses a 56-byte scalar with clamping (RFC 7748). This method
    /// hashes the Ed448 seed with SHAKE256, takes the first 56 bytes, and clamps them with TX448.ClampPrivateKey. The clamping
    /// operations are equivalent: Ed448 sets k[0] &amp;= 0xFC and k[55] |= 0x80 (plus k[56] = 0), while X448 clamping does the
    /// same for the 56-byte scalar. The resulting scalar matches the one used for the Ed448 public key, so the converted
    /// X448 public key (from this private via GeneratePublicKey) matches the converted Ed448 public key (via ToX448PublicKey).
    /// </remarks>
    /// <param name="AEd448PrivateKey">The Ed448 private key (57-byte seed).</param>
    /// <returns>The X448 private key (56-byte clamped scalar) for the same scalar.</returns>
    class function ToX448PrivateKey(const AEd448PrivateKey: IEd448PrivateKeyParameters): IX448PrivateKeyParameters; static;
  end;

implementation

{ TCurve448KeyUtilities }

class function TCurve448KeyUtilities.ToX448PrivateKey(const AEd448PrivateKey: IEd448PrivateKeyParameters): IX448PrivateKeyParameters;
var
  LSeed, LHash, LScalar: TCryptoLibByteArray;
  LXof: IXof;
begin
  if AEd448PrivateKey = nil then
    raise EArgumentNilCryptoLibException.Create(SCurve448Ed448PrivateKeyNil);
  LSeed := AEd448PrivateKey.GetEncoded();
  LXof := TDigestUtilities.GetDigest('SHAKE256-512') as IXof;
  System.SetLength(LHash, Ed448KeySizeBytes * 2);
  LXof.BlockUpdate(LSeed, 0, Ed448KeySizeBytes);
  LXof.OutputFinal(LHash, 0, System.Length(LHash));
  System.SetLength(LScalar, X448KeySizeBytes);
  System.Move(LHash[0], LScalar[0], X448KeySizeBytes);
  TX448.ClampPrivateKey(LScalar);
  Result := TX448PrivateKeyParameters.Create(LScalar);
end;

class function TCurve448KeyUtilities.ToX448PublicKey(const AEd448PublicKey: IEd448PublicKeyParameters): IX448PublicKeyParameters;
var
  LPk, LEncoded: TCryptoLibByteArray;
  LY, LU, LV, LY2, LInv, LDummy: TCryptoLibUInt32Array;
begin
  if AEd448PublicKey = nil then
    raise EArgumentNilCryptoLibException.Create(SCurve448Ed448PublicKeyNil);
  LPk := AEd448PublicKey.GetEncoded();
  LY := TX448Field.Create();
  TX448Field.Decode448(LPk, 0, LY);
  LU := TX448Field.Create();
  LV := TX448Field.Create();
  LY2 := TX448Field.Create();
  LInv := TX448Field.Create();
  LDummy := TX448Field.Create();
  TX448Field.Sqr(LY, LY2);
  TX448Field.Negate(LY2, LU);
  TX448Field.AddOne(LU);
  TX448Field.Mul(LY2, Ed448CurveParamD, LV);
  TX448Field.AddOne(LV);
  if not TX448Field.SqrtRatioVar(LU, LV, LDummy) then
    raise EArgumentCryptoLibException.Create(SCurve448Ed448PublicKeyInvalid);
  if TX448Field.IsZeroVar(LU) then
    raise EArgumentCryptoLibException.Create(SCurve448Ed448PublicKeyInvalid);
  TX448Field.Inv(LU, LInv);
  TX448Field.Mul(LY2, LInv, LU);
  TX448Field.Mul(LU, LV, LU);
  TX448Field.Normalize(LU);
  System.SetLength(LEncoded, X448KeySizeBytes);
  TX448Field.Encode(LU, LEncoded, 0);
  Result := TX448PublicKeyParameters.Create(LEncoded);
end;

end.
