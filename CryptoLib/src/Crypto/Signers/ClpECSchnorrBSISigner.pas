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

unit ClpECSchnorrBSISigner;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIECInterface,
  ClpIECPrivateKeyParameters,
  ClpIECPublicKeyParameters,
  ClpISchnorr,
  ClpIECSchnorrBSISigner,
  ClpIDigest,
  ClpBits,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  TECSchnorrBSISigner = class sealed(TInterfacedObject, ISchnorr,
    IECSchnorrBSISigner)

  public
    function GetAlgorithmName: String; inline;
    property AlgorithmName: String read GetAlgorithmName;

    function Do_Sign(const &message: TCryptoLibByteArray; const digest: IDigest;
      const pv_key: IECPrivateKeyParameters; const k: TBigInteger)
      : TCryptoLibByteArray;

    function Do_Verify(const &message: TCryptoLibByteArray;
      const digest: IDigest; const pu_key: IECPublicKeyParameters;
      const sig: TCryptoLibByteArray): Boolean;

  end;

implementation

uses
  // included here to avoid circular dependency :)
  ClpECSchnorrSigner;

{ TECSchnorrBSISigner }

function TECSchnorrBSISigner.Do_Sign(const &message: TCryptoLibByteArray;
  const digest: IDigest; const pv_key: IECPrivateKeyParameters;
  const k: TBigInteger): TCryptoLibByteArray;
var
  curve: IECCurve;
  n, r, s: TBigInteger;
  G, q: IECPoint;
  xQ, tempR: TCryptoLibByteArray;
begin

  curve := pv_key.parameters.curve;
  n := curve.order;
  G := pv_key.parameters.G;

  q := G.Multiply(k);

  xQ := q.Normalize.XCoord.ToBigInteger.ToByteArray;

  System.SetLength(tempR, digest.GetDigestSize);
  digest.BlockUpdate(&message, 0, System.Length(&message));
  digest.BlockUpdate(xQ, 0, System.Length(xQ));
  digest.DoFinal(tempR, 0);

  r := TBigInteger.Create(1, tempR);
  s := (k.Subtract(r.Multiply(pv_key.D))).&Mod(n);
  if (r.CompareTo(TBigInteger.Zero) = 0) or (s.CompareTo(TBigInteger.Zero) = 0)
  then
  begin
    Result := Nil;
    Exit;
  end
  else
  begin
    Result := TECSchnorrSigner.Encode_Sig(r, s);
    Exit;
  end;
end;

function TECSchnorrBSISigner.Do_Verify(const &message: TCryptoLibByteArray;
  const digest: IDigest; const pu_key: IECPublicKeyParameters;
  const sig: TCryptoLibByteArray): Boolean;
var
  curve: IECCurve;
  n, r, s, v: TBigInteger;
  Size: Int32;
  G, q, sG, rW: IECPoint;
  xQ, tempV: TCryptoLibByteArray;
  R_and_S: TCryptoLibGenericArray<TBigInteger>;
begin

  curve := pu_key.parameters.curve;
  n := curve.order;
  G := pu_key.parameters.G;
  Size := TBits.Asr32(curve.FieldSize, 3);

  R_and_S := TECSchnorrSigner.Decode_Sig(sig);

  r := R_and_S[0];
  s := R_and_S[1];

  if (not(r.IsInitialized) or (r.CompareTo(TBigInteger.Two.Pow(Size * 8)
    .Subtract(TBigInteger.One)) = 1) or (s.CompareTo(TBigInteger.Zero) = 0) or
    (s.CompareTo(n.Subtract(TBigInteger.One)) = 1)) then
  begin
    Result := False;
    Exit;
  end;

  sG := G.Multiply(s);

  rW := pu_key.q.Multiply(r);
  q := sG.Add(rW);
  xQ := q.Normalize.XCoord.ToBigInteger.ToByteArray;

  System.SetLength(tempV, digest.GetDigestSize);
  digest.BlockUpdate(&message, 0, System.Length(&message));
  digest.BlockUpdate(xQ, 0, System.Length(xQ));
  digest.DoFinal(tempV, 0);

  v := TBigInteger.Create(1, tempV);
  Result := v.Equals(r);
  Exit;

end;

function TECSchnorrBSISigner.GetAlgorithmName: String;
begin
  Result := 'BSI';
end;

end.
