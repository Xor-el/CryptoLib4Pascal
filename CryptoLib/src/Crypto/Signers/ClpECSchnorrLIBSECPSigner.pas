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

unit ClpECSchnorrLIBSECPSigner;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIECInterface,
  ClpIECPrivateKeyParameters,
  ClpIECPublicKeyParameters,
  ClpISchnorr,
  ClpIECSchnorrLIBSECPSigner,
  ClpIDigest,
  ClpBits,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  TECSchnorrLIBSECPSigner = class sealed(TInterfacedObject, ISchnorr,
    IECSchnorrLIBSECPSigner)

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

{ TECSchnorrLIBSECPSigner }

function TECSchnorrLIBSECPSigner.Do_Sign(const &message: TCryptoLibByteArray;
  const digest: IDigest; const pv_key: IECPrivateKeyParameters;
  const k: TBigInteger): TCryptoLibByteArray;
var
  curve: IECCurve;
  n, r, s, h, tempK: TBigInteger;
  G, q: IECPoint;
  rQ, tempH: TCryptoLibByteArray;
begin

  curve := pv_key.parameters.curve;
  n := curve.order;
  G := pv_key.parameters.G;

  q := G.Multiply(k);

  tempK := k;
  if q.Normalize.YCoord.ToBigInteger.&And(TBigInteger.One)
    .CompareTo(TBigInteger.One) = 0 then // if Q.y is Odd
  begin
    tempK := n.Subtract(tempK);
    q := G.Multiply(tempK);
  end;

  rQ := q.Normalize.XCoord.ToBigInteger.&Mod(n).ToByteArray;
  digest.TransformBytes(rQ);
  digest.TransformBytes(&message);
  tempH := digest.TransformFinal.GetBytes();

  h := TBigInteger.Create(1, tempH);
  r := q.Normalize.XCoord.ToBigInteger.&Mod(n);
  s := (tempK.Subtract(h.Multiply(pv_key.D))).&Mod(n);

  Result := TECSchnorrSigner.Encode_Sig(r, s);
  Exit;

end;

function TECSchnorrLIBSECPSigner.Do_Verify(const &message: TCryptoLibByteArray;
  const digest: IDigest; const pu_key: IECPublicKeyParameters;
  const sig: TCryptoLibByteArray): Boolean;
var
  curve: IECCurve;
  n, r, s, h, v: TBigInteger;
  Size: Int32;
  G, sG, hW, LR: IECPoint;
  tempH, rb: TCryptoLibByteArray;
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

  rb := r.ToByteArray;

  digest.TransformBytes(rb);
  digest.TransformBytes(&message);
  tempH := digest.TransformFinal.GetBytes();

  h := TBigInteger.Create(1, tempH);
  if (h.CompareTo(TBigInteger.Zero) = 0) or (h.CompareTo(n) = 1) then
  begin
    Result := False;
    Exit;
  end;

  hW := pu_key.q.Multiply(h);
  LR := sG.Add(hW);
  v := LR.Normalize.XCoord.ToBigInteger.&Mod(n);

  Result := v.Equals(r);
  Exit;

end;

function TECSchnorrLIBSECPSigner.GetAlgorithmName: String;
begin
  Result := 'LIBSECP';
end;

end.
