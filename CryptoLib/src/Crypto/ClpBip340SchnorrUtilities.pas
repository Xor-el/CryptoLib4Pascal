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

unit ClpBip340SchnorrUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpIECCommon,
  ClpIECFieldElement,
  ClpIECParameters,
  ClpIDigest,
  ClpECUtilities,
  ClpECAlgorithms,
  ClpByteUtilities,
  ClpDigestUtilities,
  ClpBigIntegerUtilities,
  ClpCryptoLibTypes;

type
  TBip340SchnorrUtilities = class sealed(TObject)
  public
    const
    BIP340_PUBKEY_SIZE = 32;
    BIP340_SIG_SIZE = 64;
    BIP340_SECKEY_SIZE = 32;

    class function TaggedHash(const ATag, AMsg: TCryptoLibByteArray): TCryptoLibByteArray; static;
    class function LiftX(const ADomain: IECDomainParameters; const AXBytes: TCryptoLibByteArray): IECPoint; static;
    class function HasEvenY(const AP: IECPoint): Boolean; static;
    class function BytesFromPoint(const AP: IECPoint): TCryptoLibByteArray; static;
    class procedure XorBytes(const AA: TCryptoLibByteArray; AOffA: Int32;
      const AB: TCryptoLibByteArray; AOffB: Int32; var AOut: TCryptoLibByteArray;
      AOutOff: Int32; ALen: Int32); static;
  end;

implementation

{ TBip340SchnorrUtilities }

class function TBip340SchnorrUtilities.TaggedHash(const ATag,
  AMsg: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LDigest: IDigest;
  LTagHash: TCryptoLibByteArray;
  LTagLen: Int32;
begin
  LDigest := TDigestUtilities.GetDigest('SHA-256');
  LDigest.BlockUpdate(ATag, 0, System.Length(ATag));
  System.SetLength(LTagHash, LDigest.GetDigestSize());
  LDigest.DoFinal(LTagHash, 0);
  LTagLen := System.Length(LTagHash);
  LDigest.Reset();
  LDigest.BlockUpdate(LTagHash, 0, LTagLen);
  LDigest.BlockUpdate(LTagHash, 0, LTagLen);
  if (AMsg <> nil) and (System.Length(AMsg) > 0) then
    LDigest.BlockUpdate(AMsg, 0, System.Length(AMsg));
  System.SetLength(Result, LDigest.GetDigestSize());
  LDigest.DoFinal(Result, 0);
end;

class function TBip340SchnorrUtilities.LiftX(const ADomain: IECDomainParameters;
  const AXBytes: TCryptoLibByteArray): IECPoint;
var
  LCurve: IECCurve;
  LX: TBigInteger;
  LC: IECFieldElement;
  LY: IECFieldElement;
  LP: IECPoint;
begin
  if (System.Length(AXBytes) <> BIP340_PUBKEY_SIZE) then
    raise EArgumentCryptoLibException.Create('LiftX: x must be 32 bytes');
  LCurve := ADomain.Curve;
  LX := TBigInteger.Create(1, AXBytes);
  if (LX.CompareTo(LCurve.Field.Characteristic) >= 0) then
    raise EArgumentCryptoLibException.Create('LiftX: x >= p');
  LC := LCurve.FromBigInteger(LX).Square().Multiply(LCurve.FromBigInteger(LX))
    .Add(LCurve.FromBigInteger(TBigInteger.ValueOf(7)));
  LY := LC.Sqrt();
  if (LY = nil) then
    raise EArgumentCryptoLibException.Create('LiftX: no square root');
  LP := LCurve.CreateRawPoint(LCurve.FromBigInteger(LX), LY);
  if (not HasEvenY(LP)) then
    LP := LP.Negate();
  Result := TECAlgorithms.ValidatePoint(LP);
end;

class function TBip340SchnorrUtilities.HasEvenY(const AP: IECPoint): Boolean;
var
  LY: TBigInteger;
begin
  if (AP = nil) or (AP.IsInfinity) then
    raise EArgumentCryptoLibException.Create('HasEvenY: invalid point');
  LY := AP.Normalize().AffineYCoord.ToBigInteger();
  Result := LY.&And(TBigInteger.One).CompareTo(TBigInteger.Zero) = 0;
end;

class function TBip340SchnorrUtilities.BytesFromPoint(const AP: IECPoint): TCryptoLibByteArray;
var
  LX: TBigInteger;
begin
  if (AP = nil) or (AP.IsInfinity) then
    raise EArgumentCryptoLibException.Create('BytesFromPoint: invalid point');
  LX := AP.Normalize().AffineXCoord.ToBigInteger();
  Result := TBigIntegerUtilities.AsUnsignedByteArray(BIP340_PUBKEY_SIZE, LX);
end;

class procedure TBip340SchnorrUtilities.XorBytes(const AA: TCryptoLibByteArray;
  AOffA: Int32; const AB: TCryptoLibByteArray; AOffB: Int32;
  var AOut: TCryptoLibByteArray; AOutOff: Int32; ALen: Int32);
begin
  TByteUtilities.&Xor(ALen, AA, AOffA, AB, AOffB, AOut, AOutOff);
end;

end.
