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

unit ClpBip327MuSig2Utilities;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpIECCommon,
  ClpIECParameters,
  ClpBip340SchnorrUtilities,
  ClpECUtilities,
  ClpECAlgorithms,
  ClpBigIntegerUtilities,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Raised when a signer or the nonce aggregator sends an invalid contribution.
  /// FSignerIndex is the 0-based signer index, or -1 for aggregator (e.g. invalid aggnonce).
  /// FContribution is one of 'pubkey', 'pubnonce', 'aggnonce', 'psig'.
  /// </summary>
  EBip327InvalidContributionException = class(ECryptoLibException)
  strict private
    var
      FSignerIndex: Int32;
      FContribution: string;
  public
    constructor Create(const AMessage: string; ASignerIndex: Int32;
      const AContribution: string);
    property SignerIndex: Int32 read FSignerIndex;
    property Contribution: string read FContribution;
  end;

  TBip327MuSig2Utilities = class sealed(TObject)
  public
    const
      BIP327_PLAIN_PUBKEY_SIZE = 33;
      BIP327_PUBNONCE_SIZE = 66;
      BIP327_SECNONCE_SIZE = 97;
      BIP327_PSIG_SIZE = 32;
      /// <summary>Tag for BIP-327 KeyAgg list (UTF-8).</summary>
      KEYAGG_LIST_TAG_STR = 'KeyAgg list';
      /// <summary>Tag for BIP-327 KeyAgg coefficient (UTF-8).</summary>
      KEYAGG_COEFFICIENT_TAG_STR = 'KeyAgg coefficient';
      /// <summary>Tag for MuSig/aux (UTF-8).</summary>
      MUSIG_AUX_TAG_STR = 'MuSig/aux';
      /// <summary>Tag for MuSig/nonce (UTF-8).</summary>
      MUSIG_NONCE_TAG_STR = 'MuSig/nonce';
      /// <summary>Tag for MuSig/noncecoef (UTF-8).</summary>
      MUSIG_NONCECOEFF_TAG_STR = 'MuSig/noncecoef';
      /// <summary>Tag for MuSig/deterministic/nonce (UTF-8).</summary>
      MUSIG_DETERMINISTIC_NONCE_TAG_STR = 'MuSig/deterministic/nonce';

    /// <summary>33-byte compressed encoding of point P. Fails if P is infinity.</summary>
    class function CBytes(const ADomain: IECDomainParameters;
      const AP: IECPoint): TCryptoLibByteArray; static;
    /// <summary>33 zero bytes if P is infinity, else CBytes(ADomain, P).</summary>
    class function CBytesExt(const ADomain: IECDomainParameters;
      const AP: IECPoint): TCryptoLibByteArray; static;
    /// <summary>Decode 33-byte compressed point. Raises on invalid encoding.</summary>
    class function CPoint(const ADomain: IECDomainParameters;
      const ABytes: TCryptoLibByteArray): IECPoint; overload; static;
    /// <summary>Decode with optional signer index for blame.</summary>
    class function CPoint(const ADomain: IECDomainParameters;
      const ABytes: TCryptoLibByteArray; ASignerIndex: Int32): IECPoint; overload; static;
    /// <summary>33 zero bytes returns curve infinity; else CPoint.</summary>
    class function CPointExt(const ADomain: IECDomainParameters;
      const ABytes: TCryptoLibByteArray): IECPoint; static;
    /// <summary>Individual public key (33-byte compressed) from 32-byte secret key.</summary>
    class function IndividualPubKey(const ADomain: IECDomainParameters;
      const ASk: TCryptoLibByteArray): TCryptoLibByteArray; static;
  end;

implementation

{ EBip327InvalidContributionException }

constructor EBip327InvalidContributionException.Create(const AMessage: string;
  ASignerIndex: Int32; const AContribution: string);
begin
  inherited Create(AMessage);
  FSignerIndex := ASignerIndex;
  FContribution := AContribution;
end;

{ TBip327MuSig2Utilities }

class function TBip327MuSig2Utilities.CBytes(const ADomain: IECDomainParameters;
  const AP: IECPoint): TCryptoLibByteArray;
begin
  if (AP = nil) or (AP.IsInfinity) then
    raise EArgumentCryptoLibException.Create('CBytes: point must not be infinity');
  Result := AP.GetEncoded(True);
  if System.Length(Result) <> BIP327_PLAIN_PUBKEY_SIZE then
    raise EArgumentCryptoLibException.Create('CBytes: invalid encoded length');
end;

class function TBip327MuSig2Utilities.CBytesExt(const ADomain: IECDomainParameters;
  const AP: IECPoint): TCryptoLibByteArray;
var
  LI: Int32;
begin
  if (AP = nil) or (AP.IsInfinity) then
  begin
    System.SetLength(Result, BIP327_PLAIN_PUBKEY_SIZE);
    for LI := 0 to System.Length(Result) - 1 do
      Result[LI] := 0;
    Exit;
  end;
  Result := CBytes(ADomain, AP);
end;

class function TBip327MuSig2Utilities.CPoint(const ADomain: IECDomainParameters;
  const ABytes: TCryptoLibByteArray): IECPoint;
begin
  Result := CPoint(ADomain, ABytes, -1);
end;

class function TBip327MuSig2Utilities.CPoint(const ADomain: IECDomainParameters;
  const ABytes: TCryptoLibByteArray; ASignerIndex: Int32): IECPoint;
var
  LCurve: IECCurve;
begin
  if (ABytes = nil) or (System.Length(ABytes) <> BIP327_PLAIN_PUBKEY_SIZE) then
    raise EBip327InvalidContributionException.Create(
      'CPoint: invalid length (expected 33)', ASignerIndex, 'pubkey');
  LCurve := ADomain.Curve;
  try
    Result := LCurve.DecodePoint(ABytes);
  except
    on E: Exception do
      raise EBip327InvalidContributionException.Create(
        'CPoint: ' + E.Message, ASignerIndex, 'pubkey');
  end;
end;

class function TBip327MuSig2Utilities.CPointExt(const ADomain: IECDomainParameters;
  const ABytes: TCryptoLibByteArray): IECPoint;
var
  LCurve: IECCurve;
  LAllZero: Boolean;
  LI: Int32;
begin
  if (ABytes = nil) or (System.Length(ABytes) <> BIP327_PLAIN_PUBKEY_SIZE) then
    raise EArgumentCryptoLibException.Create('CPointExt: invalid length (expected 33)');
  LAllZero := True;
  for LI := 0 to System.Length(ABytes) - 1 do
    if ABytes[LI] <> 0 then
    begin
      LAllZero := False;
      Break;
    end;
  if LAllZero then
  begin
    LCurve := ADomain.Curve;
    Result := LCurve.GetInfinity;
    Exit;
  end;
  Result := CPoint(ADomain, ABytes);
end;

class function TBip327MuSig2Utilities.IndividualPubKey(const ADomain: IECDomainParameters;
  const ASk: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LN: TBigInteger;
  LD: TBigInteger;
  LP: IECPoint;
begin
  if (ASk = nil) or (System.Length(ASk) <> TBip340SchnorrUtilities.BIP340_SECKEY_SIZE) then
    raise EArgumentCryptoLibException.Create('IndividualPubkey: sk must be 32 bytes');
  LN := ADomain.N;
  LD := TBigInteger.Create(1, ASk).&Mod(LN);
  if (LD.SignValue = 0) or (LD.CompareTo(LN) >= 0) then
    raise EArgumentCryptoLibException.Create('IndividualPubkey: invalid secret key');
  LP := TECAlgorithms.ReferenceMultiply(ADomain.G, LD).Normalize();
  Result := CBytes(ADomain, LP);
end;

end.
