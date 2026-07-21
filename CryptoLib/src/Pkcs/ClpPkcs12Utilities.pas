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

unit ClpPkcs12Utilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIPkcsAsn1Objects,
  ClpPkcsAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpCryptoLibConfig,
  ClpCryptoLibTypes;

resourcestring
  SErrorConstructingMac = 'error constructing MAC: %s';
  SContentInfoContentMissing = 'ContentInfo content missing';
  SEncryptedContentMissing = 'EncryptedContentInfo content missing';
  SNegativePkcs12IterationCount = 'negative iteration count found';
  SPkcs12IterationCountsOutOfRange = 'iteration counts >= 2^31 are not supported';
  SPkcs12IterationExceedsMax = 'iteration count %d greater than %d';
  SIterationsNil = 'iterations cannot be nil';

type
  /// <summary>
  /// Utility class for re-encoding PKCS#12 files to definite length.
  /// </summary>
  TPkcs12Utilities = class sealed(TObject)
  strict private
    class function DLEncode(const AAsn1Encodable: IAsn1Encodable): TCryptoLibByteArray; static;

  public
    class function ValidateIterations(AIterationCount: Int32): Int32; overload; static;
    class function ValidateIterations(const AIterations: IDerInteger): Int32; overload; static;
    class function GetContent(const AInfo: IPkcsContentInfo): IAsn1Encodable; static;
    class function GetContentOctets(const AInfo: IPkcsContentInfo): TCryptoLibByteArray; static;
    class function GetEncryptedContent(const AEncrypted: IPkcsEncryptedData): IAsn1OctetString; static;
    /// <summary>
    /// Re-encode the outer layer of the PKCS#12 file to definite length encoding.
    /// </summary>
    /// <param name="ABerPkcs12File">Original PKCS#12 file.</param>
    /// <returns>Byte array representing the DER encoding of the PFX structure.</returns>
    class function ConvertToDefiniteLength(const ABerPkcs12File: TCryptoLibByteArray): TCryptoLibByteArray; overload; static;
    /// <summary>
    /// Re-encode the PKCS#12 structure to definite length at the inner layer as well,
    /// recomputing the MAC accordingly.
    /// </summary>
    /// <param name="ABerPkcs12File">Original PKCS#12 file.</param>
    /// <param name="APassword">Password for MAC verification/recomputation.</param>
    /// <returns>Byte array representing the DER encoding of the PFX structure.</returns>
    class function ConvertToDefiniteLength(const ABerPkcs12File: TCryptoLibByteArray;
      const APassword: TCryptoLibCharArray): TCryptoLibByteArray; overload; static;
  end;

implementation

uses
  ClpPkcs12Store;

{ TPkcs12Utilities }

class function TPkcs12Utilities.ValidateIterations(AIterationCount: Int32): Int32;
var
  LMax: Int32;
begin
  if AIterationCount < 0 then
    raise EInvalidOperationCryptoLibException.CreateRes(@SNegativePkcs12IterationCount);
  LMax := TCryptoLibConfig.Pkcs12.MaxIterationCount;
  if AIterationCount > LMax then
    raise EInvalidOperationCryptoLibException.CreateResFmt(@SPkcs12IterationExceedsMax, [AIterationCount, LMax]);
  Result := AIterationCount;
end;

class function TPkcs12Utilities.ValidateIterations(const AIterations: IDerInteger): Int32;
var
  LInt: Int32;
begin
  if AIterations = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SIterationsNil);
  if not AIterations.TryGetIntValueExact(LInt) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SPkcs12IterationCountsOutOfRange);
  Result := ValidateIterations(LInt);
end;

class function TPkcs12Utilities.GetContent(const AInfo: IPkcsContentInfo): IAsn1Encodable;
begin
  Result := AInfo.Content;
  if Result = nil then
    raise EAsn1ParsingCryptoLibException.CreateRes(@SContentInfoContentMissing);
end;

class function TPkcs12Utilities.GetContentOctets(const AInfo: IPkcsContentInfo): TCryptoLibByteArray;
begin
  Result := TAsn1OctetString.GetInstance(GetContent(AInfo)).GetOctets();
end;

class function TPkcs12Utilities.GetEncryptedContent(const AEncrypted: IPkcsEncryptedData): IAsn1OctetString;
begin
  Result := AEncrypted.Content;
  if Result = nil then
    raise EAsn1ParsingCryptoLibException.CreateRes(@SEncryptedContentMissing);
end;

class function TPkcs12Utilities.DLEncode(const AAsn1Encodable: IAsn1Encodable): TCryptoLibByteArray;
begin
  Result := AAsn1Encodable.GetEncoded(TAsn1Encodable.DL);
end;

class function TPkcs12Utilities.ConvertToDefiniteLength(const ABerPkcs12File: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LPfx: IPfx;
begin
  LPfx := TPfx.GetInstance(ABerPkcs12File);
  Result := DLEncode(LPfx);
end;

class function TPkcs12Utilities.ConvertToDefiniteLength(const ABerPkcs12File: TCryptoLibByteArray;
  const APassword: TCryptoLibCharArray): TCryptoLibByteArray;
var
  LPfx: IPfx;
  LInfo: IPkcsContentInfo;
  LContentOctets: TCryptoLibByteArray;
  LObj: IAsn1Object;
  LContentNew: IAsn1OctetString;
  LInfoNew: IPkcsContentInfo;
  LMacData: IMacData;
  LMacAlgID: IAlgorithmIdentifier;
  LMacResult: TCryptoLibByteArray;
  LMac: IDigestInfo;
  LValidatedIt: Int32;
  LPfxNew: IPfx;
begin
  LPfx := TPfx.GetInstance(ABerPkcs12File);
  LInfo := LPfx.AuthSafe;
  LContentOctets := TPkcs12Utilities.GetContentOctets(LInfo);
  LObj := TAsn1Object.FromByteArray(LContentOctets);
  LContentOctets := DLEncode(LObj);
  LContentNew := TDerOctetString.FromContents(LContentOctets);
  LInfoNew := TPkcsContentInfo.Create(LInfo.ContentType, LContentNew);

  LMacData := LPfx.MacData;
  if LMacData <> nil then
  begin
    try
      LMacAlgID := LMacData.Mac.DigestAlgorithm;
      LValidatedIt := TPkcs12Utilities.ValidateIterations(LMacData.Iterations);
      LMacResult := TPkcs12Store.CalculatePbeMac(LMacAlgID, LMacData.MacSalt.GetOctets(),
        LValidatedIt, APassword, False, LContentOctets);
      LMac := TDigestInfo.Create(LMacAlgID, TDerOctetString.FromContents(LMacResult));
      LMacData := TMacData.Create(LMac, LMacData.MacSalt, LMacData.Iterations);
    except
      on E: Exception do
        raise EIOCryptoLibException.CreateResFmt(@SErrorConstructingMac, [E.Message]);
    end;
  end;

  LPfxNew := TPfx.Create(LInfoNew, LMacData);
  Result := DLEncode(LPfxNew);
end;

end.
