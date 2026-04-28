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
  ClpPkcs12Store,
  ClpX509Asn1Objects,
  ClpCryptoLibTypes;

resourcestring
  SErrorConstructingMac = 'error constructing MAC: %s';

type
  /// <summary>
  /// Utility class for re-encoding PKCS#12 files to definite length.
  /// </summary>
  TPkcs12Utilities = class sealed(TObject)
  strict private
    class function DLEncode(const AAsn1Encodable: IAsn1Encodable): TCryptoLibByteArray; static;
  public
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

{ TPkcs12Utilities }

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
  LContent: IAsn1OctetString;
  LContentOctets: TCryptoLibByteArray;
  LObj: IAsn1Object;
  LContentNew: IAsn1OctetString;
  LInfoNew: IPkcsContentInfo;
  LMacData: IMacData;
  LMacDigestAlgorithm: IAlgorithmIdentifier;
  LSalt: TCryptoLibByteArray;
  LMacResult: TCryptoLibByteArray;
  LMac: IDigestInfo;
  LPfxNew: IPfx;
begin
  LPfx := TPfx.GetInstance(ABerPkcs12File);
  LInfo := LPfx.AuthSafe;
  LContent := TAsn1OctetString.GetInstance(LInfo.Content);
  LContentOctets := LContent.GetOctets();
  LObj := TAsn1Object.FromByteArray(LContentOctets);
  LContentOctets := DLEncode(LObj);
  LContentNew := TDerOctetString.Create(LContentOctets);
  LInfoNew := TPkcsContentInfo.Create(LInfo.ContentType, LContentNew);

  LMacData := LPfx.MacData;
  if LMacData <> nil then
  begin
    try
      LMacDigestAlgorithm := LMacData.Mac.DigestAlgorithm;
      LSalt := LMacData.MacSalt.GetOctets();
      LMacResult := TPkcs12Store.CalculatePbeMac(LMacDigestAlgorithm, LSalt,
        LMacData.Iterations.IntValueExact, APassword, False, LContentOctets);
      LMac := TDigestInfo.Create(LMacDigestAlgorithm, TDerOctetString.Create(LMacResult) as IDerOctetString);
      LMacData := TMacData.Create(LMac, LMacData.MacSalt, LMacData.Iterations);
    except
      on E: Exception do
        raise EIOCryptoLibException.Create(Format(SErrorConstructingMac, [E.Message]));
    end;
  end;

  LPfxNew := TPfx.Create(LInfoNew, LMacData);
  Result := DLEncode(LPfxNew);
end;

end.
