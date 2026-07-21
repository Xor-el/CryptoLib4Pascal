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

unit ClpPkixCrlUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIStore,
  ClpIPkixTypes,
  ClpIX509StoreSelectors,
  ClpIX509Certificate,
  ClpIX509Crl,
  ClpNullable,
  ClpCryptoLibTypes;

resourcestring
  SCrlStoreSearchFailed = 'exception searching the X.509 CRL store: %s';

type
  /// <summary>
  /// Collects the CRLs relevant to a certificate from the configured CRL stores.
  /// </summary>
  TPkixCrlUtilities = class sealed(TObject)

  strict private
    class function Contains(const AArray: TCryptoLibGenericArray<IX509Crl>; const ACrl: IX509Crl): Boolean; static;

  public
    /// <summary>Every CRL in the parameters' stores matched by ASelector.</summary>
    class function FindCrls(const ASelector: ISelector<IX509Crl>;
      const APkixParams: IPkixParameters): TCryptoLibGenericArray<IX509Crl>; overload; static;
    /// <summary>
    /// As above, then narrowed per RFC 5280 6.3.3 to CRLs still current at the validity date and
    /// issued before the checked certificate expires.
    /// </summary>
    class function FindCrls(const ASelector: ISelector<IX509Crl>; const APkixParams: IPkixParameters;
      AValidityDate: TDateTime): TCryptoLibGenericArray<IX509Crl>; overload; static;
  end;

implementation

{ TPkixCrlUtilities }

class function TPkixCrlUtilities.Contains(const AArray: TCryptoLibGenericArray<IX509Crl>;
  const ACrl: IX509Crl): Boolean;
var
  LIdx: Int32;
begin
  for LIdx := 0 to System.High(AArray) do
  begin
    if AArray[LIdx].Equals(ACrl) then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := False;
end;

class function TPkixCrlUtilities.FindCrls(const ASelector: ISelector<IX509Crl>;
  const APkixParams: IPkixParameters): TCryptoLibGenericArray<IX509Crl>;
var
  LStores: TCryptoLibGenericArray<IStore<IX509Crl>>;
  LMatches: TCryptoLibGenericArray<IX509Crl>;
  LOuter, LInner, LCount: Int32;
  LFoundValidStore: Boolean;
  LLastError: String;
begin
  LStores := APkixParams.GetStoresCrl();
  LFoundValidStore := False;
  LLastError := '';

  Result := nil;
  LCount := 0;
  for LOuter := 0 to System.High(LStores) do
  begin
    try
      LMatches := LStores[LOuter].EnumerateMatches(ASelector);
      for LInner := 0 to System.High(LMatches) do
      begin
        if not Contains(Result, LMatches[LInner]) then
        begin
          System.SetLength(Result, LCount + 1);
          Result[LCount] := LMatches[LInner];
          System.Inc(LCount);
        end;
      end;
      LFoundValidStore := True;
    except
      on E: Exception do
        LLastError := E.Message;
    end;
  end;

  // one usable store is enough; only a total failure is reported
  if (not LFoundValidStore) and (LLastError <> '') then
    raise ECrlCryptoLibException.CreateResFmt(@SCrlStoreSearchFailed, [LLastError]);
end;

class function TPkixCrlUtilities.FindCrls(const ASelector: ISelector<IX509Crl>;
  const APkixParams: IPkixParameters; AValidityDate: TDateTime): TCryptoLibGenericArray<IX509Crl>;
var
  LInitial: TCryptoLibGenericArray<IX509Crl>;
  LIdx, LCount: Int32;
  LCrl: IX509Crl;
  LNextUpdate: TNullable<TDateTime>;
  LCert: IX509Certificate;
  LCrlSelector: IX509CrlStoreSelector;
begin
  LCert := nil;
  if Supports(ASelector, IX509CrlStoreSelector, LCrlSelector) then
    LCert := LCrlSelector.CertificateChecking;

  LInitial := FindCrls(ASelector, APkixParams);

  System.SetLength(Result, System.Length(LInitial));
  LCount := 0;

  // RFC 5280 6.3.3: keep CRLs that have not lapsed, and that predate the checked
  // certificate's expiry
  for LIdx := 0 to System.High(LInitial) do
  begin
    LCrl := LInitial[LIdx];
    LNextUpdate := LCrl.NextUpdate;

    if (not LNextUpdate.HasValue) or (LNextUpdate.Value > AValidityDate) then
    begin
      if (LCert = nil) or (LCrl.ThisUpdate < LCert.NotAfter) then
      begin
        Result[LCount] := LCrl;
        System.Inc(LCount);
      end;
    end;
  end;

  System.SetLength(Result, LCount);
end;

end.
