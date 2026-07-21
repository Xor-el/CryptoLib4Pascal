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

unit ClpX509DefaultEntryConverter;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpIX509NameEntryConverter,
  ClpX509NameEntryConverter,
  ClpX509Asn1Objects,
  ClpCryptoLibExceptions;

resourcestring
  SCannotRecodeValueForOid = 'cannot recode value for OID %s';
  SCountryCodeAttributeMustBeExactlyTwoChars = 'country code attribute %s must be exactly 2 characters per ISO 3166-1 / X.520, got %d: %s';
  SCommonNameAttributeExceedsMaxLength = 'commonName length %d exceeds RFC 5280 ub-common-name (64): %s';

type
  /// <summary>
  /// The default converter for X509 DN entries when going from their string value to ASN.1 strings.
  /// </summary>
  TX509DefaultEntryConverter = class(TX509NameEntryConverter, IX509NameEntryConverter)

  public
    /// <summary>
    /// Apply default conversion for the given value depending on the oid and the character range of the value.
    /// </summary>
    function GetConvertedValue(const AOid: IDerObjectIdentifier;
      const AValue: String): IAsn1Object; override;

  end;

implementation

{ TX509DefaultEntryConverter }

function TX509DefaultEntryConverter.GetConvertedValue(const AOid: IDerObjectIdentifier;
  const AValue: String): IAsn1Object;
var
  LValue: String;
begin
  if (System.Length(AValue) <> 0) and (AValue[1] = '#') then
  begin
    try
      Result := ConvertHexEncoded(AValue, 1);
      Exit;
    except
      on E: Exception do
        raise ECryptoLibException.CreateResFmt(@SCannotRecodeValueForOid, [AOid.Id]);
    end;
  end;

  LValue := AValue;
  if (System.Length(LValue) <> 0) and (LValue[1] = '\') then
  begin
    LValue := System.Copy(LValue, 2, System.Length(LValue) - 1);
  end;

  // EmailAddress and DC
  if AOid.Equals(TX509Name.EmailAddress) or AOid.Equals(TX509Name.DC) then
  begin
    Result := TDerIA5String.Create(LValue);
    Exit;
  end;

  // DateOfBirth: accept time string as well as # (for compatibility)
  if AOid.Equals(TX509Name.DateOfBirth) then
  begin
    Result := TAsn1GeneralizedTime.Create(LValue);
    Exit;
  end;

  // RFC 5280 sec. 4.1.2.4 / X.520: countryName is PrintableString (SIZE (2)).
  // CAB Forum Baseline narrows to ISO 3166-1 alpha-2; reject wrong-length input at build time.
  if AOid.Equals(TX509Name.C) or AOid.Equals(TX509Name.JurisdictionC) then
  begin
    if System.Length(LValue) <> 2 then
      raise EArgumentCryptoLibException.CreateResFmt(@SCountryCodeAttributeMustBeExactlyTwoChars, [AOid.Id, System.Length(LValue), LValue]);

    Result := TDerPrintableString.Create(LValue);
    Exit;
  end;

  // SerialNumber, DnQualifier, TelephoneNumber
  if AOid.Equals(TX509Name.SerialNumber) or
    AOid.Equals(TX509Name.DnQualifier) or
    AOid.Equals(TX509Name.TelephoneNumber) then
  begin
    Result := TDerPrintableString.Create(LValue);
    Exit;
  end;

  // RFC 5280 sec. A.1 / X.520: commonName is DirectoryString { ub-common-name } with ub-common-name = 64.
  // Reject over-length CNs at build time; most validators reject them anyway.
  // Parsing existing DER with longer CNs remains lenient because the decode path does not use this converter.
  if AOid.Equals(TX509Name.CN) and (System.Length(LValue) > 64) then
    raise EArgumentCryptoLibException.CreateResFmt(@SCommonNameAttributeExceedsMaxLength,
      [System.Length(LValue), LValue]);

  Result := TDerUtf8String.Create(LValue);
end;

end.
