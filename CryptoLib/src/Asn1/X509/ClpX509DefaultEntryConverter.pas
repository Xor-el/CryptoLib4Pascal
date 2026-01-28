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
  ClpCryptoLibTypes;

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
        raise ECryptoLibException.CreateFmt('can''t recode value for oid %s', [AOid.Id]);
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

  // C, SerialNumber, DnQualifier, TelephoneNumber
  if AOid.Equals(TX509Name.C) or
    AOid.Equals(TX509Name.SerialNumber) or
    AOid.Equals(TX509Name.DnQualifier) or
    AOid.Equals(TX509Name.TelephoneNumber) then
  begin
    Result := TDerPrintableString.Create(LValue);
    Exit;
  end;

  Result := TDerUtf8String.Create(LValue);
end;

end.
