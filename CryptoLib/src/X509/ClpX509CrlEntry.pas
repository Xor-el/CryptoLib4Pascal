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

unit ClpX509CrlEntry;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpAsn1Objects,
  ClpIX509Extension,
  ClpIX509CrlEntry,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpX509ExtensionBase,
  ClpX509ExtensionUtilities,
  ClpAsn1Dumper,
  ClpCryptoLibTypes;

type
  TX509CrlEntry = class(TX509ExtensionBase, IX509CrlEntry)
  strict private
    var
      FCrlEntry: ICrlEntry;
      FIsIndirect: Boolean;
      FPreviousCertificateIssuer: IX509Name;
      FCertificateIssuer: IX509Name;
      FHashValueSet: Boolean;
      FHashValue: Int32;

    function LoadCertificateIssuer: IX509Name;
  strict protected
    function GetX509Extensions: IX509Extensions; override;
  public
    constructor Create(const ACrlEntry: ICrlEntry); overload;
    constructor Create(const ACrlEntry: ICrlEntry; AIsIndirect: Boolean;
      const APreviousCertificateIssuer: IX509Name); overload;

    function GetCrlEntry: ICrlEntry;
    function GetCertificateIssuer: IX509Name;
    function GetEncoded: TCryptoLibByteArray;
    function GetSerialNumber: TBigInteger;
    function GetRevocationDate: TDateTime;
    function GetHasExtensions: Boolean;
    function Equals(const AOther: TObject): Boolean; reintroduce;
    function GetHashCode: Int32; reintroduce;
    function ToString: String; override;

    property CrlEntry: ICrlEntry read GetCrlEntry;
    property SerialNumber: TBigInteger read GetSerialNumber;
    property RevocationDate: TDateTime read GetRevocationDate;
    property HasExtensions: Boolean read GetHasExtensions;
  end;

implementation

{ TX509CrlEntry }

constructor TX509CrlEntry.Create(const ACrlEntry: ICrlEntry);
begin
  inherited Create();
  FCrlEntry := ACrlEntry;
  FIsIndirect := False;
  FPreviousCertificateIssuer := nil;
  FCertificateIssuer := LoadCertificateIssuer();
end;

constructor TX509CrlEntry.Create(const ACrlEntry: ICrlEntry; AIsIndirect: Boolean;
  const APreviousCertificateIssuer: IX509Name);
begin
  inherited Create();
  FCrlEntry := ACrlEntry;
  FIsIndirect := AIsIndirect;
  FPreviousCertificateIssuer := APreviousCertificateIssuer;
  FCertificateIssuer := LoadCertificateIssuer();
end;

function TX509CrlEntry.GetX509Extensions: IX509Extensions;
begin
  Result := FCrlEntry.Extensions;
end;

function TX509CrlEntry.LoadCertificateIssuer: IX509Name;
var
  LCertificateIssuer: IGeneralNames;
  LNames: TCryptoLibGenericArray<IGeneralName>;
  I: Int32;
  LObj: IAsn1Object;
begin
  if not FIsIndirect then
  begin
    Result := nil;
    Exit;
  end;

  LObj := GetExtensionParsedValue(TX509Extensions.CertificateIssuer);
  if LObj = nil then
  begin
    Result := FPreviousCertificateIssuer;
    Exit;
  end;

  try
    LCertificateIssuer := TGeneralNames.GetInstance(LObj as IAsn1Convertible);
    if LCertificateIssuer <> nil then
    begin
      LNames := LCertificateIssuer.GetNames;
      for I := 0 to System.High(LNames) do
        if LNames[I].TagNo = TGeneralName.DirectoryName then
        begin
          Result := TX509Name.GetInstance(LNames[I].Name);
          Exit;
        end;
    end;
  except
    // ignore
  end;

  Result := nil;
end;

function TX509CrlEntry.GetCrlEntry: ICrlEntry;
begin
  Result := FCrlEntry;
end;

function TX509CrlEntry.GetCertificateIssuer: IX509Name;
begin
  Result := FCertificateIssuer;
end;

function TX509CrlEntry.GetEncoded: TCryptoLibByteArray;
begin
  try
    Result := FCrlEntry.GetDerEncoded();
  except
    on E: Exception do
      raise ECrlCryptoLibException.Create(E.ToString);
  end;
end;

function TX509CrlEntry.GetSerialNumber: TBigInteger;
begin
  Result := FCrlEntry.UserCertificate.Value;
end;

function TX509CrlEntry.GetRevocationDate: TDateTime;
begin
  Result := FCrlEntry.RevocationDate.ToDateTime;
end;

function TX509CrlEntry.GetHasExtensions: Boolean;
begin
  Result := FCrlEntry.Extensions <> nil;
end;

function TX509CrlEntry.Equals(const AOther: TObject): Boolean;
var
  LThat: IX509CrlEntry;
begin
  if Self = AOther then
  begin
    Result := True;
    Exit;
  end;

  if not Supports(AOther, IX509CrlEntry, LThat) then
  begin
    Result := False;
    Exit;
  end;

  if FHashValueSet and (LThat as TX509CrlEntry).FHashValueSet then
  begin
    if FHashValue <> (LThat as TX509CrlEntry).FHashValue then
    begin
      Result := False;
      Exit;
    end;
  end;

  Result := FCrlEntry.Equals(LThat.CrlEntry as IAsn1Convertible);
end;

function TX509CrlEntry.GetHashCode: Int32;
begin
  if not FHashValueSet then
  begin
    FHashValue := FCrlEntry.GetHashCode();
    FHashValueSet := True;
  end;
  Result := FHashValue;
end;

function TX509CrlEntry.ToString: String;
var
  LBuf: TStringBuilder;
  LExtensions: IX509Extensions;
  LOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
  I: Int32;
  LOid: IDerObjectIdentifier;
  LExt: IX509Extension;
  LObj: IAsn1Object;
begin
  LBuf := TStringBuilder.Create();
  try
    LBuf.Append('        userCertificate: ').Append(SerialNumber.ToString).AppendLine;
    LBuf.Append('         revocationDate: ').Append(DateTimeToStr(RevocationDate)).AppendLine;
    LBuf.Append('      certificateIssuer: ');
    if FCertificateIssuer <> nil then
      LBuf.Append(FCertificateIssuer.ToString)
    else
      LBuf.Append('null');
    LBuf.AppendLine;

    LExtensions := FCrlEntry.Extensions;
    if LExtensions <> nil then
    begin
      LOids := LExtensions.ExtensionOids;
      if System.Length(LOids) > 0 then
      begin
        LBuf.AppendLine('   crlEntryExtensions:');
        for I := 0 to System.High(LOids) do
        begin
          LOid := LOids[I];
          LExt := LExtensions.GetExtension(LOid);
          if (LExt <> nil) and (LExt.Value <> nil) then
          begin
            LObj := TX509ExtensionUtilities.FromExtensionValue(LExt.Value);
            LBuf.Append('                       critical(').Append(LExt.IsCritical).Append(') ');
            try
              if LOid.Equals(TX509Extensions.ReasonCode) then
                LBuf.Append(TCrlReason.Create(TDerEnumerated.GetInstance(LObj)).ToString())
              else if LOid.Equals(TX509Extensions.CertificateIssuer) then
                LBuf.Append('Certificate issuer: ').Append(TGeneralNames.GetInstance(LObj as IAsn1Sequence).ToString())
              else
              begin
                LBuf.Append(LOid.Id);
                LBuf.Append(' value = ').Append(TAsn1Dumper.DumpAsString(LObj));
              end;
              LBuf.AppendLine;
            except
              LBuf.Append(LOid.Id);
              LBuf.Append(' value = *****').AppendLine;
            end;
          end
          else
            LBuf.AppendLine;
        end;
      end;
    end;

    Result := LBuf.ToString;
  finally
    LBuf.Free;
  end;
end;

end.
