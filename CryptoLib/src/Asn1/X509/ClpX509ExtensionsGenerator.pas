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

unit ClpX509ExtensionsGenerator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIX509ExtensionsGenerator,
  ClpIX509Asn1Objects,
  ClpIX509Extension,
  ClpX509Extension,
  ClpX509Asn1Objects,
  ClpCryptoLibTypes,
  ClpCryptoLibComparers;

type
  /// <remarks>Generator for X.509 extensions</remarks>
  TX509ExtensionsGenerator = class(TInterfacedObject, IX509ExtensionsGenerator)

  strict private
  var
    FExtensions: TDictionary<IDerObjectIdentifier, IX509Extension>;
    FOrdering: TList<IDerObjectIdentifier>;

  strict private
    class var
      FDupsAllowed: TDictionary<IDerObjectIdentifier, Boolean>;

    class procedure Boot; static;
    class constructor Create;
    class destructor Destroy;

  strict private
    procedure ImplAddExtension(const AOid: IDerObjectIdentifier;
      const AX509Extension: IX509Extension);
    procedure ImplAddExtensionDup(const AExistingExtension: IX509Extension;
      const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtValue: TCryptoLibByteArray);

  public
    constructor Create;
    destructor Destroy; override;

    procedure AddExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtValue: IAsn1Convertible); overload;
    procedure AddExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtValue: IAsn1Encodable); overload;
    procedure AddExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtValue: TCryptoLibByteArray); overload;
    procedure AddExtension(const AOid: IDerObjectIdentifier;
      const AX509Extension: IX509Extension); overload;
    procedure AddExtensions(const AExtensions: IX509Extensions);
    function Generate: IX509Extensions;
    function GetExtension(const AOid: IDerObjectIdentifier): IX509Extension;
    function HasExtension(const AOid: IDerObjectIdentifier): Boolean;
    function IsEmpty: Boolean;
    procedure RemoveExtension(const AOid: IDerObjectIdentifier);
    procedure ReplaceExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtValue: IAsn1Convertible); overload;
    procedure ReplaceExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtValue: IAsn1Encodable); overload;
    procedure ReplaceExtension(const AOid: IDerObjectIdentifier; ACritical: Boolean;
      const AExtValue: TCryptoLibByteArray); overload;
    procedure ReplaceExtension(const AOid: IDerObjectIdentifier;
      const AX509Extension: IX509Extension); overload;
    procedure Reset;

  end;

implementation

{ TX509ExtensionsGenerator }

class constructor TX509ExtensionsGenerator.Create;
begin
  Boot;
end;

class destructor TX509ExtensionsGenerator.Destroy;
begin
  FDupsAllowed.Free;
end;

class procedure TX509ExtensionsGenerator.Boot;
begin
  FDupsAllowed := TDictionary<IDerObjectIdentifier, Boolean>.Create(TCryptoLibComparers.OidEqualityComparer);
  // OIDs that allow duplicate extensions
  FDupsAllowed.Add(TX509Extensions.SubjectAlternativeName, True);
  FDupsAllowed.Add(TX509Extensions.IssuerAlternativeName, True);
  FDupsAllowed.Add(TX509Extensions.SubjectDirectoryAttributes, True);
  FDupsAllowed.Add(TX509Extensions.CertificateIssuer, True);
end;

constructor TX509ExtensionsGenerator.Create;
begin
  inherited Create();
  FExtensions := TDictionary<IDerObjectIdentifier, IX509Extension>.Create(TCryptoLibComparers.OidEqualityComparer);
  FOrdering := TList<IDerObjectIdentifier>.Create(TCryptoLibComparers.OidComparer);
end;

destructor TX509ExtensionsGenerator.Destroy;
begin
  FExtensions.Free;
  FOrdering.Free;
  inherited Destroy;
end;

procedure TX509ExtensionsGenerator.AddExtension(const AOid: IDerObjectIdentifier;
  ACritical: Boolean; const AExtValue: IAsn1Convertible);
begin
  AddExtension(AOid, ACritical, AExtValue.ToAsn1Object());
end;

procedure TX509ExtensionsGenerator.AddExtension(const AOid: IDerObjectIdentifier;
  ACritical: Boolean; const AExtValue: IAsn1Encodable);
var
  LExisting: IX509Extension;
begin
  if FExtensions.TryGetValue(AOid, LExisting) then
  begin
    ImplAddExtensionDup(LExisting, AOid, ACritical, AExtValue.GetEncoded(TAsn1Encodable.Der));
  end
  else
  begin
    ImplAddExtension(AOid, TX509Extension.Create(ACritical, TDerOctetString.Create(AExtValue)));
  end;
end;

procedure TX509ExtensionsGenerator.AddExtension(const AOid: IDerObjectIdentifier;
  ACritical: Boolean; const AExtValue: TCryptoLibByteArray);
var
  LExisting: IX509Extension;
begin
  if FExtensions.TryGetValue(AOid, LExisting) then
  begin
    ImplAddExtensionDup(LExisting, AOid, ACritical, AExtValue);
  end
  else
  begin
    ImplAddExtension(AOid, TX509Extension.Create(ACritical, TDerOctetString.FromContents(AExtValue)));
  end;
end;

procedure TX509ExtensionsGenerator.AddExtension(const AOid: IDerObjectIdentifier;
  const AX509Extension: IX509Extension);
begin
  if HasExtension(AOid) then
    raise EArgumentCryptoLibException.CreateFmt('extension %s already added', [AOid.Id]);
  ImplAddExtension(AOid, AX509Extension);
end;

procedure TX509ExtensionsGenerator.AddExtensions(const AExtensions: IX509Extensions);
var
  LOid: IDerObjectIdentifier;
  LExt: IX509Extension;
begin
  for LOid in AExtensions.GetExtensionOids() do
  begin
    LExt := AExtensions.GetExtension(LOid);
    AddExtension(LOid, LExt.IsCritical, LExt.Value.GetOctets());
  end;
end;

function TX509ExtensionsGenerator.Generate: IX509Extensions;
begin
  Result := TX509Extensions.Create(FOrdering, FExtensions);
end;

function TX509ExtensionsGenerator.GetExtension(const AOid: IDerObjectIdentifier): IX509Extension;
begin
  if not FExtensions.TryGetValue(AOid, Result) then
    Result := nil;
end;

function TX509ExtensionsGenerator.HasExtension(const AOid: IDerObjectIdentifier): Boolean;
begin
  Result := FExtensions.ContainsKey(AOid);
end;

function TX509ExtensionsGenerator.IsEmpty: Boolean;
begin
  Result := FOrdering.Count < 1;
end;

procedure TX509ExtensionsGenerator.RemoveExtension(const AOid: IDerObjectIdentifier);
begin
  if not HasExtension(AOid) then
    raise EInvalidOperationCryptoLibException.CreateFmt('extension %s not present', [AOid.Id]);
  FOrdering.Remove(AOid);
  FExtensions.Remove(AOid);
end;

procedure TX509ExtensionsGenerator.ReplaceExtension(const AOid: IDerObjectIdentifier;
  ACritical: Boolean; const AExtValue: IAsn1Convertible);
begin
  ReplaceExtension(AOid, ACritical, AExtValue.ToAsn1Object());
end;

procedure TX509ExtensionsGenerator.ReplaceExtension(const AOid: IDerObjectIdentifier;
  ACritical: Boolean; const AExtValue: IAsn1Encodable);
begin
  ReplaceExtension(AOid, TX509Extension.Create(ACritical, TDerOctetString.Create(AExtValue)));
end;

procedure TX509ExtensionsGenerator.ReplaceExtension(const AOid: IDerObjectIdentifier;
  ACritical: Boolean; const AExtValue: TCryptoLibByteArray);
begin
  ReplaceExtension(AOid, TX509Extension.Create(ACritical, TDerOctetString.FromContents(AExtValue)));
end;

procedure TX509ExtensionsGenerator.ReplaceExtension(const AOid: IDerObjectIdentifier;
  const AX509Extension: IX509Extension);
begin
  if not HasExtension(AOid) then
    raise EInvalidOperationCryptoLibException.CreateFmt('extension %s not present', [AOid.Id]);
  FExtensions[AOid] := AX509Extension;
end;

procedure TX509ExtensionsGenerator.Reset;
begin
  FExtensions.Clear;
  FOrdering.Clear;
end;

procedure TX509ExtensionsGenerator.ImplAddExtension(const AOid: IDerObjectIdentifier;
  const AX509Extension: IX509Extension);
begin
  FOrdering.Add(AOid);
  FExtensions.Add(AOid, AX509Extension);
end;

procedure TX509ExtensionsGenerator.ImplAddExtensionDup(const AExistingExtension: IX509Extension;
  const AOid: IDerObjectIdentifier; ACritical: Boolean; const AExtValue: TCryptoLibByteArray);
var
  LSeq1, LSeq2, LConcat: IAsn1Sequence;
begin
  if not FDupsAllowed.ContainsKey(AOid) then
    raise EArgumentCryptoLibException.CreateFmt('extension %s already added', [AOid.Id]);

  LSeq1 := TAsn1Sequence.GetInstance(AExistingExtension.Value.GetOctets());
  LSeq2 := TAsn1Sequence.GetInstance(AExtValue);
  LConcat := TDerSequence.Concatenate([LSeq1, LSeq2]);

  FExtensions[AOid] := TX509Extension.Create(AExistingExtension.IsCritical or ACritical,
    TDerOctetString.Create(LConcat));
end;

end.
