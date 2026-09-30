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

unit ClpTrustAnchor;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIPkixTypes,
  ClpIX509Certificate,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIAsymmetricKeyParameter,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  STrustedCertNil = 'trusted certificate cannot be nil';
  SCaPrincipalNil = 'CA principal cannot be nil';
  SCaPublicKeyNil = 'CA public key cannot be nil';

type
  /// <summary>
  /// A most-trusted CA, given either as a trusted certificate or as a name plus public key,
  /// optionally narrowed by name constraints.
  /// </summary>
  TTrustAnchor = class(TInterfacedObject, ITrustAnchor)

  strict private
  var
    FTrustedCert: IX509Certificate;
    FCaPrincipal: IX509Name;
    FPubKey: IAsymmetricKeyParameter;
    FNameConstraintsBytes: TCryptoLibByteArray;
    FNameConstraints: INameConstraints;

    procedure SetNameConstraints(const ABytes: TCryptoLibByteArray);

  strict protected
    function GetTrustedCert: IX509Certificate;
    function GetCA: IX509Name;
    function GetCAPublicKey: IAsymmetricKeyParameter;

  public
    /// <summary>Anchor given as a trusted certificate.</summary>
    /// <param name="ANameConstraints">
    /// The DER encoding of a NameConstraints extension value (value only, no OID or criticality),
    /// or nil to omit.
    /// </param>
    constructor Create(const ATrustedCert: IX509Certificate;
      const ANameConstraints: TCryptoLibByteArray); overload;
    /// <summary>Anchor given as a distinguished name and public key.</summary>
    constructor Create(const ACaPrincipal: IX509Name; const APubKey: IAsymmetricKeyParameter;
      const ANameConstraints: TCryptoLibByteArray); overload;

    function GetNameConstraints: TCryptoLibByteArray;
    function GetNameConstraintsObject: INameConstraints;
    function ToString: String; override;
  end;

implementation

{ TTrustAnchor }

constructor TTrustAnchor.Create(const ATrustedCert: IX509Certificate;
  const ANameConstraints: TCryptoLibByteArray);
begin
  inherited Create();
  if ATrustedCert = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@STrustedCertNil);
  FTrustedCert := ATrustedCert;
  SetNameConstraints(ANameConstraints);
end;

constructor TTrustAnchor.Create(const ACaPrincipal: IX509Name; const APubKey: IAsymmetricKeyParameter;
  const ANameConstraints: TCryptoLibByteArray);
begin
  inherited Create();
  if ACaPrincipal = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SCaPrincipalNil);
  if APubKey = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SCaPublicKeyNil);
  FCaPrincipal := ACaPrincipal;
  FPubKey := APubKey;
  SetNameConstraints(ANameConstraints);
end;

procedure TTrustAnchor.SetNameConstraints(const ABytes: TCryptoLibByteArray);
begin
  FNameConstraintsBytes := System.Copy(ABytes);
  if FNameConstraintsBytes = nil then
    FNameConstraints := nil
  else
    FNameConstraints := TNameConstraints.GetInstance(FNameConstraintsBytes);
end;

function TTrustAnchor.GetTrustedCert: IX509Certificate;
begin
  Result := FTrustedCert;
end;

function TTrustAnchor.GetCA: IX509Name;
begin
  Result := FCaPrincipal;
end;

function TTrustAnchor.GetCAPublicKey: IAsymmetricKeyParameter;
begin
  Result := FPubKey;
end;

function TTrustAnchor.GetNameConstraints: TCryptoLibByteArray;
begin
  Result := System.Copy(FNameConstraintsBytes);
end;

function TTrustAnchor.GetNameConstraintsObject: INameConstraints;
begin
  Result := FNameConstraints;
end;

function TTrustAnchor.ToString: String;
var
  LBuilder: TStringBuilder;
begin
  LBuilder := TStringBuilder.Create();
  try
    LBuilder.AppendLine('[');
    if FPubKey <> nil then
    begin
      LBuilder.Append('  Trusted CA Issuer Name: ').AppendLine(FCaPrincipal.ToString());
    end
    else if FTrustedCert <> nil then
    begin
      LBuilder.Append('  Trusted CA cert: ').AppendLine(FTrustedCert.ToString());
    end;
    if FNameConstraints <> nil then
    begin
      LBuilder.AppendLine('  Name Constraints: present');
    end;
    LBuilder.AppendLine(']');
    Result := LBuilder.ToString();
  finally
    LBuilder.Free;
  end;
end;

end.
