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

unit ClpX509V1CertificateGenerator;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIX509Certificate,
  ClpX509Certificate,
  ClpIAsymmetricKeyParameter,
  ClpISignatureFactory,
  ClpV1TbsCertificateGenerator,
  ClpSubjectPublicKeyInfoFactory,
  ClpX509Utilities,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  IX509V1CertificateGenerator = interface
    ['{C2D3E4F5-A6B7-8901-CDEF-234567890123}']
    procedure Reset;
    procedure SetSerialNumber(const ASerialNumber: TBigInteger);
    procedure SetIssuerDN(const AIssuer: IX509Name);
    procedure SetValidity(const AValidity: IValidity);
    procedure SetNotBefore(const ADate: TDateTime);
    procedure SetNotAfter(const ADate: TDateTime);
    procedure SetSubjectDN(const ASubject: IX509Name);
    procedure SetPublicKey(const APublicKey: IAsymmetricKeyParameter);
    function Generate(const ASignatureFactory: ISignatureFactory): IX509Certificate;
    function GetSignatureAlgNames: TCryptoLibStringArray;
  end;

  TX509V1CertificateGenerator = class(TInterfacedObject, IX509V1CertificateGenerator)
  strict private
    FTbsGen: IV1TbsCertificateGenerator;
  public
    constructor Create;
    procedure Reset;
    procedure SetSerialNumber(const ASerialNumber: TBigInteger);
    procedure SetIssuerDN(const AIssuer: IX509Name);
    procedure SetValidity(const AValidity: IValidity);
    procedure SetNotBefore(const ADate: TDateTime);
    procedure SetNotAfter(const ADate: TDateTime);
    procedure SetSubjectDN(const ASubject: IX509Name);
    procedure SetPublicKey(const APublicKey: IAsymmetricKeyParameter);
    function Generate(const ASignatureFactory: ISignatureFactory): IX509Certificate;
    function GetSignatureAlgNames: TCryptoLibStringArray;
  end;

implementation

{ TX509V1CertificateGenerator }

constructor TX509V1CertificateGenerator.Create;
begin
  inherited Create;
  FTbsGen := TV1TbsCertificateGenerator.Create;
end;

procedure TX509V1CertificateGenerator.Reset;
begin
  FTbsGen := TV1TbsCertificateGenerator.Create;
end;

procedure TX509V1CertificateGenerator.SetSerialNumber(const ASerialNumber: TBigInteger);
begin
  if ASerialNumber.SignValue <= 0 then
    raise EArgumentCryptoLibException.Create('serial number must be a positive integer');
  FTbsGen.SetSerialNumber(TDerInteger.Create(ASerialNumber));
end;

procedure TX509V1CertificateGenerator.SetIssuerDN(const AIssuer: IX509Name);
begin
  FTbsGen.SetIssuer(AIssuer);
end;

procedure TX509V1CertificateGenerator.SetValidity(const AValidity: IValidity);
begin
  FTbsGen.SetValidity(AValidity);
end;

procedure TX509V1CertificateGenerator.SetNotBefore(const ADate: TDateTime);
begin
  FTbsGen.SetStartDate(TTime.Create(ADate));
end;

procedure TX509V1CertificateGenerator.SetNotAfter(const ADate: TDateTime);
begin
  FTbsGen.SetEndDate(TTime.Create(ADate));
end;

procedure TX509V1CertificateGenerator.SetSubjectDN(const ASubject: IX509Name);
begin
  FTbsGen.SetSubject(ASubject);
end;

procedure TX509V1CertificateGenerator.SetPublicKey(const APublicKey: IAsymmetricKeyParameter);
begin
  try
    FTbsGen.SetSubjectPublicKeyInfo(
      TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(APublicKey));
  except
    on E: Exception do
      raise EArgumentCryptoLibException.Create('unable to process key - ' + E.ToString);
  end;
end;

function TX509V1CertificateGenerator.Generate(const ASignatureFactory: ISignatureFactory): IX509Certificate;
var
  LSigAlgID: IAlgorithmIdentifier;
  LTbs: ITbsCertificateStructure;
  LSignature: IDerBitString;
  LStruct: IX509CertificateStructure;
begin
  LSigAlgID := ASignatureFactory.AlgorithmDetails;
  FTbsGen.SetSignature(LSigAlgID);
  LTbs := FTbsGen.GenerateTbsCertificate;
  LSignature := TX509Utilities.GenerateSignature(ASignatureFactory, LTbs);
  LStruct := TX509CertificateStructure.Create(LTbs, LSigAlgID, LSignature);
  Result := TX509Certificate.Create(LStruct);
end;

function TX509V1CertificateGenerator.GetSignatureAlgNames: TCryptoLibStringArray;
begin
  Result := TX509Utilities.GetAlgNames;
end;

end.
