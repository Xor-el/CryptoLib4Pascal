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

unit ClpV1TbsCertificateGenerator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Interface for V1 TbsCertificate structure generator.
  /// </summary>
  IV1TbsCertificateGenerator = interface
    ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}']
    procedure SetSerialNumber(const ASerialNumber: IDerInteger);
    procedure SetSignature(const ASignature: IAlgorithmIdentifier);
    procedure SetIssuer(const AIssuer: IX509Name);
    procedure SetValidity(const AValidity: IValidity);
    procedure SetStartDate(const AStartDate: ITime); overload;
    procedure SetStartDate(const AStartDate: IAsn1UtcTime); overload;
    procedure SetEndDate(const AEndDate: ITime); overload;
    procedure SetEndDate(const AEndDate: IAsn1UtcTime); overload;
    procedure SetSubject(const ASubject: IX509Name);
    procedure SetSubjectPublicKeyInfo(const APubKeyInfo: ISubjectPublicKeyInfo);
    function GenerateTbsCertificate: ITbsCertificateStructure;
  end;

  /// <summary>
  /// Generator for Version 1 TbsCertificateStructures.
  /// </summary>
  TV1TbsCertificateGenerator = class(TInterfacedObject, IV1TbsCertificateGenerator)
  strict private
    FSerialNumber: IDerInteger;
    FSignature: IAlgorithmIdentifier;
    FIssuer: IX509Name;
    FValidity: IValidity;
    FStartDate: ITime;
    FEndDate: ITime;
    FSubject: IX509Name;
    FSubjectPublicKeyInfo: ISubjectPublicKeyInfo;
  public
    procedure SetSerialNumber(const ASerialNumber: IDerInteger);
    procedure SetSignature(const ASignature: IAlgorithmIdentifier);
    procedure SetIssuer(const AIssuer: IX509Name);
    procedure SetValidity(const AValidity: IValidity);
    procedure SetStartDate(const AStartDate: ITime); overload;
    procedure SetStartDate(const AStartDate: IAsn1UtcTime); overload;
    procedure SetEndDate(const AEndDate: ITime); overload;
    procedure SetEndDate(const AEndDate: IAsn1UtcTime); overload;
    procedure SetSubject(const ASubject: IX509Name);
    procedure SetSubjectPublicKeyInfo(const APubKeyInfo: ISubjectPublicKeyInfo);
    function GenerateTbsCertificate: ITbsCertificateStructure;
  end;

implementation

{ TV1TbsCertificateGenerator }

procedure TV1TbsCertificateGenerator.SetSerialNumber(const ASerialNumber: IDerInteger);
begin
  FSerialNumber := ASerialNumber;
end;

procedure TV1TbsCertificateGenerator.SetSignature(const ASignature: IAlgorithmIdentifier);
begin
  FSignature := ASignature;
end;

procedure TV1TbsCertificateGenerator.SetIssuer(const AIssuer: IX509Name);
begin
  FIssuer := AIssuer;
end;

procedure TV1TbsCertificateGenerator.SetValidity(const AValidity: IValidity);
begin
  FValidity := AValidity;
  FStartDate := nil;
  FEndDate := nil;
end;

procedure TV1TbsCertificateGenerator.SetStartDate(const AStartDate: ITime);
begin
  FValidity := nil;
  FStartDate := AStartDate;
end;

procedure TV1TbsCertificateGenerator.SetStartDate(const AStartDate: IAsn1UtcTime);
begin
  SetStartDate(TTime.Create(AStartDate));
end;

procedure TV1TbsCertificateGenerator.SetEndDate(const AEndDate: ITime);
begin
  FValidity := nil;
  FEndDate := AEndDate;
end;

procedure TV1TbsCertificateGenerator.SetEndDate(const AEndDate: IAsn1UtcTime);
begin
  SetEndDate(TTime.Create(AEndDate));
end;

procedure TV1TbsCertificateGenerator.SetSubject(const ASubject: IX509Name);
begin
  FSubject := ASubject;
end;

procedure TV1TbsCertificateGenerator.SetSubjectPublicKeyInfo(const APubKeyInfo: ISubjectPublicKeyInfo);
begin
  FSubjectPublicKeyInfo := APubKeyInfo;
end;

function TV1TbsCertificateGenerator.GenerateTbsCertificate: ITbsCertificateStructure;
var
  LValidity: IValidity;
begin
  if (FSerialNumber = nil) or (FSignature = nil) or (FIssuer = nil) or
     ((FValidity = nil) and ((FStartDate = nil) or (FEndDate = nil))) or
     (FSubject = nil) or (FSubjectPublicKeyInfo = nil) then
    raise EInvalidOperationCryptoLibException.Create('not all mandatory fields set in V1 TBScertificate generator');

  if FValidity <> nil then
    LValidity := FValidity
  else
    LValidity := TValidity.Create(FStartDate, FEndDate);

  Result := TTbsCertificateStructure.Create(TDerInteger.Zero, FSerialNumber,
    FSignature, FIssuer, LValidity, FSubject, FSubjectPublicKeyInfo, nil, nil, nil);
end;

end.
