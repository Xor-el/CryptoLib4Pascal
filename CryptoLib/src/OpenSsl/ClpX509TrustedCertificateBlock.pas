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

unit ClpX509TrustedCertificateBlock;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpAsn1Streams,
  ClpIX509Certificate,
  ClpX509Certificate,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpICertificateTrustBlock,
  ClpCertificateTrustBlock,
  ClpIX509TrustedCertificateBlock,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SCertificateNil = 'certificate cannot be nil';

type
  TX509TrustedCertificateBlock = class(TInterfacedObject, IX509TrustedCertificateBlock)
  strict private
  var
    FCertificate: IX509Certificate;
    FTrustBlock: ICertificateTrustBlock;

  public
    constructor Create(const ACertificate: IX509Certificate;
      const ATrustBlock: ICertificateTrustBlock); overload;
    constructor Create(const AEncoding: TCryptoLibByteArray); overload;

    function GetCertificate: IX509Certificate;
    function GetTrustBlock: ICertificateTrustBlock;
    function GetEncoded: TCryptoLibByteArray;
  end;

implementation

{ TX509TrustedCertificateBlock }

constructor TX509TrustedCertificateBlock.Create(const ACertificate: IX509Certificate;
  const ATrustBlock: ICertificateTrustBlock);
begin
  inherited Create();
  if ACertificate = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SCertificateNil);
  FCertificate := ACertificate;
  FTrustBlock := ATrustBlock;
end;

constructor TX509TrustedCertificateBlock.Create(const AEncoding: TCryptoLibByteArray);
var
  LStream: TAsn1InputStream;
  LTrustObject: IAsn1Object;
begin
  inherited Create();
  LStream := TAsn1InputStream.Create(AEncoding);
  try
    FCertificate := TX509Certificate.Create(
      TX509CertificateStructure.GetInstance(LStream.ReadObject()));

    LTrustObject := LStream.ReadObject();
    if LTrustObject <> nil then
      FTrustBlock := TCertificateTrustBlock.Create(LTrustObject.GetEncoded())
    else
      FTrustBlock := nil;
  finally
    LStream.Free;
  end;
end;

function TX509TrustedCertificateBlock.GetCertificate: IX509Certificate;
begin
  Result := FCertificate;
end;

function TX509TrustedCertificateBlock.GetTrustBlock: ICertificateTrustBlock;
begin
  Result := FTrustBlock;
end;

function TX509TrustedCertificateBlock.GetEncoded: TCryptoLibByteArray;
var
  LCertEncoded, LTrustEncoded: TCryptoLibByteArray;
begin
  LCertEncoded := FCertificate.GetEncoded();
  if FTrustBlock = nil then
  begin
    Result := LCertEncoded;
    Exit;
  end;

  LTrustEncoded := FTrustBlock.ToAsn1Sequence().GetEncoded();
  System.SetLength(Result, System.Length(LCertEncoded) + System.Length(LTrustEncoded));
  System.Move(LCertEncoded[0], Result[0], System.Length(LCertEncoded));
  if System.Length(LTrustEncoded) > 0 then
    System.Move(LTrustEncoded[0], Result[System.Length(LCertEncoded)], System.Length(LTrustEncoded));
end;

end.
