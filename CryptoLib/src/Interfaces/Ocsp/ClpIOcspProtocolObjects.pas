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

unit ClpIOcspProtocolObjects;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpIX509Asn1Objects,
  ClpIX509Extension,
  ClpIX509Certificate,
  ClpIOcspAsn1Objects,
  ClpIDigestFactory,
  ClpIAsymmetricKeyParameter,
  ClpIStore,
  ClpBigInteger,
  ClpNullable,
  ClpCryptoLibTypes;

type
  // every TDateTime crossing this layer is UTC, matching the rest of the X.509 and PKIX code

  // Forward declarations
  IOcspExtensions = interface;
  ICertificateStatus = interface;
  IRevokedStatus = interface;
  IUnknownStatus = interface;
  ICertificateID = interface;
  IRespID = interface;
  IReq = interface;
  ISingleResp = interface;
  IRespData = interface;
  IOcspReq = interface;
  IBasicOcspResp = interface;
  IOcspResp = interface;

  /// <summary>
  /// Common accessors of the OCSP protocol objects that carry X.509 extensions
  /// (RFC 6960 sec. 4.4).
  /// </summary>
  IOcspExtensions = interface(IInterface)
    ['{2A9F7C31-6B04-4E58-9D72-C1E58A0F3B46}']

    function GetNonCriticalExtensionOids: TCryptoLibStringArray;
    function GetCriticalExtensionOids: TCryptoLibStringArray;
    function GetExtensionValue(const AOid: IDerObjectIdentifier): IAsn1OctetString;
    function GetExtension(const AOid: IDerObjectIdentifier): IX509Extension;
    function GetExtensionParsedValue(const AOid: IDerObjectIdentifier): IAsn1Object;
  end;

  /// <summary>
  /// Revocation status of a certificate as reported by an OCSP responder (RFC 6960 sec. 2.2).
  /// </summary>
  /// <remarks>
  /// A nil <see cref="ICertificateStatus" /> is the "good" status; the CHOICE has no content
  /// for that alternative, so there is nothing for an object to carry.
  /// </remarks>
  ICertificateStatus = interface(IInterface)
    ['{B4E0517D-3C29-4A86-91FB-7D0682E4C539}']
  end;

  /// <summary>The "revoked" status, wrapping a RevokedInfo (RFC 6960 sec. 4.2.1).</summary>
  IRevokedStatus = interface(ICertificateStatus)
    ['{7D3168AC-05E9-4B7F-A2C4-9E360B1D84F7}']

    function GetRevocationTime: TDateTime;
    function GetHasRevocationReason: Boolean;
    /// <summary>
    /// The revocation reason. Optional: test <see cref="HasRevocationReason" /> first, since
    /// this raises when the responder omitted it.
    /// </summary>
    function GetRevocationReason: Int32;
    function ToAsn1Structure: IRevokedInfo;

    property RevocationTime: TDateTime read GetRevocationTime;
    property HasRevocationReason: Boolean read GetHasRevocationReason;
    property RevocationReason: Int32 read GetRevocationReason;
  end;

  /// <summary>The "unknown" status (RFC 6960 sec. 4.2.1).</summary>
  IUnknownStatus = interface(ICertificateStatus)
    ['{C5920E64-8B17-4D3A-B0F5-46E7218C9D03}']
  end;

  /// <summary>
  /// Identifier of the certificate a request or response is about (RFC 6960 sec. 4.1.1).
  /// </summary>
  ICertificateID = interface(IInterface)
    ['{9E14B27F-D0A6-4358-8C91-53F7B640EA28}']

    function GetHashAlgOid: String;
    function GetIssuerNameHash: TCryptoLibByteArray;
    function GetIssuerKeyHash: TCryptoLibByteArray;
    function GetSerialNumber: TBigInteger;

    /// <summary>Whether this identifier was derived from AIssuerCert.</summary>
    function MatchesIssuer(const AIssuerCert: IX509Certificate): Boolean; overload;
    function MatchesIssuer(const ADigestFactory: IDigestFactory;
      const AIssuerCert: IX509Certificate): Boolean; overload;

    function ToAsn1Structure: ICertID;

    function Equals(const AOther: ICertificateID): Boolean;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}

    property HashAlgOid: String read GetHashAlgOid;
    property SerialNumber: TBigInteger read GetSerialNumber;
  end;

  /// <summary>Carrier for a ResponderID (RFC 6960 sec. 4.2.1).</summary>
  IRespID = interface(IInterface)
    ['{16F8A94C-7E23-4D05-BA6F-38C0E5719B4D}']

    function ToAsn1Structure: IResponderID;

    function Equals(const AOther: IRespID): Boolean;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
  end;

  /// <summary>One entry of an OCSP request list (RFC 6960 sec. 4.1.1).</summary>
  IReq = interface(IOcspExtensions)
    ['{4C7B0D82-A395-41E6-B8D7-2F1069C34A5B}']

    function GetCertID: ICertificateID;
    function GetSingleRequestExtensions: IX509Extensions;

    property SingleRequestExtensions: IX509Extensions read GetSingleRequestExtensions;
  end;

  /// <summary>One entry of an OCSP response list (RFC 6960 sec. 4.2.1).</summary>
  ISingleResp = interface(IOcspExtensions)
    ['{0B6D3F51-92C8-4A74-85E1-D7304B9F26AC}']

    function GetCertID: ICertificateID;
    /// <summary>The status of the certificate; nil is the "good" status.</summary>
    function GetCertStatus: ICertificateStatus;
    function GetThisUpdate: TDateTime;
    /// <summary>The optional nextUpdate field; unset when the responder omitted it.</summary>
    function GetNextUpdate: TNullable<TDateTime>;
    function GetSingleExtensions: IX509Extensions;

    function ToAsn1Structure: ISingleResponse;

    property ThisUpdate: TDateTime read GetThisUpdate;
    property NextUpdate: TNullable<TDateTime> read GetNextUpdate;
    property SingleExtensions: IX509Extensions read GetSingleExtensions;
  end;

  /// <summary>The tbsResponseData of a basic OCSP response (RFC 6960 sec. 4.2.1).</summary>
  IRespData = interface(IOcspExtensions)
    ['{D8203E7A-45B1-4C69-90AF-6E132B5D7C84}']

    function GetVersion: Int32;
    function GetResponderId: IRespID;
    function GetProducedAt: TDateTime;
    function GetResponses: TCryptoLibGenericArray<ISingleResp>;
    function GetResponseExtensions: IX509Extensions;

    function ToAsn1Structure: IResponseData;

    property Version: Int32 read GetVersion;
    property ProducedAt: TDateTime read GetProducedAt;
    property ResponseExtensions: IX509Extensions read GetResponseExtensions;
  end;

  /// <summary>An OCSP request (RFC 6960 sec. 4.1.1).</summary>
  IOcspReq = interface(IOcspExtensions)
    ['{3F91C0D6-8A47-4B25-B1E3-570D9C486FA2}']

    /// <summary>The DER encoding of the tbsRequest field, i.e. the bytes the signature covers.</summary>
    function GetTbsRequest: TCryptoLibByteArray;
    function GetVersion: Int32;
    function GetRequestorName: IGeneralName;
    function GetRequestList: TCryptoLibGenericArray<IReq>;
    function GetRequestExtensions: IX509Extensions;
    function GetSignatureAlgorithm: IAlgorithmIdentifier;
    function GetSignatureAlgOid: String;
    function GetSignature: TCryptoLibByteArray;
    function GetIsSigned: Boolean;

    /// <summary>The certificates carried by a signed request; nil when the request is unsigned.</summary>
    function GetCerts: TCryptoLibGenericArray<IX509Certificate>;
    /// <summary>
    /// The same certificates as a store; nil when the request is unsigned. A signed request with
    /// no certificates gives an empty store.
    /// </summary>
    function GetCertificates: IStore<IX509Certificate>;

    /// <summary>Verify the signature over the tbsRequest field.</summary>
    function Verify(const APublicKey: IAsymmetricKeyParameter): Boolean;

    function GetEncoded: TCryptoLibByteArray;
    function ToAsn1Structure: IOcspRequest;

    property Version: Int32 read GetVersion;
    property RequestorName: IGeneralName read GetRequestorName;
    property RequestExtensions: IX509Extensions read GetRequestExtensions;
    property SignatureAlgorithm: IAlgorithmIdentifier read GetSignatureAlgorithm;
    property SignatureAlgOid: String read GetSignatureAlgOid;
    property IsSigned: Boolean read GetIsSigned;
  end;

  /// <summary>
  /// A basic OCSP response (RFC 6960 sec. 4.2.1).
  /// </summary>
  IBasicOcspResp = interface(IOcspExtensions)
    ['{A70E58C3-1D46-4F9B-82A5-C64B0937ED15}']

    /// <summary>The DER encoding of the tbsResponseData field, i.e. the bytes the signature covers.</summary>
    function GetTbsResponseData: TCryptoLibByteArray;
    function GetVersion: Int32;
    function GetResponderId: IRespID;
    function GetProducedAt: TDateTime;
    function GetResponses: TCryptoLibGenericArray<ISingleResp>;
    function GetResponseExtensions: IX509Extensions;
    function GetSignatureAlgorithm: IAlgorithmIdentifier;
    function GetSignature: TCryptoLibByteArray;

    /// <summary>The certificates carried by the response; empty when it carries none.</summary>
    function GetCerts: TCryptoLibGenericArray<IX509Certificate>;
    function GetCertificates: IStore<IX509Certificate>;

    /// <summary>Verify the signature over the tbsResponseData field.</summary>
    function Verify(const APublicKey: IAsymmetricKeyParameter): Boolean;

    function GetEncoded: TCryptoLibByteArray;
    function ToAsn1Structure: IBasicOcspResponse;

    function Equals(const AOther: IBasicOcspResp): Boolean;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}

    property Version: Int32 read GetVersion;
    property ProducedAt: TDateTime read GetProducedAt;
    property ResponseExtensions: IX509Extensions read GetResponseExtensions;
    property SignatureAlgorithm: IAlgorithmIdentifier read GetSignatureAlgorithm;
  end;

  /// <summary>An OCSP response (RFC 6960 sec. 4.2.1).</summary>
  IOcspResp = interface(IInterface)
    ['{5E0B4A72-C138-4967-8D2F-B49107E3C6A0}']

    /// <summary>The responseStatus field; see <c>TOcspRespStatus</c> for the values.</summary>
    function GetStatus: Int32;

    /// <summary>
    /// The decoded basic response, or nil when the response carries no bytes. Raises when the
    /// responseType is not id-pkix-ocsp-basic; <see cref="GetRawResponse" /> then gives the
    /// undecoded octets.
    /// </summary>
    function GetResponseObject: IBasicOcspResp;
    /// <summary>The undecoded response octets, whatever the responseType; nil when absent.</summary>
    function GetRawResponse: IAsn1OctetString;

    function GetEncoded: TCryptoLibByteArray;
    function ToAsn1Structure: IOcspResponse;

    function Equals(const AOther: IOcspResp): Boolean;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}

    property Status: Int32 read GetStatus;
  end;

implementation

end.
