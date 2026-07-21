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

unit ClpIOcspGenerators;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIX509Asn1Objects,
  ClpIX509Certificate,
  ClpIOcspProtocolObjects,
  ClpISignatureFactory,
  ClpIAsymmetricKeyParameter,
  ClpISecureRandom,
  ClpNullable,
  ClpCryptoLibTypes;

type
  // every TDateTime crossing this layer is UTC, matching the rest of the X.509 and PKIX code

  /// <summary>Generator for OCSP requests (RFC 6960 sec. 4.1).</summary>
  IOcspReqGenerator = interface(IInterface)
    ['{6D82F0B4-59A1-4C37-9E0D-B3714A6C58E9}']

    /// <summary>Add a request for the given certificate identifier.</summary>
    procedure AddRequest(const ACertId: ICertificateID); overload;
    /// <summary>Add a request for the given certificate identifier, with extensions.</summary>
    procedure AddRequest(const ACertId: ICertificateID;
      const ASingleRequestExtensions: IX509Extensions); overload;

    /// <summary>Set the requestor name from a directory name.</summary>
    procedure SetRequestorName(const ARequestorName: IX509Name); overload;
    procedure SetRequestorName(const ARequestorName: IGeneralName); overload;
    procedure SetRequestExtensions(const ARequestExtensions: IX509Extensions);

    /// <summary>Generate an unsigned request.</summary>
    function Generate: IOcspReq; overload;
    function Generate(const ASigningAlgorithm: String; const APrivateKey: IAsymmetricKeyParameter;
      const AChain: TCryptoLibGenericArray<IX509Certificate>): IOcspReq; overload;
    function Generate(const ASigningAlgorithm: String; const APrivateKey: IAsymmetricKeyParameter;
      const AChain: TCryptoLibGenericArray<IX509Certificate>;
      const ARandom: ISecureRandom): IOcspReq; overload;
    function Generate(const ASignatureFactory: ISignatureFactory;
      const AChain: TCryptoLibGenericArray<IX509Certificate>): IOcspReq; overload;
  end;

  /// <summary>Generator for basic OCSP responses (RFC 6960 sec. 4.2).</summary>
  IBasicOcspRespGenerator = interface(IInterface)
    ['{E2470C95-B863-4D1A-8F52-0A9D6B37E14C}']

    /// <summary>Add a response for a certificate identifier; a nil status is "good".</summary>
    procedure AddResponse(const ACertID: ICertificateID;
      const ACertStatus: ICertificateStatus); overload;
    procedure AddResponse(const ACertID: ICertificateID; const ACertStatus: ICertificateStatus;
      const ASingleExtensions: IX509Extensions); overload;
    procedure AddResponse(const ACertID: ICertificateID; const ACertStatus: ICertificateStatus;
      const ANextUpdate: TNullable<TDateTime>;
      const ASingleExtensions: IX509Extensions); overload;
    procedure AddResponse(const ACertID: ICertificateID; const ACertStatus: ICertificateStatus;
      AThisUpdate: TDateTime; const ANextUpdate: TNullable<TDateTime>;
      const ASingleExtensions: IX509Extensions); overload;

    procedure SetResponseExtensions(const AResponseExtensions: IX509Extensions);

    function Generate(const ASigningAlgorithm: String; const APrivateKey: IAsymmetricKeyParameter;
      const AChain: TCryptoLibGenericArray<IX509Certificate>;
      AProducedAt: TDateTime): IBasicOcspResp; overload;
    function Generate(const ASigningAlgorithm: String; const APrivateKey: IAsymmetricKeyParameter;
      const AChain: TCryptoLibGenericArray<IX509Certificate>; AProducedAt: TDateTime;
      const ARandom: ISecureRandom): IBasicOcspResp; overload;
    function Generate(const ASignatureFactory: ISignatureFactory;
      const AChain: TCryptoLibGenericArray<IX509Certificate>;
      AProducedAt: TDateTime): IBasicOcspResp; overload;
  end;

  /// <summary>
  /// Generator for OCSP responses (RFC 6960 sec. 4.2). Only basic responses can be wrapped.
  /// </summary>
  IOcspRespGenerator = interface(IInterface)
    ['{81C5D739-4E06-42BA-A7F3-9C58201BD64E}']

    /// <summary>
    /// Wrap AResponse in a response with the given status; a nil AResponse produces a response
    /// with no responseBytes, as required for every non-successful status.
    /// </summary>
    function Generate(AStatus: Int32; const AResponse: IBasicOcspResp): IOcspResp;
  end;

implementation

end.
