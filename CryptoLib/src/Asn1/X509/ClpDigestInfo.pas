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

unit ClpDigestInfo;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIAlgorithmIdentifier,
  ClpAlgorithmIdentifier,
  ClpIDigestInfo,
  ClpCryptoLibTypes;

resourcestring
  SBadSequenceSize = 'Bad sequence size: %d';

type
  /// <summary>
  /// The DigestInfo object.
  /// DigestInfo ::= SEQUENCE {
  ///   digestAlgorithm AlgorithmIdentifier,
  ///   digest OCTET STRING
  /// }
  /// </summary>
  TDigestInfo = class(TAsn1Encodable, IDigestInfo)

  strict private
  var
    FDigestAlgorithm: IAlgorithmIdentifier;
    FDigest: IAsn1OctetString;

  strict protected
    function GetDigestAlgorithm: IAlgorithmIdentifier;
    function GetDigest: IAsn1OctetString;
    function GetDigestBytes: TCryptoLibByteArray;

  public
    /// <summary>
    /// Parse a DigestInfo from an object.
    /// </summary>
    class function GetInstance(obj: TObject): IDigestInfo; overload; static;

    /// <summary>
    /// Parse a DigestInfo from DER-encoded bytes.
    /// </summary>
    class function GetInstance(const encoded: TCryptoLibByteArray): IDigestInfo; overload; static;

    constructor Create(const seq: IAsn1Sequence); overload;
    constructor Create(const algId: IAlgorithmIdentifier;
      const digest: TCryptoLibByteArray); overload;
    constructor Create(const digestAlgorithm: IAlgorithmIdentifier;
      const digest: IAsn1OctetString); overload;

    function GetDerEncoded: TCryptoLibByteArray;
    function ToAsn1Object: IAsn1Object; override;

    property DigestAlgorithm: IAlgorithmIdentifier read GetDigestAlgorithm;
    property Digest: IAsn1OctetString read GetDigest;

  end;

implementation

{ TDigestInfo }

class function TDigestInfo.GetInstance(obj: TObject): IDigestInfo;
begin
  if obj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(obj, IDigestInfo, Result) then
    Exit;

  if obj is TAsn1Sequence then
    Result := TDigestInfo.Create(obj as TAsn1Sequence)
  else
    Result := TDigestInfo.Create(TAsn1Sequence.GetInstance(obj as TAsn1Encodable));
end;

class function TDigestInfo.GetInstance(const encoded: TCryptoLibByteArray): IDigestInfo;
var
  asn1Obj: IAsn1Object;
begin
  asn1Obj := TAsn1Object.FromByteArray(encoded);
  Result := TDigestInfo.Create(asn1Obj as IAsn1Sequence);
end;

constructor TDigestInfo.Create(const seq: IAsn1Sequence);
var
  count: Int32;
begin
  inherited Create();

  count := seq.Count;
  if count <> 2 then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [count]);
  end;

  FDigestAlgorithm := TAlgorithmIdentifier.GetInstance(seq[0].ToAsn1Object() as TObject);
  FDigest := TAsn1OctetString.GetInstance(seq[1].ToAsn1Object() as TObject);
end;

constructor TDigestInfo.Create(const algId: IAlgorithmIdentifier;
  const digest: TCryptoLibByteArray);
begin
  inherited Create();

  if algId = nil then
  begin
    raise EArgumentNilCryptoLibException.Create('algId');
  end;

  FDigestAlgorithm := algId;
  FDigest := TDerOctetString.Create(digest);
end;

constructor TDigestInfo.Create(const digestAlgorithm: IAlgorithmIdentifier;
  const digest: IAsn1OctetString);
begin
  inherited Create();

  if digestAlgorithm = nil then
  begin
    raise EArgumentNilCryptoLibException.Create('digestAlgorithm');
  end;

  if digest = nil then
  begin
    raise EArgumentNilCryptoLibException.Create('digest');
  end;

  FDigestAlgorithm := digestAlgorithm;
  FDigest := digest;
end;

function TDigestInfo.GetDigestAlgorithm: IAlgorithmIdentifier;
begin
  Result := FDigestAlgorithm;
end;

function TDigestInfo.GetDigest: IAsn1OctetString;
begin
  Result := FDigest;
end;

function TDigestInfo.GetDigestBytes: TCryptoLibByteArray;
begin
  Result := FDigest.GetOctets();
end;

function TDigestInfo.GetDerEncoded: TCryptoLibByteArray;
begin
  Result := ToAsn1Object.GetDerEncoded();
end;

function TDigestInfo.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create([FDigestAlgorithm, FDigest]);
end;

end.
