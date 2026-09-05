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

unit ClpHpkeKdf;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIDigest,
  ClpPack,
  ClpConverters,
  ClpDigestUtilities,
  ClpHkdfParameters,
  ClpHkdfBytesGenerator,
  ClpIHkdfBytesGenerator,
  ClpHpkeTypes,
  ClpIHpkeKdf,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  ClpArrayUtilities;

resourcestring
  SExpandLengthTooLarge = 'Expand length cannot be larger than 2^16';
  SInvalidKdfId = 'invalid kdf id';

type
  /// <summary>
  /// RFC 9180 sec. 4 labeled KDF. LabeledExtract / LabeledExpand build the
  /// "HPKE-v1"-prefixed inputs and delegate to the HKDF primitive.
  /// </summary>
  THpkeKdf = class sealed(TInterfacedObject, IHpkeKdf)

  strict private
  const
    VersionLabel = 'HPKE-v1';

  var
    FKdf: IHkdfBytesGenerator;
    FHashLen: Int32;

    function GetHashSize(): Int32;

  public
    constructor Create(AKdfId: THpkeKdfId);

    function LabeledExtract(const ASalt, ASuiteId: TCryptoLibByteArray;
      const ALabel: String; const AIkm: TCryptoLibByteArray)
      : TCryptoLibByteArray;

    function LabeledExpand(const APrk, ASuiteId: TCryptoLibByteArray;
      const ALabel: String; const AInfo: TCryptoLibByteArray; AL: Int32)
      : TCryptoLibByteArray;

    function Extract(const ASalt, AIkm: TCryptoLibByteArray)
      : TCryptoLibByteArray;

    function Expand(const APrk, AInfo: TCryptoLibByteArray; AL: Int32)
      : TCryptoLibByteArray;

    property HashSize: Int32 read GetHashSize;
  end;

implementation

{ THpkeKdf }

constructor THpkeKdf.Create(AKdfId: THpkeKdfId);
var
  LHash: IDigest;
begin
  inherited Create();
  case AKdfId of
    THpkeKdfId.HkdfSha256:
      LHash := TDigestUtilities.GetDigest('SHA-256');
    THpkeKdfId.HkdfSha384:
      LHash := TDigestUtilities.GetDigest('SHA-384');
    THpkeKdfId.HkdfSha512:
      LHash := TDigestUtilities.GetDigest('SHA-512');
  else
    raise EArgumentCryptoLibException.CreateRes(@SInvalidKdfId);
  end;
  FKdf := THkdfBytesGenerator.Create(LHash);
  FHashLen := LHash.GetDigestSize();
end;

function THpkeKdf.GetHashSize: Int32;
begin
  Result := FHashLen;
end;

function THpkeKdf.LabeledExtract(const ASalt, ASuiteId: TCryptoLibByteArray;
  const ALabel: String; const AIkm: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LLabeledIkm: TCryptoLibByteArray;
begin
  LLabeledIkm := TArrayUtilities.Concatenate<Byte>
    ([TConverters.ConvertStringToBytes(VersionLabel, TEncoding.ASCII), ASuiteId,
    TConverters.ConvertStringToBytes(ALabel, TEncoding.ASCII), AIkm]);
  Result := FKdf.ExtractPRK(ASalt, LLabeledIkm);
end;

function THpkeKdf.LabeledExpand(const APrk, ASuiteId: TCryptoLibByteArray;
  const ALabel: String; const AInfo: TCryptoLibByteArray; AL: Int32)
  : TCryptoLibByteArray;
var
  LLabeledInfo: TCryptoLibByteArray;
begin
  if AL > (1 shl 16) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SExpandLengthTooLarge);
  end;

  LLabeledInfo := TArrayUtilities.Concatenate<Byte>
    ([TPack.UInt16_To_BE(UInt16(AL)),
    TConverters.ConvertStringToBytes(VersionLabel, TEncoding.ASCII), ASuiteId,
    TConverters.ConvertStringToBytes(ALabel, TEncoding.ASCII), AInfo]);

  FKdf.Init(THkdfParameters.SkipExtractParameters(APrk, LLabeledInfo));

  System.SetLength(Result, AL);
  FKdf.GenerateBytes(Result, 0, AL);
end;

function THpkeKdf.Extract(const ASalt, AIkm: TCryptoLibByteArray)
  : TCryptoLibByteArray;
begin
  Result := FKdf.ExtractPRK(ASalt, AIkm);
end;

function THpkeKdf.Expand(const APrk, AInfo: TCryptoLibByteArray; AL: Int32)
  : TCryptoLibByteArray;
begin
  if AL > (1 shl 16) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SExpandLengthTooLarge);
  end;

  FKdf.Init(THkdfParameters.SkipExtractParameters(APrk, AInfo));

  System.SetLength(Result, AL);
  FKdf.GenerateBytes(Result, 0, AL);
end;

end.
