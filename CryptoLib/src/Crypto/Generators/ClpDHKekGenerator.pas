{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpDHKekGenerator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Classes,
  ClpIDigest,
  ClpIDerivationFunction,
  ClpIDerivationParameters,
  ClpIDHKekGenerator,
  ClpIDHKdfParameters,
  ClpIAsn1Objects,
  ClpAsn1Objects,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpIX9DHAsn1Objects,
  ClpX9DHAsn1Objects,
  ClpDigestSink,
  ClpCheck,
  ClpPack,
  ClpCryptoLibTypes;

resourcestring
  SOutputBufferTooShort = 'Output buffer too short';
  SOutputLengthTooLarge = 'Output length too large';
  SDHKekNotInitialized = 'DH KEK generator not initialized';

type
  /// <summary>
  /// RFC 2631 Diffie-hellman KEK derivation function.
  /// </summary>
  TDHKekGenerator = class sealed(TInterfacedObject, IDHKekGenerator,
    IDerivationFunction)

  strict private
  var
    FDigest: IDigest;
    FParams: IDHKdfParameters;

    function GetDigest(): IDigest;

  public
    constructor Create(const ADigest: IDigest);

    procedure Init(const AParameters: IDerivationParameters);

    function GenerateBytes(const AOutput: TCryptoLibByteArray;
      AOutOff, ALength: Int32): Int32;

    property Digest: IDigest read GetDigest;
  end;

implementation

{ TDHKekGenerator }

constructor TDHKekGenerator.Create(const ADigest: IDigest);
begin
  inherited Create();
  if ADigest = nil then
    raise EArgumentNilCryptoLibException.Create('digest');
  FDigest := ADigest;
end;

function TDHKekGenerator.GetDigest: IDigest;
begin
  Result := FDigest;
end;

procedure TDHKekGenerator.Init(const AParameters: IDerivationParameters);
var
  LParams: IDHKdfParameters;
begin
  if AParameters = nil then
    raise EArgumentNilCryptoLibException.Create('AParameters');

  if not Supports(AParameters, IDHKdfParameters, LParams) then
    raise EInvalidCastCryptoLibException.Create('AParameters');

  FParams := LParams;
end;

function TDHKekGenerator.GenerateBytes(const AOutput: TCryptoLibByteArray;
  AOutOff, ALength: Int32): Int32;
var
  LOutputLength, LDigestSize, LOutOff, LLength: Int32;
  LMaxOut: UInt64;
  LCounter32: UInt32;
  LCounterOctets: TCryptoLibByteArray;
  LZ, LPartyAInfo: TCryptoLibByteArray;
  LKeyInfo: IKeySpecificInfo;
  LPartyAOctet, LSuppPubOctet: IAsn1OctetString;
  LOtherInfo: IOtherInfo;
  LDigestSink: TDigestSink;
  LTmp: TCryptoLibByteArray;
begin
  TCheck.OutputLength(AOutput, AOutOff, ALength, SOutputBufferTooShort);

  if FParams = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SDHKekNotInitialized);

  LOutputLength := ALength;
  LDigestSize := FDigest.GetDigestSize();
  LOutOff := AOutOff;
  LLength := ALength;

  LMaxOut := UInt64(UInt32($FFFFFFFF)) * UInt64(LDigestSize);
  if UInt64(LLength) > LMaxOut then
    raise EArgumentCryptoLibException.CreateRes(@SOutputLengthTooLarge);

  LZ := FParams.Z;
  LPartyAInfo := FParams.ExtraInfo;

  FDigest.Reset();

  LDigestSink := TDigestSink.Create(FDigest);
  try
    System.SetLength(LCounterOctets, 4);
    LCounter32 := 0;

    while LLength > 0 do
    begin
      FDigest.BlockUpdate(LZ, 0, System.Length(LZ));

      System.Inc(LCounter32);
      TPack.UInt32_To_BE(LCounter32, LCounterOctets);

      LKeyInfo := TKeySpecificInfo.Create(FParams.Algorithm,
        TDerOctetString.Create(LCounterOctets) as IAsn1OctetString);

      if LPartyAInfo <> nil then
        LPartyAOctet := TDerOctetString.Create(LPartyAInfo) as IAsn1OctetString
      else
        LPartyAOctet := nil;

      LSuppPubOctet := TDerOctetString.Create(
        TPack.UInt32_To_BE(UInt32(FParams.KeySize))) as IAsn1OctetString;

      LOtherInfo := TOtherInfo.Create(LKeyInfo, LPartyAOctet, LSuppPubOctet);

      LOtherInfo.EncodeTo(LDigestSink, TAsn1Encodable.Der);

      if LLength < LDigestSize then
      begin
        System.SetLength(LTmp, LDigestSize);
        FDigest.DoFinal(LTmp, 0);
        System.Move(LTmp[0], AOutput[LOutOff], LLength * System.SizeOf(Byte));
        Break;
      end;

      FDigest.DoFinal(AOutput, LOutOff);
      LOutOff := LOutOff + LDigestSize;
      LLength := LLength - LDigestSize;
    end;
  finally
    LDigestSink.Free;
  end;

  Result := LOutputLength;
end;

end.
