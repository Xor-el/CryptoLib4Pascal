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
  ClpIDigest,
  ClpIDerivationFunction,
  ClpIDerivationParameters,
  ClpIDHKekGenerator,
  ClpIDHKdfParameters,
  ClpIAsn1Objects,
  ClpAsn1Objects,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpCheck,
  ClpPack,
  ClpCryptoLibTypes;

resourcestring
  SOutputBufferTooShort = 'Output buffer too short';
  SOutputLengthTooLarge = 'Output length too large';

type
  /// <summary>
  /// RFC 2631 Diffie-hellman KEK derivation function.
  /// </summary>
  TDHKekGenerator = class sealed(TInterfacedObject, IDHKekGenerator,
    IDerivationFunction)

  strict private
  var
    FDigest: IDigest;
    FAlgorithm: IDerObjectIdentifier;
    FKeySize: Int32;
    FZ: TCryptoLibByteArray;
    FPartyAInfo: TCryptoLibByteArray;

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
  if not Supports(AParameters, IDHKdfParameters, LParams) then
    raise EInvalidCastCryptoLibException.Create('AParameters');

  FAlgorithm := LParams.Algorithm;
  FKeySize := LParams.KeySize;
  FZ := LParams.GetZ();
  FPartyAInfo := LParams.GetExtraInfo();
end;

function TDHKekGenerator.GenerateBytes(const AOutput: TCryptoLibByteArray;
  AOutOff, ALength: Int32): Int32;
var
  LOBytes: Int64;
  LDigestSize, LCThreshold, LI, LOutOff, LLength: Int32;
  LDig, LOther: TCryptoLibByteArray;
  LCounter: UInt32;
  LKeyInfo, LV1DerSequence: IDerSequence;
  LV1: IAsn1EncodableVector;
begin
  TCheck.OutputLength(AOutput, AOutOff, ALength, SOutputBufferTooShort);

  LOBytes := ALength;
  LDigestSize := FDigest.GetDigestSize();
  LOutOff := AOutOff;
  LLength := ALength;

  if LOBytes > ((Int64(2) shl 32) - 1) then
    raise EArgumentCryptoLibException.CreateRes(@SOutputLengthTooLarge);

  LCThreshold := Int32((LOBytes + LDigestSize - 1) div LDigestSize);

  System.SetLength(LDig, LDigestSize);

  LCounter := 1;

  for LI := 0 to LCThreshold - 1 do
  begin
    LKeyInfo := TDerSequence.Create(
      FAlgorithm,
      TDerOctetString.Create(
        TPack.UInt32_To_BE(LCounter)) as IDerOctetString);

    LV1 := TAsn1EncodableVector.Create(LKeyInfo);

    if FPartyAInfo <> nil then
    begin
      LV1.Add(TDerTaggedObject.Create(True, 0,
        TDerOctetString.Create(FPartyAInfo) as IDerOctetString)
        as IDerTaggedObject);
    end;

    LV1.Add(TDerTaggedObject.Create(True, 2,
      TDerOctetString.Create(
        TPack.UInt32_To_BE(UInt32(FKeySize))) as IDerOctetString)
      as IDerTaggedObject);

    LV1DerSequence := TDerSequence.Create(LV1);
    LOther := LV1DerSequence.GetDerEncoded();

    FDigest.BlockUpdate(FZ, 0, System.Length(FZ));
    FDigest.BlockUpdate(LOther, 0, System.Length(LOther));
    FDigest.DoFinal(LDig, 0);

    if LLength > LDigestSize then
    begin
      System.Move(LDig[0], AOutput[LOutOff],
        LDigestSize * System.SizeOf(Byte));
      LOutOff := LOutOff + LDigestSize;
      LLength := LLength - LDigestSize;
    end
    else
    begin
      System.Move(LDig[0], AOutput[LOutOff],
        LLength * System.SizeOf(Byte));
    end;

    Inc(LCounter);
  end;

  FDigest.Reset();

  Result := Int32(LOBytes);
end;

end.
