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

unit ClpHkdfBytesGenerator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Math,
  SysUtils,
  ClpHMac,
  ClpIHMac,
  ClpIDigest,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpIHkdfParameters,
  ClpIHkdfBytesGenerator,
  ClpIDerivationFunction,
  ClpIDerivationParameters,
  ClpCryptoLibTypes;

resourcestring
  SSizeTooBigHKDF = 'HKDF Cannot Generate More Than 255 Blocks of HashLen Size';
  SSizeTooBigHKDF2 = 'HKDF May Only Be Used For 255 * HashLen Bytes of Output';
  SInvalidParameterHKDF =
    'HKDF Parameters Required For "HkdfBytesGenerator", "parameters"';

type

  /// <summary>
  /// HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
  /// implemented <br />according to IETF RFC 5869, May 2010 as specified by
  /// H. Krawczyk, IBM <br />Research &amp;amp; P. Eronen, Nokia. It uses a
  /// HMac internally to compute the OKM <br />(output keying material) and
  /// is likely to have better security properties <br />than KDF's based on
  /// just a hash function.
  /// </summary>
  THkdfBytesGenerator = class(TInterfacedObject, IDerivationFunction,
    IHkdfBytesGenerator)

  strict private
  var
    FHMacHash: IHMac;
    FHashLen, FGeneratedBytes: Int32;
    FInfo, FCurrentT: TCryptoLibByteArray;

    /// <summary>
    /// Performs the extract part of the key derivation function.
    /// </summary>
    /// <param name="salt">
    /// the salt to use
    /// </param>
    /// <param name="ikm">
    /// the input keying material
    /// </param>
    /// <returns>
    /// the PRK as KeyParameter
    /// </returns>
    function Extract(const ASalt, AIkm: TCryptoLibByteArray): IKeyParameter;

    /// <summary>
    /// Performs the expand part of the key derivation function, using
    /// currentT <br />as input and output buffer.
    /// </summary>
    /// <exception cref="EDataLengthCryptoLibException">
    /// if the total number of bytes generated is larger than the one
    /// specified by RFC 5869 (255 * HashLen)
    /// </exception>
    procedure ExpandNext();

  strict protected
    function GetDigest: IDigest; virtual;

  public

    /// <summary>
    /// Creates a HKDFBytesGenerator based on the given hash function.
    /// </summary>
    /// <param name="hash">
    /// the digest to be used as the source of generatedBytes bytes
    /// </param>
    constructor Create(const AHash: IDigest);

    procedure Init(const AParameters: IDerivationParameters); virtual;

    function GenerateBytes(const AOutput: TCryptoLibByteArray;
      AOutOff, ALen: Int32): Int32; virtual;

    property Digest: IDigest read GetDigest;

  end;

implementation

{ THkdfBytesGenerator }

constructor THkdfBytesGenerator.Create(const AHash: IDigest);
begin
  inherited Create();
  FHMacHash := THMac.Create(AHash);
  FHashLen := AHash.GetDigestSize();
end;

procedure THkdfBytesGenerator.ExpandNext;
var
  LN: Int32;
begin
  LN := (FGeneratedBytes div FHashLen) + 1;
  if LN >= 256 then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SSizeTooBigHKDF);
  end;
  // special case for T(0): T(0) is empty, so no update
  if (FGeneratedBytes <> 0) then
  begin
    FHMacHash.BlockUpdate(FCurrentT, 0, FHashLen);
  end;
  FHMacHash.BlockUpdate(FInfo, 0, System.Length(FInfo));
  FHMacHash.Update(Byte(LN));
  FHMacHash.DoFinal(FCurrentT, 0);
end;

function THkdfBytesGenerator.Extract(const ASalt, AIkm: TCryptoLibByteArray): IKeyParameter;
var
  LTemp, LPrk: TCryptoLibByteArray;
begin
  if ASalt = nil then
  begin
    System.SetLength(LTemp, FHashLen);
    FHMacHash.Init(TKeyParameter.Create(LTemp) as IKeyParameter);
  end
  else
  begin
    FHMacHash.Init(TKeyParameter.Create(ASalt) as IKeyParameter);
  end;

  FHMacHash.BlockUpdate(AIkm, 0, System.Length(AIkm));

  System.SetLength(LPrk, FHashLen);
  FHMacHash.DoFinal(LPrk, 0);
  Result := TKeyParameter.Create(LPrk);
end;

function THkdfBytesGenerator.GenerateBytes(const AOutput: TCryptoLibByteArray;
  AOutOff, ALen: Int32): Int32;
var
  LToGenerate, LPosInT, LLeftInT, LToCopy, LOutOff: Int32;
begin
  if (FGeneratedBytes + ALen) > (255 * FHashLen) then
    raise EDataLengthCryptoLibException.CreateRes(@SSizeTooBigHKDF2);

  if FGeneratedBytes mod FHashLen = 0 then
    ExpandNext();

  LToGenerate := ALen;
  LPosInT := FGeneratedBytes mod FHashLen;
  LLeftInT := FHashLen - (FGeneratedBytes mod FHashLen);
  LToCopy := Min(LLeftInT, LToGenerate);
  System.Move(FCurrentT[LPosInT], AOutput[AOutOff], LToCopy);
  FGeneratedBytes := FGeneratedBytes + LToCopy;
  LToGenerate := LToGenerate - LToCopy;
  LOutOff := AOutOff + LToCopy;

  while LToGenerate > 0 do
  begin
    ExpandNext();
    LToCopy := Min(FHashLen, LToGenerate);
    System.Move(FCurrentT[0], AOutput[LOutOff], LToCopy);
    FGeneratedBytes := FGeneratedBytes + LToCopy;
    LToGenerate := LToGenerate - LToCopy;
    LOutOff := LOutOff + LToCopy;
  end;

  Result := ALen;
end;

function THkdfBytesGenerator.GetDigest: IDigest;
begin
  Result := FHMacHash.GetUnderlyingDigest();
end;

procedure THkdfBytesGenerator.Init(const AParameters: IDerivationParameters);
var
  LHkdfParameters: IHkdfParameters;
begin
  if not Supports(AParameters, IHkdfParameters, LHkdfParameters) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidParameterHKDF);

  if LHkdfParameters.SkipExtract then
  begin
    FHMacHash.Init(TKeyParameter.Create(LHkdfParameters.GetIkm()) as IKeyParameter);
  end
  else
  begin
    FHMacHash.Init(Extract(LHkdfParameters.GetSalt(), LHkdfParameters.GetIkm()));
  end;

  FInfo := LHkdfParameters.GetInfo();

  FGeneratedBytes := 0;
  System.SetLength(FCurrentT, FHashLen);
end;

end.
