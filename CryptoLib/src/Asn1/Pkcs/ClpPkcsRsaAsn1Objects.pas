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

unit ClpPkcsRsaAsn1Objects;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpIPkcsRsaAsn1Objects,
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpPkcsObjectIdentifiers,
  ClpOiwObjectIdentifiers,
  ClpCryptoLibTypes,
  ClpAsn1Utilities;

resourcestring
  SBadSequenceSize = 'Bad sequence size: %d';
  SUnexpectedElementsInSequence = 'Unexpected elements in sequence';

type
  /// <summary>
  /// The RsaPrivateKeyStructure object.
  /// </summary>
  TRsaPrivateKeyStructure = class(TAsn1Encodable, IRsaPrivateKeyStructure)

  strict private
  var
    FVersion: IDerInteger;
    FModulus: TBigInteger;
    FPublicExponent: TBigInteger;
    FPrivateExponent: TBigInteger;
    FPrime1: TBigInteger;
    FPrime2: TBigInteger;
    FExponent1: TBigInteger;
    FExponent2: TBigInteger;
    FCoefficient: TBigInteger;

  strict protected
    function GetModulus: TBigInteger;
    function GetPublicExponent: TBigInteger;
    function GetPrivateExponent: TBigInteger;
    function GetPrime1: TBigInteger;
    function GetPrime2: TBigInteger;
    function GetExponent1: TBigInteger;
    function GetExponent2: TBigInteger;
    function GetCoefficient: TBigInteger;

  public
    class function GetInstance(AObj: TObject): IRsaPrivateKeyStructure; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IRsaPrivateKeyStructure; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IRsaPrivateKeyStructure; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IRsaPrivateKeyStructure; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IRsaPrivateKeyStructure; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AModulus, APublicExponent, APrivateExponent,
      APrime1, APrime2, AExponent1, AExponent2, ACoefficient: TBigInteger); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Modulus: TBigInteger read GetModulus;
    property PublicExponent: TBigInteger read GetPublicExponent;
    property PrivateExponent: TBigInteger read GetPrivateExponent;
    property Prime1: TBigInteger read GetPrime1;
    property Prime2: TBigInteger read GetPrime2;
    property Exponent1: TBigInteger read GetExponent1;
    property Exponent2: TBigInteger read GetExponent2;
    property Coefficient: TBigInteger read GetCoefficient;

  end;

  /// <summary>
  /// The RsassaPssParameters object.
  /// <pre>
  /// RSASSA-PSS-params ::= SEQUENCE {
  ///   hashAlgorithm      [0] OAEP-PSSDigestAlgorithms  DEFAULT sha1,
  ///    maskGenAlgorithm   [1] PKCS1MGFAlgorithms  DEFAULT mgf1SHA1,
  ///    saltLength         [2] INTEGER  DEFAULT 20,
  ///    trailerField       [3] TrailerField  DEFAULT trailerFieldBC
  ///  }
  /// </pre>
  /// </summary>
  TRsassaPssParameters = class(TAsn1Encodable, IRsassaPssParameters)

  strict private
    class var
      FDefaultHashAlgorithm, FDefaultMaskGenAlgorithm: IAlgorithmIdentifier;
      FDefaultSaltLength, FDefaultTrailerField: IDerInteger;

    class procedure Boot; static;
    class constructor Create;

  var
    FHashAlgorithm: IAlgorithmIdentifier;
    FMaskGenAlgorithm: IAlgorithmIdentifier;
    FSaltLength: IDerInteger;
    FTrailerField: IDerInteger;

  strict protected
    function GetHashAlgorithm: IAlgorithmIdentifier;
    function GetMaskGenAlgorithm: IAlgorithmIdentifier;
    function GetSaltLength: IDerInteger;
    function GetTrailerField: IDerInteger;

  public
    class function GetInstance(AObj: TObject): IRsassaPssParameters; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IRsassaPssParameters; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IRsassaPssParameters; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IRsassaPssParameters; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IRsassaPssParameters; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create; overload;
    constructor Create(const AHashAlgorithm, AMaskGenAlgorithm: IAlgorithmIdentifier;
      const ASaltLength, ATrailerField: IDerInteger); overload;

    function ToAsn1Object: IAsn1Object; override;

    property HashAlgorithm: IAlgorithmIdentifier read GetHashAlgorithm;
    property MaskGenAlgorithm: IAlgorithmIdentifier read GetMaskGenAlgorithm;
    property SaltLength: IDerInteger read GetSaltLength;
    property TrailerField: IDerInteger read GetTrailerField;

    class property DefaultHashAlgorithm: IAlgorithmIdentifier read FDefaultHashAlgorithm;
    class property DefaultMaskGenAlgorithm: IAlgorithmIdentifier read FDefaultMaskGenAlgorithm;
    class property DefaultSaltLength: IDerInteger read FDefaultSaltLength;
    class property DefaultTrailerField: IDerInteger read FDefaultTrailerField;

  end;

implementation

{ TRsaPrivateKeyStructure }

class function TRsaPrivateKeyStructure.GetInstance(AObj: TObject): IRsaPrivateKeyStructure;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IRsaPrivateKeyStructure, Result) then
    Exit;

  Result := TRsaPrivateKeyStructure.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TRsaPrivateKeyStructure.GetInstance(const AObj: IAsn1Convertible): IRsaPrivateKeyStructure;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IRsaPrivateKeyStructure, Result) then
    Exit;

  Result := TRsaPrivateKeyStructure.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TRsaPrivateKeyStructure.GetInstance(const AEncoded: TCryptoLibByteArray): IRsaPrivateKeyStructure;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TRsaPrivateKeyStructure.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TRsaPrivateKeyStructure.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IRsaPrivateKeyStructure;
begin
  Result := TRsaPrivateKeyStructure.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TRsaPrivateKeyStructure.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IRsaPrivateKeyStructure;
begin
  Result := TRsaPrivateKeyStructure.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TRsaPrivateKeyStructure.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
  LVersion: IDerInteger;
begin
  inherited Create();

  LCount := ASeq.Count;
  if LCount <> 9 then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);
  end;

  LVersion := TDerInteger.GetInstance(ASeq[0]);
  FModulus := TDerInteger.GetInstance(ASeq[1]).Value;
  FPublicExponent := TDerInteger.GetInstance(ASeq[2]).Value;
  FPrivateExponent := TDerInteger.GetInstance(ASeq[3]).Value;
  FPrime1 := TDerInteger.GetInstance(ASeq[4]).Value;
  FPrime2 := TDerInteger.GetInstance(ASeq[5]).Value;
  FExponent1 := TDerInteger.GetInstance(ASeq[6]).Value;
  FExponent2 := TDerInteger.GetInstance(ASeq[7]).Value;
  FCoefficient := TDerInteger.GetInstance(ASeq[8]).Value;

  if not LVersion.HasValue(0) then
    raise EArgumentCryptoLibException.Create('wrong version for RSA private key');

  FVersion := LVersion;
end;

constructor TRsaPrivateKeyStructure.Create(const AModulus, APublicExponent, APrivateExponent,
  APrime1, APrime2, AExponent1, AExponent2, ACoefficient: TBigInteger);
begin
  inherited Create();

  if not AModulus.IsInitialized then
    raise EArgumentNilCryptoLibException.Create('modulus');
  if not APublicExponent.IsInitialized then
    raise EArgumentNilCryptoLibException.Create('publicExponent');
  if not APrivateExponent.IsInitialized then
    raise EArgumentNilCryptoLibException.Create('privateExponent');
  if not APrime1.IsInitialized then
    raise EArgumentNilCryptoLibException.Create('prime1');
  if not APrime2.IsInitialized then
    raise EArgumentNilCryptoLibException.Create('prime2');
  if not AExponent1.IsInitialized then
    raise EArgumentNilCryptoLibException.Create('exponent1');
  if not AExponent2.IsInitialized then
    raise EArgumentNilCryptoLibException.Create('exponent2');
  if not ACoefficient.IsInitialized then
    raise EArgumentNilCryptoLibException.Create('coefficient');

  FVersion := TDerInteger.Zero;
  FModulus := AModulus;
  FPublicExponent := APublicExponent;
  FPrivateExponent := APrivateExponent;
  FPrime1 := APrime1;
  FPrime2 := APrime2;
  FExponent1 := AExponent1;
  FExponent2 := AExponent2;
  FCoefficient := ACoefficient;
end;

function TRsaPrivateKeyStructure.GetModulus: TBigInteger;
begin
  Result := FModulus;
end;

function TRsaPrivateKeyStructure.GetPublicExponent: TBigInteger;
begin
  Result := FPublicExponent;
end;

function TRsaPrivateKeyStructure.GetPrivateExponent: TBigInteger;
begin
  Result := FPrivateExponent;
end;

function TRsaPrivateKeyStructure.GetPrime1: TBigInteger;
begin
  Result := FPrime1;
end;

function TRsaPrivateKeyStructure.GetPrime2: TBigInteger;
begin
  Result := FPrime2;
end;

function TRsaPrivateKeyStructure.GetExponent1: TBigInteger;
begin
  Result := FExponent1;
end;

function TRsaPrivateKeyStructure.GetExponent2: TBigInteger;
begin
  Result := FExponent2;
end;

function TRsaPrivateKeyStructure.GetCoefficient: TBigInteger;
begin
  Result := FCoefficient;
end;

function TRsaPrivateKeyStructure.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create([
    FVersion,
    TDerInteger.Create(FModulus) as IDerInteger,
    TDerInteger.Create(FPublicExponent) as IDerInteger,
    TDerInteger.Create(FPrivateExponent) as IDerInteger,
    TDerInteger.Create(FPrime1) as IDerInteger,
    TDerInteger.Create(FPrime2) as IDerInteger,
    TDerInteger.Create(FExponent1) as IDerInteger,
    TDerInteger.Create(FExponent2) as IDerInteger,
    TDerInteger.Create(FCoefficient) as IDerInteger
  ]);
end;

{ TRsassaPssParameters }

class constructor TRsassaPssParameters.Create;
begin
  Boot;
end;

class procedure TRsassaPssParameters.Boot;
begin
  FDefaultHashAlgorithm := TAlgorithmIdentifier.Create(TOiwObjectIdentifiers.IdSha1, TDerNull.Instance);
  FDefaultMaskGenAlgorithm := TAlgorithmIdentifier.Create(TPkcsObjectIdentifiers.IdMgf1, DefaultHashAlgorithm);
  FDefaultSaltLength := TDerInteger.ValueOf(20);
  FDefaultTrailerField := TDerInteger.One;
end;

class function TRsassaPssParameters.GetInstance(AObj: TObject): IRsassaPssParameters;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IRsassaPssParameters, Result) then
    Exit;

  Result := TRsassaPssParameters.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TRsassaPssParameters.GetInstance(const AObj: IAsn1Convertible): IRsassaPssParameters;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IRsassaPssParameters, Result) then
    Exit;

  Result := TRsassaPssParameters.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TRsassaPssParameters.GetInstance(const AEncoded: TCryptoLibByteArray): IRsassaPssParameters;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TRsassaPssParameters.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TRsassaPssParameters.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IRsassaPssParameters;
begin
  Result := TRsassaPssParameters.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TRsassaPssParameters.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IRsassaPssParameters;
begin
  Result := TRsassaPssParameters.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TRsassaPssParameters.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
begin
  inherited Create();
  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 0) or (LCount > 4) then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);

  FHashAlgorithm := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IAlgorithmIdentifier>(ASeq, LPos, 0, True,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IAlgorithmIdentifier
    begin
      Result := TAlgorithmIdentifier.GetTagged(ATagged, AState);
    end);
  if FHashAlgorithm = nil then
    FHashAlgorithm := DefaultHashAlgorithm;

  FMaskGenAlgorithm := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IAlgorithmIdentifier>(ASeq, LPos, 1, True,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IAlgorithmIdentifier
    begin
      Result := TAlgorithmIdentifier.GetTagged(ATagged, AState);
    end);
  if FMaskGenAlgorithm = nil then
    FMaskGenAlgorithm := DefaultMaskGenAlgorithm;

  FSaltLength := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IDerInteger>(ASeq, LPos, 2, True,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IDerInteger
    begin
      Result := TDerInteger.GetTagged(ATagged, AState);
    end);
  if FSaltLength = nil then
    FSaltLength := DefaultSaltLength;

  FTrailerField := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IDerInteger>(ASeq, LPos, 3, True,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IDerInteger
    begin
      Result := TDerInteger.GetTagged(ATagged, AState);
    end);
  if FTrailerField = nil then
    FTrailerField := DefaultTrailerField;

  if LPos <> LCount then
    raise EArgumentCryptoLibException.CreateRes(@SUnexpectedElementsInSequence);
end;

constructor TRsassaPssParameters.Create;
begin
  inherited Create();
  FHashAlgorithm := DefaultHashAlgorithm;
  FMaskGenAlgorithm := DefaultMaskGenAlgorithm;
  FSaltLength := DefaultSaltLength;
  FTrailerField := DefaultTrailerField;
end;

constructor TRsassaPssParameters.Create(const AHashAlgorithm, AMaskGenAlgorithm: IAlgorithmIdentifier;
  const ASaltLength, ATrailerField: IDerInteger);
begin
  inherited Create();
  if AHashAlgorithm = nil then
    FHashAlgorithm := DefaultHashAlgorithm
  else
    FHashAlgorithm := AHashAlgorithm;

  if AMaskGenAlgorithm = nil then
    FMaskGenAlgorithm := DefaultMaskGenAlgorithm
  else
    FMaskGenAlgorithm := AMaskGenAlgorithm;

  if ASaltLength = nil then
    FSaltLength := DefaultSaltLength
  else
    FSaltLength := ASaltLength;

  if ATrailerField = nil then
    FTrailerField := DefaultTrailerField
  else
    FTrailerField := ATrailerField;
end;

function TRsassaPssParameters.GetHashAlgorithm: IAlgorithmIdentifier;
begin
  Result := FHashAlgorithm;
end;

function TRsassaPssParameters.GetMaskGenAlgorithm: IAlgorithmIdentifier;
begin
  Result := FMaskGenAlgorithm;
end;

function TRsassaPssParameters.GetSaltLength: IDerInteger;
begin
  Result := FSaltLength;
end;

function TRsassaPssParameters.GetTrailerField: IDerInteger;
begin
  Result := FTrailerField;
end;

function TRsassaPssParameters.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(4);

  if not DefaultHashAlgorithm.Equals(FHashAlgorithm) then
  begin
    LV.Add(TDerTaggedObject.Create(True, 0, FHashAlgorithm));
  end;

  if not DefaultMaskGenAlgorithm.Equals(FMaskGenAlgorithm) then
  begin
    LV.Add(TDerTaggedObject.Create(True, 1, FMaskGenAlgorithm));
  end;

  if not DefaultSaltLength.Equals(FSaltLength) then
  begin
    LV.Add(TDerTaggedObject.Create(True, 2, FSaltLength));
  end;

  if not DefaultTrailerField.Equals(FTrailerField) then
  begin
    LV.Add(TDerTaggedObject.Create(True, 3, FTrailerField));
  end;

  Result := TDerSequence.Create(LV);
end;

end.
