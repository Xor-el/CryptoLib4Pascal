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

unit ClpX509RsaAsn1Objects;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpIX509RsaAsn1Objects,
  ClpCryptoLibTypes;

resourcestring
  SBadSequenceSize = 'Bad sequence size: %d';
  SNotCA = 'Not a valid RSA modulus';
  SNotValidPublicExponent = 'Not a valid RSA public exponent';

type
  /// <summary>
  /// The RsaPublicKeyStructure object.
  /// </summary>
  TRsaPublicKeyStructure = class(TAsn1Encodable, IRsaPublicKeyStructure)

  strict private
  var
    FModulus: TBigInteger;
    FPublicExponent: TBigInteger;

  strict protected
    function GetModulus: TBigInteger;
    function GetPublicExponent: TBigInteger;

  public
    class function GetInstance(AObj: TObject): IRsaPublicKeyStructure; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IRsaPublicKeyStructure; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IRsaPublicKeyStructure; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IRsaPublicKeyStructure; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IRsaPublicKeyStructure; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AModulus, APublicExponent: TBigInteger); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Modulus: TBigInteger read GetModulus;
    property PublicExponent: TBigInteger read GetPublicExponent;

  end;

implementation

{ TRsaPublicKeyStructure }

class function TRsaPublicKeyStructure.GetInstance(AObj: TObject): IRsaPublicKeyStructure;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IRsaPublicKeyStructure, Result) then
    Exit;

  Result := TRsaPublicKeyStructure.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TRsaPublicKeyStructure.GetInstance(const AObj: IAsn1Convertible): IRsaPublicKeyStructure;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IRsaPublicKeyStructure, Result) then
    Exit;

  Result := TRsaPublicKeyStructure.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TRsaPublicKeyStructure.GetInstance(const AEncoded: TCryptoLibByteArray): IRsaPublicKeyStructure;
begin
  Result := TRsaPublicKeyStructure.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TRsaPublicKeyStructure.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IRsaPublicKeyStructure;
begin
  Result := TRsaPublicKeyStructure.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TRsaPublicKeyStructure.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IRsaPublicKeyStructure;
begin
  Result := TRsaPublicKeyStructure.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TRsaPublicKeyStructure.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
begin
  inherited Create();

  LCount := ASeq.Count;
  if LCount <> 2 then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);
  end;

  // Note: we are accepting technically incorrect (i.e. negative) values here
  FModulus := TDerInteger.GetInstance(ASeq[0]).PositiveValue;
  FPublicExponent := TDerInteger.GetInstance(ASeq[1]).PositiveValue;
end;

constructor TRsaPublicKeyStructure.Create(const AModulus, APublicExponent: TBigInteger);
begin
  inherited Create();

  if AModulus.IsInitialized = False then
    raise EArgumentNilCryptoLibException.Create('modulus');
  if APublicExponent.IsInitialized = False then
    raise EArgumentNilCryptoLibException.Create('publicExponent');
  if AModulus.SignValue <= 0 then
    raise EArgumentCryptoLibException.Create(SNotCA);
  if APublicExponent.SignValue <= 0 then
    raise EArgumentCryptoLibException.Create(SNotValidPublicExponent);

  FModulus := AModulus;
  FPublicExponent := APublicExponent;
end;

function TRsaPublicKeyStructure.GetModulus: TBigInteger;
begin
  Result := FModulus;
end;

function TRsaPublicKeyStructure.GetPublicExponent: TBigInteger;
begin
  Result := FPublicExponent;
end;

function TRsaPublicKeyStructure.ToAsn1Object: IAsn1Object;
var
  LModulus, LExponent: IDerInteger;
begin
  LModulus := TDerInteger.Create(FModulus);
  LExponent := TDerInteger.Create(FPublicExponent);
  Result := TDerSequence.Create([LModulus, LExponent]);
end;

end.
