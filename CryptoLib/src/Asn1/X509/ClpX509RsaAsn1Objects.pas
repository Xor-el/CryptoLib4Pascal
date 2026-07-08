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
  ClpCryptoLibTypes,
  ClpAsn1Utilities;

resourcestring
  SBadSequenceSize = 'bad sequence size: %d';
  SInvalidRsaModulus = 'not a valid RSA modulus';
  SInvalidRsaPublicExponent = 'not a valid RSA public exponent';
  SModulusNil = 'modulus cannot be nil';
  SPublicExponentNil = 'public exponent cannot be nil';

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
  LPos: Int32;
begin
  inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 2, 2);
  // Note: we are accepting technically incorrect (i.e. negative) values here
  FModulus := TAsn1Utilities.Read<IDerInteger>(ASeq, LPos, TDerInteger.GetInstance).PositiveValue;
  FPublicExponent := TAsn1Utilities.Read<IDerInteger>(ASeq, LPos, TDerInteger.GetInstance).PositiveValue;
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);
end;

constructor TRsaPublicKeyStructure.Create(const AModulus, APublicExponent: TBigInteger);
begin
  inherited Create();

  if AModulus.IsInitialized = False then
    raise EArgumentNilCryptoLibException.CreateRes(@SModulusNil);
  if APublicExponent.IsInitialized = False then
    raise EArgumentNilCryptoLibException.CreateRes(@SPublicExponentNil);
  if AModulus.SignValue <= 0 then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidRsaModulus);
  if APublicExponent.SignValue <= 0 then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidRsaPublicExponent);

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
