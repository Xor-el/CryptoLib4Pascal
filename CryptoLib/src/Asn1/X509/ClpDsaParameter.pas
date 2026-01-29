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

unit ClpDsaParameter;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIDsaParameter,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpBigInteger,
  ClpCryptoLibTypes;

resourcestring
  SBadSequenceSize = 'Bad Sequence Size "seq": %d';
  SInvalidDsaParameter = 'Invalid DsaParameter: %s';

type
  TDsaParameter = class(TAsn1Encodable, IDsaParameter)

  strict private
  var
    FP, FQ, FG: IDerInteger;

    function GetG: TBigInteger; inline;
    function GetP: TBigInteger; inline;
    function GetQ: TBigInteger; inline;

    constructor Create(const ASeq: IAsn1Sequence); overload;

  public
    constructor Create(const AP, AQ, AG: TBigInteger); overload;

    function ToAsn1Object(): IAsn1Object; override;

    property P: TBigInteger read GetP;
    property Q: TBigInteger read GetQ;
    property G: TBigInteger read GetG;

    /// <summary>
    /// Parse a DsaParameter from an object.
    /// </summary>
    class function GetInstance(AObj: TObject): IDsaParameter; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IDsaParameter; overload; static;
    /// <summary>
    /// Parse a DsaParameter from DER-encoded bytes.
    /// </summary>
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IDsaParameter; overload; static;
    /// <summary>
    /// Parse a DsaParameter from a tagged object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1TaggedObject; AExplicitly: Boolean): IDsaParameter; overload; static;
    /// <summary>
    /// Get tagged DsaParameter.
    /// </summary>
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDsaParameter; static;

  end;

implementation

{ TDsaParameter }

function TDsaParameter.GetP: TBigInteger;
begin
  result := FP.PositiveValue;
end;

function TDsaParameter.GetQ: TBigInteger;
begin
  result := FQ.PositiveValue;
end;

function TDsaParameter.GetG: TBigInteger;
begin
  result := FG.PositiveValue;
end;

function TDsaParameter.ToAsn1Object: IAsn1Object;
begin
  result := TDerSequence.Create([FP, FQ, FG]);
end;

constructor TDsaParameter.Create(const ASeq: IAsn1Sequence);
begin
  Inherited Create();
  if (ASeq.Count <> 3) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize,
      [ASeq.Count]);
  end;

  FP := TDerInteger.GetInstance(ASeq[0]);
  FQ := TDerInteger.GetInstance(ASeq[1]);
  FG := TDerInteger.GetInstance(ASeq[2]);
end;

constructor TDsaParameter.Create(const AP, AQ, AG: TBigInteger);
begin
  Inherited Create();
  FP := TDerInteger.Create(AP);
  FQ := TDerInteger.Create(AQ);
  FG := TDerInteger.Create(AG);
end;

class function TDsaParameter.GetInstance(AObj: TObject): IDsaParameter;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDsaParameter, Result) then
    Exit;

  Result := TDsaParameter.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TDsaParameter.GetInstance(const AObj: IAsn1Convertible): IDsaParameter;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDsaParameter, Result) then
    Exit;

  Result := TDsaParameter.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TDsaParameter.GetInstance(const AEncoded: TCryptoLibByteArray): IDsaParameter;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TDsaParameter.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TDsaParameter.GetInstance(const AObj: IAsn1TaggedObject; AExplicitly: Boolean): IDsaParameter;
begin
  Result := TDsaParameter.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TDsaParameter.GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDsaParameter;
begin
  Result := TDsaParameter.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

end.
