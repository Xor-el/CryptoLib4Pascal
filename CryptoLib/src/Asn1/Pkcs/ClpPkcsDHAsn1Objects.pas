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

unit ClpPkcsDHAsn1Objects;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpIPkcsDHAsn1Objects,
  ClpBigInteger,
  ClpCryptoLibTypes;

resourcestring
  SBadSequenceSize = 'Bad sequence size: %d';

type
  /// <summary>
  /// The DHParameter object (PKCS#3: P, G, optional L).
  /// </summary>
  TDHParameter = class(TAsn1Encodable, IDHParameter)
  strict private
  var
    FP, FG: IDerInteger;
    FL: IDerInteger;

    function GetP: TBigInteger; inline;
    function GetG: TBigInteger; inline;
    function GetL: IDerInteger; inline;

    constructor Create(const ASeq: IAsn1Sequence); overload;

  public
    constructor Create(const AP, AG: TBigInteger; AL: Int32); overload;

    class function GetInstance(AObj: TObject): IDHParameter; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IDHParameter; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IDHParameter; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IDHParameter; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IDHParameter; static;

    function ToAsn1Object: IAsn1Object; override;

    property P: TBigInteger read GetP;
    property G: TBigInteger read GetG;
    property L: IDerInteger read GetL;
  end;

implementation

{ TDHParameter }

constructor TDHParameter.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
begin
  inherited Create();
  LCount := ASeq.Count;
  if (LCount < 2) or (LCount > 3) then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);
  FP := TDerInteger.GetInstance(ASeq[0]);
  FG := TDerInteger.GetInstance(ASeq[1]);
  if LCount > 2 then
    FL := TDerInteger.GetInstance(ASeq[2])
  else
    FL := nil;
end;

constructor TDHParameter.Create(const AP, AG: TBigInteger; AL: Int32);
begin
  inherited Create();
  FP := TDerInteger.Create(AP);
  FG := TDerInteger.Create(AG);
  if AL <> 0 then
    FL := TDerInteger.ValueOf(AL)
  else
    FL := nil;
end;

function TDHParameter.GetP: TBigInteger;
begin
  Result := FP.PositiveValue;
end;

function TDHParameter.GetG: TBigInteger;
begin
  Result := FG.PositiveValue;
end;

function TDHParameter.GetL: IDerInteger;
begin
  Result := FL;
end;

class function TDHParameter.GetInstance(AObj: TObject): IDHParameter;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if Supports(AObj, IDHParameter, Result) then
    Exit;
  Result := TDHParameter.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TDHParameter.GetInstance(const AObj: IAsn1Convertible): IDHParameter;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if Supports(AObj, IDHParameter, Result) then
    Exit;
  Result := TDHParameter.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TDHParameter.GetInstance(const AEncoded: TCryptoLibByteArray): IDHParameter;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;
  Result := TDHParameter.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TDHParameter.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IDHParameter;
begin
  Result := TDHParameter.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TDHParameter.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IDHParameter;
begin
  Result := TDHParameter.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

function TDHParameter.ToAsn1Object: IAsn1Object;
begin
  if FL <> nil then
    Result := TDerSequence.Create([FP, FG, FL])
  else
    Result := TDerSequence.Create([FP, FG]);
end;

end.
