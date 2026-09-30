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

unit ClpCertificateTrustBlock;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIAsn1Core,
  ClpAsn1Core,
  ClpIAsn1Objects,
  ClpAsn1Objects,
  ClpICertificateTrustBlock,
  ClpCryptoLibTypes;

type
  TCertificateTrustBlock = class(TInterfacedObject, ICertificateTrustBlock)
  strict private
  var
    FUses: IAsn1Sequence;
    FProhibitions: IAsn1Sequence;
    FAlias: IDerUtf8String;

    class function ToSequence(const AOids: TCryptoLibGenericArray<IDerObjectIdentifier>): IAsn1Sequence; static;
    class function ToSet(const ASeq: IAsn1Sequence): TCryptoLibGenericArray<IDerObjectIdentifier>; static;

  public
    constructor Create(const AUses: TCryptoLibGenericArray<IDerObjectIdentifier>); overload;
    constructor Create(const AAlias: String;
      const AUses: TCryptoLibGenericArray<IDerObjectIdentifier>); overload;
    constructor Create(const AAlias: String;
      const AUses, AProhibitions: TCryptoLibGenericArray<IDerObjectIdentifier>); overload;
    constructor Create(const AEncoded: TCryptoLibByteArray); overload;

    function GetAlias: String;
    function GetUses: TCryptoLibGenericArray<IDerObjectIdentifier>;
    function GetProhibitions: TCryptoLibGenericArray<IDerObjectIdentifier>;
    function ToAsn1Sequence: IAsn1Sequence;
  end;

implementation

{ TCertificateTrustBlock }

constructor TCertificateTrustBlock.Create(const AUses: TCryptoLibGenericArray<IDerObjectIdentifier>);
begin
  Create('', AUses, nil);
end;

constructor TCertificateTrustBlock.Create(const AAlias: String;
  const AUses: TCryptoLibGenericArray<IDerObjectIdentifier>);
begin
  Create(AAlias, AUses, nil);
end;

constructor TCertificateTrustBlock.Create(const AAlias: String;
  const AUses, AProhibitions: TCryptoLibGenericArray<IDerObjectIdentifier>);
begin
  inherited Create();
  FUses := ToSequence(AUses);
  FProhibitions := ToSequence(AProhibitions);
  if AAlias <> '' then
    FAlias := TDerUtf8String.Create(AAlias)
  else
    FAlias := nil;
end;

constructor TCertificateTrustBlock.Create(const AEncoded: TCryptoLibByteArray);
var
  LSeq: IAsn1Sequence;
  LIdx: Int32;
  LElement: IAsn1Encodable;
  LSequence: IAsn1Sequence;
  LTagged: IAsn1TaggedObject;
  LUtf8: IDerUtf8String;
begin
  inherited Create();
  LSeq := TAsn1Sequence.GetInstance(AEncoded);
  for LIdx := 0 to LSeq.Count - 1 do
  begin
    LElement := LSeq[LIdx];
    if Supports(LElement, IAsn1Sequence, LSequence) then
      FUses := LSequence
    else if Supports(LElement, IAsn1TaggedObject, LTagged) then
      FProhibitions := TAsn1Sequence.GetInstance(LTagged, False)
    else if Supports(LElement, IDerUtf8String, LUtf8) then
      FAlias := LUtf8;
  end;
end;

class function TCertificateTrustBlock.ToSequence(
  const AOids: TCryptoLibGenericArray<IDerObjectIdentifier>): IAsn1Sequence;
var
  LVec: IAsn1EncodableVector;
  LIdx: Int32;
begin
  if (AOids = nil) or (System.Length(AOids) < 1) then
  begin
    Result := nil;
    Exit;
  end;

  LVec := TAsn1EncodableVector.Create();
  for LIdx := 0 to System.High(AOids) do
    LVec.Add(AOids[LIdx] as IAsn1Encodable);
  Result := TDerSequence.Create(LVec);
end;

class function TCertificateTrustBlock.ToSet(
  const ASeq: IAsn1Sequence): TCryptoLibGenericArray<IDerObjectIdentifier>;
var
  LIdx: Int32;
begin
  if ASeq = nil then
  begin
    Result := nil;
    Exit;
  end;

  System.SetLength(Result, ASeq.Count);
  for LIdx := 0 to ASeq.Count - 1 do
    Result[LIdx] := TDerObjectIdentifier.GetInstance(ASeq[LIdx]);
end;

function TCertificateTrustBlock.GetAlias: String;
begin
  if FAlias <> nil then
    Result := FAlias.GetString()
  else
    Result := '';
end;

function TCertificateTrustBlock.GetUses: TCryptoLibGenericArray<IDerObjectIdentifier>;
begin
  Result := ToSet(FUses);
end;

function TCertificateTrustBlock.GetProhibitions: TCryptoLibGenericArray<IDerObjectIdentifier>;
begin
  Result := ToSet(FProhibitions);
end;

function TCertificateTrustBlock.ToAsn1Sequence: IAsn1Sequence;
var
  LVec: IAsn1EncodableVector;
begin
  LVec := TAsn1EncodableVector.Create();
  if FUses <> nil then
    LVec.Add(FUses as IAsn1Encodable);
  if FProhibitions <> nil then
    LVec.Add(TDerTaggedObject.Create(False, 0, FProhibitions) as IAsn1Encodable);
  if FAlias <> nil then
    LVec.Add(FAlias as IAsn1Encodable);
  Result := TDerSequence.Create(LVec);
end;

end.
