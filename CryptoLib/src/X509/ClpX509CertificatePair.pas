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

unit ClpX509CertificatePair;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIX509CertificatePair,
  ClpIX509Certificate,
  ClpX509Certificate,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpAsn1Core,
  ClpAsn1Objects,
  ClpCryptoLibTypes;

resourcestring
  SAtLeastOneOfPairPresent = 'At least one of the pair shall be present';

type
  /// <summary>
  /// Cross certificate pair (RFC 2587). Forward = cert from other CA to this CA; Reverse = cert from this CA to other CA.
  /// </summary>
  TX509CertificatePair = class(TInterfacedObject, IX509CertificatePair)

  strict private
  var
    FForward: IX509Certificate;
    FReverse: IX509Certificate;

  strict protected
    function GetForward: IX509Certificate;
    function GetReverse: IX509Certificate;

  public
    constructor Create(const AForward, AReverse: IX509Certificate); overload;
    constructor Create(const APair: ICertificatePair); overload;

    function GetCertificatePair: ICertificatePair;
    function GetEncoded: TCryptoLibByteArray;

    function Equals(const AOther: IX509CertificatePair): Boolean; reintroduce;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI} override;

    property Forward: IX509Certificate read GetForward;
    property Reverse: IX509Certificate read GetReverse;

  end;

implementation

{ TX509CertificatePair }

constructor TX509CertificatePair.Create(const AForward, AReverse: IX509Certificate);
begin
  inherited Create();
  if (AForward = nil) and (AReverse = nil) then
    raise EArgumentCryptoLibException.Create(SAtLeastOneOfPairPresent);
  FForward := AForward;
  FReverse := AReverse;
end;

constructor TX509CertificatePair.Create(const APair: ICertificatePair);
var
  LForwardStruct: IX509CertificateStructure;
  LReverseStruct: IX509CertificateStructure;
begin
  inherited Create();
  if APair = nil then
    raise EArgumentNilCryptoLibException.Create('pair');

  LForwardStruct := APair.Forward;
  LReverseStruct := APair.Reverse;

  if (LForwardStruct = nil) and (LReverseStruct = nil) then
    raise EArgumentCryptoLibException.Create(SAtLeastOneOfPairPresent);

  if LForwardStruct <> nil then
    FForward := TX509Certificate.Create(LForwardStruct)
  else
    FForward := nil;

  if LReverseStruct <> nil then
    FReverse := TX509Certificate.Create(LReverseStruct)
  else
    FReverse := nil;
end;

function TX509CertificatePair.GetForward: IX509Certificate;
begin
  Result := FForward;
end;

function TX509CertificatePair.GetReverse: IX509Certificate;
begin
  Result := FReverse;
end;

function TX509CertificatePair.GetCertificatePair: ICertificatePair;
var
  LForwardStruct: IX509CertificateStructure;
  LReverseStruct: IX509CertificateStructure;
begin
  LForwardStruct := nil;
  LReverseStruct := nil;
  if FForward <> nil then
    LForwardStruct := FForward.CertificateStructure;
  if FReverse <> nil then
    LReverseStruct := FReverse.CertificateStructure;
  Result := TCertificatePair.Create(LForwardStruct, LReverseStruct);
end;

function TX509CertificatePair.GetEncoded: TCryptoLibByteArray;
var
  LPair: ICertificatePair;
begin
  try
    LPair := GetCertificatePair();
    Result := LPair.GetEncoded(TAsn1Encodable.Der);
  except
    on E: Exception do
      raise ECertificateCryptoLibException.Create('Failed to encode certificate pair: ' + E.Message);
  end;
end;

function TX509CertificatePair.Equals(const AOther: IX509CertificatePair): Boolean;
var
  LOtherForward, LOtherReverse: IX509Certificate;
  LForwardEq, LReverseEq: Boolean;
begin
  if (Self as IX509CertificatePair) = AOther then
  begin
    Result := True;
    Exit;
  end;

  if AOther = nil then
  begin
    Result := False;
    Exit;
  end;

  LOtherForward := AOther.Forward;
  LOtherReverse := AOther.Reverse;

  if (FForward = nil) and (LOtherForward = nil) then
    LForwardEq := True
  else if (FForward = nil) or (LOtherForward = nil) then
    LForwardEq := False
  else
    LForwardEq := FForward.Equals(LOtherForward);

  if not LForwardEq then
  begin
    Result := False;
    Exit;
  end;

  if (FReverse = nil) and (LOtherReverse = nil) then
    LReverseEq := True
  else if (FReverse = nil) or (LOtherReverse = nil) then
    LReverseEq := False
  else
    LReverseEq := FReverse.Equals(LOtherReverse);

  Result := LReverseEq;
end;

function TX509CertificatePair.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
var
  LHash: Int32;
begin
  LHash := -1;
  if FForward <> nil then
    LHash := LHash xor FForward.GetHashCode;
  if FReverse <> nil then
    LHash := (LHash * 17) xor FReverse.GetHashCode;
  Result := LHash;
end;

end.
