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

unit ClpCertStatus;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIPkixTypes,
  ClpNullable;

type
  /// <summary>Revocation status accumulated over the CRLs checked for a certificate; keeps the reason
  /// code apart from whether the certificate is revoked.</summary>
  TCertStatus = class(TInterfacedObject, ICertStatus)

  strict private
  var
    FRevocationDate: TNullable<TDateTime>;
    FReasonCode: TNullable<Int32>;

  strict protected
    function GetIsRevoked: Boolean;
    function GetRevocationDate: TNullable<TDateTime>;
    function GetReasonCode: TNullable<Int32>;
    function GetReason: Int32; overload;
    function GetReasonText: String;
    procedure SetRevoked(const ARevocationDate: TDateTime; const AReasonCode: TNullable<Int32>);
    procedure SetUnrevoked();

  public
    constructor Create();

    /// <summary>Whether <paramref name="AReasonCode" /> is a CRLReason defined by RFC 5280 5.3.1.</summary>
    class function IsReasonCodeKnown(AReasonCode: Int32): Boolean; static;
    /// <summary>The CRLReason to process an entry by: its reason code if defined, else unspecified.</summary>
    class function GetReason(const AReasonCode: TNullable<Int32>): Int32; overload; static;
  end;

implementation

const
  // indexed by CRLReason value (RFC 5280 5.3.1); 7 is unused
  ReasonNames: array [0 .. 10] of String = ('unspecified', 'keyCompromise', 'cACompromise',
    'affiliationChanged', 'superseded', 'cessationOfOperation', 'certificateHold', 'unknown',
    'removeFromCRL', 'privilegeWithdrawn', 'aACompromise');

{ TCertStatus }

constructor TCertStatus.Create();
begin
  inherited Create();
  FRevocationDate := TNullable<TDateTime>.None;
  FReasonCode := TNullable<Int32>.None;
end;

class function TCertStatus.IsReasonCodeKnown(AReasonCode: Int32): Boolean;
begin
  // value 7 is not used (RFC 5280 5.3.1)
  Result := (AReasonCode >= 0) and (AReasonCode <= 10) and (AReasonCode <> 7);
end;

class function TCertStatus.GetReason(const AReasonCode: TNullable<Int32>): Int32;
begin
  if AReasonCode.HasValue and IsReasonCodeKnown(AReasonCode.Value) then
    Result := AReasonCode.Value
  else
    Result := 0; // unspecified
end;

function TCertStatus.GetIsRevoked: Boolean;
begin
  Result := FRevocationDate.HasValue;
end;

function TCertStatus.GetRevocationDate: TNullable<TDateTime>;
begin
  Result := FRevocationDate;
end;

function TCertStatus.GetReasonCode: TNullable<Int32>;
begin
  Result := FReasonCode;
end;

function TCertStatus.GetReason: Int32;
begin
  Result := GetReason(FReasonCode);
end;

function TCertStatus.GetReasonText: String;
begin
  if FReasonCode.HasValue and (not IsReasonCodeKnown(FReasonCode.Value)) then
    Result := Format('(unknown code: %d)', [FReasonCode.Value])
  else
    Result := ReasonNames[GetReason(FReasonCode)];
end;

procedure TCertStatus.SetRevoked(const ARevocationDate: TDateTime; const AReasonCode: TNullable<Int32>);
begin
  FRevocationDate := TNullable<TDateTime>.Some(ARevocationDate);
  FReasonCode := AReasonCode;
end;

procedure TCertStatus.SetUnrevoked();
begin
  FRevocationDate := TNullable<TDateTime>.None;
  FReasonCode := TNullable<Int32>.None;
end;

end.
