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

unit ClpReasonsMask;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIPkixTypes,
  ClpX509Asn1Objects;

type
  /// <summary>
  /// The set of CRL revocation reasons a distribution point covers, accumulated across CRLs.
  /// </summary>
  TReasonsMask = class(TInterfacedObject, IReasonsMask)

  strict private
  var
    FReasons: Int32;

  strict protected
    function GetReasons: Int32;

  public
    /// <summary>Every revocation reason flag set.</summary>
    class function AllReasons: Int32; static;

    constructor Create(); overload;
    constructor Create(AReasons: Int32); overload;

    procedure AddReasons(const AMask: IReasonsMask);
    function IsAllReasons: Boolean;
    function HasNewReasons(const AMask: IReasonsMask): Boolean;
  end;

implementation

{ TReasonsMask }

class function TReasonsMask.AllReasons: Int32;
begin
  Result := TReasonFlags.AACompromise or TReasonFlags.AffiliationChanged or TReasonFlags.CACompromise or
    TReasonFlags.CertificateHold or TReasonFlags.CessationOfOperation or TReasonFlags.KeyCompromise or
    TReasonFlags.PrivilegeWithdrawn or TReasonFlags.Unused or TReasonFlags.Superseded;
end;

constructor TReasonsMask.Create();
begin
  Create(0);
end;

constructor TReasonsMask.Create(AReasons: Int32);
begin
  inherited Create();
  FReasons := AReasons;
end;

function TReasonsMask.GetReasons: Int32;
begin
  Result := FReasons;
end;

procedure TReasonsMask.AddReasons(const AMask: IReasonsMask);
begin
  FReasons := FReasons or AMask.Reasons;
end;

function TReasonsMask.IsAllReasons: Boolean;
begin
  Result := (AllReasons and (not FReasons)) = 0;
end;

function TReasonsMask.HasNewReasons(const AMask: IReasonsMask): Boolean;
begin
  Result := (AMask.Reasons and (not FReasons)) <> 0;
end;

end.
