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
  /// <summary>
  /// Revocation status of a certificate, carried through path validation. Values other than
  /// <see cref="Unrevoked" /> and <see cref="Undetermined" /> are CRL reason codes.
  /// </summary>
  TCertStatus = class(TInterfacedObject, ICertStatus)

  public const
    Unrevoked = Int32(11);
    Undetermined = Int32(12);

  strict private
  var
    FStatus: Int32;
    FRevocationDate: TNullable<TDateTime>;

  strict protected
    function GetStatus: Int32;
    procedure SetStatus(AValue: Int32);
    function GetRevocationDate: TNullable<TDateTime>;
    procedure SetRevocationDate(const AValue: TNullable<TDateTime>);

  public
    constructor Create();
  end;

implementation

{ TCertStatus }

constructor TCertStatus.Create();
begin
  inherited Create();
  FStatus := Unrevoked;
  FRevocationDate := TNullable<TDateTime>.None;
end;

function TCertStatus.GetStatus: Int32;
begin
  Result := FStatus;
end;

procedure TCertStatus.SetStatus(AValue: Int32);
begin
  FStatus := AValue;
end;

function TCertStatus.GetRevocationDate: TNullable<TDateTime>;
begin
  Result := FRevocationDate;
end;

procedure TCertStatus.SetRevocationDate(const AValue: TNullable<TDateTime>);
begin
  FRevocationDate := AValue;
end;

end.
