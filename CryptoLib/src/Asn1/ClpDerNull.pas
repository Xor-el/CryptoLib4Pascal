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

unit ClpDerNull;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpAsn1Tags,
  ClpIProxiedInterface,
  ClpAsn1Null,
  ClpIDerNull;

type

  /// <summary>
  /// A Null object.
  /// </summary>
  TDerNull = class(TAsn1Null, IDerNull)

  strict private

    class function GetInstance: IDerNull; static; inline;

  class var

    FInstance: IDerNull;
    FZeroBytes: TCryptoLibByteArray;

    class constructor DerNull();

  strict protected
    constructor Create(dummy: Int32);
    function Asn1Equals(const asn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;

  public

    procedure Encode(const derOut: IDerOutputStream); override;
    class property Instance: IDerNull read GetInstance;

  end;

implementation

{ TDerNull }

function TDerNull.Asn1Equals(const asn1Object: IAsn1Object): Boolean;
begin
  result := Supports(asn1Object, IDerNull);
end;

function TDerNull.Asn1GetHashCode: Int32;
begin
  result := -1;
end;

{$IFNDEF _FIXINSIGHT_}

constructor TDerNull.Create(dummy: Int32);
begin
  Inherited Create();
end;
{$ENDIF}

class constructor TDerNull.DerNull;
begin
  FInstance := TDerNull.Create(0);
  System.SetLength(FZeroBytes, 0);
end;

procedure TDerNull.Encode(const derOut: IDerOutputStream);
begin
  derOut.WriteEncoded(TAsn1Tags.Null, FZeroBytes);
end;

class function TDerNull.GetInstance: IDerNull;
begin
  result := FInstance;
end;

end.
