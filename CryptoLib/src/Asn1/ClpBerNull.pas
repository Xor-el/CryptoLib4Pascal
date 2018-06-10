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

unit ClpBerNull;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Tags,
  ClpAsn1OutputStream,
  ClpBerOutputStream,
  ClpDerNull,
  ClpIProxiedInterface,
  ClpIBerNull;

type

  /// <summary>
  /// A BER Null object.
  /// </summary>
  TBerNull = class sealed(TDerNull, IBerNull)

  strict private

    class function GetInstance: IBerNull; static; inline;

    class var

      FInstance: IBerNull;

    constructor Create(dummy: Int32);

    class constructor BerNull();

  public

    procedure Encode(const derOut: IDerOutputStream); override;
    class property Instance: IBerNull read GetInstance;

  end;

implementation

{ TBerNull }

constructor TBerNull.Create(dummy: Int32);
begin
  Inherited Create(dummy);
end;

class constructor TBerNull.BerNull;
begin
  FInstance := TBerNull.Create(0);
end;

procedure TBerNull.Encode(const derOut: IDerOutputStream);
begin

  if ((derOut is TAsn1OutputStream) or (derOut is TBerOutputStream)) then
  begin
    derOut.WriteByte(TAsn1Tags.Null);
  end
  else
  begin
    Inherited Encode(derOut);
  end;
end;

class function TBerNull.GetInstance: IBerNull;
begin
  result := FInstance;
end;

end.
