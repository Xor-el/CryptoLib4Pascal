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

unit ClpParametersWithIV;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIParametersWithIV,
  ClpICipherParameters,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SIVNil = 'IV Cannot be Nil';

type
  TParametersWithIV = class sealed(TInterfacedObject, IParametersWithIV,
    ICipherParameters)

  strict private
  var
    FParameters: ICipherParameters;
    FIv: TCryptoLibByteArray;

    function GetParameters: ICipherParameters; inline;

  public
    constructor Create(const AParameters: ICipherParameters;
      const AIv: TCryptoLibByteArray); overload;
    constructor Create(const AParameters: ICipherParameters;
      const AIv: TCryptoLibByteArray; AIvOff, AIvLen: Int32); overload;
    destructor Destroy; override;
    function GetIV(): TCryptoLibByteArray; inline;
    property Parameters: ICipherParameters read GetParameters;
    procedure Clear(); inline;

  end;

implementation

{ TParametersWithIV }

constructor TParametersWithIV.Create(const AParameters: ICipherParameters;
  const AIv: TCryptoLibByteArray);
begin
  inherited Create();
  Create(AParameters, AIv, 0, System.Length(AIv))
end;

procedure TParametersWithIV.Clear;
begin
  TArrayUtilities.Fill<Byte>(FIv, 0, System.Length(FIv), Byte(0));
end;

constructor TParametersWithIV.Create(const AParameters: ICipherParameters;
  const AIv: TCryptoLibByteArray; AIvOff, AIvLen: Int32);
begin
  inherited Create();
  // NOTE: 'parameters' may be null to imply key re-use
  if (AIv = nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SIVNil);
  end;

  FParameters := AParameters;
  FIv := TArrayUtilities.CopyOfRange<Byte>(AIv, AIvOff, AIvOff + AIvLen);
end;

destructor TParametersWithIV.Destroy;
begin
  Clear();
  inherited Destroy;
end;

function TParametersWithIV.GetIV: TCryptoLibByteArray;
begin
  Result := System.Copy(FIv);
end;

function TParametersWithIV.GetParameters: ICipherParameters;
begin
  Result := FParameters;
end;

end.
