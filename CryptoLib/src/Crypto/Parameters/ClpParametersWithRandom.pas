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

unit ClpParametersWithRandom;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpIParametersWithRandom,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpICipherParameters;

resourcestring
  SParameters = 'Parameters';
  SRandom = 'Random';

type
  TParametersWithRandom = class(TInterfacedObject, ICipherParameters,
    IParametersWithRandom)

  strict private
  var
    FParameters: ICipherParameters;
    FRandom: ISecureRandom;
    function GetRandom: ISecureRandom; inline;
    function GetParameters: ICipherParameters; inline;

  public

    constructor Create(const AParameters: ICipherParameters); overload;

    constructor Create(const AParameters: ICipherParameters;
      const ARandom: ISecureRandom); overload;

    property Random: ISecureRandom read GetRandom;

    property Parameters: ICipherParameters read GetParameters;

  end;

implementation

{ TParametersWithRandom }

constructor TParametersWithRandom.Create(const AParameters: ICipherParameters);
begin
  Create(AParameters, TSecureRandom.Create() as ISecureRandom);
end;

constructor TParametersWithRandom.Create(const AParameters: ICipherParameters;
  const ARandom: ISecureRandom);
begin
  inherited Create();
  if (AParameters = nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SParameters);
  end;

  if (ARandom = nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SRandom);
  end;

  FParameters := AParameters;
  FRandom := ARandom;
end;

function TParametersWithRandom.GetParameters: ICipherParameters;
begin
  Result := FParameters;
end;

function TParametersWithRandom.GetRandom: ISecureRandom;
begin
  Result := FRandom;
end;

end.
