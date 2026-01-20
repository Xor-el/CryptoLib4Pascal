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

unit ClpRsaBlindingFactorGenerator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpBigIntegers,
  ClpICipherParameters,
  ClpParameterUtilities,
  ClpIRsaKeyParameters,
  ClpIRsaBlindingFactorGenerator,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpCryptoLibTypes;

resourcestring
  SGeneratorNotInit = 'Generator not initialised';
  SPublicKeyRequired = 'Generator requires RSA public key';

type
  /// <summary>
  /// Generate a random factor suitable for use with RSA blind signatures.
  /// </summary>
  TRsaBlindingFactorGenerator = class(TInterfacedObject, IRsaBlindingFactorGenerator)

  strict private
  var
    FKey: IRsaKeyParameters;
    FRandom: ISecureRandom;

  public
    constructor Create();

    procedure Init(const param: ICipherParameters);
    function GenerateBlindingFactor: TBigInteger;

  end;

implementation

{ TRsaBlindingFactorGenerator }

constructor TRsaBlindingFactorGenerator.Create;
begin
  inherited Create();
  FKey := nil;
  FRandom := nil;
end;

procedure TRsaBlindingFactorGenerator.Init(const param: ICipherParameters);
var
  LParameters: ICipherParameters;
  providedRandom: ISecureRandom;
begin
  LParameters := TParameterUtilities.GetRandom(param, providedRandom);
  FKey := LParameters as IRsaKeyParameters;

  if providedRandom <> nil then
    FRandom := providedRandom
  else
    FRandom := TSecureRandom.Create();

  if FKey.IsPrivate then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SPublicKeyRequired);
  end;
end;

function TRsaBlindingFactorGenerator.GenerateBlindingFactor: TBigInteger;
var
  m: TBigInteger;
  len: Int32;
  factor: TBigInteger;
begin
  if FKey = nil then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes(@SGeneratorNotInit);
  end;

  m := FKey.Modulus;
  len := m.BitLength - 1; // must be less than m.BitLength

  repeat
    factor := TBigInteger.Create(len, FRandom);
  until (factor.CompareTo(TBigInteger.Two) >= 0) and
    TBigIntegers.ModOddIsCoprimeVar(m, factor);

  Result := factor;
end;

end.
