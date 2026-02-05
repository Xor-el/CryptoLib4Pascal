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

unit ClpCipherKeyGenerator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpSecureRandom,
  ClpISecureRandom,
  ClpICipherKeyGenerator,
  ClpKeyGenerationParameters,
  ClpIKeyGenerationParameters,
  ClpCryptoLibTypes;

resourcestring
  SInvalidStrengthValue =
    'Strength must be a Positive Value, "defaultStrength"';
  SParametersNil = 'Parameters Cannot be Nil';
  SGeneratorNotInitialized = 'Generator has not been Initialised';

type

  /// <summary>
  /// The base class for symmetric, or secret, cipher key generators.
  /// </summary>
  TCipherKeyGenerator = class(TInterfacedObject, ICipherKeyGenerator)

  strict private
  var
    FUninitialised: Boolean;
    FDefaultStrength: Int32;

    function GetDefaultStrength: Int32; inline;

  strict protected
  var
    FRandom: ISecureRandom;
    FStrength: Int32;

    procedure EngineInit(const AParameters: IKeyGenerationParameters); virtual;
    function EngineGenerateKey: TCryptoLibByteArray; virtual;

  public

    constructor Create(); overload;
    constructor Create(ADefaultStrength: Int32); overload;

    /// <summary>
    /// initialise the key generator.
    /// </summary>
    /// <param name="parameters">
    /// the parameters to be used for key generation
    /// </param>
    procedure Init(const AParameters: IKeyGenerationParameters);

    /// <summary>
    /// Generate a secret key.
    /// </summary>
    /// <returns>
    /// a byte array containing the key value.
    /// </returns>
    function GenerateKey: TCryptoLibByteArray;

    property DefaultStrength: Int32 read GetDefaultStrength;
  end;

implementation

{ TCipherKeyGenerator }

constructor TCipherKeyGenerator.Create;
begin
  inherited Create();
  FUninitialised := True;
end;

constructor TCipherKeyGenerator.Create(ADefaultStrength: Int32);
begin
  inherited Create();
  FUninitialised := True;
  if ADefaultStrength < 1 then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidStrengthValue);
  end;

  FDefaultStrength := ADefaultStrength;
end;

function TCipherKeyGenerator.EngineGenerateKey: TCryptoLibByteArray;
begin
  Result := TSecureRandom.GetNextBytes(FRandom, FStrength);
end;

procedure TCipherKeyGenerator.EngineInit(const AParameters: IKeyGenerationParameters);
begin
  FRandom := AParameters.Random;
  FStrength := (AParameters.Strength + 7) div 8;
end;

function TCipherKeyGenerator.GenerateKey: TCryptoLibByteArray;
begin
  if FUninitialised then
  begin
    if FDefaultStrength < 1 then
      raise EInvalidOperationCryptoLibException.CreateRes(@SGeneratorNotInitialized);

    FUninitialised := False;
    EngineInit(TKeyGenerationParameters.Create(TSecureRandom.Create()
      as ISecureRandom, FDefaultStrength) as IKeyGenerationParameters);
  end;

  Result := EngineGenerateKey();
end;

function TCipherKeyGenerator.GetDefaultStrength: Int32;
begin
  Result := FDefaultStrength;
end;

procedure TCipherKeyGenerator.Init(const AParameters: IKeyGenerationParameters);
begin
  if AParameters = nil then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SParametersNil);
  end;

  FUninitialised := False;

  EngineInit(AParameters);
end;

end.
