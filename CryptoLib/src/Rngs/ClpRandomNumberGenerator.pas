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

unit ClpRandomNumberGenerator;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpOSRandomProvider,
  ClpIRandomNumberGenerator,
  ClpIRandomSourceProvider;

resourcestring
  SRandomNumberGeneratorOutputBufferNil =
    'Random Number Generator Output Buffer Cannot Be Nil';
  SRandomSourceProviderNil =
    'Random Source Provider Cannot Be Nil';

type
  TRandomNumberGenerator = class abstract(TInterfacedObject, IRandomNumberGenerator)

  strict protected
    class procedure ValidateOutputBufferNotNull(const ABuffer
      : TCryptoLibByteArray); static; inline;

  public

    class function CreateRng(): IRandomNumberGenerator; overload; static;

    class function CreateRng(const ARandomSource: IRandomSourceProvider)
      : IRandomNumberGenerator; overload; static;

    procedure GetBytes(const AData: TCryptoLibByteArray); virtual; abstract;

    procedure GetNonZeroBytes(const AData: TCryptoLibByteArray); virtual; abstract;

  end;


implementation

type
  TDefaultRandomNumberGenerator = class sealed(TRandomNumberGenerator,
    IRandomNumberGenerator)

  strict private
    FRandomSource: IRandomSourceProvider;

  public
    constructor Create(const ARandomSource: IRandomSourceProvider);

    procedure GetBytes(const AData: TCryptoLibByteArray); override;

    procedure GetNonZeroBytes(const AData: TCryptoLibByteArray); override;

  end;

{ TRandomNumberGenerator }

class procedure TRandomNumberGenerator.ValidateOutputBufferNotNull
  (const ABuffer: TCryptoLibByteArray);
begin
  if ABuffer = nil then
  begin
    raise EArgumentNilCryptoLibException.CreateRes
      (@SRandomNumberGeneratorOutputBufferNil);
  end;
end;

class function TRandomNumberGenerator.CreateRng: IRandomNumberGenerator;
begin
  result := TDefaultRandomNumberGenerator.Create(TOSRandomProvider.Instance);
end;

class function TRandomNumberGenerator.CreateRng(const ARandomSource
  : IRandomSourceProvider): IRandomNumberGenerator;
begin
  if ARandomSource = nil then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SRandomSourceProviderNil);
  end;
  result := TDefaultRandomNumberGenerator.Create(ARandomSource);
end;

{ TDefaultRandomNumberGenerator }

constructor TDefaultRandomNumberGenerator.Create
  (const ARandomSource: IRandomSourceProvider);
begin
  inherited Create;
  FRandomSource := ARandomSource;
end;

procedure TDefaultRandomNumberGenerator.GetBytes
  (const AData: TCryptoLibByteArray);
begin
  TRandomNumberGenerator.ValidateOutputBufferNotNull(AData);
  FRandomSource.GetBytes(AData);
end;

procedure TDefaultRandomNumberGenerator.GetNonZeroBytes
  (const AData: TCryptoLibByteArray);
begin
  TRandomNumberGenerator.ValidateOutputBufferNotNull(AData);
  FRandomSource.GetNonZeroBytes(AData);
end;

end.
