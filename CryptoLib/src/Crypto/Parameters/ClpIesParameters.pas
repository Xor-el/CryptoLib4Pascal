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

unit ClpIesParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpICipherParameters,
  ClpIIesParameters,
  ClpCryptoLibTypes;

type

  /// <summary>
  /// Parameters for using an integrated cipher in stream mode.
  /// </summary>
  TIesParameters = class(TInterfacedObject, IIesParameters, ICipherParameters)

  strict private
  var
    FDerivation, FEncoding: TCryptoLibByteArray;
    FMacKeySize: Int32;

  strict protected
    function GetMacKeySize(): Int32; inline;

  public
    function GetDerivationV(): TCryptoLibByteArray; inline;
    function GetEncodingV(): TCryptoLibByteArray; inline;

    property MacKeySize: Int32 read GetMacKeySize;

    constructor Create(const ADerivation, AEncoding: TCryptoLibByteArray;
      AMacKeySize: Int32);
  end;

  TIesCipherParameters = class sealed(TInterfacedObject, IIesCipherParameters,
    ICipherParameters)

  strict private
  var
    FPrivateKey: ICipherParameters;
    FPublicKey: ICipherParameters;
    FIesParameters: IIesParameters;

    function GetPrivateKey: ICipherParameters; inline;
    function GetPublicKey: ICipherParameters; inline;
    function GetIesParameters: IIesParameters; inline;

  public
    constructor Create(const APrivateKey, APublicKey: ICipherParameters;
      const AIesParameters: IIesParameters);

    property PrivateKey: ICipherParameters read GetPrivateKey;
    property PublicKey: ICipherParameters read GetPublicKey;
    property IesParameters: IIesParameters read GetIesParameters;
  end;

  TIesWithCipherParameters = class(TIesParameters, IIesParameters,
    IIesWithCipherParameters)

  strict private
  var
    FCipherKeySize: Int32;

    function GetCipherKeySize: Int32; inline;

  public
    constructor Create(const ADerivation, AEncoding: TCryptoLibByteArray;
      AMacKeySize, ACipherKeySize: Int32);

    property CipherKeySize: Int32 read GetCipherKeySize;
  end;

implementation

{ TIesParameters }

constructor TIesParameters.Create(const ADerivation,
  AEncoding: TCryptoLibByteArray; AMacKeySize: Int32);
begin
  inherited Create();
  FDerivation := ADerivation;
  FEncoding := AEncoding;
  FMacKeySize := AMacKeySize;
end;

function TIesParameters.GetDerivationV: TCryptoLibByteArray;
begin
  Result := System.Copy(FDerivation);
end;

function TIesParameters.GetEncodingV: TCryptoLibByteArray;
begin
  Result := System.Copy(FEncoding);
end;

function TIesParameters.GetMacKeySize: Int32;
begin
  Result := FMacKeySize;
end;

{ TIesCipherParameters }

constructor TIesCipherParameters.Create(const APrivateKey,
  APublicKey: ICipherParameters; const AIesParameters: IIesParameters);
begin
  inherited Create();
  FPrivateKey := APrivateKey;
  FPublicKey := APublicKey;
  FIesParameters := AIesParameters;
end;

function TIesCipherParameters.GetPrivateKey: ICipherParameters;
begin
  Result := FPrivateKey;
end;

function TIesCipherParameters.GetPublicKey: ICipherParameters;
begin
  Result := FPublicKey;
end;

function TIesCipherParameters.GetIesParameters: IIesParameters;
begin
  Result := FIesParameters;
end;

{ TIesWithCipherParameters }

function TIesWithCipherParameters.GetCipherKeySize: Int32;
begin
  Result := FCipherKeySize;
end;

constructor TIesWithCipherParameters.Create(const ADerivation,
  AEncoding: TCryptoLibByteArray; AMacKeySize, ACipherKeySize: Int32);
begin
  inherited Create(ADerivation, AEncoding, AMacKeySize);
  FCipherKeySize := ACipherKeySize;
end;

end.
