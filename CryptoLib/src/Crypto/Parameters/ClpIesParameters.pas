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

unit ClpIESParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpICipherParameters,
  ClpIIESParameters,
  ClpCryptoLibTypes;

type

  /// <summary>
  /// parameters for using an integrated cipher in stream mode.
  /// </summary>
  TIesParameters = class(TInterfacedObject, IIesParameters, ICipherParameters)

  strict private
  var
    Fderivation, Fencoding: TCryptoLibByteArray;
    FmacKeySize: Int32;
  strict protected
    function GetMacKeySize(): Int32; inline;
  public
    function GetDerivationV(): TCryptoLibByteArray; inline;
    function GetEncodingV(): TCryptoLibByteArray; inline;
    property MacKeySize: Int32 read GetMacKeySize;

    /// <param name="ADerivation">
    /// the derivation parameter for the KDF function.
    /// </param>
    /// <param name="AEncoding">
    /// the encoding parameter for the KDF function.
    /// </param>
    /// <param name="AMacKeySize">
    /// the size of the MAC key (in bits).
    /// </param>
    constructor Create(const ADerivation, AEncoding: TCryptoLibByteArray;
      AMacKeySize: Int32);
  end;

implementation

{ TIESParameters }

constructor TIesParameters.Create(const ADerivation,
  AEncoding: TCryptoLibByteArray; AMacKeySize: Int32);
begin
  Inherited Create();
  Fderivation := ADerivation;
  Fencoding := AEncoding;
  FmacKeySize := AMacKeySize;
end;

function TIesParameters.GetDerivationV: TCryptoLibByteArray;
begin
  Result := System.Copy(Fderivation);
end;

function TIesParameters.GetEncodingV: TCryptoLibByteArray;
begin
  Result := System.Copy(Fencoding);
end;

function TIesParameters.GetMacKeySize: Int32;
begin
  Result := FmacKeySize;
end;

end.
