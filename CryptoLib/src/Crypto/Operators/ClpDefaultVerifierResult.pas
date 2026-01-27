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

unit ClpDefaultVerifierResult;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIVerifier,
  ClpISigner,
  ClpCryptoLibTypes,
  ClpArrayUtilities;

type
  /// <summary>
  /// Default implementation of IVerifier for signature verification operations.
  /// </summary>
  TDefaultVerifierResult = class sealed(TInterfacedObject, IVerifier)

  strict private
  var
    FSigner: ISigner;

  public
    constructor Create(const ASigner: ISigner);

    function IsVerified(const AData: TCryptoLibByteArray): Boolean; overload;
    function IsVerified(const ASource: TCryptoLibByteArray; AOff, ALength: Int32): Boolean; overload;
  end;

implementation

{ TDefaultVerifierResult }

constructor TDefaultVerifierResult.Create(const ASigner: ISigner);
begin
  inherited Create();
  FSigner := ASigner;
end;

function TDefaultVerifierResult.IsVerified(const AData: TCryptoLibByteArray): Boolean;
begin
  Result := FSigner.VerifySignature(AData);
end;

function TDefaultVerifierResult.IsVerified(const ASource: TCryptoLibByteArray; AOff, ALength: Int32): Boolean;
var
  LSignature: TCryptoLibByteArray;
begin
  LSignature := TArrayUtilities.CopyOfRange<Byte>(ASource, AOff, AOff + ALength);
  Result := FSigner.VerifySignature(LSignature);
end;

end.
