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

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpDefaultVerifierCalculator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpIStreamCalculator,
  ClpIVerifier,
  ClpISigner,
  ClpSignerSink,
  ClpDefaultVerifierResult;

type
  /// <summary>
  /// Default implementation of IStreamCalculator for verifier operations.
  /// </summary>
  TDefaultVerifierCalculator = class sealed(TInterfacedObject, IStreamCalculator<IVerifier>)

  strict private
  var
    FSignerSink: TSignerSink;

  public
    constructor Create(const ASigner: ISigner);
    destructor Destroy; override;

    function GetStream: TStream;
    function GetResult: IVerifier;

    property Stream: TStream read GetStream;
  end;

implementation

{ TDefaultVerifierCalculator }

constructor TDefaultVerifierCalculator.Create(const ASigner: ISigner);
begin
  inherited Create();
  FSignerSink := TSignerSink.Create(ASigner);
end;

destructor TDefaultVerifierCalculator.Destroy;
begin
  FSignerSink.Free;
  inherited Destroy;
end;

function TDefaultVerifierCalculator.GetStream: TStream;
begin
  Result := FSignerSink;
end;

function TDefaultVerifierCalculator.GetResult: IVerifier;
begin
  Result := TDefaultVerifierResult.Create(FSignerSink.Signer);
end;

end.
