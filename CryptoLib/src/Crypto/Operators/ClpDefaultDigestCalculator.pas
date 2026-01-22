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

unit ClpDefaultDigestCalculator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpIStreamCalculator,
  ClpIBlockResult,
  ClpIDigest,
  ClpDigestSink,
  ClpDefaultDigestResult;

type
  /// <summary>
  /// Default implementation of IStreamCalculator for digest operations.
  /// </summary>
  TDefaultDigestCalculator = class sealed(TInterfacedObject, IStreamCalculator<IBlockResult>)

  strict private
  var
    FDigestSink: TDigestSink;

  public
    constructor Create(const ADigest: IDigest);
    destructor Destroy; override;

    function GetStream: TStream;
    function GetResult: IBlockResult;

    property Stream: TStream read GetStream;
  end;

implementation

{ TDefaultDigestCalculator }

constructor TDefaultDigestCalculator.Create(const ADigest: IDigest);
begin
  inherited Create();
  FDigestSink := TDigestSink.Create(ADigest);
end;

destructor TDefaultDigestCalculator.Destroy;
begin
  FDigestSink.Free;
  inherited Destroy;
end;

function TDefaultDigestCalculator.GetStream: TStream;
begin
  Result := FDigestSink;
end;

function TDefaultDigestCalculator.GetResult: IBlockResult;
begin
  Result := TDefaultDigestResult.Create(FDigestSink.Digest);
end;

end.
