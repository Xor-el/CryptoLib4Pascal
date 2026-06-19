{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit PqcTestSampler;

interface

uses
  SysUtils;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

type
  TPqcTestSampler = class sealed(TObject)
  strict private
    FFull: Boolean;
    FOffset: Int32;
    function ShouldSkip(ACount: Int32): Boolean;
  public
    constructor Create(AFull: Boolean = False);
    function SkipTest(const ACount: string): Boolean; overload;
    function SkipTest(ACount: Int32): Boolean; overload;
  end;

implementation

{ TPqcTestSampler }

constructor TPqcTestSampler.Create(AFull: Boolean);
begin
  inherited Create;
  FFull := AFull;
  Randomize;
  FOffset := Random(10);
end;

function TPqcTestSampler.ShouldSkip(ACount: Int32): Boolean;
begin
  Result := (ACount <> 0) and ((ACount + FOffset) mod 9 <> 0);
end;

function TPqcTestSampler.SkipTest(const ACount: string): Boolean;
begin
  Result := SkipTest(StrToInt(ACount));
end;

function TPqcTestSampler.SkipTest(ACount: Int32): Boolean;
begin
  Result := (not FFull) and ShouldSkip(ACount);
end;

end.
