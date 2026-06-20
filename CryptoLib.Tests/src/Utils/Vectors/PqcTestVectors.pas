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

unit PqcTestVectors;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  RspTxtVectorParser;

type
  TPqcTestVectors = class sealed(TObject)
  public
    class procedure RunVectors(const ARelativePath: string;
      ACallback: TRspTxtVectorCallback); static;
  end;

implementation

{ TPqcTestVectors }

class procedure TPqcTestVectors.RunVectors(const ARelativePath: string;
  ACallback: TRspTxtVectorCallback);
begin
  TRspTxtVectorParser.RunVectors(ARelativePath, ACallback);
end;

end.
