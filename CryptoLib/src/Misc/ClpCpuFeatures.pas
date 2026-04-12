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

unit ClpCpuFeatures;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpSimdLevels,
  ClpX86SimdFeatures,
  ClpArmSimdFeatures;

type
  TCpuFeaturesX86 = class of TX86SimdFeatures;
  TCpuFeaturesArm = class of TArmSimdFeatures;

  TCpuFeatures = class sealed(TObject)
  strict private
    class function GetX86(): TCpuFeaturesX86; static;
    class function GetArm(): TCpuFeaturesArm; static;

  public
    class property X86: TCpuFeaturesX86 read GetX86;
    class property Arm: TCpuFeaturesArm read GetArm;
  end;

implementation

{ TCpuFeatures }

class function TCpuFeatures.GetX86(): TCpuFeaturesX86;
begin
  Result := TX86SimdFeatures;
end;

class function TCpuFeatures.GetArm(): TCpuFeaturesArm;
begin
  Result := TArmSimdFeatures;
end;

end.
