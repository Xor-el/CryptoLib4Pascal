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
  ClpSimdLevels
{$IF DEFINED(CRYPTOLIB_X86)}
  , ClpX86SimdFeatures
{$IFEND}
{$IF DEFINED(CRYPTOLIB_ARM)}
  , ClpArmSimdFeatures
{$IFEND}
  ;

type
{$IF DEFINED(CRYPTOLIB_X86)}
  TCpuFeaturesX86 = class of TX86SimdFeatures;
{$IFEND}
{$IF DEFINED(CRYPTOLIB_ARM)}
  TCpuFeaturesArm = class of TArmSimdFeatures;
{$IFEND}

  TCpuFeatures = class sealed(TObject)
  strict private
{$IF DEFINED(CRYPTOLIB_X86)}
    class function GetX86(): TCpuFeaturesX86; static;
{$IFEND}
{$IF DEFINED(CRYPTOLIB_ARM)}
    class function GetArm(): TCpuFeaturesArm; static;
{$IFEND}

  public
{$IF DEFINED(CRYPTOLIB_X86)}
    class property X86: TCpuFeaturesX86 read GetX86;
{$IFEND}
{$IF DEFINED(CRYPTOLIB_ARM)}
    class property Arm: TCpuFeaturesArm read GetArm;
{$IFEND}
  end;

implementation

{ TCpuFeatures }

{$IF DEFINED(CRYPTOLIB_X86)}
class function TCpuFeatures.GetX86(): TCpuFeaturesX86;
begin
  Result := TX86SimdFeatures;
end;
{$IFEND}

{$IF DEFINED(CRYPTOLIB_ARM)}
class function TCpuFeatures.GetArm(): TCpuFeaturesArm;
begin
  Result := TArmSimdFeatures;
end;
{$IFEND}

end.
