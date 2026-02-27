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

unit ClpECCurveConstants;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type
  TECCurveConstants = class sealed(TObject)
  public
    const COORD_AFFINE = 0;
    const COORD_HOMOGENEOUS = 1;
    const COORD_JACOBIAN = 2;
    const COORD_JACOBIAN_CHUDNOVSKY = 3;
    const COORD_JACOBIAN_MODIFIED = 4;
    const COORD_LAMBDA_AFFINE = 5;
    const COORD_LAMBDA_PROJECTIVE = 6;
    const COORD_SKEWED = 7;

    class function GetAllCoordinateSystems: TCryptoLibInt32Array; static;
  end;

implementation

class function TECCurveConstants.GetAllCoordinateSystems: TCryptoLibInt32Array;
begin
  Result := TCryptoLibInt32Array.Create(COORD_AFFINE, COORD_HOMOGENEOUS,
    COORD_JACOBIAN, COORD_JACOBIAN_CHUDNOVSKY, COORD_JACOBIAN_MODIFIED,
    COORD_LAMBDA_AFFINE, COORD_LAMBDA_PROJECTIVE, COORD_SKEWED);
end;

end.
