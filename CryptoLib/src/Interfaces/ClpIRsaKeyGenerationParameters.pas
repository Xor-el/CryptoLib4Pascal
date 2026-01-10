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

unit ClpIRsaKeyGenerationParameters;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIKeyGenerationParameters;

type
  IRsaKeyGenerationParameters = interface(IKeyGenerationParameters)
    ['{C3D4E5F6-A7B8-9012-CDEF-123456789012}']

    function GetPublicExponent: TBigInteger;
    function GetCertainty: Int32;

    function Equals(const other: IRsaKeyGenerationParameters): Boolean;

    property PublicExponent: TBigInteger read GetPublicExponent;
    property Certainty: Int32 read GetCertainty;

  end;

implementation

end.
